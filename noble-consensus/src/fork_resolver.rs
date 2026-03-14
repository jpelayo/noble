// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Automatic fork resolution state machine.
//!
//! Pure decision logic — no I/O.  `HealingManager` owns an instance and
//! calls `evaluate()` / `evaluate_cross_chain()` directly each tick,
//! acting on the returned decisions inline.

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

/// Fork resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkResolutionStrategy {
    /// Alert only — never auto-resolve.
    Manual,
    /// Resolve when >66% of peers are on a different fork.
    PeerSupermajority,
    /// Resolve using height as primary factor, chain owner edge as secondary,
    /// and decay-weighted vote legitimacy as tiebreaker for cross-chain.
    /// The chain owner (block 1 proposer) gets a virtual height bonus of
    /// `CHAIN_OWNER_EDGE_BLOCKS`, making their fork win at equal height
    /// and resist switching when slightly behind.
    LongestMostLegitimate,
}

/// Chain owner (block 1 validator) edge in virtual blocks.
/// The owner's chain is treated as this many blocks taller in fork evaluation.
/// Protocol constant — not configurable via TOML.
pub const CHAIN_OWNER_EDGE_BLOCKS: u64 = 5;

/// Fork info fed from node.rs (same data as `getDetectedForks` RPC).
#[derive(Debug, Clone)]
pub struct ForkInfo {
    pub tip_hash: Hash256,
    pub height: u64,
    pub peer_count: usize,
    pub is_local: bool,
    /// Whether the chain owner (block 1's validator) is on this fork.
    pub has_chain_owner: bool,
}

/// Cross-chain fork info derived from `discovered_blockchains`.
#[derive(Debug, Clone)]
pub struct CrossChainForkInfo {
    pub chain_id: u32,
    pub peer_count: usize,
    pub chain_tip_height: Option<u64>,
    /// Decay-weighted vote legitimacy score (fixed-point × 1000).
    /// Higher = more recent validator participation.
    pub chain_vote_weight: Option<u64>,
    pub last_seen: u64,
}

/// Resolution decision returned by `evaluate()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkDecision {
    /// No action required.
    NoAction,
    /// Threshold met but dwell timer not expired.
    Pending { cycles_remaining: u32 },
    /// Auto-resolve: reset chain and re-sync to the target.
    Resolve {
        target_hash: Hash256,
        target_height: u64,
        reason: String,
    },
}

/// Cross-chain adoption decision returned by `evaluate_cross_chain()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossChainDecision {
    /// No action required.
    NoAction,
    /// Threshold met but dwell timer not expired.
    Pending { cycles_remaining: u32 },
    /// Adopt the target chain: wipe all data and re-sync from scratch.
    Adopt {
        target_chain_id: u32,
        reason: String,
    },
}

/// Decay-weighted vote legitimacy score.
///
/// Uses exponential decay with half-life of ~14 blocks (decay factor 0.95).
/// Recent blocks' votes count more than older ones, capturing whether a
/// chain is actively maintained by validators or has stagnated.
///
/// `score = Σ (votes_i × decay^(tip_height - block_height_i))`
///
/// For efficient cross-chain comparison, each node maintains a running
/// accumulator: `weight = weight × decay + new_votes` on each commit.
/// The raw accumulator value is announced in NodeAnnounce and stored
/// in DiscoveredBlockchainInfo as `chain_vote_weight`.
///
/// Fixed-point: values are × 1000 to avoid floating point.
pub const VOTE_DECAY_FACTOR_NUM: u64 = 950;
pub const VOTE_DECAY_FACTOR_DENOM: u64 = 1000;

/// Apply decay to a running vote weight accumulator and add new votes.
///
/// `new_weight = old_weight × (950/1000) + new_votes × 1000`
pub fn decay_vote_weight(old_weight: u64, new_votes: u64) -> u64 {
    // Multiply-then-divide for precision; fall back to divide-first on overflow.
    let decayed = match old_weight.checked_mul(VOTE_DECAY_FACTOR_NUM) {
        Some(product) => product / VOTE_DECAY_FACTOR_DENOM,
        None => old_weight / VOTE_DECAY_FACTOR_DENOM * VOTE_DECAY_FACTOR_NUM,
    };
    decayed.saturating_add(new_votes.saturating_mul(1000))
}

/// Pure fork resolution state machine.
pub struct ForkResolver {
    strategy: ForkResolutionStrategy,
    /// Minimum cycles a fork must persist before resolution (default: 3).
    min_fork_duration: u32,
    /// Current dwell counter (incremented each evaluation where threshold is met).
    fork_dwell_counter: u32,
    /// Height of the fork we're tracking (reset if dominant fork shrinks).
    /// Uses height instead of hash because actively growing forks change hash
    /// every cycle but should still accumulate dwell time.
    tracked_fork_height: Option<u64>,
    /// Finalized height floor — never resolve past this.
    finalized_height: u64,
    /// Cross-chain: chain_id being tracked for adoption.
    tracked_cross_chain_id: Option<u32>,
    /// Cross-chain dwell counter (separate from same-chain).
    cross_chain_dwell_counter: u32,
}

impl ForkResolver {
    pub fn new(strategy: ForkResolutionStrategy, min_fork_duration: u32) -> Self {
        Self {
            strategy,
            min_fork_duration,
            fork_dwell_counter: 0,
            tracked_fork_height: None,
            finalized_height: 0,
            tracked_cross_chain_id: None,
            cross_chain_dwell_counter: 0,
        }
    }

    /// Evaluate fork data and return a resolution decision.
    ///
    /// Called once per cycle boundary (or at a regular interval) with:
    /// - `local_height`: our committed chain tip
    /// - `forks`: all known fork groups (including the local one)
    /// - `total_peers`: total number of connected peers
    pub fn evaluate(
        &mut self,
        local_height: u64,
        forks: &[ForkInfo],
        total_peers: usize,
        local_tip_hash: Hash256,
    ) -> ForkDecision {
        // Manual strategy never auto-resolves.
        if self.strategy == ForkResolutionStrategy::Manual {
            return ForkDecision::NoAction;
        }

        // No peers → no resolution possible.
        if total_peers == 0 {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Find the dominant non-local fork (highest peer_count, then height).
        let dominant = forks
            .iter()
            .filter(|f| !f.is_local)
            .max_by_key(|f| (f.peer_count, f.height));

        let dominant = match dominant {
            Some(d) => d,
            None => {
                self.reset_tracking();
                return ForkDecision::NoAction;
            }
        };

        // Check strategy threshold.
        let threshold_met = match self.strategy {
            ForkResolutionStrategy::PeerSupermajority => {
                // >66%: dominant_peers * 3 > total_peers * 2
                dominant.peer_count * 3 > total_peers * 2
            }
            ForkResolutionStrategy::LongestMostLegitimate => {
                // Virtual height model: chain owner gets CHAIN_OWNER_EDGE_BLOCKS bonus.
                let local_has_owner = forks.iter()
                    .any(|f| f.is_local && f.has_chain_owner);
                let dominant_effective = dominant.height
                    .saturating_add(if dominant.has_chain_owner { CHAIN_OWNER_EDGE_BLOCKS } else { 0 });
                let local_effective = local_height
                    .saturating_add(if local_has_owner { CHAIN_OWNER_EDGE_BLOCKS } else { 0 });
                // Strict > preserves original 4+ block lead requirement when no owner info.
                // With owner edge (5 blocks), equal actual height becomes 15 > 13 = true.
                // Owner 2 behind: 13 > 13 = false → does NOT switch (tight bound).
                // Owner 1 behind: 14 > 13 = true → switches.
                dominant_effective > local_effective.saturating_add(3)
            }
            ForkResolutionStrategy::Manual => false,
        };

        // Same-height deadlock: if the dominant fork is at our exact height and we've
        // been in disagreement for min_fork_duration cycles, the height threshold will
        // NEVER be met (both chains grow or neither grows). Break the deadlock by
        // yielding to the dominant fork. Tiebreaker: chain owner wins, else majority
        // peer count, else lower tip hash.
        if !threshold_met && dominant.height == local_height
            && self.strategy == ForkResolutionStrategy::LongestMostLegitimate
        {
            // Track the same-height fork for dwell accumulation even though
            // threshold isn't met — needed so dwell counter reaches min_fork_duration.
            match self.tracked_fork_height {
                Some(prev_h) if dominant.height < prev_h => {
                    self.fork_dwell_counter = 0;
                }
                None => {
                    self.fork_dwell_counter = 0;
                }
                _ => {}
            }
            self.tracked_fork_height = Some(dominant.height);
            self.fork_dwell_counter += 1;

            if self.fork_dwell_counter >= self.min_fork_duration {
                let local_has_owner = forks.iter().any(|f| f.is_local && f.has_chain_owner);
                let should_yield = if dominant.has_chain_owner && !local_has_owner {
                    true // Chain owner's fork wins
                } else if !dominant.has_chain_owner && local_has_owner {
                    false // We're the chain owner, don't yield
                } else if dominant.peer_count > 1 {
                    true // Majority peer count (excluding us)
                } else {
                    // True tie — deterministic tiebreak by lower tip hash
                    dominant.tip_hash.as_bytes() < local_tip_hash.as_bytes()
                };
                if should_yield {
                    // Override threshold_met — proceed to resolution.
                } else {
                    self.reset_tracking();
                    return ForkDecision::NoAction;
                }
            } else {
                return ForkDecision::Pending {
                    cycles_remaining: self.min_fork_duration - self.fork_dwell_counter,
                };
            }
        } else if !threshold_met {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Safety: never resolve past finalized height.
        if dominant.height <= self.finalized_height {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Track the fork by height.  If the dominant fork's height decreased,
        // a different (shorter) fork took over — reset the dwell counter.
        // A growing fork (increasing height) keeps its dwell time, even though
        // its tip_hash changes every cycle.
        match self.tracked_fork_height {
            Some(prev_h) if dominant.height < prev_h => {
                // Different fork became dominant (shorter) — reset.
                self.fork_dwell_counter = 0;
            }
            None => {
                // First time tracking — start fresh.
                self.fork_dwell_counter = 0;
            }
            _ => {} // Same or growing fork — keep dwell counter.
        }
        self.tracked_fork_height = Some(dominant.height);

        self.fork_dwell_counter += 1;

        if self.fork_dwell_counter < self.min_fork_duration {
            return ForkDecision::Pending {
                cycles_remaining: self.min_fork_duration - self.fork_dwell_counter,
            };
        }

        // Dwell expired — resolve.
        let reason = match self.strategy {
            ForkResolutionStrategy::PeerSupermajority => format!(
                "peer supermajority ({}/{} peers) on fork at height {}",
                dominant.peer_count, total_peers, dominant.height
            ),
            ForkResolutionStrategy::LongestMostLegitimate => {
                let local_has_owner = forks.iter()
                    .any(|f| f.is_local && f.has_chain_owner);
                let dominant_effective = dominant.height
                    .saturating_add(if dominant.has_chain_owner { CHAIN_OWNER_EDGE_BLOCKS } else { 0 });
                let local_effective = local_height
                    .saturating_add(if local_has_owner { CHAIN_OWNER_EDGE_BLOCKS } else { 0 });
                let owner_note = match (local_has_owner, dominant.has_chain_owner) {
                    (false, true) => " (chain owner on dominant fork)",
                    (true, false) => " (chain owner on local fork)",
                    _ => "",
                };
                format!(
                    "fork resolution{}: dominant effective={} vs local effective={} (actual: local={}, fork={})",
                    owner_note, dominant_effective, local_effective, local_height, dominant.height
                )
            }
            ForkResolutionStrategy::Manual => unreachable!(),
        };

        let decision = ForkDecision::Resolve {
            target_hash: dominant.tip_hash,
            target_height: dominant.height,
            reason,
        };

        self.reset_tracking();
        decision
    }

    /// Evaluate cross-chain fork data for potential chain adoption.
    ///
    /// Called when the node has discovered blockchains with different chain_ids.
    /// Uses height as primary comparison and decay-weighted vote legitimacy
    /// as tiebreaker when chains are similar in length.
    ///
    /// Adoption is only considered when the local node has zero same-chain
    /// peers (i.e., it's alone on its chain).
    pub fn evaluate_cross_chain(
        &mut self,
        local_chain_id: u32,
        local_height: u64,
        local_vote_weight: u64,
        same_chain_peer_count: usize,
        cross_chain_forks: &[CrossChainForkInfo],
        is_local_chain_owner: bool,
    ) -> CrossChainDecision {
        // Manual strategy never auto-adopts.
        if self.strategy == ForkResolutionStrategy::Manual {
            return CrossChainDecision::NoAction;
        }

        // If we have same-chain peers, we're not alone — no adoption needed.
        if same_chain_peer_count > 0 {
            self.reset_cross_chain_tracking();
            return CrossChainDecision::NoAction;
        }

        // Filter to candidates with actual peers.
        let candidates: Vec<&CrossChainForkInfo> = cross_chain_forks
            .iter()
            .filter(|f| f.peer_count > 0)
            .collect();

        if candidates.is_empty() {
            self.reset_cross_chain_tracking();
            return CrossChainDecision::NoAction;
        }

        // Find the best candidate using a composite score.
        let local_score = Self::chain_score(local_height, local_vote_weight, is_local_chain_owner);
        let best = candidates
            .iter()
            .filter_map(|c| {
                let remote_height = c.chain_tip_height.unwrap_or(0);
                let remote_weight = c.chain_vote_weight.unwrap_or(0);
                // We don't know who owns remote chains, so no owner bonus.
                let remote_score = Self::chain_score(remote_height, remote_weight, false);

                // The remote chain must be strictly better, or equal with lower chain_id.
                let is_better = remote_score > local_score
                    || (remote_score == local_score && c.chain_id < local_chain_id);

                if is_better {
                    Some((c, remote_score, remote_height, remote_weight))
                } else {
                    None
                }
            })
            .max_by_key(|(_, score, _, _)| *score);

        let (dominant, _score, remote_height, remote_weight) = match best {
            Some(b) => b,
            None => {
                self.reset_cross_chain_tracking();
                return CrossChainDecision::NoAction;
            }
        };

        // Track the cross-chain target — if it changed, reset dwell counter.
        if self.tracked_cross_chain_id != Some(dominant.chain_id) {
            self.tracked_cross_chain_id = Some(dominant.chain_id);
            self.cross_chain_dwell_counter = 0;
        }

        self.cross_chain_dwell_counter += 1;

        if self.cross_chain_dwell_counter < self.min_fork_duration {
            return CrossChainDecision::Pending {
                cycles_remaining: self.min_fork_duration - self.cross_chain_dwell_counter,
            };
        }

        // Build reason string.
        let reason = if self.strategy == ForkResolutionStrategy::LongestMostLegitimate {
            format!(
                "cross-chain adoption: remote chain {:#010X} (height={}, vote_weight={}) \
                 vs local (height={}, vote_weight={}) — \
                 {} peers on remote chain, 0 on local",
                dominant.chain_id, remote_height, remote_weight,
                local_height, local_vote_weight,
                dominant.peer_count,
            )
        } else {
            format!(
                "cross-chain adoption: remote chain {:#010X} at height {} \
                 vs local height {} — {} peers on remote, 0 on local",
                dominant.chain_id, remote_height, local_height, dominant.peer_count,
            )
        };

        let decision = CrossChainDecision::Adopt {
            target_chain_id: dominant.chain_id,
            reason,
        };

        self.reset_cross_chain_tracking();
        decision
    }

    /// Compute a composite chain score for cross-chain comparison.
    ///
    /// - Height is the primary factor (multiplied by 10_000).
    /// - Decay-weighted vote weight is a secondary factor. Average votes per
    ///   block (vote_weight / max(height,1)) is used so longer chains aren't
    ///   penalized just for accumulating decay. Capped at 9_999.
    /// - Chain owner bonus: `CHAIN_OWNER_EDGE_BLOCKS * 10_000` when the local
    ///   node is the chain owner (equivalent to treating the chain as 5 blocks
    ///   taller). Only applies to the local chain; remote chains don't get bonus
    ///   since we don't know their ownership.
    fn chain_score(height: u64, vote_weight: u64, is_chain_owner: bool) -> u64 {
        let owner_bonus = if is_chain_owner { CHAIN_OWNER_EDGE_BLOCKS.saturating_mul(10_000) } else { 0 };
        let primary = height.saturating_mul(10_000);
        let avg = vote_weight / height.max(1);
        let secondary = avg.min(9_999);
        primary.saturating_add(secondary).saturating_add(owner_bonus)
    }

    fn reset_tracking(&mut self) {
        self.fork_dwell_counter = 0;
        self.tracked_fork_height = None;
    }

    fn reset_cross_chain_tracking(&mut self) {
        self.cross_chain_dwell_counter = 0;
        self.tracked_cross_chain_id = None;
    }

    // ── Public accessors ──

    pub fn strategy(&self) -> ForkResolutionStrategy {
        self.strategy
    }

    pub fn dwell_counter(&self) -> u32 {
        self.fork_dwell_counter
    }

    pub fn cross_chain_dwell_counter(&self) -> u32 {
        self.cross_chain_dwell_counter
    }

    pub fn min_fork_duration(&self) -> u32 {
        self.min_fork_duration
    }

    pub fn tracked_fork_height(&self) -> Option<u64> {
        self.tracked_fork_height
    }

    pub fn tracked_cross_chain_id(&self) -> Option<u32> {
        self.tracked_cross_chain_id
    }

    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    pub fn set_strategy(&mut self, strategy: ForkResolutionStrategy) {
        self.strategy = strategy;
        self.reset_tracking();
        self.reset_cross_chain_tracking();
    }

    pub fn set_finalized_height(&mut self, height: u64) {
        self.finalized_height = height;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(n: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Hash256::from_bytes(bytes)
    }

    fn local_fork(height: u64) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(0),
            height,
            peer_count: 1,
            is_local: true,
            has_chain_owner: false,
        }
    }

    fn local_fork_owner(height: u64) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(0),
            height,
            peer_count: 1,
            is_local: true,
            has_chain_owner: true,
        }
    }

    fn remote_fork(id: u8, height: u64, peer_count: usize) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(id),
            height,
            peer_count,
            is_local: false,
            has_chain_owner: false,
        }
    }

    fn remote_fork_owner(id: u8, height: u64, peer_count: usize) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(id),
            height,
            peer_count,
            is_local: false,
            has_chain_owner: true,
        }
    }

    #[test]
    fn manual_strategy_never_resolves() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::Manual, 3);
        let forks = vec![local_fork(5), remote_fork(1, 100, 10)];
        assert_eq!(fr.evaluate(5, &forks, 10, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn peer_supermajority_triggers() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 1);
        // 3/4 peers on fork = 75% > 66%
        let forks = vec![local_fork(5), remote_fork(1, 5, 3)];
        let result = fr.evaluate(5, &forks, 4, hash(0));
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 5),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn peer_supermajority_below_threshold() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 3);
        // 1/3 peers on fork = 33% < 66%
        let forks = vec![local_fork(5), remote_fork(1, 5, 1)];
        assert_eq!(fr.evaluate(5, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn longest_most_legitimate_triggers() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        // Fork 4 blocks ahead (local=5, fork=9, diff=4 > 3), no owner info
        let forks = vec![local_fork(5), remote_fork(1, 9, 2)];
        let result = fr.evaluate(5, &forks, 3, hash(0));
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 9),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn longest_most_legitimate_below_threshold() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);
        // Fork 2 blocks ahead (local=5, fork=7, diff=2 <= 3), no owner info
        let forks = vec![local_fork(5), remote_fork(1, 7, 2)];
        assert_eq!(fr.evaluate(5, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn dwell_timer_delays_resolution() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);
        let forks = vec![local_fork(5), remote_fork(1, 20, 2)];

        // First evaluation: dwell starts
        assert_eq!(
            fr.evaluate(5, &forks, 3, hash(0)),
            ForkDecision::Pending {
                cycles_remaining: 2
            }
        );
        // Second
        assert_eq!(
            fr.evaluate(5, &forks, 3, hash(0)),
            ForkDecision::Pending {
                cycles_remaining: 1
            }
        );
        // Third: dwell expired → resolve
        match fr.evaluate(5, &forks, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 20),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn fork_shrink_resets_dwell() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);

        // Fork A at height 20 — accumulate 2 dwell ticks
        let forks_a = vec![local_fork(5), remote_fork(1, 20, 2)];
        assert!(matches!(
            fr.evaluate(5, &forks_a, 3, hash(0)),
            ForkDecision::Pending { .. }
        ));
        assert!(matches!(
            fr.evaluate(5, &forks_a, 3, hash(0)),
            ForkDecision::Pending { .. }
        ));
        assert_eq!(fr.dwell_counter(), 2);

        // Fork B at height 15 replaces A (shorter dominant fork) — dwell resets
        let forks_b = vec![local_fork(5), remote_fork(2, 15, 3)];
        let result = fr.evaluate(5, &forks_b, 4, hash(0));
        assert_eq!(
            result,
            ForkDecision::Pending {
                cycles_remaining: 2
            }
        );
        assert_eq!(fr.dwell_counter(), 1);
    }

    #[test]
    fn fork_growth_keeps_dwell() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);

        // Fork at height 20 — first dwell tick
        let forks_1 = vec![local_fork(5), remote_fork(1, 20, 2)];
        assert!(matches!(
            fr.evaluate(5, &forks_1, 3, hash(0)),
            ForkDecision::Pending { .. }
        ));
        assert_eq!(fr.dwell_counter(), 1);

        // Fork grows to height 21 — dwell continues (not reset)
        let forks_2 = vec![local_fork(5), remote_fork(2, 21, 2)];
        assert!(matches!(
            fr.evaluate(5, &forks_2, 3, hash(0)),
            ForkDecision::Pending { .. }
        ));
        assert_eq!(fr.dwell_counter(), 2);

        // Fork grows to height 22 — dwell completes → resolve
        let forks_3 = vec![local_fork(5), remote_fork(3, 22, 2)];
        match fr.evaluate(5, &forks_3, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 22),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn never_resolves_past_finality() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        fr.set_finalized_height(10);
        // Fork at height 8 — below finalized
        let forks = vec![local_fork(5), remote_fork(1, 8, 5)];
        assert_eq!(fr.evaluate(5, &forks, 5, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn no_peers_no_resolution() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 1);
        let forks = vec![local_fork(5)];
        assert_eq!(fr.evaluate(5, &forks, 0, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn strategy_change_resets_state() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);
        let forks = vec![local_fork(5), remote_fork(1, 20, 2)];
        fr.evaluate(5, &forks, 3, hash(0));
        assert_eq!(fr.dwell_counter(), 1);

        fr.set_strategy(ForkResolutionStrategy::PeerSupermajority);
        assert_eq!(fr.dwell_counter(), 0);
        assert_eq!(fr.tracked_fork_height(), None);
    }

    // ── Cross-chain tests ──

    fn cross_chain(chain_id: u32, height: u64, vote_weight: u64, peers: usize) -> CrossChainForkInfo {
        CrossChainForkInfo {
            chain_id,
            peer_count: peers,
            chain_tip_height: Some(height),
            chain_vote_weight: Some(vote_weight),
            last_seen: 1000,
        }
    }

    #[test]
    fn cross_chain_manual_never_adopts() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::Manual, 1);
        let forks = vec![cross_chain(0xBBBB, 100, 50_000, 3)];
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 5, 5_000, 0, &forks, false),
            CrossChainDecision::NoAction,
        );
    }

    #[test]
    fn cross_chain_with_same_chain_peers_no_adopt() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![cross_chain(0xBBBB, 100, 50_000, 3)];
        // 1 same-chain peer → not alone → no adoption
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 5, 5_000, 1, &forks, false),
            CrossChainDecision::NoAction,
        );
    }

    #[test]
    fn cross_chain_longer_chain_adopts() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![cross_chain(0xBBBB, 20, 10_000, 1)];
        // Local height=5, remote height=20 → remote is better
        let result = fr.evaluate_cross_chain(0xAAAA, 5, 5_000, 0, &forks, false);
        match result {
            CrossChainDecision::Adopt { target_chain_id, .. } => {
                assert_eq!(target_chain_id, 0xBBBB);
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }

    #[test]
    fn cross_chain_shorter_chain_no_adopt() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![cross_chain(0xBBBB, 3, 1_000, 1)];
        // Local height=10, remote height=3 → local is better
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 10, 5_000, 0, &forks, false),
            CrossChainDecision::NoAction,
        );
    }

    #[test]
    fn cross_chain_equal_height_lower_chain_id_wins() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        // Equal height (10), remote chain_id=0x1000 < local chain_id=0x2000
        let forks = vec![cross_chain(0x1000, 10, 5_000, 1)];
        let result = fr.evaluate_cross_chain(0x2000, 10, 5_000, 0, &forks, false);
        match result {
            CrossChainDecision::Adopt { target_chain_id, .. } => {
                assert_eq!(target_chain_id, 0x1000);
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }

    #[test]
    fn cross_chain_equal_height_higher_chain_id_no_adopt() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        // Equal height (10), remote chain_id=0x3000 > local chain_id=0x2000
        let forks = vec![cross_chain(0x3000, 10, 5_000, 1)];
        assert_eq!(
            fr.evaluate_cross_chain(0x2000, 10, 5_000, 0, &forks, false),
            CrossChainDecision::NoAction,
        );
    }

    #[test]
    fn cross_chain_legitimacy_tiebreaker() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        // Same height (10), remote has higher vote weight → adopt
        // Remote: avg = 8000/10 = 800. Local: avg = 2000/10 = 200.
        let forks = vec![cross_chain(0xBBBB, 10, 8_000, 1)];
        let result = fr.evaluate_cross_chain(0xAAAA, 10, 2_000, 0, &forks, false);
        match result {
            CrossChainDecision::Adopt { target_chain_id, .. } => {
                assert_eq!(target_chain_id, 0xBBBB);
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }

    #[test]
    fn cross_chain_legitimacy_local_better_votes() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        // Same height (10), local has higher vote weight → no adopt
        let forks = vec![cross_chain(0xBBBB, 10, 2_000, 1)];
        // Local vote weight 8000 > remote 2000
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 10, 8_000, 0, &forks, false),
            CrossChainDecision::NoAction,
        );
    }

    #[test]
    fn cross_chain_dwell_timer() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);
        let forks = vec![cross_chain(0xBBBB, 20, 10_000, 1)];

        // First: pending
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 5, 5_000, 0, &forks, false),
            CrossChainDecision::Pending { cycles_remaining: 2 },
        );
        // Second: pending
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 5, 5_000, 0, &forks, false),
            CrossChainDecision::Pending { cycles_remaining: 1 },
        );
        // Third: adopt
        match fr.evaluate_cross_chain(0xAAAA, 5, 5_000, 0, &forks, false) {
            CrossChainDecision::Adopt { target_chain_id, .. } => {
                assert_eq!(target_chain_id, 0xBBBB);
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }

    #[test]
    fn cross_chain_target_change_resets_dwell() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 3);

        // Track chain A for 2 cycles
        let forks_a = vec![cross_chain(0xAAAA, 20, 10_000, 1)];
        fr.evaluate_cross_chain(0x1111, 5, 5_000, 0, &forks_a, false);
        fr.evaluate_cross_chain(0x1111, 5, 5_000, 0, &forks_a, false);
        assert_eq!(fr.cross_chain_dwell_counter(), 2);

        // Switch to chain B → dwell resets
        let forks_b = vec![cross_chain(0xBBBB, 25, 15_000, 2)];
        let result = fr.evaluate_cross_chain(0x1111, 5, 5_000, 0, &forks_b, false);
        assert_eq!(
            result,
            CrossChainDecision::Pending { cycles_remaining: 2 },
        );
        assert_eq!(fr.cross_chain_dwell_counter(), 1);
    }

    #[test]
    fn decay_vote_weight_basic() {
        // Start with 0, add 5 votes
        let w = decay_vote_weight(0, 5);
        assert_eq!(w, 5_000); // 5 × 1000

        // Decay + add 3 more votes
        let w = decay_vote_weight(w, 3);
        // 5000 × 0.95 = 4750, + 3000 = 7750
        assert_eq!(w, 7_750);

        // Decay with 0 votes (validator participation drops)
        let w = decay_vote_weight(w, 0);
        // 7750 × 0.95 = 7362 (truncated)
        assert_eq!(w, 7_362);
    }

    #[test]
    fn decay_converges_to_zero() {
        let mut w = 100_000u64;
        for _ in 0..200 {
            w = decay_vote_weight(w, 0);
        }
        assert_eq!(w, 0, "decay should converge to 0 with no new votes");
    }

    #[test]
    fn no_owner_info_original_behavior() {
        // When has_chain_owner is false on all forks, behaviour is the original >3 threshold.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(5), remote_fork(1, 9, 2)];
        let result = fr.evaluate(5, &forks, 3, hash(0));
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 9),
            other => panic!("expected Resolve, got {:?}", other),
        }

        // 3 blocks ahead is NOT enough (must be >3)
        let mut fr2 = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks2 = vec![local_fork(5), remote_fork(1, 8, 2)];
        assert_eq!(fr2.evaluate(5, &forks2, 3, hash(0)), ForkDecision::NoAction);
    }

    // ── Chain owner tiebreaker tests ──

    #[test]
    fn chain_owner_equal_height_switch() {
        // Equal height (10), owner on dominant fork → should switch.
        // dominant effective = 10+5=15, local effective = 10+0=10, threshold = 10+3=13
        // 15 > 13 → switch
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(10), remote_fork_owner(1, 10, 2)];
        let result = fr.evaluate(10, &forks, 3, hash(0));
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 10),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn chain_owner_behind_1_block_switch() {
        // Owner 1 block behind (owner=9, us=10).
        // dominant effective = 9+5=14, local effective = 10+0=10, threshold = 10+3=13
        // 14 > 13 → true → Switch
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(10), remote_fork_owner(1, 9, 2)];
        let result = fr.evaluate(10, &forks, 3, hash(0));
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 9),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn chain_owner_behind_2_blocks_no_switch() {
        // Owner 2 blocks behind (owner=8, us=10).
        // dominant effective = 8+5=13, local effective = 10+0=10, threshold = 10+3=13
        // 13 > 13 → false → NoAction (boundary: tied, no switch)
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(10), remote_fork_owner(1, 8, 2)];
        assert_eq!(fr.evaluate(10, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn chain_owner_behind_3_blocks_no_switch() {
        // Owner 3 blocks behind (owner=7, us=10).
        // dominant effective = 7+5=12, local effective = 10+0=10, threshold = 10+3=13
        // 12 > 13 → false → NoAction
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(10), remote_fork_owner(1, 7, 2)];
        assert_eq!(fr.evaluate(10, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn chain_owner_local_stays() {
        // We are the owner (local), equal height → should NOT switch.
        // dominant effective = 10+0=10, local effective = 10+5=15, threshold = 15+3=18
        // 10 > 18 → false → NoAction
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork_owner(10), remote_fork(1, 10, 2)];
        assert_eq!(fr.evaluate(10, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn non_owner_needs_9_blocks_to_override_owner() {
        // We are owner (local=10), non-owner remote at 18.
        // dominant effective = 18+0=18, local effective = 10+5=15, threshold = 15+3=18
        // 18 > 18 → false → NoAction (8-block lead not enough)
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork_owner(10), remote_fork(1, 18, 2)];
        assert_eq!(fr.evaluate(10, &forks, 3, hash(0)), ForkDecision::NoAction);

        // Non-owner at 19: 19 > 18 → true → Switch
        let mut fr2 = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks2 = vec![local_fork_owner(10), remote_fork(1, 19, 2)];
        match fr2.evaluate(10, &forks2, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 19),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn chain_owner_cross_chain_bonus() {
        // When local node IS chain owner, cross-chain score gets bonus.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        // Remote: height=12, vote_weight=5000 → score = 12*10000 + min(5000/12, 9999) = 120416
        // Local:  height=10, vote_weight=5000, owner → score = 10*10000 + min(5000/10, 9999) + 5*10000 = 150500
        // Local > remote → NoAction
        let forks = vec![cross_chain(0xBBBB, 12, 5_000, 1)];
        assert_eq!(
            fr.evaluate_cross_chain(0xAAAA, 10, 5_000, 0, &forks, true),
            CrossChainDecision::NoAction,
        );

        // Without owner: local score = 100500 < 120416 → Adopt
        let mut fr2 = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let result = fr2.evaluate_cross_chain(0xAAAA, 10, 5_000, 0, &forks, false);
        match result {
            CrossChainDecision::Adopt { target_chain_id, .. } => {
                assert_eq!(target_chain_id, 0xBBBB);
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }
}
