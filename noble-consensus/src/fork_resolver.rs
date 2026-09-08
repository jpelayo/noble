// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Automatic fork resolution state machine.
//!
//! Pure decision logic — no I/O.  `HealingManager` owns an instance and
//! calls `evaluate()` / `evaluate_cross_chain()` directly each tick,
//! acting on the returned decisions inline.

use std::cmp::Reverse;

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

/// Fork resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkResolutionStrategy {
    /// Alert only — never auto-resolve.
    Manual,
    /// Resolve when >66% of peers are on a different fork.
    PeerSupermajority,
    /// Pick the longest, most legitimate chain among the CANDIDATES.
    ///
    /// Same-chain forks are ranked by [`Legitimacy`] — read from verified
    /// certificates over the segment above the common ancestor — and the
    /// winner is never touched: every other node adopts it. Cross-chain
    /// adoption still uses decay-weighted vote weight as its tiebreaker.
    LongestMostLegitimate,
}

/// Chain owner (block 1 validator) edge — cross-chain scoring only.
///
/// It once gave the owner's same-chain fork a virtual +5 in height, which let
/// an owner that minted alone out-rank a witnessed chain. Same-chain decisions
/// no longer consult ownership at all; the constant remains for the
/// cross-chain score and for API compatibility.
pub const CHAIN_OWNER_EDGE_BLOCKS: u64 = 5;

// ── Legitimacy ───────────────────────────────────────────────────────────────

/// Legitimacy of one candidate chain's segment above the common ancestor,
/// read from certificates the evaluating node fetched and verified itself.
///
/// Derived `Ord` is lexicographic in field order, and that order IS the
/// fork-choice rule — "longest, most legitimate":
///
/// | # | key               | meaning |
/// |---|-------------------|---------|
/// | 0 | `fully_witnessed` | every block carries ≥ `min_unique_voters` distinct verified signers |
/// | 1 | `length`          | blocks above the ancestor |
/// | 2 | `votes`           | Σ verified witness signatures over the segment |
/// | 3 | `participation`   | distinct keys appearing as signer or proposer |
///
/// Key 0 keeps the standing rule that a self-voted run is never adopted while
/// a fully witnessed chain exists, at any length. When no candidate is fully
/// witnessed the key ties and 1–3 decide among what exists — the decision is
/// never null. The tip hash breaks a full tie deterministically (see
/// [`ForkResolver::evaluate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Legitimacy {
    pub fully_witnessed: bool,
    pub length: u64,
    pub votes: u64,
    pub participation: u64,
}

impl Legitimacy {
    /// Stable string for RPC / GUI / events.
    pub fn label(&self) -> &'static str {
        if self.fully_witnessed { "witnessed" } else { "under_witnessed" }
    }
}

/// What the evaluating node knows about a fork's segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentLegitimacy {
    /// Fetched and verified. Comparable.
    Known(Legitimacy),
    /// Not yet fetched/verified. Never adoptable until it is; the resolver
    /// asks for it to be assessed and decides nothing meanwhile.
    Unknown,
}

impl SegmentLegitimacy {
    /// Stable string for RPC / GUI / events.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Known(l) => l.label(),
            Self::Unknown => "unknown",
        }
    }
}

/// Fork info fed from node.rs (same data as `getDetectedForks` RPC).
#[derive(Debug, Clone)]
pub struct ForkInfo {
    pub tip_hash: Hash256,
    pub height: u64,
    pub peer_count: usize,
    pub is_local: bool,
    /// Whether the chain owner (block 1's validator) is on this fork.
    /// Informational; same-chain decisions do not consult it.
    pub has_chain_owner: bool,
    /// Legitimacy of this fork's segment above the common ancestor.
    pub legitimacy: SegmentLegitimacy,
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

/// A same-chain decision. A decision, not an instruction to edit the chain:
/// it can only name a candidate to adopt, ask for one to be assessed, or hold.
/// There is no variant that removes blocks or adopts nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkDecision {
    /// We hold the winning chain, or there is nothing to decide.
    Hold,
    /// The winner is known; the dwell has not elapsed.
    Pending { cycles_remaining: u32 },
    /// A candidate is not yet fetched/verified: fetch `(from_height,
    /// target_height]` with its certificates. Nothing is decided meanwhile.
    Assess {
        target_hash: Hash256,
        target_height: u64,
        from_height: u64,
    },
    /// A NAMED candidate won and we are not on it: adopt it.
    Adopt {
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
    /// Minimum CYCLES the same winner must persist before a loser adopts it.
    min_fork_duration: u32,
    /// Distinct cycles the current winner has been the winner.
    fork_dwell_counter: u32,
    /// Height of the winner being tracked (reset if the winner shrinks — a
    /// different, shorter chain took over). Height rather than hash because a
    /// growing winner changes hash every cycle yet is the same chain.
    tracked_fork_height: Option<u64>,
    /// Cycle in which the dwell counter last advanced. Dwell counts cycles,
    /// not evaluations: `evaluate` runs on a 10 s tick, and counting ticks made
    /// `fork_resolution_delay_cycles = 3` mean thirty seconds.
    last_dwell_cycle: Option<u64>,
    /// Current consensus cycle, fed by `note_cycle`.
    current_cycle: u64,
    /// Finalized height floor — never adopt a winner whose tip is below it.
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
            last_dwell_cycle: None,
            current_cycle: 0,
            finalized_height: 0,
            tracked_cross_chain_id: None,
            cross_chain_dwell_counter: 0,
        }
    }

    /// Tell the resolver which consensus cycle it is. Dwell advances at most
    /// once per distinct cycle.
    pub fn note_cycle(&mut self, cycle: u64) {
        self.current_cycle = cycle;
    }

    /// Decide among the candidate chains.
    ///
    /// - `local_height` / `local_tip_hash`: our committed tip.
    /// - `ancestor`: the common ancestor height. A fork is a CANDIDATE only if
    ///   it has blocks above it. A node sitting on the ancestor — offline, or
    ///   freshly rolled back — is not a candidate; it adopts the winner and
    ///   can make nobody else lose.
    /// - `forks`: every known fork group, the local one included.
    ///
    /// Exactly one winner always exists among the candidates: the maximum by
    /// ([`Legitimacy`], lower tip hash). If we hold it → `Hold`. If any
    /// candidate is `Unknown` → `Assess` it first; nothing is decided on an
    /// unverified chain. Otherwise → `Adopt` the winner after the dwell.
    ///
    /// The winner receives nothing but `Hold`. The decision never removes
    /// blocks and never adopts an unnamed target.
    pub fn evaluate(
        &mut self,
        local_height: u64,
        ancestor: u64,
        forks: &[ForkInfo],
        total_peers: usize,
        local_tip_hash: Hash256,
    ) -> ForkDecision {
        if self.strategy == ForkResolutionStrategy::Manual {
            return ForkDecision::Hold;
        }
        if total_peers == 0 {
            self.reset_tracking();
            return ForkDecision::Hold;
        }

        let candidates: Vec<&ForkInfo> = forks.iter().filter(|f| f.height > ancestor).collect();
        let rivals_exist = candidates.iter().any(|f| !f.is_local);
        if !rivals_exist {
            // Only we have blocks above the ancestor (or nobody does).
            self.reset_tracking();
            return ForkDecision::Hold;
        }

        // Nothing is decided on an unverified chain. Assess the tallest one.
        if let Some(u) = candidates
            .iter()
            .filter(|f| !f.is_local && f.legitimacy == SegmentLegitimacy::Unknown)
            .max_by_key(|f| (f.height, f.peer_count))
        {
            return ForkDecision::Assess {
                target_hash: u.tip_hash,
                target_height: u.height,
                from_height: ancestor,
            };
        }

        let key = |f: &ForkInfo| -> (Legitimacy, Reverse<[u8; 32]>) {
            let leg = match f.legitimacy {
                SegmentLegitimacy::Known(l) => l,
                // Local is always Known by construction; a defensive default
                // ranks an unknown local below everything, so we would adopt.
                SegmentLegitimacy::Unknown => Legitimacy::default(),
            };
            (leg, Reverse(f.tip_hash.0))
        };

        let winner = match self.strategy {
            ForkResolutionStrategy::PeerSupermajority => {
                // >66% of peers on one rival fork → that fork; else we hold.
                match candidates
                    .iter()
                    .filter(|f| !f.is_local && f.peer_count * 3 > total_peers * 2)
                    .max_by_key(|f| (f.peer_count, key(f)))
                {
                    Some(w) => *w,
                    None => {
                        self.reset_tracking();
                        return ForkDecision::Hold;
                    }
                }
            }
            ForkResolutionStrategy::LongestMostLegitimate => *candidates
                .iter()
                .max_by_key(|f| key(f))
                .expect("candidates is non-empty: a rival exists"),
            ForkResolutionStrategy::Manual => unreachable!("handled above"),
        };

        if winner.is_local || winner.tip_hash == local_tip_hash {
            self.reset_tracking();
            return ForkDecision::Hold;
        }
        // Never adopt below finality.
        if winner.height <= self.finalized_height {
            self.reset_tracking();
            return ForkDecision::Hold;
        }
        if !self.dwell_expired(winner.height) {
            return self.pending();
        }
        let (w, l) = (key(winner).0, key(forks.iter().find(|f| f.is_local).unwrap_or(winner)).0);
        self.reset_tracking();
        ForkDecision::Adopt {
            target_hash: winner.tip_hash,
            target_height: winner.height,
            reason: format!(
                "longest most legitimate: winner (witnessed={}, length={}, votes={}, participation={}) \
                 outranks local (witnessed={}, length={}, votes={}, participation={}); \
                 heights local={local_height} winner={}",
                w.fully_witnessed, w.length, w.votes, w.participation,
                l.fully_witnessed, l.length, l.votes, l.participation,
                winner.height
            ),
        }
    }

    /// Advance the dwell for the tracked winner — at most once per cycle —
    /// and report whether it has persisted for `min_fork_duration` cycles.
    fn dwell_expired(&mut self, winner_height: u64) -> bool {
        match self.tracked_fork_height {
            Some(prev) if winner_height < prev => {
                self.fork_dwell_counter = 0;
                self.last_dwell_cycle = None;
            }
            None => {
                self.fork_dwell_counter = 0;
                self.last_dwell_cycle = None;
            }
            _ => {}
        }
        self.tracked_fork_height = Some(winner_height);
        if self.last_dwell_cycle != Some(self.current_cycle) {
            self.fork_dwell_counter += 1;
            self.last_dwell_cycle = Some(self.current_cycle);
        }
        self.fork_dwell_counter >= self.min_fork_duration
    }

    fn pending(&self) -> ForkDecision {
        ForkDecision::Pending {
            cycles_remaining: self.min_fork_duration.saturating_sub(self.fork_dwell_counter),
        }
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
        self.last_dwell_cycle = None;
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

    fn leg(w: bool, length: u64, votes: u64, participation: u64) -> SegmentLegitimacy {
        SegmentLegitimacy::Known(Legitimacy { fully_witnessed: w, length, votes, participation })
    }

    /// Fully witnessed by two validators, one vote each per block.
    fn dual(length: u64) -> SegmentLegitimacy { leg(true, length, length * 2, 2) }
    /// One validator minting alone.
    fn solo(length: u64) -> SegmentLegitimacy { leg(false, length, length, 1) }

    fn fork(id: u8, height: u64, peers: usize, is_local: bool, legitimacy: SegmentLegitimacy) -> ForkInfo {
        ForkInfo { tip_hash: hash(id), height, peer_count: peers, is_local, has_chain_owner: false, legitimacy }
    }
    fn local(height: u64, l: SegmentLegitimacy) -> ForkInfo { fork(0, height, 1, true, l) }
    fn remote(id: u8, height: u64, peers: usize, l: SegmentLegitimacy) -> ForkInfo { fork(id, height, peers, false, l) }

    /// Plain-height helpers for the strategy/dwell tests: both fully witnessed.
    fn local_fork(height: u64) -> ForkInfo { local(height, dual(height)) }
    fn remote_fork(id: u8, height: u64, peers: usize) -> ForkInfo { remote(id, height, peers, dual(height)) }

    fn fr(min: u32) -> ForkResolver { ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, min) }

    fn adopt_target(d: ForkDecision) -> u64 {
        match d {
            ForkDecision::Adopt { target_height, .. } => target_height,
            other => panic!("expected Adopt, got {other:?}"),
        }
    }

    // ── The principles ──

    #[test]
    fn the_bare_ancestor_is_never_a_candidate() {
        // We sit on the ancestor (no blocks above it). One rival has blocks.
        // We adopt. There is no decision that makes the rival abandon.
        let mut r = fr(1);
        let forks = vec![local(1279, leg(true, 0, 0, 0)), remote(1, 1289, 1, solo(10))];
        assert_eq!(adopt_target(r.evaluate(1279, 1279, &forks, 1, hash(0))), 1289);
    }

    #[test]
    fn winner_only_ever_receives_hold() {
        // Over many candidate sets, whichever fork is the max by Legitimacy
        // gets Hold from its own point of view — never Adopt, never anything
        // that touches its blocks.
        let mut seed = 0x9E37_79B9u32;
        let mut next = || { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; seed };
        for _ in 0..500 {
            let n = 2 + (next() % 4) as usize;
            let ancestor = 100;
            let mut forks: Vec<ForkInfo> = (0..n)
                .map(|i| {
                    let length = 1 + (next() % 12) as u64;
                    let w = next() % 2 == 0;
                    let votes = if w { length * 2 } else { length };
                    let part = if w { 2 } else { 1 };
                    fork(i as u8 + 1, ancestor + length, 1, false, leg(w, length, votes, part))
                })
                .collect();
            let win = forks
                .iter()
                .enumerate()
                .max_by_key(|(_, f)| match f.legitimacy { SegmentLegitimacy::Known(l) => (l, Reverse(f.tip_hash.0)), _ => unreachable!() })
                .map(|(i, _)| i)
                .unwrap();
            forks[win].is_local = true;
            let (h, t) = (forks[win].height, forks[win].tip_hash);
            let mut r = fr(1);
            assert_eq!(r.evaluate(h, ancestor, &forks, n, t), ForkDecision::Hold, "winner must hold: {forks:?}");
        }
    }

    #[test]
    fn two_node_solo_divergence_picks_length() {
        // The live 0x93CDD0F8 case: ancestor 1279; A 10 solo blocks, B 5.
        let a = solo(10);
        let b = solo(5);
        // B's view → adopt A.
        let mut r = fr(1);
        let from_b = vec![local(1284, b), remote(1, 1289, 1, a)];
        assert_eq!(adopt_target(r.evaluate(1284, 1279, &from_b, 1, hash(0))), 1289);
        // A's view → hold. Exactly one side moves.
        let mut r = fr(1);
        let from_a = vec![local(1289, a), remote(2, 1284, 1, b)];
        assert_eq!(r.evaluate(1289, 1279, &from_a, 1, hash(0)), ForkDecision::Hold);
    }

    #[test]
    fn peer_arriving_at_ancestor_makes_nobody_abandon() {
        // The exact race that destroyed A: the rival rolled back to the
        // ancestor mid-adoption. It has no blocks above it → not a candidate.
        let mut r = fr(1);
        let forks = vec![local(1289, solo(10)), remote(1, 1279, 1, leg(true, 0, 0, 0))];
        assert_eq!(r.evaluate(1289, 1279, &forks, 1, hash(0)), ForkDecision::Hold);
    }

    // ── The ordering ──

    #[test]
    fn witnessed_beats_longer_self_voted() {
        let mut r = fr(1);
        let forks = vec![local(1290, solo(11)), remote(1, 1284, 1, dual(5))];
        assert_eq!(adopt_target(r.evaluate(1290, 1279, &forks, 1, hash(0))), 1284);
        let mut r = fr(1);
        let forks = vec![local(1284, dual(5)), remote(1, 1290, 1, solo(11))];
        assert_eq!(r.evaluate(1284, 1279, &forks, 1, hash(0)), ForkDecision::Hold);
    }

    #[test]
    fn longer_wins_within_a_class() {
        let mut r = fr(1);
        let forks = vec![local(105, dual(5)), remote(1, 108, 1, dual(8))];
        assert_eq!(adopt_target(r.evaluate(105, 100, &forks, 1, hash(0))), 108);
    }

    #[test]
    fn equal_length_more_votes_wins() {
        let mut r = fr(1);
        let forks = vec![local(105, leg(true, 5, 10, 2)), remote(1, 105, 1, leg(true, 5, 15, 3))];
        assert_eq!(adopt_target(r.evaluate(105, 100, &forks, 1, hash(0))), 105);
    }

    #[test]
    fn equal_votes_more_participation_wins() {
        let mut r = fr(1);
        let forks = vec![local(105, leg(true, 5, 10, 2)), remote(1, 105, 1, leg(true, 5, 10, 3))];
        assert_eq!(adopt_target(r.evaluate(105, 100, &forks, 1, hash(0))), 105);
    }

    #[test]
    fn full_tie_breaks_on_hash_and_is_complementary() {
        // Identical legitimacy on both sides: the lower tip hash wins, and
        // evaluating from each side yields exactly one Adopt.
        let lo = hash(1);
        let hi = hash(9);
        let l = solo(5);
        let mut r = fr(1);
        let from_hi = vec![
            ForkInfo { tip_hash: hi, height: 105, peer_count: 1, is_local: true, has_chain_owner: false, legitimacy: l },
            ForkInfo { tip_hash: lo, height: 105, peer_count: 1, is_local: false, has_chain_owner: false, legitimacy: l },
        ];
        assert!(matches!(r.evaluate(105, 100, &from_hi, 1, hi), ForkDecision::Adopt { target_hash, .. } if target_hash == lo));
        let mut r = fr(1);
        let from_lo = vec![
            ForkInfo { tip_hash: lo, height: 105, peer_count: 1, is_local: true, has_chain_owner: false, legitimacy: l },
            ForkInfo { tip_hash: hi, height: 105, peer_count: 1, is_local: false, has_chain_owner: false, legitimacy: l },
        ];
        assert_eq!(r.evaluate(105, 100, &from_lo, 1, lo), ForkDecision::Hold);
    }

    #[test]
    fn unknown_rival_is_assessed_not_adopted() {
        let mut r = fr(1);
        let forks = vec![local(105, dual(5)), remote(1, 120, 1, SegmentLegitimacy::Unknown)];
        match r.evaluate(105, 100, &forks, 1, hash(0)) {
            ForkDecision::Assess { target_height, from_height, .. } => {
                assert_eq!((target_height, from_height), (120, 100));
            }
            other => panic!("an unassessed rival must be assessed, got {other:?}"),
        }
    }

    #[test]
    fn chain_owner_has_no_say_in_same_chain_decisions() {
        let mut r = fr(1);
        let mut owner = local(105, dual(5));
        owner.has_chain_owner = true;
        let forks = vec![owner, remote(1, 108, 1, dual(8))];
        assert_eq!(adopt_target(r.evaluate(105, 100, &forks, 1, hash(0))), 108);
    }

    // ── Dwell, finality, strategies ──

    #[test]
    fn dwell_counts_cycles_not_ticks() {
        let mut r = fr(3);
        let forks = vec![local_fork(5), remote_fork(1, 20, 2)];
        r.note_cycle(100);
        // Thirty evaluations inside one cycle: one unit of dwell.
        for _ in 0..30 {
            assert!(matches!(r.evaluate(5, 4, &forks, 3, hash(0)), ForkDecision::Pending { .. }));
        }
        assert_eq!(r.dwell_counter(), 1);
        r.note_cycle(101);
        assert_eq!(r.evaluate(5, 4, &forks, 3, hash(0)), ForkDecision::Pending { cycles_remaining: 1 });
        r.note_cycle(102);
        assert_eq!(adopt_target(r.evaluate(5, 4, &forks, 3, hash(0))), 20);
    }

    #[test]
    fn fork_shrink_resets_dwell() {
        let mut r = fr(3);
        let a = vec![local_fork(5), remote_fork(1, 20, 2)];
        r.note_cycle(1); r.evaluate(5, 4, &a, 3, hash(0));
        r.note_cycle(2); r.evaluate(5, 4, &a, 3, hash(0));
        assert_eq!(r.dwell_counter(), 2);
        // A shorter winner takes over → dwell restarts.
        let b = vec![local_fork(5), remote_fork(2, 15, 3)];
        r.note_cycle(3);
        assert_eq!(r.evaluate(5, 4, &b, 4, hash(0)), ForkDecision::Pending { cycles_remaining: 2 });
        assert_eq!(r.dwell_counter(), 1);
    }

    #[test]
    fn fork_growth_keeps_dwell() {
        let mut r = fr(3);
        r.note_cycle(1); r.evaluate(5, 4, &[local_fork(5), remote_fork(1, 20, 2)], 3, hash(0));
        r.note_cycle(2); r.evaluate(5, 4, &[local_fork(5), remote_fork(2, 21, 2)], 3, hash(0));
        assert_eq!(r.dwell_counter(), 2);
        r.note_cycle(3);
        assert_eq!(adopt_target(r.evaluate(5, 4, &[local_fork(5), remote_fork(3, 22, 2)], 3, hash(0))), 22);
    }

    #[test]
    fn never_adopts_below_finality() {
        let mut r = fr(1);
        r.set_finalized_height(10);
        let forks = vec![local_fork(5), remote_fork(1, 8, 5)];
        assert_eq!(r.evaluate(5, 4, &forks, 5, hash(0)), ForkDecision::Hold);
    }

    #[test]
    fn no_peers_no_decision() {
        let mut r = fr(1);
        assert_eq!(r.evaluate(5, 4, &[local_fork(5)], 0, hash(0)), ForkDecision::Hold);
    }

    #[test]
    fn manual_strategy_never_adopts() {
        let mut r = ForkResolver::new(ForkResolutionStrategy::Manual, 3);
        let forks = vec![local_fork(5), remote_fork(1, 100, 10)];
        assert_eq!(r.evaluate(5, 4, &forks, 10, hash(0)), ForkDecision::Hold);
    }

    #[test]
    fn peer_supermajority_triggers() {
        let mut r = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 1);
        let forks = vec![local_fork(5), remote_fork(1, 5, 3)];
        assert_eq!(adopt_target(r.evaluate(5, 4, &forks, 4, hash(0))), 5);
    }

    #[test]
    fn peer_supermajority_below_threshold() {
        let mut r = ForkResolver::new(ForkResolutionStrategy::PeerSupermajority, 3);
        let forks = vec![local_fork(5), remote_fork(1, 5, 1)];
        assert_eq!(r.evaluate(5, 4, &forks, 3, hash(0)), ForkDecision::Hold);
    }

    #[test]
    fn strategy_change_resets_state() {
        let mut r = fr(3);
        r.note_cycle(1);
        r.evaluate(5, 4, &[local_fork(5), remote_fork(1, 20, 2)], 3, hash(0));
        assert_eq!(r.dwell_counter(), 1);
        r.set_strategy(ForkResolutionStrategy::PeerSupermajority);
        assert_eq!(r.dwell_counter(), 0);
        assert_eq!(r.tracked_fork_height(), None);
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
