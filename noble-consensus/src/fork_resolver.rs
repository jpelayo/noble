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
    /// Resolve by verified legitimacy first, then length.
    ///
    /// Same-chain forks are ranked by [`SegmentLegitimacy`]: a segment with any
    /// under-witnessed block is Tier 0 and is never adopted while a witnessed
    /// alternative exists; witnessed segments are graded ([`Grade`]) and only
    /// among equal grades does height decide. Cross-chain adoption still uses
    /// decay-weighted vote weight as its tiebreaker.
    LongestMostLegitimate,
}

/// Chain owner (block 1 validator) edge.
///
/// Historically a virtual +5 in height, which let the owner's fork win while
/// *shorter* — and therefore let an owner that minted alone out-rank a
/// witnessed chain. Ownership is now a **tiebreak** among otherwise equal
/// forks (see `Grade` ordering); this constant is retained for API
/// compatibility and no longer contributes to any height comparison.
pub const CHAIN_OWNER_EDGE_BLOCKS: u64 = 5;

// ── Legitimacy gradation ─────────────────────────────────────────────────────

/// Grade of a fully-witnessed segment (every block has ≥ `min_unique_voters`
/// verified witnesses). Derived `Ord` is lexicographic in field order, which
/// *is* the rule: a chain is only as legitimate as its weakest block, so
/// minimums rank before sums and sums before length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct Grade {
    /// `min_b w(b)` — witnesses on the least-witnessed block.
    pub weakest: u64,
    /// `min_b r1(b)` — round-1 (independent) witnesses on the weakest block.
    pub weakest_r1: u64,
    /// Distinct validator keys that witnessed anywhere in the segment.
    pub coverage: u64,
    /// `Σ_b w(b)` — total witness support; length re-enters here, weighted.
    pub total: u64,
}

/// Grade of a self-voted segment, used only when every candidate is Tier 0.
/// Witnesses cannot separate solo runs, so the unit is **participation** —
/// who took part in each block in any role (witness or proposer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct SoloGrade {
    /// Distinct validators participating anywhere in the segment.
    pub variety: u64,
    /// `⌊1000 · Σ_b |P(b)| / |S|⌋` — average participants per block.
    pub density_x1000: u64,
    /// Blocks inside the segment that were fully witnessed.
    pub witnessed_blocks: u64,
    /// `min_k |{b : k ∈ P(b)}|` — the least-participating key's block count.
    pub balance: u64,
    /// `Σ_b |P(b)|` — total participation.
    pub total: u64,
}

/// Verified legitimacy of a fork's segment above the common ancestor.
///
/// Computed from `WitnessCertificate`s that the evaluating node has fetched
/// and verified itself — never from anything a peer announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SegmentLegitimacy {
    /// Every block in the segment is witnessed. Tier 1.
    Witnessed(Grade),
    /// At least one block in the segment has fewer than `min_unique_voters`
    /// verified witnesses (or none provable). Tier 0 — legitimacy zero against
    /// any witnessed alternative; graded among its own kind.
    SelfVoted { first_solo: u64, grade: SoloGrade },
    /// The fork's tip *is* the common ancestor: it holds the shared witnessed
    /// prefix and nothing above it. Counts as a witnessed alternative.
    NotContesting,
    /// Not yet assessed. Never adoptable until it is; bounded lifetime.
    Unknown,
}

impl SegmentLegitimacy {
    /// Stable string for RPC / GUI / events.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Witnessed(_) => "witnessed",
            Self::SelfVoted { .. } => "self_voted",
            Self::NotContesting => "not_contesting",
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
    pub has_chain_owner: bool,
    /// Verified legitimacy of this fork's segment above the common ancestor.
    pub legitimacy: SegmentLegitimacy,
    /// Local fork only: highest height `h` such that every block in
    /// `(ancestor, h]` is witnessed — where a self-voted local segment is
    /// abandoned to. Ignored for remote forks.
    pub witnessed_prefix_end: u64,
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
    /// The dominant rival's legitimacy is unknown: fetch heights
    /// `(from_height, target_height]` with their vote witnesses and decide
    /// next tick. Nothing is adopted on an unassessed chain.
    Assess {
        target_hash: Hash256,
        target_height: u64,
        from_height: u64,
    },
    /// Our own segment is self-voted and a peer holds the witnessed prefix we
    /// share: roll back to `to_height`, adopt nothing, resume consensus.
    AbandonSelfVoted {
        to_height: u64,
        first_solo: u64,
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

/// Grade of a witnessed fork; `Grade::default()` (all zeros) for anything else.
fn grade_of(f: &ForkInfo) -> Grade {
    match f.legitimacy {
        SegmentLegitimacy::Witnessed(g) => g,
        _ => Grade::default(),
    }
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

        let local = forks.iter().find(|f| f.is_local);
        let local_leg = local.map(|f| f.legitimacy).unwrap_or(SegmentLegitimacy::Unknown);
        let prefix_end = local.map(|f| f.witnessed_prefix_end).unwrap_or(local_height);
        let rivals: Vec<&ForkInfo> = forks.iter().filter(|f| !f.is_local).collect();
        if rivals.is_empty() {
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // ── Legitimacy hierarchy — decided BEFORE any height logic ──
        //
        // A self-voted segment has legitimacy zero against anything witnessed.
        // It is never adopted while a witnessed alternative exists, and its
        // owner must abandon it. Among only self-voted segments, participation
        // from varied peers decides. Length enters only inside a tier.
        if let SegmentLegitimacy::SelfVoted { first_solo, grade } = local_leg {
            let local_info = local.expect("local fork present when legitimacy is known");
            return self.evaluate_self_voted_local(
                local_info, prefix_end, first_solo, grade, &rivals, local_tip_hash,
            );
        }

        // Local is witnessed (or holds only the shared prefix). Self-voted rivals
        // are never adoptable. Unknown rivals must be assessed before anything.
        let local_grade = match local_leg {
            SegmentLegitimacy::Witnessed(g) => g,
            _ => Grade::default(),
        };
        let mut witnessed: Vec<&ForkInfo> = Vec::new();
        let mut unknown: Option<&ForkInfo> = None;
        for r in &rivals {
            match r.legitimacy {
                SegmentLegitimacy::Witnessed(_) => witnessed.push(r),
                SegmentLegitimacy::Unknown => {
                    let better = unknown
                        .map(|u| (r.peer_count, r.height) > (u.peer_count, u.height))
                        .unwrap_or(true);
                    if better { unknown = Some(r); }
                }
                // Legitimacy zero — never adopted. Behind-us-on-our-chain — nothing to adopt.
                SegmentLegitimacy::SelfVoted { .. } | SegmentLegitimacy::NotContesting => {}
            }
        }
        if witnessed.is_empty() {
            // Only an unassessed rival that is actually ahead is worth fetching.
            if let Some(u) = unknown {
                if u.height > local_height {
                    return ForkDecision::Assess {
                        target_hash: u.tip_hash,
                        target_height: u.height,
                        from_height: prefix_end.min(local_height),
                    };
                }
            }
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Among witnessed rivals, grade decides first.
        let best = *witnessed
            .iter()
            .max_by_key(|f| (grade_of(f), f.height, f.has_chain_owner, f.peer_count, Reverse(f.tip_hash.0)))
            .expect("non-empty");
        let best_grade = grade_of(best);
        if best_grade > local_grade {
            // Higher legitimacy wins regardless of length — after dwell, never past finality.
            if best.height <= self.finalized_height {
                self.reset_tracking();
                return ForkDecision::NoAction;
            }
            if !self.dwell_expired(best.height) {
                return self.pending();
            }
            self.reset_tracking();
            return ForkDecision::Resolve {
                target_hash: best.tip_hash,
                target_height: best.height,
                reason: format!(
                    "legitimacy: rival segment grade {best_grade:?} outranks local {local_grade:?} \
                     (heights: local={local_height}, rival={})",
                    best.height
                ),
            };
        }
        if best_grade < local_grade {
            // Every witnessed rival is less legitimate than we are.
            self.reset_tracking();
            return ForkDecision::NoAction;
        }

        // Equal grade: the existing rules decide (height, then owner as a
        // tiebreak, then peers, then hash). Only equally-graded rivals compete.
        let equal: Vec<ForkInfo> = forks
            .iter()
            .filter(|f| f.is_local || (matches!(f.legitimacy, SegmentLegitimacy::Witnessed(g) if g == local_grade)))
            .cloned()
            .collect();
        self.evaluate_equal_grade(local_height, &equal, total_peers, local_tip_hash)
    }

    /// Step 4 for a self-voted local segment: we never keep it against anything
    /// witnessed, and among solo runs the better-participated one survives.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_self_voted_local(
        &mut self,
        local: &ForkInfo,
        prefix_end: u64,
        first_solo: u64,
        my_grade: SoloGrade,
        rivals: &[&ForkInfo],
        local_tip_hash: Hash256,
    ) -> ForkDecision {
        // 1. A witnessed rival exists → abandon ours and adopt it, even if shorter.
        if let Some(best) = rivals
            .iter()
            .filter(|f| matches!(f.legitimacy, SegmentLegitimacy::Witnessed(_)))
            .max_by_key(|f| (grade_of(f), f.height, f.has_chain_owner, f.peer_count, Reverse(f.tip_hash.0)))
        {
            if !self.dwell_expired(best.height) {
                return self.pending();
            }
            self.reset_tracking();
            return ForkDecision::Resolve {
                target_hash: best.tip_hash,
                target_height: best.height,
                reason: format!(
                    "local segment is self-voted from height {first_solo} (legitimacy 0) — \
                     yielding to witnessed rival at height {}",
                    best.height
                ),
            };
        }
        // 2. A peer sits on the witnessed prefix we share → abandon to it, adopt nothing.
        if rivals.iter().any(|f| f.legitimacy == SegmentLegitimacy::NotContesting) {
            if !self.dwell_expired(prefix_end) {
                return self.pending();
            }
            self.reset_tracking();
            return ForkDecision::AbandonSelfVoted {
                to_height: prefix_end,
                first_solo,
                reason: format!(
                    "local segment is self-voted from height {first_solo}; a peer holds the \
                     witnessed prefix at {prefix_end} — abandoning solo blocks"
                ),
            };
        }
        // 3. Unknown rivals must be assessed before we decide anything.
        if let Some(u) = rivals
            .iter()
            .filter(|f| f.legitimacy == SegmentLegitimacy::Unknown)
            .max_by_key(|f| (f.peer_count, f.height))
        {
            return ForkDecision::Assess {
                target_hash: u.tip_hash,
                target_height: u.height,
                from_height: prefix_end,
            };
        }
        // 4. Only solo runs on offer: participation grade decides; the loser yields.
        let solo_key = |f: &ForkInfo, g: SoloGrade| {
            (g, f.height, f.has_chain_owner, f.peer_count, Reverse(f.tip_hash.0))
        };
        let mine = solo_key(local, my_grade);
        let _ = local_tip_hash;
        let best = rivals
            .iter()
            .filter_map(|f| match f.legitimacy {
                SegmentLegitimacy::SelfVoted { grade, .. } => Some((*f, solo_key(f, grade))),
                _ => None,
            })
            .max_by_key(|(_, k)| *k);
        match best {
            Some((rival, key)) if key > mine => {
                if !self.dwell_expired(rival.height) {
                    return self.pending();
                }
                self.reset_tracking();
                ForkDecision::Resolve {
                    target_hash: rival.tip_hash,
                    target_height: rival.height,
                    reason: format!(
                        "only self-voted chains present: rival participation grade {:?} outranks \
                         local {:?} — yielding",
                        key.0, my_grade
                    ),
                }
            }
            _ => {
                // We are the better-participated solo run (or alone). The rival yields.
                self.reset_tracking();
                ForkDecision::NoAction
            }
        }
    }

    /// Advance the dwell counter for a tracked rival height; true once the
    /// fork has persisted for `min_fork_duration` evaluations.
    fn dwell_expired(&mut self, tracked_height: u64) -> bool {
        match self.tracked_fork_height {
            Some(prev) if tracked_height < prev => self.fork_dwell_counter = 0,
            None => self.fork_dwell_counter = 0,
            _ => {}
        }
        self.tracked_fork_height = Some(tracked_height);
        self.fork_dwell_counter += 1;
        self.fork_dwell_counter >= self.min_fork_duration
    }

    fn pending(&self) -> ForkDecision {
        ForkDecision::Pending {
            cycles_remaining: self.min_fork_duration.saturating_sub(self.fork_dwell_counter),
        }
    }

    /// The pre-hierarchy rules, applied only among forks of EQUAL grade:
    /// height threshold, dwell, same-height deadlock with the chain owner as
    /// tiebreak, peer count, lower hash.
    fn evaluate_equal_grade(
        &mut self,
        local_height: u64,
        forks: &[ForkInfo],
        total_peers: usize,
        local_tip_hash: Hash256,
    ) -> ForkDecision {
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
                // F2: the chain-owner edge is no longer a virtual +5 in height.
                // Legitimacy was decided before reaching here; among equally
                // graded forks height decides, and ownership breaks ties only
                // at equal height (same-height deadlock below).
                let dominant_effective = dominant.height;
                let local_effective = local_height;

                // Bootstrap fork: when both chains are very short (< EARLY_CHAIN_LIMIT),
                // any lead is enough to trigger resolution after the dwell delay.
                // Without this, two nodes that independently created different genesis
                // blocks would need a 4-block lead before resolving — far too slow
                // during the critical bootstrap phase.
                const EARLY_CHAIN_LIMIT: u64 = 10;
                if local_height < EARLY_CHAIN_LIMIT && dominant.height < EARLY_CHAIN_LIMIT {
                    // Any strictly-ahead fork triggers (after dwell).
                    dominant_effective > local_effective
                } else {
                    // Steady state: 4+ block lead required.
                    dominant_effective > local_effective.saturating_add(3)
                }
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
                    // Same-height deadlock resolved — skip normal dwell tracking
                    // and jump directly to resolution. Safety: never resolve
                    // past finalized height.
                    if dominant.height <= self.finalized_height {
                        self.reset_tracking();
                        return ForkDecision::NoAction;
                    }
                    // Fall through to build ForkDecision::Resolve below.
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
        } else {
            // threshold_met == true: normal dwell tracking path.

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
                let dominant_effective = dominant.height;
                let local_effective = local_height;
                let owner_note = match (local_has_owner, dominant.has_chain_owner) {
                    (false, true) => " (chain owner on dominant fork)",
                    (true, false) => " (chain owner on local fork)",
                    _ => "",
                };
                format!(
                    "fork resolution{} (equal legitimacy grade): dominant height={} vs local height={}",
                    owner_note, dominant_effective, local_effective
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
            legitimacy: SegmentLegitimacy::Witnessed(Grade::default()),
            witnessed_prefix_end: height,
        }
    }

    fn local_fork_owner(height: u64) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(0),
            height,
            peer_count: 1,
            is_local: true,
            has_chain_owner: true,
            legitimacy: SegmentLegitimacy::Witnessed(Grade::default()),
            witnessed_prefix_end: height,
        }
    }

    fn remote_fork(id: u8, height: u64, peer_count: usize) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(id),
            height,
            peer_count,
            is_local: false,
            has_chain_owner: false,
            legitimacy: SegmentLegitimacy::Witnessed(Grade::default()),
            witnessed_prefix_end: 0,
        }
    }

    fn remote_fork_owner(id: u8, height: u64, peer_count: usize) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(id),
            height,
            peer_count,
            is_local: false,
            has_chain_owner: true,
            legitimacy: SegmentLegitimacy::Witnessed(Grade::default()),
            witnessed_prefix_end: 0,
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
        // Fork 2 blocks ahead but both above EARLY_CHAIN_LIMIT (10) — uses steady-state threshold.
        // local=15, fork=17, diff=2 <= 3 → NoAction.
        let forks = vec![local_fork(15), remote_fork(1, 17, 2)];
        assert_eq!(fr.evaluate(15, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn bootstrap_fork_resolves_with_any_lead() {
        // During bootstrap (both < 10), any lead triggers resolution after dwell.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(1), remote_fork(1, 3, 1)];
        match fr.evaluate(1, &forks, 1, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 3),
            other => panic!("expected Resolve, got {:?}", other),
        }
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
        // Steady-state (both above EARLY_CHAIN_LIMIT=10): original >3 threshold applies.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(15), remote_fork(1, 19, 2)];
        let result = fr.evaluate(15, &forks, 3, hash(0));
        match result {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 19),
            other => panic!("expected Resolve, got {:?}", other),
        }

        // 3 blocks ahead is NOT enough in steady state (must be >3)
        let mut fr2 = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks2 = vec![local_fork(15), remote_fork(1, 18, 2)];
        assert_eq!(fr2.evaluate(15, &forks2, 3, hash(0)), ForkDecision::NoAction);
    }

    // ── Chain owner: a TIEBREAK, never a height edge (F2) ──

    #[test]
    fn chain_owner_equal_height_switch() {
        // Equal height, equal grade, owner on the dominant fork: the
        // same-height deadlock breaks toward the owner.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork(10), remote_fork_owner(1, 10, 2)];
        match fr.evaluate(10, &forks, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 10),
            other => panic!("expected Resolve, got {:?}", other),
        }
    }

    #[test]
    fn chain_owner_behind_does_not_override_height() {
        // The owner used to carry a virtual +5, so its fork won while 1 block
        // SHORTER — which let an owner that minted alone out-rank a witnessed
        // chain. Ownership no longer moves height: behind is behind.
        for owner_height in [9u64, 8, 7] {
            let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
            let forks = vec![local_fork(10), remote_fork_owner(1, owner_height, 2)];
            assert_eq!(
                fr.evaluate(10, &forks, 3, hash(0)),
                ForkDecision::NoAction,
                "owner at {owner_height} behind local 10 must not win"
            );
        }
    }

    #[test]
    fn chain_owner_local_stays() {
        // We are the owner, equal height, equal grade → tiebreak favours us.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork_owner(10), remote_fork(1, 10, 2)];
        assert_eq!(fr.evaluate(10, &forks, 3, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn owner_has_no_height_edge_against_a_longer_fork() {
        // Previously a non-owner needed a 9-block lead to override the owner
        // (owner +5, plus the 3-block steady-state threshold). Now the ordinary
        // threshold applies to everyone: 3 ahead is not enough, 4 is.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![local_fork_owner(10), remote_fork(1, 13, 2)];
        assert_eq!(fr.evaluate(10, &forks, 3, hash(0)), ForkDecision::NoAction);

        let mut fr2 = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks2 = vec![local_fork_owner(10), remote_fork(1, 14, 2)];
        match fr2.evaluate(10, &forks2, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 14),
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

    // ── Legitimacy hierarchy (F2 / F10) ──

    fn witnessed(weakest: u64, weakest_r1: u64, coverage: u64, total: u64) -> SegmentLegitimacy {
        SegmentLegitimacy::Witnessed(Grade { weakest, weakest_r1, coverage, total })
    }

    fn solo(first_solo: u64, variety: u64, density_x1000: u64, witnessed_blocks: u64, balance: u64, total: u64)
        -> SegmentLegitimacy
    {
        SegmentLegitimacy::SelfVoted {
            first_solo,
            grade: SoloGrade { variety, density_x1000, witnessed_blocks, balance, total },
        }
    }

    fn local_with(height: u64, legitimacy: SegmentLegitimacy, prefix_end: u64) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(0),
            height,
            peer_count: 1,
            is_local: true,
            has_chain_owner: false,
            legitimacy,
            witnessed_prefix_end: prefix_end,
        }
    }

    fn remote_with(id: u8, height: u64, peer_count: usize, legitimacy: SegmentLegitimacy) -> ForkInfo {
        ForkInfo {
            tip_hash: hash(id),
            height,
            peer_count,
            is_local: false,
            has_chain_owner: false,
            legitimacy,
            witnessed_prefix_end: 0,
        }
    }

    /// The two-node incident, exactly: a witnessed 20-block chain must not yield
    /// to a 40-block chain minted alone. Fails on the pre-hierarchy resolver,
    /// which compared height only and returned `Resolve`.
    #[test]
    fn self_voted_longer_fork_never_wins() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(20, witnessed(2, 2, 2, 40), 20),
            remote_with(1, 40, 1, solo(21, 1, 1000, 0, 20, 20)),
        ];
        assert_eq!(fr.evaluate(20, &forks, 2, hash(0)), ForkDecision::NoAction);
    }

    #[test]
    fn self_voted_local_abandons_to_shorter_witnessed_rival() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(36, solo(27, 1, 1000, 0, 10, 10), 26),
            remote_with(1, 30, 1, witnessed(2, 2, 2, 8)),
        ];
        match fr.evaluate(36, &forks, 2, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 30),
            other => panic!("a self-voted local segment must yield, got {other:?}"),
        }
    }

    #[test]
    fn owner_edge_cannot_rescue_a_self_voted_owner() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let mut local = local_with(40, solo(21, 1, 1000, 0, 20, 20), 20);
        local.has_chain_owner = true;
        let forks = vec![local, remote_with(1, 24, 1, witnessed(2, 2, 2, 8))];
        match fr.evaluate(40, &forks, 2, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 24),
            other => panic!("ownership must not outrank legitimacy, got {other:?}"),
        }
    }

    #[test]
    fn unknown_rival_is_assessed_not_adopted() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(20, witnessed(2, 2, 2, 40), 20),
            remote_with(1, 40, 3, SegmentLegitimacy::Unknown),
        ];
        match fr.evaluate(20, &forks, 3, hash(0)) {
            ForkDecision::Assess { target_height, from_height, .. } => {
                assert_eq!(target_height, 40);
                assert_eq!(from_height, 20);
            }
            other => panic!("an unassessed rival must be assessed first, got {other:?}"),
        }
    }

    #[test]
    fn an_offline_node_never_adopts_a_solo_run() {
        // B was merely offline: it holds the witnessed prefix at 26 and nothing
        // above. A solo-mined to 36. From B's side: NoAction. From A's side:
        // abandon to 26. Decisions are complementary.
        let mut b = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let b_view = vec![
            local_with(26, SegmentLegitimacy::NotContesting, 26),
            remote_with(1, 36, 1, solo(27, 1, 1000, 0, 10, 10)),
        ];
        assert_eq!(b.evaluate(26, &b_view, 1, hash(0)), ForkDecision::NoAction);

        let mut a = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let a_view = vec![
            local_with(36, solo(27, 1, 1000, 0, 10, 10), 26),
            remote_with(2, 26, 1, SegmentLegitimacy::NotContesting),
        ];
        match a.evaluate(36, &a_view, 1, hash(0)) {
            ForkDecision::AbandonSelfVoted { to_height, first_solo, .. } => {
                assert_eq!(to_height, 26);
                assert_eq!(first_solo, 27);
            }
            other => panic!("the solo node must come back to the prefix, got {other:?}"),
        }
    }

    #[test]
    fn only_solo_runs_present_the_more_varied_one_wins() {
        // Local: 10 blocks all by key A. Rival: 6 blocks, A and B alternating.
        // Variety 2 beats variety 1 despite being shorter; local yields.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(36, solo(27, 1, 1000, 0, 10, 10), 26),
            remote_with(1, 32, 1, solo(27, 2, 1000, 0, 3, 6)),
        ];
        match fr.evaluate(36, &forks, 1, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 32),
            other => panic!("more varied participation must win, got {other:?}"),
        }
    }

    #[test]
    fn solo_density_beats_solo_length_at_equal_variety() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(40, solo(21, 2, 1000, 0, 10, 20), 20),
            remote_with(1, 30, 1, solo(21, 2, 1500, 0, 5, 15)),
        ];
        match fr.evaluate(40, &forks, 1, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 30),
            other => panic!("denser participation must win, got {other:?}"),
        }
    }

    #[test]
    fn solo_balance_separates_9_1_from_5_5() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(30, solo(21, 2, 1000, 0, 1, 10), 20),   // 9/1 split
            remote_with(1, 30, 1, solo(21, 2, 1000, 0, 5, 10)), // 5/5 split
        ];
        match fr.evaluate(30, &forks, 1, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 30),
            other => panic!("balanced participation must win, got {other:?}"),
        }
    }

    #[test]
    fn two_identical_solo_runs_yield_exactly_one_side() {
        // Equal on every measure; lower tip hash wins — from BOTH points of view.
        let g = solo(21, 1, 1000, 0, 10, 10);
        // Node with tip hash(0) vs node with tip hash(1): hash(0) is lower.
        let mut lo = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let lo_view = vec![local_with(30, g, 20), remote_with(1, 30, 1, g)];
        assert_eq!(lo.evaluate(30, &lo_view, 1, hash(0)), ForkDecision::NoAction, "lower hash keeps its run");

        let mut hi = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let mut hi_local = local_with(30, g, 20);
        hi_local.tip_hash = hash(1);
        let mut hi_rival = remote_with(0, 30, 1, g);
        hi_rival.tip_hash = hash(0);
        let hi_view = vec![hi_local, hi_rival];
        match hi.evaluate(30, &hi_view, 1, hash(1)) {
            ForkDecision::Resolve { target_hash, .. } => assert_eq!(target_hash, hash(0)),
            other => panic!("higher hash must yield, got {other:?}"),
        }
    }

    #[test]
    fn grade_orders_weakest_before_total_before_length() {
        // 6 blocks all 3-witness beats 10 blocks all 2-witness: weakest first.
        assert!(Grade { weakest: 3, weakest_r1: 3, coverage: 3, total: 18 }
            > Grade { weakest: 2, weakest_r1: 2, coverage: 2, total: 20 });
        // Equal weakest: total decides.
        assert!(Grade { weakest: 2, weakest_r1: 2, coverage: 2, total: 20 }
            > Grade { weakest: 2, weakest_r1: 2, coverage: 2, total: 12 });
        // Equal grade → the resolver falls through to height.
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let g = witnessed(2, 2, 2, 20);
        let forks = vec![local_with(15, g, 15), remote_with(1, 19, 2, g)];
        match fr.evaluate(15, &forks, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 19),
            other => panic!("equal grade must fall through to height, got {other:?}"),
        }
    }

    #[test]
    fn a_more_legitimate_but_shorter_witnessed_fork_wins() {
        let mut fr = ForkResolver::new(ForkResolutionStrategy::LongestMostLegitimate, 1);
        let forks = vec![
            local_with(30, witnessed(2, 2, 2, 60), 30),
            remote_with(1, 26, 2, witnessed(3, 3, 3, 78)),
        ];
        match fr.evaluate(30, &forks, 3, hash(0)) {
            ForkDecision::Resolve { target_height, .. } => assert_eq!(target_height, 26),
            other => panic!("higher grade must win regardless of length, got {other:?}"),
        }
    }
}
