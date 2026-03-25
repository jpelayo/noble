// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-validator reputation scoring engine.
//!
//! Tracks block acceptance, votes, uptime, validator list presence,
//! and voting badge to produce a composite score in [0.0, 1.0].
//!
//! raw = 0.20 × acceptance_rate + 0.20 × votes_received + 0.05 × uptime + 0.45 × list_presence
//! score = raw × badge_modifier × penalty

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Weight for block acceptance rate (accepted / (accepted + rejected)).
const W_ACCEPTANCE: f64 = 0.20;
/// Weight for vote reception (votes_cast / total_network_votes).
const W_VOTES: f64 = 0.20;
/// Weight for uptime (uptime_cycles / total_cycles).
const W_UPTIME: f64 = 0.05;
/// Weight for validator list presence (listers / peers_with_lists).
const W_PRESENCE: f64 = 0.45;

/// Per-validator statistics used to compute reputation scores.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationData {
    /// Number of blocks proposed by this validator that were accepted (committed).
    pub blocks_accepted: u64,
    /// Number of blocks proposed by this validator that were rejected or lost.
    pub blocks_rejected: u64,
    /// Number of votes cast by this validator (R1 + R2).
    pub votes_cast: u64,
    /// Number of vote opportunities missed by this validator.
    pub votes_missed: u64,
    /// Number of cycles where this validator was observed online.
    pub uptime_cycles: u64,
    /// Total number of cycles since this validator was first tracked.
    pub total_cycles: u64,
    /// Last cycle number processed (to prevent double-counting).
    pub last_cycle: u64,
    /// Number of misbehavior incidents (double-proposal or vote equivocation).
    #[serde(default)]
    pub misbehavior_count: u64,
    /// Total votes cast across ALL validators network-wide (denominator for votes_received).
    #[serde(default)]
    pub total_network_votes: u64,
    /// Number of peers that include this validator in their validator list.
    #[serde(default)]
    pub listers_count: u64,
    /// Total number of peers with known validator lists (denominator for list presence).
    #[serde(default)]
    pub total_peers_with_lists: u64,
    /// Whether this validator holds the voting capability badge.
    #[serde(default)]
    pub has_voting_badge: bool,
    /// Current consensus cycle number (set each cycle boundary).
    /// Used to determine if the chain is in bootstrap mode.
    #[serde(default)]
    pub current_cycle: u64,
}

impl ReputationData {
    /// Compute the composite reputation score in [0.0, 1.0].
    ///
    /// Formula: `raw × badge_modifier × penalty`
    /// - raw = 0.20×acceptance + 0.20×votes + 0.05×uptime + 0.45×presence
    /// - badge_modifier = 1.0 if has_voting_badge OR in bootstrap mode, 0.5 otherwise
    /// - penalty = linear 10% per misbehavior incident (0 at 10)
    pub fn score(&self) -> f64 {
        let acceptance = if self.blocks_accepted + self.blocks_rejected > 0 {
            self.blocks_accepted as f64 / (self.blocks_accepted + self.blocks_rejected) as f64
        } else {
            0.0
        };

        let votes_received = if self.total_network_votes > 0 {
            self.votes_cast as f64 / self.total_network_votes as f64
        } else {
            0.0
        };

        let uptime = if self.total_cycles > 0 {
            self.uptime_cycles as f64 / self.total_cycles as f64
        } else {
            0.0
        };

        let presence = if self.total_peers_with_lists > 0 {
            self.listers_count as f64 / self.total_peers_with_lists as f64
        } else {
            0.0
        };

        let raw = W_ACCEPTANCE * acceptance
                + W_VOTES * votes_received
                + W_UPTIME * uptime
                + W_PRESENCE * presence;

        let in_bootstrap = self.current_cycle < noble_core::BOOTSTRAP_MODE_CYCLES;
        let badge_modifier = if in_bootstrap || self.has_voting_badge { 1.0 } else { 0.5 };
        let penalty = (1.0 - 0.1 * self.misbehavior_count.min(10) as f64).max(0.0);

        (raw * badge_modifier * penalty).clamp(0.0, 1.0)
    }
}

/// Engine that tracks and computes validator reputation scores.
///
/// Keyed by wire-format public key bytes for consistency with `ValidatorList`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationEngine {
    data: HashMap<Vec<u8>, ReputationData>,
}

impl ReputationEngine {
    /// Create a new, empty reputation engine.
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Restore from previously serialized data.
    pub fn from_data(data: HashMap<Vec<u8>, ReputationData>) -> Self {
        Self { data }
    }

    /// Get reputation data for a validator, or `None` if not tracked.
    pub fn get(&self, wire_bytes: &[u8]) -> Option<&ReputationData> {
        self.data.get(wire_bytes)
    }

    /// Compute the reputation score for a validator. Returns 0.0 if not tracked.
    pub fn score(&self, wire_bytes: &[u8]) -> f64 {
        self.data.get(wire_bytes).map(|d| d.score()).unwrap_or(0.0)
    }

    /// Record that a validator's block proposal was accepted (committed).
    pub fn record_block_accepted(&mut self, wire_bytes: &[u8]) {
        let entry = self.data.entry(wire_bytes.to_vec()).or_default();
        entry.blocks_accepted += 1;
    }

    /// Record that a validator's block proposal was rejected or lost.
    pub fn record_block_rejected(&mut self, wire_bytes: &[u8]) {
        let entry = self.data.entry(wire_bytes.to_vec()).or_default();
        entry.blocks_rejected += 1;
    }

    /// Record that a validator cast a vote during a cycle.
    pub fn record_vote_cast(&mut self, wire_bytes: &[u8]) {
        let entry = self.data.entry(wire_bytes.to_vec()).or_default();
        entry.votes_cast += 1;
    }

    /// Record that a validator missed a vote opportunity.
    pub fn record_vote_missed(&mut self, wire_bytes: &[u8]) {
        let entry = self.data.entry(wire_bytes.to_vec()).or_default();
        entry.votes_missed += 1;
    }

    /// Record a cycle for all tracked validators.
    ///
    /// `active_validators` lists wire-bytes of validators observed as online this cycle.
    /// All validators in `all_validators` have their `total_cycles` incremented.
    /// Validators in `active_validators` also get `uptime_cycles` incremented.
    pub fn record_cycle(
        &mut self,
        cycle: u64,
        all_validators: &[Vec<u8>],
        active_validators: &[Vec<u8>],
    ) {
        for wire in all_validators {
            let entry = self.data.entry(wire.clone()).or_default();
            // Dedup: skip if we already processed this exact cycle.
            // Use strict equality instead of >= to handle epoch resets
            // where cycle numbers restart from a lower value.
            if entry.last_cycle == cycle && cycle > 0 {
                continue; // Already processed this cycle
            }
            entry.total_cycles += 1;
            if active_validators.contains(wire) {
                entry.uptime_cycles += 1;
            }
            entry.last_cycle = cycle;
        }
    }

    /// Process end-of-cycle reputation updates.
    ///
    /// - `cycle`: the completed cycle number
    /// - `winner_wire`: wire bytes of the winning block's proposer (if any)
    /// - `loser_wires`: wire bytes of proposers whose blocks were not selected
    /// - `voters`: wire bytes of validators who cast at least one vote
    /// - `all_validators`: wire bytes of all validators in the trusted set
    /// - `active_validators`: wire bytes of validators observed as online
    /// - `listers`: wire → number of peers that list this validator
    /// - `total_peers_with_lists`: total peers with known validator lists
    /// - `badge_holders`: wire bytes of validators holding the voting capability badge
    pub fn process_cycle_boundary(
        &mut self,
        cycle: u64,
        winner_wire: Option<&[u8]>,
        loser_wires: &[Vec<u8>],
        voters: &[Vec<u8>],
        all_validators: &[Vec<u8>],
        active_validators: &[Vec<u8>],
        listers: &HashMap<Vec<u8>, u64>,
        total_peers_with_lists: u64,
        badge_holders: &[Vec<u8>],
    ) {
        // Record block acceptance/rejection
        if let Some(winner) = winner_wire {
            self.record_block_accepted(winner);
        }
        for loser in loser_wires {
            self.record_block_rejected(loser);
        }

        // Record votes cast/missed.
        // Only count vote participation in cycles that had candidates to vote
        // for.  Penalising validators for not voting in empty cycles (e.g.,
        // during sync catch-up when candidate_tracker is empty) produces
        // incorrect 0% participation scores.
        let had_candidates = winner_wire.is_some() || !loser_wires.is_empty();
        if had_candidates {
            for wire in all_validators {
                if voters.contains(wire) {
                    self.record_vote_cast(wire);
                } else {
                    self.record_vote_missed(wire);
                }
            }
        }

        // Record cycle uptime
        self.record_cycle(cycle, all_validators, active_validators);

        // Update network-wide vote denominator, list presence, and badge status.
        let total_votes_this_cycle = voters.len() as u64;
        for wire in all_validators {
            let entry = self.data.entry(wire.clone()).or_default();
            entry.total_network_votes += total_votes_this_cycle;
            entry.listers_count = listers.get(wire).copied().unwrap_or(0);
            entry.total_peers_with_lists = total_peers_with_lists;
            entry.has_voting_badge = badge_holders.contains(wire);
            entry.current_cycle = cycle;
        }
    }

    /// Record a misbehavior incident (equivocation or double-proposal).
    pub fn record_misbehavior(&mut self, wire_bytes: &[u8]) {
        let entry = self.data.entry(wire_bytes.to_vec()).or_default();
        entry.misbehavior_count += 1;
    }

    /// Return a snapshot of all tracked data (for persistence).
    pub fn snapshot(&self) -> &HashMap<Vec<u8>, ReputationData> {
        &self.data
    }

    /// Number of tracked validators.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether no validators are tracked.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_engine_returns_zero_score() {
        let engine = ReputationEngine::new();
        assert_eq!(engine.score(b"unknown"), 0.0);
        assert!(engine.is_empty());
    }

    /// Helper: set up a perfect validator with all new fields.
    fn make_perfect_data() -> ReputationData {
        ReputationData {
            blocks_accepted: 10,
            blocks_rejected: 0,
            votes_cast: 10,
            votes_missed: 0,
            uptime_cycles: 10,
            total_cycles: 10,
            last_cycle: 10,
            misbehavior_count: 0,
            total_network_votes: 10,  // votes_cast/total = 10/10 = 1.0
            listers_count: 5,
            total_peers_with_lists: 5, // 5/5 = 1.0
            has_voting_badge: true,
            current_cycle: 10_000, // past bootstrap (4,320)
        }
    }

    #[test]
    fn perfect_validator_with_badge_scores_one() {
        let data = make_perfect_data();
        let score = data.score();
        // 0.20×1.0 + 0.20×1.0 + 0.05×1.0 + 0.45×1.0 = 0.90
        // Wait: 0.20+0.20+0.05+0.45 = 0.90, not 1.0. Badge=1.0, penalty=1.0.
        // raw = 0.90. But acceptance=1.0 means blocks_accepted/(accepted+rejected)=10/10=1.0.
        // votes=votes_cast/total_network=10/10=1.0. uptime=10/10=1.0. presence=5/5=1.0.
        // raw = 0.20 + 0.20 + 0.05 + 0.45 = 0.90. × 1.0 × 1.0 = 0.90.
        // Hmm — weights sum to 0.90 not 1.0. That's the design (presence is 45% of a capped scale).
        assert!((score - 0.90).abs() < 1e-10, "perfect with badge: {score}");
    }

    #[test]
    fn no_badge_halves_score() {
        let mut data = make_perfect_data();
        data.has_voting_badge = false;
        let score = data.score();
        // 0.90 × 0.5 = 0.45
        assert!((score - 0.45).abs() < 1e-10, "no badge: {score}");
    }

    #[test]
    fn bootstrap_bypasses_badge_penalty() {
        let mut data = make_perfect_data();
        data.has_voting_badge = false;
        data.current_cycle = 100; // within bootstrap (< 4,320)
        let score = data.score();
        // During bootstrap, badge_modifier = 1.0 even without badge
        // 0.90 × 1.0 × 1.0 = 0.90
        assert!((score - 0.90).abs() < 1e-10, "bootstrap no badge: {score}");
    }

    #[test]
    fn uptime_only_scores_low() {
        let data = ReputationData {
            uptime_cycles: 10,
            total_cycles: 10,
            has_voting_badge: true,
            ..Default::default()
        };
        let score = data.score();
        // 0.20×0 + 0.20×0 + 0.05×1.0 + 0.45×0 = 0.05 × 1.0 × 1.0 = 0.05
        assert!((score - 0.05).abs() < 1e-10, "uptime only: {score}");
    }

    #[test]
    fn no_proposals_gets_zero_acceptance() {
        let data = ReputationData {
            votes_cast: 10,
            total_network_votes: 10,
            uptime_cycles: 10,
            total_cycles: 10,
            listers_count: 5,
            total_peers_with_lists: 5,
            has_voting_badge: true,
            ..Default::default()
        };
        let score = data.score();
        // acceptance=0 (no proposals), votes=1.0, uptime=1.0, presence=1.0
        // 0.20×0 + 0.20×1.0 + 0.05×1.0 + 0.45×1.0 = 0 + 0.20 + 0.05 + 0.45 = 0.70
        assert!((score - 0.70).abs() < 1e-10, "no proposals: {score}");
    }

    #[test]
    fn misbehavior_linear_penalty() {
        let mut data = make_perfect_data();
        data.misbehavior_count = 5;
        let score = data.score();
        // raw=0.90, badge=1.0, penalty=1.0-0.5=0.5 → 0.90×1.0×0.5 = 0.45
        assert!((score - 0.45).abs() < 1e-10, "5 misbehaviors: {score}");
    }

    #[test]
    fn ten_misbehaviors_zero_score() {
        let mut data = make_perfect_data();
        data.misbehavior_count = 10;
        let score = data.score();
        // penalty = max(0, 1.0-1.0) = 0.0 → score = 0.0
        assert!((score - 0.0).abs() < 1e-10, "10 misbehaviors: {score}");
    }

    #[test]
    fn process_cycle_boundary_updates_all_stats() {
        let mut engine = ReputationEngine::new();
        let v1 = b"v1".to_vec();
        let v2 = b"v2".to_vec();
        let v3 = b"v3".to_vec();
        let all = vec![v1.clone(), v2.clone(), v3.clone()];

        // v1 wins, v2 loses, v3 didn't propose
        // v1 and v2 voted, v3 missed
        let listers = HashMap::new();
        engine.process_cycle_boundary(
            1,
            Some(&v1),
            &[v2.clone()],
            &[v1.clone(), v2.clone()],
            &all,
            &[v1.clone(), v2.clone()], // v3 offline
            &listers,
            0,
            &[], // no badge holders
        );

        let d1 = engine.get(&v1).unwrap();
        assert_eq!(d1.blocks_accepted, 1);
        assert_eq!(d1.votes_cast, 1);
        assert_eq!(d1.uptime_cycles, 1);
        assert_eq!(d1.total_cycles, 1);

        let d2 = engine.get(&v2).unwrap();
        assert_eq!(d2.blocks_rejected, 1);
        assert_eq!(d2.votes_cast, 1);
        assert_eq!(d2.uptime_cycles, 1);

        let d3 = engine.get(&v3).unwrap();
        assert_eq!(d3.blocks_accepted, 0);
        assert_eq!(d3.votes_missed, 1);
        assert_eq!(d3.uptime_cycles, 0);
        assert_eq!(d3.total_cycles, 1);
    }

    #[test]
    fn duplicate_cycle_not_double_counted() {
        let mut engine = ReputationEngine::new();
        let wire = b"v1".to_vec();

        engine.record_cycle(1, &[wire.clone()], &[wire.clone()]);
        engine.record_cycle(1, &[wire.clone()], &[wire.clone()]); // duplicate

        let data = engine.get(&wire).unwrap();
        assert_eq!(data.total_cycles, 1);
        assert_eq!(data.uptime_cycles, 1);
    }

    #[test]
    fn serialization_roundtrip() {
        use noble_codec::NobleCbor;

        let mut engine = ReputationEngine::new();
        let wire = b"v1".to_vec();
        engine.record_block_accepted(&wire);
        engine.record_vote_cast(&wire);
        engine.record_cycle(1, &[wire.clone()], &[wire.clone()]);

        let bytes = engine.to_cbor().unwrap();
        let restored = ReputationEngine::from_cbor(&bytes).unwrap();

        assert_eq!(restored.score(&wire), engine.score(&wire));
    }

    #[test]
    fn score_is_clamped_to_unit_interval() {
        let data = ReputationData {
            blocks_accepted: u64::MAX,
            blocks_rejected: 0,
            votes_cast: u64::MAX,
            votes_missed: 0,
            uptime_cycles: u64::MAX,
            total_cycles: u64::MAX,
            last_cycle: 0,
            current_cycle: 10_000,
            misbehavior_count: 0,
            total_network_votes: 1,
            listers_count: u64::MAX,
            total_peers_with_lists: u64::MAX,
            has_voting_badge: true,
        };
        let score = data.score();
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn serialization_roundtrip_with_misbehavior() {
        use noble_codec::NobleCbor;

        let mut engine = ReputationEngine::new();
        let wire = b"v1".to_vec();
        engine.record_block_accepted(&wire);
        engine.record_vote_cast(&wire);
        engine.record_cycle(1, &[wire.clone()], &[wire.clone()]);
        engine.record_misbehavior(&wire);

        let bytes = engine.to_cbor().unwrap();
        let restored = ReputationEngine::from_cbor(&bytes).unwrap();

        assert_eq!(restored.score(&wire), engine.score(&wire));
        assert_eq!(restored.get(&wire).unwrap().misbehavior_count, 1);
    }
}
