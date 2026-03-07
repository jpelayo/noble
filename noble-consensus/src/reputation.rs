// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-validator reputation scoring engine.
//!
//! Tracks block proposals (accepted/rejected), votes (cast/missed),
//! and uptime to produce a composite score in [0.0, 1.0].
//!
//! Score = 0.4 × acceptance_rate + 0.3 × participation_rate + 0.3 × uptime_ratio

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Weight for block acceptance component of the score.
const W_ACCEPTANCE: f64 = 0.4;
/// Weight for vote participation component of the score.
const W_PARTICIPATION: f64 = 0.3;
/// Weight for uptime component of the score.
const W_UPTIME: f64 = 0.3;

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
}

impl ReputationData {
    /// Compute the composite reputation score in [0.0, 1.0].
    pub fn score(&self) -> f64 {
        let acceptance = if self.blocks_accepted + self.blocks_rejected > 0 {
            self.blocks_accepted as f64 / (self.blocks_accepted + self.blocks_rejected) as f64
        } else {
            // No proposals yet — neutral (treat as 50% acceptance)
            0.5
        };

        let participation = if self.votes_cast + self.votes_missed > 0 {
            self.votes_cast as f64 / (self.votes_cast + self.votes_missed) as f64
        } else {
            0.0
        };

        let uptime = if self.total_cycles > 0 {
            self.uptime_cycles as f64 / self.total_cycles as f64
        } else {
            0.0
        };

        let raw = W_ACCEPTANCE * acceptance + W_PARTICIPATION * participation + W_UPTIME * uptime;
        // Misbehavior penalty: each incident halves the score, capped at 10.
        let penalty = if self.misbehavior_count > 0 {
            0.5_f64.powi(self.misbehavior_count.min(10) as i32)
        } else {
            1.0
        };
        (raw * penalty).clamp(0.0, 1.0)
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
    pub fn process_cycle_boundary(
        &mut self,
        cycle: u64,
        winner_wire: Option<&[u8]>,
        loser_wires: &[Vec<u8>],
        voters: &[Vec<u8>],
        all_validators: &[Vec<u8>],
        active_validators: &[Vec<u8>],
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

    #[test]
    fn perfect_validator_scores_one() {
        let mut engine = ReputationEngine::new();
        let wire = b"validator1".to_vec();

        // Perfect block acceptance: 10 accepted, 0 rejected
        for _ in 0..10 {
            engine.record_block_accepted(&wire);
        }
        // Perfect participation: 10 votes, 0 missed
        for _ in 0..10 {
            engine.record_vote_cast(&wire);
        }
        // Perfect uptime: 10/10 cycles
        for cycle in 1..=10 {
            engine.record_cycle(cycle, &[wire.clone()], &[wire.clone()]);
        }

        let score = engine.score(&wire);
        // 0.4 * 1.0 + 0.3 * 1.0 + 0.3 * 1.0 = 1.0
        assert!((score - 1.0).abs() < 1e-10);
    }

    #[test]
    fn no_proposals_gets_neutral_acceptance() {
        let mut engine = ReputationEngine::new();
        let wire = b"validator1".to_vec();

        // No proposals, perfect votes, perfect uptime
        for _ in 0..10 {
            engine.record_vote_cast(&wire);
        }
        for cycle in 1..=10 {
            engine.record_cycle(cycle, &[wire.clone()], &[wire.clone()]);
        }

        let score = engine.score(&wire);
        // 0.4 * 0.5 + 0.3 * 1.0 + 0.3 * 1.0 = 0.2 + 0.3 + 0.3 = 0.8
        assert!((score - 0.8).abs() < 1e-10);
    }

    #[test]
    fn poor_validator_scores_low() {
        let mut engine = ReputationEngine::new();
        let wire = b"badval".to_vec();

        // 1 accepted, 9 rejected = 10% acceptance
        engine.record_block_accepted(&wire);
        for _ in 0..9 {
            engine.record_block_rejected(&wire);
        }
        // 2 votes cast, 8 missed = 20% participation
        engine.record_vote_cast(&wire);
        engine.record_vote_cast(&wire);
        for _ in 0..8 {
            engine.record_vote_missed(&wire);
        }
        // 1 uptime cycle out of 10 = 10% uptime
        engine.record_cycle(1, &[wire.clone()], &[wire.clone()]);
        for cycle in 2..=10 {
            engine.record_cycle(cycle, &[wire.clone()], &[]);
        }

        let score = engine.score(&wire);
        // 0.4 * 0.1 + 0.3 * 0.2 + 0.3 * 0.1 = 0.04 + 0.06 + 0.03 = 0.13
        assert!((score - 0.13).abs() < 1e-10);
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
        engine.process_cycle_boundary(
            1,
            Some(&v1),
            &[v2.clone()],
            &[v1.clone(), v2.clone()],
            &all,
            &[v1.clone(), v2.clone()], // v3 offline
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
            misbehavior_count: 0,
        };
        let score = data.score();
        assert!(score >= 0.0 && score <= 1.0);
    }

    #[test]
    fn misbehavior_reduces_score() {
        let mut engine = ReputationEngine::new();
        let wire = b"validator1".to_vec();

        // Perfect validator
        for _ in 0..10 {
            engine.record_block_accepted(&wire);
            engine.record_vote_cast(&wire);
        }
        for cycle in 1..=10 {
            engine.record_cycle(cycle, &[wire.clone()], &[wire.clone()]);
        }

        let clean_score = engine.score(&wire);
        assert!((clean_score - 1.0).abs() < 1e-10);

        // Record 1 misbehavior → 0.5× penalty
        engine.record_misbehavior(&wire);
        let penalized_score = engine.score(&wire);
        assert!(
            (penalized_score - 0.5).abs() < 1e-10,
            "1 misbehavior should halve score, got {}",
            penalized_score
        );
    }

    #[test]
    fn multiple_misbehaviors_compound() {
        let mut engine = ReputationEngine::new();
        let wire = b"badactor".to_vec();

        for _ in 0..10 {
            engine.record_block_accepted(&wire);
            engine.record_vote_cast(&wire);
        }
        for cycle in 1..=10 {
            engine.record_cycle(cycle, &[wire.clone()], &[wire.clone()]);
        }

        // 2 incidents → 0.25× factor
        engine.record_misbehavior(&wire);
        engine.record_misbehavior(&wire);
        let score = engine.score(&wire);
        assert!(
            (score - 0.25).abs() < 1e-10,
            "2 misbehaviors should quarter score, got {}",
            score
        );
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
