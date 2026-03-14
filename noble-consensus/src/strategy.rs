// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Configurable voting strategy for candidate block selection.
//!
//! Each node can independently choose how it selects which candidate block
//! to vote for during the Reflection phase (Round 1) and Confirmation
//! phase (Round 2) of the PoR consensus cycle.

use std::collections::HashMap;

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

use crate::candidate::CandidateTracker;
use crate::registry::ValidatorSnapshot;

/// Configurable strategy for selecting which candidate block to vote for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum VotingStrategy {
    /// Vote for the first valid candidate block received.
    /// Fast but biased toward low-latency validators.
    FirstValid,

    /// Always vote for a specific validator's block (by public key hex).
    /// Falls back to FollowMajority → Random if that validator doesn't propose.
    FixedValidator {
        /// Hex-encoded public key of the preferred validator.
        validator_key: String,
    },

    /// Rotate through accepted validators in deterministic order (sorted by pubkey).
    /// Each cycle, the "preferred" validator advances by one position.
    /// Falls back to FollowMajority → Random if the expected validator doesn't propose.
    RoundRobin,

    /// Rotate through a user-defined subset of preferred validators.
    SubsetRotation {
        /// Hex-encoded public keys of preferred validators, in rotation order.
        validators: Vec<String>,
    },

    /// Randomly select among valid candidates each cycle.
    /// Uses cycle number as deterministic seed for reproducibility.
    Random,

    /// Vote for the candidate from the validator with the highest weight.
    /// Ties broken by insertion order (stable sort).
    WeightedReputation,

    /// Follow the majority: vote for the candidate with the most votes so far.
    /// Falls back to Random if no votes observed yet.
    FollowMajority,

    /// Do not auto-vote. Wait for operator input via RPC (`noble_castVote`).
    /// If no manual vote is cast before the phase ends, no vote is broadcast.
    Manual,

    /// Weighted probability selection following operator-defined list order (default).
    /// Position `i` gets weight `N - i` (position 0 = N, last = 1).
    /// Total weight = `N*(N+1)/2`. Deterministic via `cycle % total_weight`.
    #[default]
    WeightedProbability,
}

impl VotingStrategy {
    /// Human-readable strategy name for RPC/GUI display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::FirstValid => "first_valid",
            Self::FixedValidator { .. } => "fixed_validator",
            Self::RoundRobin => "round_robin",
            Self::SubsetRotation { .. } => "subset_rotation",
            Self::Random => "random",
            Self::WeightedReputation => "weighted_reputation",
            Self::FollowMajority => "follow_majority",
            Self::Manual => "manual",
            Self::WeightedProbability => "weighted_probability",
        }
    }
}

/// Select the preferred candidate based on the configured voting strategy.
///
/// Returns `None` if no suitable candidate matches the strategy (e.g. Manual
/// with no manual vote, or no candidates at all).
pub fn select_candidate(
    strategy: &VotingStrategy,
    candidates: &CandidateTracker,
    snapshot: &ValidatorSnapshot,
    current_cycle: u64,
    manual_vote: Option<Hash256>,
    vote_tallies: Option<&HashMap<Hash256, usize>>,
) -> Option<Hash256> {
    let all = candidates.all_candidates();
    if all.is_empty() {
        return None;
    }

    match strategy {
        VotingStrategy::FirstValid => first_validator(&all),

        VotingStrategy::FixedValidator { validator_key } => {
            let target_bytes = hex::decode(validator_key).ok()?;
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == target_bytes {
                    return Some(entry.block_hash);
                }
            }
            fallback(&all, vote_tallies, current_cycle)
        }

        VotingStrategy::RoundRobin => {
            let validators = snapshot.ordered_validator_keys();
            if validators.is_empty() {
                return fallback(&all, vote_tallies, current_cycle);
            }
            let idx = (current_cycle as usize) % validators.len();
            let preferred = &validators[idx];
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == *preferred {
                    return Some(entry.block_hash);
                }
            }
            fallback(&all, vote_tallies, current_cycle)
        }

        VotingStrategy::SubsetRotation { validators } => {
            if validators.is_empty() {
                return fallback(&all, vote_tallies, current_cycle);
            }
            let idx = (current_cycle as usize) % validators.len();
            let target_bytes = hex::decode(&validators[idx]).ok()?;
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == target_bytes {
                    return Some(entry.block_hash);
                }
            }
            fallback(&all, vote_tallies, current_cycle)
        }

        VotingStrategy::Random => {
            // Deterministic "random" selection using cycle number as seed.
            let idx = (current_cycle as usize) % all.len();
            Some(all[idx].block_hash)
        }

        VotingStrategy::WeightedReputation => {
            // Sort candidates by validator weight (highest first).
            let mut scored: Vec<(Hash256, u64)> = all
                .iter()
                .map(|e| {
                    let weight = snapshot
                        .weight_of_wire(&e.block.header.validator_id.to_wire_bytes())
                        .unwrap_or(0);
                    (e.block_hash, weight)
                })
                .collect();
            scored.sort_by(|a, b| b.1.cmp(&a.1));
            scored.first().map(|(h, _)| *h)
        }

        VotingStrategy::FollowMajority => fallback(&all, vote_tallies, current_cycle),

        VotingStrategy::WeightedProbability => {
            let validators = snapshot.ordered_validator_keys();
            if validators.is_empty() {
                return fallback(&all, vote_tallies, current_cycle);
            }
            let n = validators.len();
            let total_weight = n * (n + 1) / 2;
            let pick = (current_cycle as usize) % total_weight;
            let mut cumulative = 0;
            let mut chosen_idx = 0;
            for i in 0..n {
                cumulative += n - i;
                if pick < cumulative {
                    chosen_idx = i;
                    break;
                }
            }
            let preferred = &validators[chosen_idx];
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == *preferred {
                    return Some(entry.block_hash);
                }
            }
            fallback(&all, vote_tallies, current_cycle)
        }

        VotingStrategy::Manual => manual_vote,
    }
}

/// Helper: return the first-seen candidate's hash (insertion order).
/// Used by the explicit `FirstValid` strategy — intentionally latency-biased:
/// "vote for the first valid candidate block received."
fn first_validator(all: &[&crate::candidate::CandidateEntry]) -> Option<Hash256> {
    all.first().map(|e| e.block_hash)
}

/// Fallback chain: FollowMajority → Random → None (don't vote).
/// Used when a strategy's primary logic can't pick (validator offline, empty list, etc.).
fn fallback(
    all: &[&crate::candidate::CandidateEntry],
    vote_tallies: Option<&HashMap<Hash256, usize>>,
    current_cycle: u64,
) -> Option<Hash256> {
    // Step 1: Follow majority — pick the vote leader.
    if let Some(tallies) = vote_tallies {
        if !tallies.is_empty() {
            let mut sorted: Vec<(Hash256, usize)> =
                tallies.iter().map(|(h, c)| (*h, *c)).collect();
            sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            return sorted.first().map(|(h, _)| *h);
        }
    }
    // Step 2: Random — deterministic pick using cycle number.
    if !all.is_empty() {
        let idx = current_cycle as usize % all.len();
        return Some(all[idx].block_hash);
    }
    // Step 3: No candidates — don't vote.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CandidateTracker;
    use crate::registry::{ValidatorRegistry, ValidatorSnapshot, SnapshotEntry};
    use crate::validator::ValidatorList;
    use noble_core::{Block, BlockHeader, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

    /// Create an empty snapshot (no validators).
    fn empty_snapshot() -> ValidatorSnapshot {
        ValidatorSnapshot {
            entries: vec![],
            ordered_keys: vec![],
            pubkey_vec: vec![],
            count: 0,
        }
    }

    /// Create a snapshot from a list of pubkeys (all weight=1, no names).
    fn snapshot_from_keys(keys: &[NoblePublicKey]) -> ValidatorSnapshot {
        let mut reg = ValidatorRegistry::empty();
        for k in keys {
            reg.add_validator(k.clone(), 1, 0);
        }
        // unwrap the Arc
        std::sync::Arc::try_unwrap(reg.create_snapshot()).unwrap()
    }

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn make_candidate(
        val_pub: &NoblePublicKey,
        val_priv: &NoblePrivateKey,
    ) -> (Box<Block>, Hash256) {
        let merkle_root = noble_core::compute_merkle_root(&[]);
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1_700_000_000,
            height: 1,
            tx_count: 0,
            validator_id: val_pub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: val_pub.key_bytes().to_vec(),
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();
        let hash = header.compute_block_hash().unwrap();
        (
            Box::new(Block {
                header,
                transactions: vec![],
            }),
            hash,
        )
    }

    fn setup_tracker_3() -> (CandidateTracker, Vec<(NoblePublicKey, Hash256)>) {
        let mut tracker = CandidateTracker::new();
        let mut infos = Vec::new();
        for _ in 0..3 {
            let (priv_key, pub_key) = make_validator();
            let (block, hash) = make_candidate(&pub_key, &priv_key);
            tracker.add_candidate(block, hash, 1000).unwrap();
            infos.push((pub_key, hash));
        }
        (tracker, infos)
    }

    #[test]
    fn first_valid_returns_first_inserted() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let result = select_candidate(&VotingStrategy::FirstValid, &tracker, &vl, 0, None, None);
        // FirstValid returns the first candidate inserted (insertion order = arrival time)
        assert_eq!(result, Some(infos[0].1));
    }

    #[test]
    fn fixed_validator_selects_correct() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let target_hex = hex::encode(infos[1].0.to_wire_bytes());
        let strategy = VotingStrategy::FixedValidator {
            validator_key: target_hex,
        };
        let result = select_candidate(&strategy, &tracker, &vl, 0, None, None);
        assert_eq!(result, Some(infos[1].1));
    }

    #[test]
    fn fixed_validator_fallback_no_tallies() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let strategy = VotingStrategy::FixedValidator {
            validator_key: "deadbeef".to_string(),
        };
        // No tallies → FollowMajority has nothing → Random picks cycle % len
        let result = select_candidate(&strategy, &tracker, &vl, 0, None, None);
        // cycle=0, 0 % 3 = 0 → first candidate
        assert_eq!(result, Some(infos[0].1));
    }

    #[test]
    fn random_is_deterministic() {
        let (tracker, _infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let r1 = select_candidate(&VotingStrategy::Random, &tracker, &vl, 42, None, None);
        let r2 = select_candidate(&VotingStrategy::Random, &tracker, &vl, 42, None, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn follow_majority_picks_leader() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let mut tallies = HashMap::new();
        tallies.insert(infos[2].1, 5);
        tallies.insert(infos[0].1, 2);
        let result = select_candidate(
            &VotingStrategy::FollowMajority,
            &tracker,
            &vl,
            0,
            None,
            Some(&tallies),
        );
        assert_eq!(result, Some(infos[2].1));
    }

    #[test]
    fn follow_majority_fallback_no_tallies() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot();
        // No tallies → Random picks cycle % len
        let result = select_candidate(
            &VotingStrategy::FollowMajority,
            &tracker,
            &vl,
            0,
            None,
            None,
        );
        // cycle=0, 0 % 3 = 0 → first candidate
        assert_eq!(result, Some(infos[0].1));
        // cycle=1 should pick a different candidate
        let r1 = select_candidate(
            &VotingStrategy::FollowMajority,
            &tracker,
            &vl,
            1,
            None,
            None,
        );
        assert_eq!(r1, Some(infos[1].1));
    }

    #[test]
    fn manual_returns_manual_vote() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let result = select_candidate(
            &VotingStrategy::Manual,
            &tracker,
            &vl,
            0,
            Some(infos[1].1),
            None,
        );
        assert_eq!(result, Some(infos[1].1));
    }

    #[test]
    fn manual_returns_none_without_vote() {
        let (tracker, _infos) = setup_tracker_3();
        let vl = empty_snapshot();
        let result = select_candidate(&VotingStrategy::Manual, &tracker, &vl, 0, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn empty_tracker_returns_none() {
        let tracker = CandidateTracker::new();
        let vl = empty_snapshot();
        let result = select_candidate(&VotingStrategy::FirstValid, &tracker, &vl, 0, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn round_robin_rotates() {
        let (tracker, infos) = setup_tracker_3();
        let keys: Vec<NoblePublicKey> = infos.iter().map(|(pk, _)| pk.clone()).collect();
        let vl = snapshot_from_keys(&keys);
        // Different cycles should potentially select different validators
        let r0 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 0, None, None);
        let r1 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 1, None, None);
        let r2 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 2, None, None);
        // All should be Some
        assert!(r0.is_some());
        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[test]
    fn round_robin_uses_manual_order() {
        let (tracker, infos) = setup_tracker_3();
        let mut reg = ValidatorRegistry::empty();
        for (pub_key, _) in &infos {
            reg.add_validator(pub_key.clone(), 1, 0);
        }
        // Reverse the order: infos[2], infos[1], infos[0]
        let reversed: Vec<Vec<u8>> = infos.iter().rev().map(|(pk, _)| pk.to_wire_bytes()).collect();
        reg.set_priority_order(reversed).unwrap();
        let vl = std::sync::Arc::try_unwrap(reg.create_snapshot()).unwrap();

        // Cycle 0 should pick infos[2] (first in reversed order)
        let r0 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 0, None, None);
        assert_eq!(r0, Some(infos[2].1));

        // Cycle 1 should pick infos[1]
        let r1 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 1, None, None);
        assert_eq!(r1, Some(infos[1].1));

        // Cycle 2 should pick infos[0]
        let r2 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 2, None, None);
        assert_eq!(r2, Some(infos[0].1));
    }

    #[test]
    fn weighted_probability_favors_first() {
        let (tracker, infos) = setup_tracker_3();
        let keys: Vec<NoblePublicKey> = infos.iter().map(|(pk, _)| pk.clone()).collect();
        let vl = snapshot_from_keys(&keys);
        // With 3 validators, weights [3,2,1], total=6.
        // Cycles 0,1,2 → position 0; cycles 3,4 → position 1; cycle 5 → position 2
        let mut counts = [0usize; 3];
        let ordered = vl.ordered_validator_keys();
        for cycle in 0..6 {
            let result = select_candidate(
                &VotingStrategy::WeightedProbability,
                &tracker,
                &vl,
                cycle,
                None,
                None,
            );
            if let Some(hash) = result {
                for (i, (pk, _)) in infos.iter().enumerate() {
                    if ordered.iter().position(|k| k == &pk.to_wire_bytes()) == Some(0) && hash == infos[i].1 {
                        // Find which ordered position was selected
                    }
                }
                // Find which position was chosen
                for (idx, key) in ordered.iter().enumerate() {
                    let expected_hash = infos.iter().find(|(pk, _)| pk.to_wire_bytes() == *key).map(|(_, h)| *h);
                    if expected_hash == Some(hash) {
                        counts[idx] += 1;
                        break;
                    }
                }
            }
        }
        // Position 0 should be selected 3 times, position 1 twice, position 2 once
        assert_eq!(counts[0], 3);
        assert_eq!(counts[1], 2);
        assert_eq!(counts[2], 1);
    }

    #[test]
    fn weighted_probability_deterministic() {
        let (tracker, infos) = setup_tracker_3();
        let keys: Vec<NoblePublicKey> = infos.iter().map(|(pk, _)| pk.clone()).collect();
        let vl = snapshot_from_keys(&keys);
        let r1 = select_candidate(&VotingStrategy::WeightedProbability, &tracker, &vl, 42, None, None);
        let r2 = select_candidate(&VotingStrategy::WeightedProbability, &tracker, &vl, 42, None, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn weighted_probability_fallback_empty() {
        let (tracker, infos) = setup_tracker_3();
        let vl = empty_snapshot(); // empty validator list
        // No tallies → FollowMajority has nothing → Random picks cycle % len
        let result = select_candidate(
            &VotingStrategy::WeightedProbability,
            &tracker,
            &vl,
            0,
            None,
            None,
        );
        // cycle=0, 0 % 3 = 0 → first candidate
        assert_eq!(result, Some(infos[0].1));
    }
}
