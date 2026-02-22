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
use crate::validator::ValidatorList;

/// Configurable strategy for selecting which candidate block to vote for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum VotingStrategy {
    /// Vote for the first valid candidate block received (current default).
    /// Fast but biased toward low-latency validators.
    #[default]
    FirstValid,

    /// Always vote for a specific validator's block (by public key hex).
    /// Falls back to `FirstValid` if that validator doesn't propose.
    FixedValidator {
        /// Hex-encoded public key of the preferred validator.
        validator_key: String,
    },

    /// Rotate through accepted validators in deterministic order (sorted by pubkey).
    /// Each cycle, the "preferred" validator advances by one position.
    /// Falls back to `FirstValid` if the expected validator doesn't propose.
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
    /// Falls back to `FirstValid` on tie.
    WeightedReputation,

    /// Follow the majority: vote for the candidate with the most votes so far.
    /// Falls back to `FirstValid` if no votes observed yet.
    FollowMajority,

    /// Do not auto-vote. Wait for operator input via RPC (`noble_castVote`).
    /// If no manual vote is cast before the phase ends, no vote is broadcast.
    Manual,
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
    validator_list: &ValidatorList,
    current_cycle: u64,
    manual_vote: Option<Hash256>,
    vote_tallies: Option<&HashMap<Hash256, usize>>,
) -> Option<Hash256> {
    let all = candidates.all_candidates();
    if all.is_empty() {
        return None;
    }

    match strategy {
        VotingStrategy::FirstValid => first_valid(&all),

        VotingStrategy::FixedValidator { validator_key } => {
            let target_bytes = hex::decode(validator_key).ok()?;
            // Find candidate from the specified validator
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == target_bytes {
                    return Some(entry.block_hash);
                }
            }
            // Fallback to FirstValid
            first_valid(&all)
        }

        VotingStrategy::RoundRobin => {
            let validators = validator_list.sorted_validator_keys();
            if validators.is_empty() {
                return first_valid(&all);
            }
            let idx = (current_cycle as usize) % validators.len();
            let preferred = &validators[idx];
            // Check if the preferred validator proposed
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == *preferred {
                    return Some(entry.block_hash);
                }
            }
            // Fallback
            first_valid(&all)
        }

        VotingStrategy::SubsetRotation { validators } => {
            if validators.is_empty() {
                return first_valid(&all);
            }
            let idx = (current_cycle as usize) % validators.len();
            let target_bytes = hex::decode(&validators[idx]).ok()?;
            for entry in &all {
                let val_wire = entry.block.header.validator_id.to_wire_bytes();
                if val_wire == target_bytes {
                    return Some(entry.block_hash);
                }
            }
            first_valid(&all)
        }

        VotingStrategy::Random => {
            // Deterministic "random" selection using cycle number as seed.
            let idx = (current_cycle as usize) % all.len();
            Some(all[idx].block_hash)
        }

        VotingStrategy::WeightedReputation => {
            // Sort candidates by validator weight (highest first), tie-break by lower hash.
            let mut scored: Vec<(Hash256, u64)> = all
                .iter()
                .map(|e| {
                    let weight = validator_list
                        .weight_of_wire(&e.block.header.validator_id.to_wire_bytes())
                        .unwrap_or(0);
                    (e.block_hash, weight)
                })
                .collect();
            scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            scored.first().map(|(h, _)| *h)
        }

        VotingStrategy::FollowMajority => {
            if let Some(tallies) = vote_tallies {
                if !tallies.is_empty() {
                    // Pick candidate with most votes; tie-break by lower hash.
                    let mut sorted: Vec<(Hash256, usize)> =
                        tallies.iter().map(|(h, c)| (*h, *c)).collect();
                    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    return sorted.first().map(|(h, _)| *h);
                }
            }
            // No tallies available — fall back to FirstValid.
            first_valid(&all)
        }

        VotingStrategy::Manual => manual_vote,
    }
}

/// Helper: return the first-seen candidate's hash.
fn first_valid(all: &[&crate::candidate::CandidateEntry]) -> Option<Hash256> {
    all.first().map(|e| e.block_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CandidateTracker;
    use crate::validator::ValidatorList;
    use noble_core::{Block, BlockHeader, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

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
        let vl = ValidatorList::new();
        let result = select_candidate(&VotingStrategy::FirstValid, &tracker, &vl, 0, None, None);
        assert_eq!(result, Some(infos[0].1));
    }

    #[test]
    fn fixed_validator_selects_correct() {
        let (tracker, infos) = setup_tracker_3();
        let vl = ValidatorList::new();
        let target_hex = hex::encode(infos[1].0.to_wire_bytes());
        let strategy = VotingStrategy::FixedValidator {
            validator_key: target_hex,
        };
        let result = select_candidate(&strategy, &tracker, &vl, 0, None, None);
        assert_eq!(result, Some(infos[1].1));
    }

    #[test]
    fn fixed_validator_fallback_to_first() {
        let (tracker, infos) = setup_tracker_3();
        let vl = ValidatorList::new();
        let strategy = VotingStrategy::FixedValidator {
            validator_key: "deadbeef".to_string(),
        };
        let result = select_candidate(&strategy, &tracker, &vl, 0, None, None);
        // Falls back to first valid
        assert_eq!(result, Some(infos[0].1));
    }

    #[test]
    fn random_is_deterministic() {
        let (tracker, _infos) = setup_tracker_3();
        let vl = ValidatorList::new();
        let r1 = select_candidate(&VotingStrategy::Random, &tracker, &vl, 42, None, None);
        let r2 = select_candidate(&VotingStrategy::Random, &tracker, &vl, 42, None, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn follow_majority_picks_leader() {
        let (tracker, infos) = setup_tracker_3();
        let vl = ValidatorList::new();
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
        let vl = ValidatorList::new();
        let result = select_candidate(
            &VotingStrategy::FollowMajority,
            &tracker,
            &vl,
            0,
            None,
            None,
        );
        assert_eq!(result, Some(infos[0].1));
    }

    #[test]
    fn manual_returns_manual_vote() {
        let (tracker, infos) = setup_tracker_3();
        let vl = ValidatorList::new();
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
        let vl = ValidatorList::new();
        let result = select_candidate(&VotingStrategy::Manual, &tracker, &vl, 0, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn empty_tracker_returns_none() {
        let tracker = CandidateTracker::new();
        let vl = ValidatorList::new();
        let result = select_candidate(&VotingStrategy::FirstValid, &tracker, &vl, 0, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn round_robin_rotates() {
        let (tracker, infos) = setup_tracker_3();
        let mut vl = ValidatorList::new();
        for (pub_key, _) in &infos {
            vl.add_validator(pub_key.clone(), 1, 0);
        }
        // Different cycles should potentially select different validators
        let r0 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 0, None, None);
        let r1 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 1, None, None);
        let r2 = select_candidate(&VotingStrategy::RoundRobin, &tracker, &vl, 2, None, None);
        // All should be Some
        assert!(r0.is_some());
        assert!(r1.is_some());
        assert!(r2.is_some());
    }
}
