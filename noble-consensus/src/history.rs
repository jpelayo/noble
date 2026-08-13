// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Cycle history tracking (H-002).
//!
//! Records the outcome of each consensus cycle for later retrieval via RPC.

use noble_crypto::Hash256;
use serde::{Deserialize, Serialize};

/// Historical record of a single consensus cycle's outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleHistoryEntry {
    /// The cycle number.
    pub cycle_number: u64,
    /// Outcome status: "finalized" or "indeterminate".
    pub status: String,
    /// Block proposals received during the cycle.
    pub proposals: Vec<CycleProposal>,
    /// Vote tallies per candidate.
    pub votes: Vec<CycleVoteTally>,
    /// Friendly name of the winning validator (if any).
    pub winner: Option<String>,
    /// Hash of the winning block (if any).
    pub winning_hash: Option<Hash256>,
    /// Whether multiple candidates shared the top vote count.
    /// Always `false` for adopted blocks (ties produce indeterminate cycles).
    /// Kept for serialization backward compatibility.
    pub disambiguation: bool,
    /// Unix timestamp when the cycle was finalized.
    pub finalized_at: u64,
}

/// A block proposal within a cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleProposal {
    /// Hex-encoded validator public key.
    pub validator: String,
    /// Hash of the proposed block.
    pub block_hash: Hash256,
    /// Number of transactions in the proposed block.
    pub tx_count: u32,
}

/// Vote tally for a candidate block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleVoteTally {
    /// Hash of the candidate block.
    pub block_hash: Hash256,
    /// Hex-encoded validator who proposed this block.
    pub validator: String,
    /// Number of R1 votes received.
    pub vote_count: usize,
    /// Number of R2 (confirmation) votes received.
    #[serde(default)]
    pub r2_vote_count: usize,
}

/// Per-block vote witness — records which validators approved each committed block.
///
/// Stored separately from cycle history (different key prefix in storage),
/// so it survives `ClearCycleHistory` at genesis.  Every committed block
/// gets one of these, providing a permanent legitimacy proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVotes {
    /// Cycle number during which this block was committed.
    pub cycle_number: u64,
    /// Denominator used in the majority computation.
    pub voter_count: usize,
    /// Consensus strength: "Strong" or "Plurality".
    pub strength: String,
    /// Validators who cast an R1 vote for this block.
    pub r1_voters: Vec<BlockVoter>,
    /// Validators who cast an R2 (confirmation) vote for this block.
    pub r2_voters: Vec<BlockVoter>,
    /// Number of distinct validator keys that voted for this block (R1+R2 combined).
    pub unique_witness_count: usize,
    /// Whether the Dual-Witness rule applied (true for block 1 only).
    pub dual_witness_required: bool,
    /// Whether the Dual-Witness threshold was met.
    pub dual_witness_met: bool,
    /// The signed votes behind this block — the part that is actually
    /// verifiable (A2). `None` only for records written before certificates
    /// existed; every block from block 1 of a fresh chain carries one.
    #[serde(default)]
    pub certificate: Option<WitnessCertificate>,
}

/// A verifiable witness certificate: the actual **signed** votes that carried a
/// block, stored alongside it.
///
/// [`BlockVotes`] records validator names and hex keys — enough for a dashboard,
/// but it proves nothing. A node importing history cannot check that those
/// validators really voted, because no signature is retained; sync consequently
/// accepted vote data after a bare CBOR decode. This type keeps the signed
/// `PorVote`s themselves, so any node can re-verify support for a block
/// independently, long after the cycle that produced it.
///
/// **Scope limit, stated honestly:** verifying a certificate proves that these
/// keys signed for this candidate in this cycle — signed *support*, and
/// block-1 Dual-Witness compliance. Under Noble's open consensus it cannot
/// prove that this was the *majority* of the network at the time, because
/// historical membership is not recorded anywhere. Do not read more into a
/// valid certificate than that.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessCertificate {
    /// Cycle the votes were cast in.
    pub cycle: u64,
    /// The candidate block these votes support.
    pub candidate_hash: Hash256,
    /// The signed votes themselves.
    pub votes: Vec<crate::vote::PorVote>,
}

/// How far a vote's cycle may sit from the certificate's declared cycle.
///
/// Mirrors the ±1 bootstrap tolerance in `VoteManager::record_vote`: the two
/// must agree, or a certificate can record a vote that can never be verified.
pub const CYCLE_BINDING_TOLERANCE: u64 = 1;

/// Why a witness certificate failed verification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WitnessError {
    #[error("vote {index} is for candidate {got}, expected {expected}")]
    WrongCandidate { index: usize, got: String, expected: String },
    #[error("vote {index} is for cycle {got}, expected {expected}")]
    WrongCycle { index: usize, got: u64, expected: u64 },
    #[error("vote {index} has an invalid signature")]
    InvalidSignature { index: usize },
}

impl WitnessCertificate {
    /// Verify every vote and return the number of **distinct** voter keys.
    ///
    /// Each vote must carry a valid signature and be bound to this
    /// certificate's candidate — otherwise votes for some other block could be
    /// presented as support for this one. Distinct keys are counted (not votes)
    /// because one validator casting both R1 and R2 is still one witness;
    /// counting votes would let a single validator appear to satisfy the
    /// Dual-Witness rule alone.
    ///
    /// **Cycle binding (G2).** The cycle is checked within
    /// [`CYCLE_BINDING_TOLERANCE`], not for exact equality, because
    /// `VoteManager::record_vote` deliberately admits votes ±1 cycle during
    /// bootstrap — peers crossing a phase boundary compute cycle numbers that
    /// differ by one. Demanding exact equality here made a certificate
    /// *unverifiable by construction* whenever two honest validators witnessed
    /// a block from adjacent cycles: the tally accepted them, the certificate
    /// recorded them, and verification then rejected the whole chain as
    /// unwitnessed. Whatever a certificate is permitted to contain must be
    /// verifiable.
    ///
    /// This does not weaken replay protection. `candidate_hash` is inside the
    /// signed payload (see [`crate::vote::PorVote::signing_payload`]), so a
    /// vote for one block can never be presented as support for another — which
    /// is the property the cycle check was mistakenly relied upon to provide.
    pub fn verify(&self) -> Result<usize, WitnessError> {
        use std::collections::HashSet;
        let mut distinct: HashSet<Vec<u8>> = HashSet::new();

        for (index, vote) in self.votes.iter().enumerate() {
            if vote.candidate_hash != self.candidate_hash {
                return Err(WitnessError::WrongCandidate {
                    index,
                    got: vote.candidate_hash.to_string(),
                    expected: self.candidate_hash.to_string(),
                });
            }
            if vote.cycle.abs_diff(self.cycle) > CYCLE_BINDING_TOLERANCE {
                return Err(WitnessError::WrongCycle {
                    index,
                    got: vote.cycle,
                    expected: self.cycle,
                });
            }
            vote.verify()
                .map_err(|_| WitnessError::InvalidSignature { index })?;
            distinct.insert(vote.voter_pubkey.to_wire_bytes());
        }

        Ok(distinct.len())
    }
}

/// A single validator's vote record within a [`BlockVotes`] witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockVoter {
    /// Hex-encoded wire-format public key of the voting validator.
    pub validator_key: String,
    /// Friendly name of the validator (may be empty if unknown).
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_codec::NobleCbor;

    #[test]
    fn cycle_history_entry_cbor_roundtrip() {
        let entry = CycleHistoryEntry {
            cycle_number: 42,
            status: "finalized".to_string(),
            proposals: vec![CycleProposal {
                validator: "abcd".to_string(),
                block_hash: Hash256::from_bytes([0x11; 32]),
                tx_count: 5,
            }],
            votes: vec![CycleVoteTally {
                block_hash: Hash256::from_bytes([0x11; 32]),
                validator: "abcd".to_string(),
                vote_count: 3,
                r2_vote_count: 2,
            }],
            winner: Some("validator-1".to_string()),
            winning_hash: Some(Hash256::from_bytes([0x11; 32])),
            disambiguation: false,
            finalized_at: 1_700_000_000,
        };

        let bytes = entry.to_cbor().unwrap();
        let decoded = CycleHistoryEntry::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.cycle_number, 42);
        assert_eq!(decoded.status, "finalized");
        assert_eq!(decoded.proposals.len(), 1);
        assert_eq!(decoded.votes.len(), 1);
        assert_eq!(decoded.winner.as_deref(), Some("validator-1"));
        assert!(!decoded.disambiguation);
    }

    #[test]
    fn indeterminate_entry_cbor_roundtrip() {
        let entry = CycleHistoryEntry {
            cycle_number: 99,
            status: "indeterminate".to_string(),
            proposals: vec![],
            votes: vec![],
            winner: None,
            winning_hash: None,
            disambiguation: false,
            finalized_at: 1_700_001_000,
        };

        let bytes = entry.to_cbor().unwrap();
        let decoded = CycleHistoryEntry::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.cycle_number, 99);
        assert_eq!(decoded.status, "indeterminate");
        assert!(decoded.winner.is_none());
        assert!(decoded.winning_hash.is_none());
    }

    #[test]
    fn block_votes_cbor_roundtrip() {
        let votes = BlockVotes {
            certificate: None,
            cycle_number: 100,
            voter_count: 3,
            strength: "Strong".to_string(),
            r1_voters: vec![
                BlockVoter {
                    validator_key: "01abcd".to_string(),
                    name: "Node A".to_string(),
                },
                BlockVoter {
                    validator_key: "01ef01".to_string(),
                    name: "Node B".to_string(),
                },
            ],
            r2_voters: vec![BlockVoter {
                validator_key: "01abcd".to_string(),
                name: "Node A".to_string(),
            }],
            unique_witness_count: 2,
            dual_witness_required: true,
            dual_witness_met: true,
        };

        let bytes = votes.to_cbor().unwrap();
        let decoded = BlockVotes::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.cycle_number, 100);
        assert_eq!(decoded.voter_count, 3);
        assert_eq!(decoded.strength, "Strong");
        assert_eq!(decoded.r1_voters.len(), 2);
        assert_eq!(decoded.r2_voters.len(), 1);
        assert_eq!(decoded.r1_voters[0].name, "Node A");
        assert_eq!(decoded.unique_witness_count, 2);
        assert!(decoded.dual_witness_required);
        assert!(decoded.dual_witness_met);
    }

    // --- A2: witness certificates must be verifiable ---

    fn signed_vote(cycle: u64, candidate: Hash256, round: u8)
        -> (crate::vote::PorVote, noble_crypto::NoblePublicKey)
    {
        let (sk, pk) = noble_crypto::secp256k1::generate_keypair();
        let priv_key = noble_crypto::NoblePrivateKey::Secp256k1(sk);
        let pub_key = noble_crypto::NoblePublicKey::Secp256k1(pk);
        let mut vote = crate::vote::PorVote::sign(cycle, candidate, &priv_key, pub_key.clone()).unwrap();
        vote.round = round;
        if round != 1 {
            // Re-sign so the signature covers the round actually carried.
            vote = crate::vote::PorVote::sign_round(cycle, candidate, round, &priv_key, pub_key.clone()).unwrap();
        }
        (vote, pub_key)
    }

    #[test]
    fn certificate_verifies_and_counts_distinct_voters() {
        let candidate = Hash256::from_bytes([0x77; 32]);
        let (v1, _) = signed_vote(5, candidate, 1);
        let (v2, _) = signed_vote(5, candidate, 1);
        let cert = WitnessCertificate { cycle: 5, candidate_hash: candidate, votes: vec![v1, v2] };
        assert_eq!(cert.verify().unwrap(), 2, "two distinct validators = two witnesses");
    }

    /// G2 regression: the tally admits ±1 cycle, so the certificate must too.
    ///
    /// `VoteManager::record_vote` deliberately accepts a vote one cycle either
    /// side of the current one during bootstrap — peers crossing a phase
    /// boundary disagree by one. Those votes carry the block, get recorded in
    /// the certificate, and under exact-match verification made the whole
    /// certificate unverifiable. A genesis witnessed by two honest validators
    /// was then reported as unwitnessed, the chain was refused permanently, and
    /// the node halted. Fails before the tolerance was introduced.
    #[test]
    fn certificate_accepts_the_adjacent_cycle_the_tally_already_accepted() {
        let candidate = Hash256::from_bytes([0x91; 32]);
        let (v_now, _) = signed_vote(7, candidate, 1);
        let (v_ahead, _) = signed_vote(8, candidate, 1);
        let (v_behind, _) = signed_vote(6, candidate, 1);
        let cert = WitnessCertificate {
            cycle: 7,
            candidate_hash: candidate,
            votes: vec![v_now, v_ahead, v_behind],
        };
        assert_eq!(
            cert.verify().unwrap(),
            3,
            "votes the tally accepted must be verifiable, not silently fatal"
        );
    }

    /// The tolerance is exactly ±1 — it is not an open door.
    #[test]
    fn certificate_still_rejects_a_vote_from_an_unrelated_cycle() {
        let candidate = Hash256::from_bytes([0x92; 32]);
        let (v_ok, _) = signed_vote(7, candidate, 1);
        let (v_far, _) = signed_vote(7 + CYCLE_BINDING_TOLERANCE + 1, candidate, 1);
        let cert = WitnessCertificate {
            cycle: 7,
            candidate_hash: candidate,
            votes: vec![v_ok, v_far],
        };
        assert!(matches!(
            cert.verify(),
            Err(WitnessError::WrongCycle { .. })
        ));
    }

    /// G1 regression: a genesis founded at cycle N must produce a certificate
    /// that verifies. Genesis used to force the certificate's cycle to 0 while
    /// its votes carried N, so founding at any cycle but the very first made
    /// the foundation permanently unprovable.
    #[test]
    fn a_genesis_founded_after_the_first_cycle_still_proves_its_witnesses() {
        let candidate = Hash256::from_bytes([0x93; 32]);
        const FOUNDING_CYCLE: u64 = 13; // as seen live: founding took 13 cycles
        let (v1, _) = signed_vote(FOUNDING_CYCLE, candidate, 1);
        let (v2, _) = signed_vote(FOUNDING_CYCLE, candidate, 1);
        let cert = WitnessCertificate {
            cycle: FOUNDING_CYCLE,
            candidate_hash: candidate,
            votes: vec![v1, v2],
        };
        assert_eq!(
            cert.verify().unwrap(),
            2,
            "a chain founded at cycle {FOUNDING_CYCLE} is as legitimate as one founded at 0"
        );
    }

    #[test]
    fn certificate_rejects_a_vote_for_a_different_candidate() {
        // Without this bind, votes for some other block could be presented as
        // support for this one.
        let candidate = Hash256::from_bytes([0x77; 32]);
        let other = Hash256::from_bytes([0x88; 32]);
        let (good, _) = signed_vote(5, candidate, 1);
        let (foreign, _) = signed_vote(5, other, 1);
        let cert = WitnessCertificate {
            cycle: 5,
            candidate_hash: candidate,
            votes: vec![good, foreign],
        };
        assert!(matches!(cert.verify(), Err(WitnessError::WrongCandidate { index: 1, .. })));
    }

    #[test]
    fn certificate_rejects_a_vote_from_a_different_cycle() {
        let candidate = Hash256::from_bytes([0x77; 32]);
        let (v, _) = signed_vote(9, candidate, 1);
        let cert = WitnessCertificate { cycle: 5, candidate_hash: candidate, votes: vec![v] };
        assert!(matches!(cert.verify(), Err(WitnessError::WrongCycle { index: 0, .. })));
    }

    #[test]
    fn certificate_rejects_a_forged_signature() {
        let candidate = Hash256::from_bytes([0x77; 32]);
        let (mut v, _) = signed_vote(5, candidate, 1);
        v.signature.signature[0] ^= 0xFF;
        let cert = WitnessCertificate { cycle: 5, candidate_hash: candidate, votes: vec![v] };
        assert!(matches!(cert.verify(), Err(WitnessError::InvalidSignature { index: 0 })));
    }

    #[test]
    fn one_validator_voting_twice_counts_as_one_witness() {
        // Dual-Witness must not be satisfiable by a single validator casting
        // both R1 and R2 — distinct KEYS are what count.
        let candidate = Hash256::from_bytes([0x77; 32]);
        let (sk, pk) = noble_crypto::secp256k1::generate_keypair();
        let priv_key = noble_crypto::NoblePrivateKey::Secp256k1(sk);
        let pub_key = noble_crypto::NoblePublicKey::Secp256k1(pk);
        let r1 = crate::vote::PorVote::sign(5, candidate, &priv_key, pub_key.clone()).unwrap();
        let cert = WitnessCertificate {
            cycle: 5,
            candidate_hash: candidate,
            votes: vec![r1.clone(), r1],
        };
        assert_eq!(cert.verify().unwrap(), 1, "same key twice is one witness");
    }
}
