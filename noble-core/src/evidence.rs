// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Misbehavior evidence for slashing misbehaving validators.
//!
//! A [`DoubleProposalEvidence`] proves that a validator proposed two different
//! blocks within the same consensus cycle, which is a slashable offense.
//!
//! A [`VoteEquivocationEvidence`] proves that a validator voted for two
//! different candidates in the same round of the same cycle.
//!
//! [`MisbehaviorEvidence`] is the unified wrapper for all evidence types.

use serde::{Deserialize, Serialize};

use noble_crypto::{sha256, Hash256, NoblePublicKey, SignatureEnvelope};

use crate::BlockHeader;

/// Wire-stable category codes for ban reasons.
///
/// Lives in `noble-core` so the consensus engine can use it without depending
/// on `noble-network`. Codes match `BanCategory` in `peer_manager.rs` exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BanCategoryCode {
    InvalidBlock = 0x01,
    InvalidTransaction = 0x02,
    ProtocolViolation = 0x03,
    DuplicateProposal = 0x04,
    ExcessiveConnections = 0x05,
    Unresponsive = 0x06,
    InvalidVote = 0x07,
    InvalidAnnounce = 0x08,
    TxFlood = 0x09,
    EvidenceReceived = 0x0A,
    Misrepresentation = 0x0B,
    ManualBan = 0x0C,
}

/// Evidence that a validator proposed two different blocks in the same cycle.
///
/// Both headers must:
/// 1. Be from the same validator (same `validator_id`)
/// 2. Be at the same height (same consensus cycle)
/// 3. Have different block hashes
/// 4. Carry valid signatures from that validator
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DoubleProposalEvidence {
    /// First block header from the misbehaving validator.
    pub header_a: BlockHeader,
    /// Second (conflicting) block header from the same validator.
    pub header_b: BlockHeader,
    /// The validator's public key (must match both headers).
    pub validator_id: NoblePublicKey,
}

/// Errors when verifying misbehavior evidence.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum EvidenceError {
    /// The two headers reference different validators.
    DifferentValidators,
    /// The two headers are at different heights (different cycles).
    DifferentHeights,
    /// The two headers have the same block hash (not a double proposal).
    SameBlockHash,
    /// Signature verification failed on one of the headers.
    InvalidSignature(String),
    /// Block hash computation failed.
    HashError(String),
    /// The two votes reference different voter keys.
    DifferentVoters,
    /// The two votes reference different rounds.
    DifferentRounds,
    /// The two votes are for the same candidate (not equivocation).
    SameCandidateHash,
    /// Evidence does not demonstrate the claimed violation.
    VerificationFailed,
    /// The two headers have different prev_block_hash values (cross-fork, not double proposal).
    CrossForkProposal,
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DifferentValidators => write!(f, "headers reference different validators"),
            Self::DifferentHeights => write!(f, "headers are at different heights"),
            Self::SameBlockHash => write!(f, "headers have the same block hash"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::HashError(e) => write!(f, "hash computation error: {e}"),
            Self::DifferentVoters => write!(f, "votes reference different voter keys"),
            Self::DifferentRounds => write!(f, "votes reference different rounds"),
            Self::SameCandidateHash => write!(f, "votes are for the same candidate"),
            Self::VerificationFailed => write!(f, "evidence does not demonstrate the claimed violation"),
            Self::CrossForkProposal => write!(f, "headers are from different forks (different prev_block_hash)"),
        }
    }
}

impl std::error::Error for EvidenceError {}

impl DoubleProposalEvidence {
    /// Create evidence from two conflicting headers.
    ///
    /// Does NOT verify — call [`verify`] separately.
    pub fn new(header_a: BlockHeader, header_b: BlockHeader) -> Self {
        let validator_id = header_a.validator_id.clone();
        Self {
            header_a,
            header_b,
            validator_id,
        }
    }

    /// Verify that this evidence is valid:
    /// 1. Both headers are from the same validator
    /// 2. Both headers are at the same height
    /// 3. The block hashes differ
    /// 4. Both headers carry valid signatures from the validator
    ///
    /// **Important limitation:** Same-height blocks from *different* consensus
    /// cycles (e.g., after empty cycles where no block was committed) are
    /// indistinguishable at the evidence level — both are valid proposals at
    /// the same height with valid signatures.  The `DeliveredBlockLog` in the
    /// consensus engine is the primary defense against false positives: it
    /// recognizes any previously-processed block hash and silently drops it
    /// before the duplicate-proposal check ever fires.
    pub fn verify(&self) -> Result<(), EvidenceError> {
        // 1. Same validator
        if self.header_a.validator_id != self.header_b.validator_id {
            return Err(EvidenceError::DifferentValidators);
        }
        if self.validator_id != self.header_a.validator_id {
            return Err(EvidenceError::DifferentValidators);
        }

        // 2. Same height
        if self.header_a.height != self.header_b.height {
            return Err(EvidenceError::DifferentHeights);
        }

        // 3. Different block hashes
        let hash_a = self
            .header_a
            .compute_block_hash()
            .map_err(|e| EvidenceError::HashError(e.to_string()))?;
        let hash_b = self
            .header_b
            .compute_block_hash()
            .map_err(|e| EvidenceError::HashError(e.to_string()))?;
        if hash_a == hash_b {
            return Err(EvidenceError::SameBlockHash);
        }

        // 3b. Same parent — blocks on different forks (different prev_block_hash)
        // are NOT genuine double proposals; they're honest proposals on competing
        // chains after a fork.
        if self.header_a.prev_block_hash != self.header_b.prev_block_hash {
            return Err(EvidenceError::CrossForkProposal);
        }

        // 3c. H2: each header's signing key must BE the accused validator.
        //
        // `verify_standalone` checks a signature against the key embedded in
        // the envelope, so on its own it only proves "somebody signed this" —
        // not that the accused did. Without this bind, an attacker could set
        // `validator_id` to a victim, sign both headers with their OWN key, and
        // produce evidence that verifies. Consumers attribute misbehaviour by
        // `validator_id`, so the victim's reputation would be destroyed for
        // blocks they never signed.
        let claimed = self.validator_id.to_wire_bytes();
        for (label, header) in [("header_a", &self.header_a), ("header_b", &self.header_b)] {
            let signer = header
                .validator_sig
                .to_noble_public_key()
                .map_err(|e| EvidenceError::InvalidSignature(format!("{label}: {e}")))?
                .to_wire_bytes();
            if signer != claimed {
                return Err(EvidenceError::InvalidSignature(format!(
                    "{label}: signed by a different key than the accused validator"
                )));
            }
        }

        // 4. Valid signatures — compute signing message, then verify via SignatureEnvelope
        let msg_a = self
            .header_a
            .compute_signing_message()
            .map_err(|e| EvidenceError::HashError(e.to_string()))?;
        self.header_a
            .validator_sig
            .verify_standalone(&msg_a)
            .map_err(|e| EvidenceError::InvalidSignature(format!("header_a: {e}")))?;

        let msg_b = self
            .header_b
            .compute_signing_message()
            .map_err(|e| EvidenceError::HashError(e.to_string()))?;
        self.header_b
            .validator_sig
            .verify_standalone(&msg_b)
            .map_err(|e| EvidenceError::InvalidSignature(format!("header_b: {e}")))?;

        Ok(())
    }
}

/// Evidence that a validator voted for two different candidates in the same round.
///
/// Uses raw fields from `noble-core` (not `PorVote` from `noble-consensus`)
/// to avoid a circular dependency.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VoteEquivocationEvidence {
    /// The cycle in which equivocation occurred.
    pub cycle: u64,
    /// The voting round (1 = R1, 2 = R2).
    pub round: u8,
    /// Hash of the first candidate voted for.
    pub candidate_a: Hash256,
    /// Hash of the second (conflicting) candidate voted for.
    pub candidate_b: Hash256,
    /// The voter's public key.
    pub voter_pubkey: NoblePublicKey,
    /// Signature over the first vote payload.
    pub signature_a: SignatureEnvelope,
    /// Signature over the second vote payload.
    pub signature_b: SignatureEnvelope,
}

/// Internal payload for vote evidence signing — must produce identical CBOR
/// to `VoteSigningPayload` in `noble-consensus/src/vote.rs`.
// NOTE: VoteEvidencePayload removed — verification now uses
// crate::wire::v1::vote_signing_payload_bytes() directly.

impl VoteEquivocationEvidence {
    /// Verify that this evidence is valid:
    /// 1. `candidate_a != candidate_b`
    /// 2. Signature A verifies against the vote payload for candidate_a
    /// 3. Signature B verifies against the vote payload for candidate_b
    pub fn verify(&self) -> Result<(), EvidenceError> {
        // 1. Votes must be for different candidates
        if self.candidate_a == self.candidate_b {
            return Err(EvidenceError::SameCandidateHash);
        }

        // 2. Verify signature A (uses frozen wire format for vote signing payload)
        let msg_a = crate::wire::v1::vote_signing_payload_bytes(
            self.cycle, &self.candidate_a, self.round,
        );
        let hash_a = sha256(&msg_a).0;
        self.voter_pubkey
            .verify(&hash_a, &self.signature_a)
            .map_err(|e| EvidenceError::InvalidSignature(format!("vote_a: {e}")))?;

        // 3. Verify signature B
        let msg_b = crate::wire::v1::vote_signing_payload_bytes(
            self.cycle, &self.candidate_b, self.round,
        );
        let hash_b = sha256(&msg_b).0;
        self.voter_pubkey
            .verify(&hash_b, &self.signature_b)
            .map_err(|e| EvidenceError::InvalidSignature(format!("vote_b: {e}")))?;

        Ok(())
    }
}

/// Which universal block validation check failed (verifiable by any node).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvalidBlockCode {
    /// B1: Block CBOR exceeds maximum size.
    BlockTooLarge { size: usize, max: usize },
    /// B4: Merkle root in header doesn't match recomputed tree.
    MerkleRootMismatch,
    /// B7: tx_count in header doesn't match actual transaction count.
    TxCountMismatch { claimed: u32, actual: u32 },
    /// B8: Validator signature verification failed.
    ValidatorSigInvalid,
    /// B12: Validator public key uses an unrecognized scheme.
    ValidatorSchemeUnrecognized(u8),
    /// Duplicate transaction ID within the block.
    DuplicateTxInBlock { first: usize, second: usize },
    /// B11: A transaction in the block failed validation.
    InvalidTransaction { index: usize, reason: String },
}

/// Evidence that a validator proposed a block that fails a universal check.
///
/// Universal checks are those any node can verify with just the block data
/// (no local chain state needed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidBlockEvidence {
    /// The invalid block (full header + transactions).
    pub block: crate::Block,
    /// Which universal check failed.
    pub failure_code: InvalidBlockCode,
}

impl InvalidBlockEvidence {
    /// Verify that this evidence is valid: re-run the claimed check and confirm it fails.
    pub fn verify(&self, chain_id: u32) -> Result<(), EvidenceError> {
        match &self.failure_code {
            InvalidBlockCode::BlockTooLarge { size, max } => {
                let cbor = noble_codec::NobleCbor::to_cbor(&self.block)
                    .map_err(|e| EvidenceError::HashError(e.to_string()))?;
                if cbor.len() > *max && cbor.len() == *size {
                    Ok(())
                } else {
                    Err(EvidenceError::VerificationFailed)
                }
            }
            InvalidBlockCode::MerkleRootMismatch => {
                let tx_ids: Vec<Hash256> = self.block.transactions.iter()
                    .map(|tx| tx.compute_tx_id(chain_id))
                    .collect::<Result<_, _>>()
                    .map_err(|e| EvidenceError::HashError(e.to_string()))?;
                let root = crate::compute_merkle_root(&tx_ids);
                if root != self.block.header.merkle_root {
                    Ok(()) // Mismatch confirmed → evidence valid
                } else {
                    Err(EvidenceError::VerificationFailed)
                }
            }
            InvalidBlockCode::TxCountMismatch { claimed, actual } => {
                let real_count = self.block.transactions.len() as u32;
                if self.block.header.tx_count != real_count
                    && *claimed == self.block.header.tx_count
                    && *actual == real_count
                {
                    Ok(())
                } else {
                    Err(EvidenceError::VerificationFailed)
                }
            }
            InvalidBlockCode::ValidatorSigInvalid => {
                let msg = self.block.header.compute_signing_message()
                    .map_err(|e| EvidenceError::HashError(e.to_string()))?;
                match self.block.header.validator_sig.verify_standalone(&msg) {
                    Err(_) => Ok(()),  // Sig fails → evidence is valid
                    Ok(()) => Err(EvidenceError::VerificationFailed), // Sig passes → evidence is wrong
                }
            }
            InvalidBlockCode::ValidatorSchemeUnrecognized(scheme_id) => {
                if *scheme_id == self.block.header.validator_id.scheme_id()
                    && !noble_crypto::is_signing_scheme(*scheme_id)
                {
                    Ok(())
                } else {
                    Err(EvidenceError::VerificationFailed)
                }
            }
            InvalidBlockCode::DuplicateTxInBlock { first, second } => {
                if *first >= self.block.transactions.len()
                    || *second >= self.block.transactions.len()
                    || first == second
                {
                    return Err(EvidenceError::VerificationFailed);
                }
                let id_a = self.block.transactions[*first].compute_tx_id(chain_id)
                    .map_err(|e| EvidenceError::HashError(e.to_string()))?;
                let id_b = self.block.transactions[*second].compute_tx_id(chain_id)
                    .map_err(|e| EvidenceError::HashError(e.to_string()))?;
                if id_a == id_b {
                    Ok(())
                } else {
                    Err(EvidenceError::VerificationFailed)
                }
            }
            InvalidBlockCode::InvalidTransaction { index, .. } => {
                if *index >= self.block.transactions.len() {
                    return Err(EvidenceError::VerificationFailed);
                }
                let tx = &self.block.transactions[*index];
                let tx_id = tx.compute_tx_id(chain_id)
                    .map_err(|e| EvidenceError::HashError(e.to_string()))?;
                let ctx = crate::validation::TxValidationContext {
                    time_context: crate::validation::TimeContext::Historical {
                        block_time: self.block.header.timestamp,
                        wall_clock: self.block.header.timestamp,
                    },
                    chain_id,
                    chain_height: self.block.header.height,
                };
                match crate::validation::validate_transaction(tx, &tx_id, &ctx) {
                    Err(_) => Ok(()),  // Tx invalid → evidence valid
                    Ok(()) => Err(EvidenceError::VerificationFailed),
                }
            }
        }
    }
}

/// Type of impossible contradiction between two NodeAnnounce messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnnounceContradiction {
    /// Different chain_id (claims two blockchains simultaneously).
    ChainId,
    /// Later timestamp with lower chain_tip_height (honest nodes never reorg themselves).
    ChainTipRegression,
    /// Same proposed_height but different proposed_hash (competing proposals).
    CompetingProposals,
}

/// Evidence that a node sent contradictory NodeAnnounce messages.
///
/// Only flags contradictions that are **logically impossible** for an honest node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnounceEquivocationEvidence {
    /// The node's identity key.
    pub identity_key: NoblePublicKey,
    /// First announcement.
    pub announce_a: crate::NodeAnnounce,
    /// Conflicting announcement.
    pub announce_b: crate::NodeAnnounce,
    /// Type of impossible contradiction.
    pub contradiction: AnnounceContradiction,
}

impl AnnounceEquivocationEvidence {
    /// Verify that this evidence is valid:
    /// 1. Same identity key on both announces
    /// 2. Both signatures are valid
    /// 3. The claimed contradiction actually holds
    pub fn verify(&self) -> Result<(), EvidenceError> {
        // 1. Same identity key
        if self.announce_a.identity_key != self.announce_b.identity_key
            || self.identity_key != self.announce_a.identity_key
        {
            return Err(EvidenceError::DifferentValidators);
        }
        // 2. Both signatures valid
        self.announce_a
            .verify_signature()
            .map_err(|e| EvidenceError::InvalidSignature(format!("announce_a: {e}")))?;
        self.announce_b
            .verify_signature()
            .map_err(|e| EvidenceError::InvalidSignature(format!("announce_b: {e}")))?;
        // 3. Verify contradiction
        match &self.contradiction {
            AnnounceContradiction::ChainId => {
                if self.announce_a.chain_id == self.announce_b.chain_id {
                    return Err(EvidenceError::VerificationFailed);
                }
            }
            AnnounceContradiction::ChainTipRegression => {
                let (a_h, b_h) = (
                    self.announce_a.chain_tip_height.unwrap_or(0),
                    self.announce_b.chain_tip_height.unwrap_or(0),
                );
                let (a_t, b_t) = (self.announce_a.timestamp, self.announce_b.timestamp);
                // Later timestamp must not have lower height
                let regression = (a_t > b_t && a_h < b_h) || (b_t > a_t && b_h < a_h);
                if !regression {
                    return Err(EvidenceError::VerificationFailed);
                }
            }
            AnnounceContradiction::CompetingProposals => {
                let same_height = self.announce_a.proposed_height.is_some()
                    && self.announce_a.proposed_height == self.announce_b.proposed_height;
                let diff_hash = self.announce_a.proposed_hash != self.announce_b.proposed_hash;
                if !same_height || !diff_hash {
                    return Err(EvidenceError::VerificationFailed);
                }
            }
        }
        Ok(())
    }
}

/// Unified wrapper for all types of misbehavior evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MisbehaviorEvidence {
    /// A validator proposed two different blocks in the same cycle.
    DoubleProposal(DoubleProposalEvidence),
    /// A validator voted for two different candidates in the same round.
    VoteEquivocation(VoteEquivocationEvidence),
    /// A validator proposed a block that fails a universal validation check.
    InvalidBlock(InvalidBlockEvidence),
    /// A node sent contradictory NodeAnnounce messages.
    AnnounceEquivocation(AnnounceEquivocationEvidence),
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{
        secp256k1, Hash256, NoblePrivateKey, NobleSigner, SignatureEnvelope, SCHEME_SECP256K1,
    };

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn make_signed_header(
        val_priv: &NoblePrivateKey,
        val_pub: &NoblePublicKey,
        height: u64,
        timestamp: u64,
    ) -> BlockHeader {
        let merkle_root = crate::compute_merkle_root(&[]);
        let mut header = BlockHeader {
            version: crate::PROTOCOL_VERSION,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp,
            height,
            tx_count: 0,
            validator_id: val_pub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: val_pub.key_bytes().to_vec(),
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();
        header
    }

    #[test]
    fn valid_evidence() {
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        let h2 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_001); // different timestamp → different hash
        let evidence = DoubleProposalEvidence::new(h1, h2);
        assert!(evidence.verify().is_ok());
    }

    #[test]
    fn h2_evidence_cannot_frame_a_validator_who_never_signed() {
        // Both headers claim the victim as validator_id but are signed by the
        // attacker. Signature verification alone passes (verify_standalone
        // checks each envelope against its OWN embedded key), so without the
        // key bind this evidence verified — and consumers attribute
        // misbehaviour by validator_id, destroying the victim's reputation for
        // blocks they never signed.
        let (attacker_priv, attacker_pub) = make_validator();
        let (_victim_priv, victim_pub) = make_validator();

        let mut h1 = make_signed_header(&attacker_priv, &attacker_pub, 10, 1_700_000_000);
        let mut h2 = make_signed_header(&attacker_priv, &attacker_pub, 10, 1_700_000_001);
        // Point the accusation at the victim, leaving the attacker's signatures.
        h1.validator_id = victim_pub.clone();
        h2.validator_id = victim_pub.clone();

        let evidence = DoubleProposalEvidence {
            header_a: h1,
            header_b: h2,
            validator_id: victim_pub,
        };
        assert!(
            matches!(evidence.verify(), Err(EvidenceError::InvalidSignature(_))),
            "evidence signed by a different key must not implicate the accused"
        );
    }

    #[test]
    fn different_validators_rejected() {
        let (pk1, pub1) = make_validator();
        let (pk2, pub2) = make_validator();
        let h1 = make_signed_header(&pk1, &pub1, 10, 1_700_000_000);
        let h2 = make_signed_header(&pk2, &pub2, 10, 1_700_000_001);
        let evidence = DoubleProposalEvidence {
            header_a: h1,
            header_b: h2,
            validator_id: pub1,
        };
        assert_eq!(
            evidence.verify().unwrap_err(),
            EvidenceError::DifferentValidators
        );
    }

    #[test]
    fn different_heights_rejected() {
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        let h2 = make_signed_header(&priv_key, &pub_key, 11, 1_700_000_001);
        let evidence = DoubleProposalEvidence::new(h1, h2);
        assert_eq!(
            evidence.verify().unwrap_err(),
            EvidenceError::DifferentHeights
        );
    }

    #[test]
    fn same_block_hash_rejected() {
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        let h2 = h1.clone(); // identical → same hash
        let evidence = DoubleProposalEvidence::new(h1, h2);
        assert_eq!(evidence.verify().unwrap_err(), EvidenceError::SameBlockHash);
    }

    #[test]
    fn cross_fork_proposal_rejected() {
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        // h2 is on a different fork (different prev_block_hash)
        let mut h2 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_001);
        h2.prev_block_hash = Hash256::from_bytes([0xAA; 32]);
        // Re-sign after changing prev_block_hash
        let msg = h2.compute_signing_message().unwrap();
        h2.validator_sig = priv_key.sign(&msg).unwrap();
        let evidence = DoubleProposalEvidence::new(h1, h2);
        assert_eq!(
            evidence.verify().unwrap_err(),
            EvidenceError::CrossForkProposal
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        let mut h2 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_001);
        // Tamper with h2's signature
        h2.validator_sig.signature[0] ^= 0xFF;
        let evidence = DoubleProposalEvidence::new(h1, h2);
        assert!(matches!(
            evidence.verify().unwrap_err(),
            EvidenceError::InvalidSignature(_)
        ));
    }

    #[test]
    fn cbor_roundtrip() {
        use noble_codec::NobleCbor;
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        let h2 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_001);
        let evidence = DoubleProposalEvidence::new(h1, h2);
        let bytes = evidence.to_cbor().unwrap();
        let decoded = DoubleProposalEvidence::from_cbor(&bytes).unwrap();
        assert_eq!(evidence, decoded);
    }

    // --- VoteEquivocationEvidence tests ---

    fn make_vote_key() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn sign_vote(
        priv_key: &NoblePrivateKey,
        cycle: u64,
        candidate: Hash256,
        round: u8,
    ) -> SignatureEnvelope {
        let payload_bytes = crate::wire::v1::vote_signing_payload_bytes(cycle, &candidate, round);
        let msg = noble_crypto::sha256(&payload_bytes).0;
        priv_key.sign(&msg).unwrap()
    }

    #[test]
    fn valid_vote_equivocation() {
        let (priv_key, pub_key) = make_vote_key();
        let candidate_a = Hash256::from_bytes([0x01; 32]);
        let candidate_b = Hash256::from_bytes([0x02; 32]);
        let sig_a = sign_vote(&priv_key, 5, candidate_a, 1);
        let sig_b = sign_vote(&priv_key, 5, candidate_b, 1);
        let evidence = VoteEquivocationEvidence {
            cycle: 5,
            round: 1,
            candidate_a,
            candidate_b,
            voter_pubkey: pub_key,
            signature_a: sig_a,
            signature_b: sig_b,
        };
        assert!(evidence.verify().is_ok());
    }

    #[test]
    fn same_candidate_rejected_vote_equivocation() {
        let (priv_key, pub_key) = make_vote_key();
        let candidate = Hash256::from_bytes([0x01; 32]);
        let sig_a = sign_vote(&priv_key, 5, candidate, 1);
        let sig_b = sign_vote(&priv_key, 5, candidate, 1);
        let evidence = VoteEquivocationEvidence {
            cycle: 5,
            round: 1,
            candidate_a: candidate,
            candidate_b: candidate,
            voter_pubkey: pub_key,
            signature_a: sig_a,
            signature_b: sig_b,
        };
        assert_eq!(
            evidence.verify().unwrap_err(),
            EvidenceError::SameCandidateHash
        );
    }

    #[test]
    fn different_voters_rejected_vote_equivocation() {
        let (priv_key1, pub_key1) = make_vote_key();
        let (priv_key2, _pub_key2) = make_vote_key();
        let candidate_a = Hash256::from_bytes([0x01; 32]);
        let candidate_b = Hash256::from_bytes([0x02; 32]);
        // Sign vote_a with key1, vote_b with key2 — wrong
        let sig_a = sign_vote(&priv_key1, 5, candidate_a, 1);
        let sig_b = sign_vote(&priv_key2, 5, candidate_b, 1);
        let evidence = VoteEquivocationEvidence {
            cycle: 5,
            round: 1,
            candidate_a,
            candidate_b,
            voter_pubkey: pub_key1,
            signature_a: sig_a,
            signature_b: sig_b,
        };
        assert!(matches!(
            evidence.verify().unwrap_err(),
            EvidenceError::InvalidSignature(_)
        ));
    }

    #[test]
    fn tampered_vote_signature_rejected() {
        let (priv_key, pub_key) = make_vote_key();
        let candidate_a = Hash256::from_bytes([0x01; 32]);
        let candidate_b = Hash256::from_bytes([0x02; 32]);
        let sig_a = sign_vote(&priv_key, 5, candidate_a, 1);
        let mut sig_b = sign_vote(&priv_key, 5, candidate_b, 1);
        sig_b.signature[0] ^= 0xFF;
        let evidence = VoteEquivocationEvidence {
            cycle: 5,
            round: 1,
            candidate_a,
            candidate_b,
            voter_pubkey: pub_key,
            signature_a: sig_a,
            signature_b: sig_b,
        };
        assert!(matches!(
            evidence.verify().unwrap_err(),
            EvidenceError::InvalidSignature(_)
        ));
    }

    #[test]
    fn vote_evidence_cbor_roundtrip() {
        use noble_codec::NobleCbor;
        let (priv_key, pub_key) = make_vote_key();
        let candidate_a = Hash256::from_bytes([0x01; 32]);
        let candidate_b = Hash256::from_bytes([0x02; 32]);
        let sig_a = sign_vote(&priv_key, 5, candidate_a, 1);
        let sig_b = sign_vote(&priv_key, 5, candidate_b, 1);
        let evidence = VoteEquivocationEvidence {
            cycle: 5,
            round: 1,
            candidate_a,
            candidate_b,
            voter_pubkey: pub_key,
            signature_a: sig_a,
            signature_b: sig_b,
        };
        let bytes = evidence.to_cbor().unwrap();
        let decoded = VoteEquivocationEvidence::from_cbor(&bytes).unwrap();
        assert_eq!(evidence, decoded);
    }

    #[test]
    fn misbehavior_evidence_cbor_roundtrip() {
        use noble_codec::NobleCbor;
        // Test double-proposal variant
        let (priv_key, pub_key) = make_validator();
        let h1 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_000);
        let h2 = make_signed_header(&priv_key, &pub_key, 10, 1_700_000_001);
        let dp = DoubleProposalEvidence::new(h1, h2);
        let me = MisbehaviorEvidence::DoubleProposal(dp);
        let bytes = me.to_cbor().unwrap();
        let decoded = MisbehaviorEvidence::from_cbor(&bytes).unwrap();
        assert!(matches!(decoded, MisbehaviorEvidence::DoubleProposal(_)));

        // Test vote equivocation variant
        let (vk, vpk) = make_vote_key();
        let ca = Hash256::from_bytes([0x01; 32]);
        let cb = Hash256::from_bytes([0x02; 32]);
        let sa = sign_vote(&vk, 5, ca, 1);
        let sb = sign_vote(&vk, 5, cb, 1);
        let ve = VoteEquivocationEvidence {
            cycle: 5,
            round: 1,
            candidate_a: ca,
            candidate_b: cb,
            voter_pubkey: vpk,
            signature_a: sa,
            signature_b: sb,
        };
        let me2 = MisbehaviorEvidence::VoteEquivocation(ve);
        let bytes2 = me2.to_cbor().unwrap();
        let decoded2 = MisbehaviorEvidence::from_cbor(&bytes2).unwrap();
        assert!(matches!(
            decoded2,
            MisbehaviorEvidence::VoteEquivocation(_)
        ));
    }
}
