// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Double-proposal evidence for slashing misbehaving validators.
//!
//! A [`DoubleProposalEvidence`] proves that a validator proposed two different
//! blocks within the same consensus cycle, which is a slashable offense.

use serde::{Deserialize, Serialize};

use noble_crypto::NoblePublicKey;

use crate::BlockHeader;

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

/// Errors when verifying double-proposal evidence.
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
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DifferentValidators => write!(f, "headers reference different validators"),
            Self::DifferentHeights => write!(f, "headers are at different heights"),
            Self::SameBlockHash => write!(f, "headers have the same block hash"),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {e}"),
            Self::HashError(e) => write!(f, "hash computation error: {e}"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{
        ed25519, Hash256, NoblePrivateKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
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
                scheme_id: SCHEME_ED25519,
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
}
