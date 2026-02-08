// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Block and BlockHeader types for the NOBLE protocol.

use serde::{Deserialize, Serialize};

use noble_codec::NobleCbor;
use noble_crypto::{sha256, Hash256, NoblePublicKey, SignatureEnvelope};

use crate::transaction::Transaction;

/// A NOBLE block header.
///
/// Contains chain-linking fields, Merkle root, and the validator's identity/signature.
/// The validator_id is typed as `NoblePublicKey` (GAP-H11) to carry scheme_id intrinsically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Protocol version.
    pub version: u16,
    /// Hash of the previous block (Hash256::ZERO for genesis).
    pub prev_block_hash: Hash256,
    /// Merkle root of all transaction IDs in this block.
    pub merkle_root: Hash256,
    /// Unix timestamp (seconds) of block creation.
    pub timestamp: u64,
    /// Block height (0 for genesis).
    pub height: u64,
    /// Number of transactions in the block body.
    pub tx_count: u32,
    /// Validator's public key, typed to carry scheme_id (GAP-H11).
    pub validator_id: NoblePublicKey,
    /// Validator's signature over the header (excluding this field itself).
    pub validator_sig: SignatureEnvelope,
}

/// Internal struct for computing the header signing message.
/// Includes all header fields EXCEPT validator_sig (circular otherwise).
#[derive(Serialize)]
struct HeaderSigningPayload {
    version: u16,
    prev_block_hash: Hash256,
    merkle_root: Hash256,
    timestamp: u64,
    height: u64,
    tx_count: u32,
    validator_id: NoblePublicKey,
}

impl BlockHeader {
    /// Compute the block hash: `sha256(canonical_cbor(full_header))`.
    pub fn compute_block_hash(&self) -> Result<Hash256, noble_codec::CodecError> {
        let canonical = self.canonical_bytes()?;
        Ok(sha256(&canonical))
    }

    /// Compute the 32-byte signing message: `sha256(canonical_cbor(header_without_sig))`.
    ///
    /// The validator_sig is excluded to avoid circularity.
    pub fn compute_signing_message(&self) -> Result<[u8; 32], noble_codec::CodecError> {
        let payload = HeaderSigningPayload {
            version: self.version,
            prev_block_hash: self.prev_block_hash,
            merkle_root: self.merkle_root,
            timestamp: self.timestamp,
            height: self.height,
            tx_count: self.tx_count,
            validator_id: self.validator_id.clone(),
        };

        let canonical = noble_codec::to_canonical_cbor(&payload)?;
        Ok(sha256(&canonical).0)
    }
}

/// A NOBLE block: header plus a body of transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Block header with chain links and validator identity.
    pub header: BlockHeader,
    /// Ordered list of transactions in this block.
    pub transactions: Vec<Transaction>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{ed25519, NoblePrivateKey, NobleSigner, SCHEME_ED25519};

    fn make_test_header() -> BlockHeader {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = NoblePublicKey::Ed25519(pk.clone());

        let mut header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::ZERO,
            merkle_root: Hash256::from_bytes([0xAA; 32]),
            timestamp: 1_700_000_000,
            height: 1,
            tx_count: 0,
            validator_id: pub_key,
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk,
                signature: vec![],
            },
        };

        // Sign the header
        let msg = header.compute_signing_message().unwrap();
        let envelope = priv_key.sign(&msg).unwrap();
        header.validator_sig = envelope;
        header
    }

    #[test]
    fn block_hash_deterministic() {
        let header = make_test_header();
        let h1 = header.compute_block_hash().unwrap();
        let h2 = header.compute_block_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn signing_message_excludes_validator_sig() {
        let header = make_test_header();
        let msg1 = header.compute_signing_message().unwrap();

        // Changing the signature should NOT change the signing message
        let mut header2 = header.clone();
        header2.validator_sig.signature = vec![0xFF; 64];
        let msg2 = header2.compute_signing_message().unwrap();

        assert_eq!(
            msg1, msg2,
            "signing message must not depend on validator_sig"
        );
    }

    #[test]
    fn block_hash_changes_with_height() {
        let mut header = make_test_header();
        let h1 = header.compute_block_hash().unwrap();
        header.height = 99;
        let h2 = header.compute_block_hash().unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn header_cbor_roundtrip() {
        let header = make_test_header();
        let bytes = header.to_cbor().unwrap();
        let decoded = BlockHeader::from_cbor(&bytes).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn block_cbor_roundtrip() {
        let block = Block {
            header: make_test_header(),
            transactions: vec![],
        };
        let bytes = block.to_cbor().unwrap();
        let decoded = Block::from_cbor(&bytes).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn validator_id_is_typed() {
        let header = make_test_header();
        // GAP-H11: validator_id carries scheme_id intrinsically
        assert_eq!(header.validator_id.scheme_id(), SCHEME_ED25519);
    }
}
