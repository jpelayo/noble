// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Genesis block definitions for mainnet and testnet.
//!
//! The genesis block is the first block in the chain (height 0). It has:
//! - `prev_block_hash`: Hash256::ZERO
//! - `height`: 0
//! - No transactions (empty Merkle root)
//! - A hard-coded validator key and self-signature

use noble_crypto::{Hash256, NoblePublicKey, SignatureEnvelope, SCHEME_ED25519};

use crate::block::{Block, BlockHeader};
use crate::constants::PROTOCOL_VERSION;
use crate::merkle::compute_merkle_root;

/// Mainnet genesis block timestamp: 2026-03-01T00:00:00Z (Unix epoch).
pub const GENESIS_TIMESTAMP: u64 = 1_772_524_800;

/// Hardcoded mainnet genesis validator public key (Ed25519).
///
/// This is the SHA-256 hash of "NOBLE_GENESIS_VALIDATOR_MAINNET" used as a
/// deterministic 32-byte public key for the genesis block. In a real deployment,
/// this would be replaced with an actual Ed25519 key from the founding validator.
const GENESIS_VALIDATOR_PUBKEY: [u8; 32] = [
    0x4e, 0x4f, 0x42, 0x4c, 0x45, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53, 0x5f, 0x56, 0x41,
    0x4c, 0x49, 0x44, 0x41, 0x54, 0x4f, 0x52, 0x5f, 0x4d, 0x41, 0x49, 0x4e, 0x4e, 0x45, 0x54, 0x00,
];

/// Hardcoded testnet genesis validator public key (Ed25519).
const TESTNET_GENESIS_VALIDATOR_PUBKEY: [u8; 32] = [
    0x54, 0x45, 0x53, 0x54, 0x4e, 0x45, 0x54, 0x5f, 0x47, 0x45, 0x4e, 0x45, 0x53, 0x49, 0x53, 0x5f,
    0x56, 0x41, 0x4c, 0x49, 0x44, 0x41, 0x54, 0x4f, 0x52, 0x5f, 0x4b, 0x45, 0x59, 0x00, 0x00, 0x00,
];

/// Genesis block validator signature placeholder.
///
/// The genesis block is special-cased in validation: its validator signature
/// is not verified cryptographically (there's no prior state to bootstrap from).
/// This placeholder is a fixed 64-byte value for determinism.
const GENESIS_SIGNATURE: [u8; 64] = [0x00; 64];

/// Construct the mainnet genesis block.
pub fn genesis_block() -> Block {
    build_genesis(GENESIS_TIMESTAMP, &GENESIS_VALIDATOR_PUBKEY)
}

/// Construct the testnet genesis block.
pub fn testnet_genesis_block() -> Block {
    build_genesis(GENESIS_TIMESTAMP, &TESTNET_GENESIS_VALIDATOR_PUBKEY)
}

/// Compute the mainnet genesis block hash.
pub fn genesis_hash() -> Hash256 {
    genesis_block()
        .header
        .compute_block_hash()
        .expect("genesis block hash computation must succeed")
}

/// Compute the testnet genesis block hash.
pub fn testnet_genesis_hash() -> Hash256 {
    testnet_genesis_block()
        .header
        .compute_block_hash()
        .expect("testnet genesis block hash computation must succeed")
}

fn build_genesis(timestamp: u64, validator_pubkey: &[u8; 32]) -> Block {
    let merkle_root = compute_merkle_root(&[]); // Empty tree

    let header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp,
        height: 0,
        tx_count: 0,
        validator_id: NoblePublicKey::Ed25519(validator_pubkey.to_vec()),
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: validator_pubkey.to_vec(),
            signature: GENESIS_SIGNATURE.to_vec(),
        },
    };

    Block {
        header,
        transactions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_codec::NobleCbor;

    #[test]
    fn genesis_block_is_deterministic() {
        let b1 = genesis_block();
        let b2 = genesis_block();
        assert_eq!(b1, b2);
    }

    #[test]
    fn genesis_hash_is_deterministic() {
        let h1 = genesis_hash();
        let h2 = genesis_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_block_fields() {
        let block = genesis_block();
        assert_eq!(block.header.version, PROTOCOL_VERSION);
        assert_eq!(block.header.prev_block_hash, Hash256::ZERO);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.tx_count, 0);
        assert_eq!(block.header.timestamp, GENESIS_TIMESTAMP);
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn genesis_merkle_root_is_empty_tree_hash() {
        let block = genesis_block();
        let expected = compute_merkle_root(&[]);
        assert_eq!(block.header.merkle_root, expected);
    }

    #[test]
    fn testnet_genesis_differs_from_mainnet() {
        let mainnet = genesis_hash();
        let testnet = testnet_genesis_hash();
        assert_ne!(mainnet, testnet, "mainnet and testnet genesis must differ");
    }

    #[test]
    fn genesis_cbor_roundtrip() {
        let block = genesis_block();
        let bytes = block.to_cbor().unwrap();
        let decoded = Block::from_cbor(&bytes).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn genesis_hash_is_not_zero() {
        assert_ne!(genesis_hash(), Hash256::ZERO);
    }
}
