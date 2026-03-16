// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Genesis block construction.
//!
//! The genesis block is the first block in the chain (height 0). It has:
//! - `prev_block_hash`: Hash256::ZERO
//! - `height`: 0
//! - No transactions (empty Merkle root)
//! - A deterministic secp256k1 keypair derived from a domain-separated seed
//! - A real cryptographic signature (not a placeholder)
//!
//! Chain identity is fully dynamic — no hardcoded networks. The binary is
//! chain-agnostic: call `build_genesis(timestamp, seed)` with any seed to
//! create a genesis block, then `derive_chain_id(&hash)` for its chain ID.

use noble_crypto::{
    sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_SECP256K1,
};

use crate::block::{Block, BlockHeader};
use crate::constants::PROTOCOL_VERSION;
use crate::merkle::compute_merkle_root;

/// Genesis block timestamp: 2026-03-01T00:00:00Z (Unix epoch).
pub const GENESIS_TIMESTAMP: u64 = 1_772_524_800;

/// Derive a deterministic secp256k1 keypair from a seed phrase.
///
/// The secret key is `sha256(seed)` (32 bytes), and the compressed public key
/// is derived from it. Deterministic: same seed → same keypair.
fn deterministic_keypair(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sk_hash = sha256(seed);
    noble_crypto::secp256k1::keypair_from_secret(&sk_hash.0)
        .expect("sha256 output exceeds curve order with probability ~2^-224")
}

/// Derive a chain identifier from a genesis block hash.
///
/// Takes the first 4 bytes of the hash and interprets them as a big-endian u32.
/// Each distinct genesis block produces a unique, deterministic chain ID.
pub fn derive_chain_id(hash: &Hash256) -> u32 {
    let bytes = hash.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub fn build_genesis(timestamp: u64, seed: &[u8]) -> Block {
    tracing::info!(timestamp, "generating genesis block");
    let (sk, pk) = deterministic_keypair(seed);
    let priv_key = NoblePrivateKey::Secp256k1(sk);
    let merkle_root = compute_merkle_root(&[]); // Empty tree

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp,
        height: 0,
        tx_count: 0,
        validator_id: NoblePublicKey::Secp256k1(pk.clone()),
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: pk,
            signature: vec![],
        },
    };

    // Produce a real cryptographic signature over the header
    let signing_msg = header
        .compute_signing_message()
        .expect("genesis header signing message must succeed");
    header.validator_sig = priv_key
        .sign(&signing_msg)
        .expect("genesis header signing must succeed");

    Block {
        header,
        transactions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_codec::NobleCbor;
    use noble_crypto::secp256k1;

    const TEST_SEED: &[u8] = b"noble-test-genesis";

    fn test_block() -> Block {
        build_genesis(GENESIS_TIMESTAMP, TEST_SEED)
    }

    fn test_hash() -> Hash256 {
        test_block()
            .header
            .compute_block_hash()
            .expect("test genesis block hash")
    }

    #[test]
    fn genesis_block_is_deterministic() {
        assert_eq!(test_block(), test_block());
    }

    #[test]
    fn genesis_hash_is_deterministic() {
        assert_eq!(test_hash(), test_hash());
    }

    #[test]
    fn genesis_block_fields() {
        let block = test_block();
        assert_eq!(block.header.version, PROTOCOL_VERSION);
        assert_eq!(block.header.prev_block_hash, Hash256::ZERO);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.header.tx_count, 0);
        assert_eq!(block.header.timestamp, GENESIS_TIMESTAMP);
        assert!(block.transactions.is_empty());
    }

    #[test]
    fn genesis_merkle_root_is_empty_tree_hash() {
        let block = test_block();
        let expected = compute_merkle_root(&[]);
        assert_eq!(block.header.merkle_root, expected);
    }

    #[test]
    fn different_seeds_produce_different_genesis() {
        let a = build_genesis(GENESIS_TIMESTAMP, b"seed-a");
        let b = build_genesis(GENESIS_TIMESTAMP, b"seed-b");
        let ha = a.header.compute_block_hash().unwrap();
        let hb = b.header.compute_block_hash().unwrap();
        assert_ne!(ha, hb, "different seeds must produce different genesis blocks");
    }

    #[test]
    fn genesis_signature_is_cryptographically_valid() {
        let block = test_block();
        let signing_msg = block.header.compute_signing_message().unwrap();
        let result = secp256k1::verify(
            &block.header.validator_sig.public_key,
            &signing_msg,
            &block.header.validator_sig.signature,
        );
        assert!(result.is_ok(), "genesis signature must verify: {result:?}");
    }

    #[test]
    fn genesis_cbor_roundtrip() {
        let block = test_block();
        let bytes = block.to_cbor().unwrap();
        let decoded = Block::from_cbor(&bytes).unwrap();
        assert_eq!(block, decoded);
    }

    #[test]
    fn genesis_hash_is_not_zero() {
        assert_ne!(test_hash(), Hash256::ZERO);
    }

    #[test]
    fn genesis_validator_id_matches_sig_pubkey() {
        let block = test_block();
        if let NoblePublicKey::Secp256k1(ref id_bytes) = block.header.validator_id {
            assert_eq!(
                id_bytes, &block.header.validator_sig.public_key,
                "validator_id and validator_sig.public_key must match"
            );
        } else {
            panic!("genesis validator must be secp256k1");
        }
    }

    #[test]
    fn deterministic_keypair_is_stable() {
        let (sk1, pk1) = deterministic_keypair(TEST_SEED);
        let (sk2, pk2) = deterministic_keypair(TEST_SEED);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let (_, pk_a) = deterministic_keypair(b"seed-a");
        let (_, pk_b) = deterministic_keypair(b"seed-b");
        assert_ne!(pk_a, pk_b);
    }

    #[test]
    fn derive_chain_id_uses_first_four_bytes() {
        let hash = test_hash();
        let id = derive_chain_id(&hash);
        let bytes = hash.as_bytes();
        let expected = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(id, expected);
    }

    #[test]
    fn chain_ids_are_deterministic() {
        let id1 = derive_chain_id(&test_hash());
        let id2 = derive_chain_id(&test_hash());
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_seeds_produce_different_chain_ids() {
        let a = build_genesis(GENESIS_TIMESTAMP, b"seed-a");
        let b = build_genesis(GENESIS_TIMESTAMP, b"seed-b");
        let ha = a.header.compute_block_hash().unwrap();
        let hb = b.header.compute_block_hash().unwrap();
        assert_ne!(derive_chain_id(&ha), derive_chain_id(&hb));
    }

    #[test]
    fn chain_id_is_nonzero() {
        assert_ne!(derive_chain_id(&test_hash()), 0);
    }
}
