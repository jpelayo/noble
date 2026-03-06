// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Genesis block definitions for mainnet and testnet.
//!
//! The genesis block is the first block in the chain (height 0). It has:
//! - `prev_block_hash`: Hash256::ZERO
//! - `height`: 0
//! - No transactions (empty Merkle root)
//! - A deterministic Ed25519 keypair derived from a domain-separated seed
//! - A real cryptographic signature (not a placeholder)

use std::sync::LazyLock;

use noble_crypto::{
    sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_ED25519,
};

use crate::block::{Block, BlockHeader};
use crate::constants::PROTOCOL_VERSION;
use crate::merkle::compute_merkle_root;

/// Mainnet genesis block timestamp: 2026-03-01T00:00:00Z (Unix epoch).
pub const GENESIS_TIMESTAMP: u64 = 1_772_524_800;

/// Domain-separated seed for deriving the mainnet genesis Ed25519 keypair.
/// The SHA-256 hash of this string is used as the Ed25519 secret key seed.
const MAINNET_SEED: &[u8] = b"NOBLE-GENESIS-VALIDATOR-MAINNET-v1";

/// Domain-separated seed for deriving the testnet genesis Ed25519 keypair.
const TESTNET_SEED: &[u8] = b"NOBLE-GENESIS-VALIDATOR-TESTNET-v1";

/// Domain-separated seed for deriving the regtest genesis Ed25519 keypair.
const REGTEST_SEED: &[u8] = b"NOBLE-GENESIS-VALIDATOR-REGTEST-v1";

/// Derive a deterministic Ed25519 keypair from a seed phrase.
///
/// The secret key is `sha256(seed)`, and the public key is derived from it.
/// This is deterministic: the same seed always produces the same keypair.
fn deterministic_keypair(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sk_bytes = sha256(seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes.0);
    let verifying_key = signing_key.verifying_key();
    (
        signing_key.to_bytes().to_vec(),
        verifying_key.to_bytes().to_vec(),
    )
}

/// Construct the mainnet genesis block.
pub fn genesis_block() -> Block {
    build_genesis(GENESIS_TIMESTAMP, MAINNET_SEED)
}

/// Construct the testnet genesis block.
pub fn testnet_genesis_block() -> Block {
    build_genesis(GENESIS_TIMESTAMP, TESTNET_SEED)
}

/// Construct the regtest genesis block.
pub fn regtest_genesis_block() -> Block {
    build_genesis(GENESIS_TIMESTAMP, REGTEST_SEED)
}

/// Compute the regtest genesis block hash.
pub fn regtest_genesis_hash() -> Hash256 {
    regtest_genesis_block()
        .header
        .compute_block_hash()
        .expect("regtest genesis block hash computation must succeed")
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

/// Derive a chain identifier from a genesis block hash.
///
/// Takes the first 4 bytes of the hash and interprets them as a big-endian u32.
/// Each distinct genesis block produces a unique, deterministic chain ID.
pub fn derive_chain_id(hash: &Hash256) -> u32 {
    let bytes = hash.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Mainnet chain identifier — derived from the mainnet genesis block hash.
pub fn mainnet_chain_id() -> u32 {
    static ID: LazyLock<u32> = LazyLock::new(|| derive_chain_id(&genesis_hash()));
    *ID
}

/// Testnet chain identifier — derived from the testnet genesis block hash.
pub fn testnet_chain_id() -> u32 {
    static ID: LazyLock<u32> = LazyLock::new(|| derive_chain_id(&testnet_genesis_hash()));
    *ID
}

/// Regtest chain identifier — derived from the regtest genesis block hash.
pub fn regtest_chain_id() -> u32 {
    static ID: LazyLock<u32> = LazyLock::new(|| derive_chain_id(&regtest_genesis_hash()));
    *ID
}

fn build_genesis(timestamp: u64, seed: &[u8]) -> Block {
    tracing::info!(timestamp, "generating genesis block");
    let (sk, pk) = deterministic_keypair(seed);
    let priv_key = NoblePrivateKey::Ed25519(sk);
    let merkle_root = compute_merkle_root(&[]); // Empty tree

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: Hash256::ZERO,
        merkle_root,
        timestamp,
        height: 0,
        tx_count: 0,
        validator_id: NoblePublicKey::Ed25519(pk.clone()),
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
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
    use noble_crypto::ed25519;

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
    fn regtest_genesis_differs_from_mainnet_and_testnet() {
        let mainnet = genesis_hash();
        let testnet = testnet_genesis_hash();
        let regtest = regtest_genesis_hash();
        assert_ne!(mainnet, regtest, "mainnet and regtest genesis must differ");
        assert_ne!(testnet, regtest, "testnet and regtest genesis must differ");
    }

    #[test]
    fn regtest_genesis_signature_is_cryptographically_valid() {
        let block = regtest_genesis_block();
        let signing_msg = block.header.compute_signing_message().unwrap();
        let result = ed25519::verify(
            &block.header.validator_sig.public_key,
            &signing_msg,
            &block.header.validator_sig.signature,
        );
        assert!(
            result.is_ok(),
            "regtest genesis signature must verify: {result:?}"
        );
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

    #[test]
    fn genesis_signature_is_cryptographically_valid() {
        let block = genesis_block();
        let signing_msg = block.header.compute_signing_message().unwrap();
        // Verify the validator signature against the public key
        let result = ed25519::verify(
            &block.header.validator_sig.public_key,
            &signing_msg,
            &block.header.validator_sig.signature,
        );
        assert!(result.is_ok(), "genesis signature must verify: {result:?}");
    }

    #[test]
    fn testnet_genesis_signature_is_cryptographically_valid() {
        let block = testnet_genesis_block();
        let signing_msg = block.header.compute_signing_message().unwrap();
        let result = ed25519::verify(
            &block.header.validator_sig.public_key,
            &signing_msg,
            &block.header.validator_sig.signature,
        );
        assert!(
            result.is_ok(),
            "testnet genesis signature must verify: {result:?}"
        );
    }

    #[test]
    fn genesis_validator_id_matches_sig_pubkey() {
        let block = genesis_block();
        if let NoblePublicKey::Ed25519(ref id_bytes) = block.header.validator_id {
            assert_eq!(
                id_bytes, &block.header.validator_sig.public_key,
                "validator_id and validator_sig.public_key must match"
            );
        } else {
            panic!("genesis validator must be Ed25519");
        }
    }

    #[test]
    fn deterministic_keypair_is_stable() {
        let (sk1, pk1) = deterministic_keypair(MAINNET_SEED);
        let (sk2, pk2) = deterministic_keypair(MAINNET_SEED);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn different_seeds_produce_different_keys() {
        let (_, pk_main) = deterministic_keypair(MAINNET_SEED);
        let (_, pk_test) = deterministic_keypair(TESTNET_SEED);
        assert_ne!(pk_main, pk_test);
    }

    #[test]
    fn derive_chain_id_uses_first_four_bytes() {
        let hash = genesis_hash();
        let id = derive_chain_id(&hash);
        let bytes = hash.as_bytes();
        let expected = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(id, expected);
    }

    #[test]
    fn chain_ids_are_deterministic() {
        assert_eq!(mainnet_chain_id(), mainnet_chain_id());
        assert_eq!(testnet_chain_id(), testnet_chain_id());
        assert_eq!(regtest_chain_id(), regtest_chain_id());
    }

    #[test]
    fn chain_ids_are_distinct() {
        assert_ne!(mainnet_chain_id(), testnet_chain_id());
        assert_ne!(mainnet_chain_id(), regtest_chain_id());
        assert_ne!(testnet_chain_id(), regtest_chain_id());
    }

    #[test]
    fn chain_ids_are_nonzero() {
        assert_ne!(mainnet_chain_id(), 0);
        assert_ne!(testnet_chain_id(), 0);
        assert_ne!(regtest_chain_id(), 0);
    }
}
