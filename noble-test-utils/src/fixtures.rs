// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Test fixture builders for NOBLE protocol types.
//!
//! Provides helper functions for creating valid, signed test transactions
//! and blocks with proper cryptographic signatures.

use noble_core::{
    Block, BlockHeader, MetadataEntry, Transaction, MAINNET_CHAIN_ID, PROTOCOL_VERSION,
};
use noble_crypto::{
    ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_ED25519,
};

/// A test keypair bundle for convenience.
pub struct TestKeypair {
    pub private_key: NoblePrivateKey,
    pub public_key: NoblePublicKey,
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

impl TestKeypair {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let (sk, pk) = ed25519::generate_keypair();
        Self {
            private_key: NoblePrivateKey::Ed25519(sk.clone()),
            public_key: NoblePublicKey::Ed25519(pk.clone()),
            sk_bytes: sk,
            pk_bytes: pk,
        }
    }
}

/// Build a signed transaction for testing.
///
/// Returns the transaction and its computed tx_id.
pub fn make_signed_tx(
    keypair: &TestKeypair,
    doc: &[u8],
    fee: u64,
    timestamp: u64,
) -> (Transaction, Hash256) {
    let checksum = sha256(doc);
    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 0,
        checksum,
        timestamp,
        fee,
        recipient: None,
        amount: None,
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: keypair.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
    };
    let msg = tx.compute_signing_message().unwrap();
    tx.publisher_sig = keypair.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
    (tx, tx_id)
}

/// Build a signed transaction with metadata.
pub fn make_signed_tx_with_metadata(
    keypair: &TestKeypair,
    doc: &[u8],
    fee: u64,
    timestamp: u64,
    metadata: Vec<MetadataEntry>,
) -> (Transaction, Hash256) {
    let checksum = sha256(doc);
    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 0,
        checksum,
        timestamp,
        fee,
        recipient: None,
        amount: None,
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: keypair.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata,
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
    };
    let msg = tx.compute_signing_message().unwrap();
    tx.publisher_sig = keypair.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
    (tx, tx_id)
}

/// Build a signed transfer transaction for testing.
///
/// Returns the transaction and its computed tx_id.
pub fn make_signed_transfer_tx(
    keypair: &TestKeypair,
    recipient: &NoblePublicKey,
    amount: u64,
    fee: u64,
    timestamp: u64,
) -> (Transaction, Hash256) {
    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 1,
        checksum: Hash256::ZERO,
        timestamp,
        fee,
        recipient: Some(recipient.clone()),
        amount: Some(amount),
        publisher_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: keypair.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
    };
    let msg = tx.compute_signing_message().unwrap();
    tx.publisher_sig = keypair.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
    (tx, tx_id)
}

/// Build a signed block containing the given transactions.
///
/// Returns the block, its hash, and the list of tx_ids.
pub fn make_signed_block(
    txs: Vec<(Transaction, Hash256)>,
    height: u64,
    prev_hash: Hash256,
    timestamp: u64,
) -> (Block, Hash256, Vec<Hash256>) {
    let validator = TestKeypair::generate();
    make_signed_block_with_validator(txs, height, prev_hash, timestamp, &validator)
}

/// Build a signed block with a specific validator keypair.
pub fn make_signed_block_with_validator(
    txs: Vec<(Transaction, Hash256)>,
    height: u64,
    prev_hash: Hash256,
    timestamp: u64,
    validator: &TestKeypair,
) -> (Block, Hash256, Vec<Hash256>) {
    let transactions: Vec<Transaction> = txs.iter().map(|(tx, _)| tx.clone()).collect();
    let tx_ids: Vec<Hash256> = txs.iter().map(|(_, id)| *id).collect();
    let merkle_root = noble_core::compute_merkle_root(&tx_ids);

    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp,
        height,
        tx_count: transactions.len() as u32,
        validator_id: validator.public_key.clone(),
        validator_sig: SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: validator.pk_bytes.clone(),
            signature: vec![],
        },
    };
    let msg = header.compute_signing_message().unwrap();
    header.validator_sig = validator.private_key.sign(&msg).unwrap();

    let block_hash = header.compute_block_hash().unwrap();
    let block = Block {
        header,
        transactions,
    };
    (block, block_hash, tx_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::MIN_TX_FEE;

    #[test]
    fn test_keypair_generates_valid_keys() {
        let kp = TestKeypair::generate();
        assert_eq!(kp.pk_bytes.len(), 32);
        assert_eq!(kp.sk_bytes.len(), 32);
    }

    #[test]
    fn make_signed_tx_is_valid() {
        let kp = TestKeypair::generate();
        let (tx, tx_id) = make_signed_tx(&kp, b"test_doc", MIN_TX_FEE, 1_700_000_000);

        // Verify signature
        let msg = tx.compute_signing_message().unwrap();
        assert!(tx.publisher_sig.verify_standalone(&msg).is_ok());

        // Verify tx_id
        let recomputed = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        assert_eq!(tx_id, recomputed);
    }

    #[test]
    fn make_signed_transfer_tx_is_valid() {
        let sender = TestKeypair::generate();
        let recipient = TestKeypair::generate();
        let (tx, tx_id) = make_signed_transfer_tx(
            &sender,
            &recipient.public_key,
            100_000,
            MIN_TX_FEE,
            1_700_000_000,
        );

        assert_eq!(tx.tx_type, 1);
        assert_eq!(tx.amount, Some(100_000));
        assert!(tx.recipient.is_some());
        assert_eq!(tx.checksum, Hash256::ZERO);

        // Verify signature
        let msg = tx.compute_signing_message().unwrap();
        assert!(tx.publisher_sig.verify_standalone(&msg).is_ok());

        // Verify tx_id
        let recomputed = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        assert_eq!(tx_id, recomputed);
    }

    #[test]
    fn make_signed_block_is_valid() {
        let kp = TestKeypair::generate();
        let (tx, tx_id) = make_signed_tx(&kp, b"block_doc", MIN_TX_FEE, 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_signed_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        assert_eq!(tx_ids.len(), 1);
        assert_eq!(block.header.height, 0);
        assert_eq!(block.transactions.len(), 1);

        // Verify block hash
        let recomputed = block.header.compute_block_hash().unwrap();
        assert_eq!(block_hash, recomputed);
    }
}
