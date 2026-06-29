// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Test fixture builders for NOBLE protocol types (UTXO model).
//!
//! Provides helper functions for creating valid, signed test transactions
//! and blocks with proper cryptographic signatures.

use noble_core::{
    Block, BlockHeader, MetadataEntry, OutPoint, Transaction, TxIn, TxOut, PROTOCOL_VERSION,
    TX_TYPE_COINBASE,
    genesis::{build_genesis, derive_chain_id, GENESIS_TIMESTAMP},
};
use noble_crypto::{
    secp256k1, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
    SCHEME_SECP256K1,
};

/// Fixed seed used by all tests to produce a deterministic genesis block.
const TEST_GENESIS_SEED: &[u8] = b"noble-test-genesis";

/// Deterministic genesis block for tests.
pub fn test_genesis_block() -> Block {
    build_genesis(GENESIS_TIMESTAMP, TEST_GENESIS_SEED)
}

/// Deterministic genesis block hash for tests.
pub fn test_genesis_hash() -> noble_crypto::Hash256 {
    test_genesis_block()
        .header
        .compute_block_hash()
        .expect("test genesis block hash computation must succeed")
}

/// Deterministic chain ID for tests — derived from the test genesis block hash.
pub fn test_chain_id() -> u32 {
    use std::sync::LazyLock;
    static ID: LazyLock<u32> = LazyLock::new(|| derive_chain_id(&test_genesis_hash()));
    *ID
}

/// A test keypair bundle for convenience.
pub struct TestKeypair {
    pub private_key: NoblePrivateKey,
    pub public_key: NoblePublicKey,
    pub sk_bytes: Vec<u8>,
    pub pk_bytes: Vec<u8>,
}

impl TestKeypair {
    /// Generate a new random secp256k1 keypair.
    pub fn generate() -> Self {
        let (sk, pk) = secp256k1::generate_keypair();
        Self {
            private_key: NoblePrivateKey::Secp256k1(sk.clone()),
            public_key: NoblePublicKey::Secp256k1(pk.clone()),
            sk_bytes: sk,
            pk_bytes: pk,
        }
    }

    /// Get the NobleAddress for this keypair.
    pub fn address(&self) -> noble_core::NobleAddress {
        noble_core::NobleAddress::Noble(self.public_key.clone())
    }
}

/// Build a signed notarization transaction (UTXO model).
///
/// Creates a notarization that consumes a fake UTXO and returns change.
/// The `fee` parameter determines the implicit fee (input_value - output_value).
/// Returns the transaction and its computed tx_id.
pub fn make_signed_tx(
    keypair: &TestKeypair,
    doc: &[u8],
    fee: u64,
    timestamp: u64,
) -> (Transaction, Hash256) {
    let checksum = sha256(doc);
    let input_value = 100_000_000 + fee; // Enough to cover fee + change

    // Fake previous UTXO outpoint
    let prev_outpoint = OutPoint {
        txid: sha256(keypair.pk_bytes.as_slice()),
        vout: 0,
    };

    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 0, // notarization
        inputs: vec![TxIn { prev_output: prev_outpoint }],
        outputs: vec![TxOut {
            value: input_value - fee, // change back to sender
            address: keypair.address(),
        }],
        checksum,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: keypair.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
            expires_at: None,
    };
    let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx.issuer_sig = keypair.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
    (tx, tx_id)
}

/// Build a signed notarization transaction with metadata.
pub fn make_signed_tx_with_metadata(
    keypair: &TestKeypair,
    doc: &[u8],
    fee: u64,
    timestamp: u64,
    metadata: Vec<MetadataEntry>,
) -> (Transaction, Hash256) {
    let checksum = sha256(doc);
    let input_value = 100_000_000 + fee;

    let prev_outpoint = OutPoint {
        txid: sha256(keypair.pk_bytes.as_slice()),
        vout: 0,
    };

    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 0,
        inputs: vec![TxIn { prev_output: prev_outpoint }],
        outputs: vec![TxOut {
            value: input_value - fee,
            address: keypair.address(),
        }],
        checksum,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: keypair.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata,
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
            expires_at: None,
    };
    let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx.issuer_sig = keypair.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
    (tx, tx_id)
}

/// Build a signed transfer transaction (UTXO model).
///
/// Creates a transfer that consumes a fake UTXO, sends `amount` to recipient,
/// and returns change to sender. Fee = input_value - amount - change.
pub fn make_signed_transfer_tx(
    keypair: &TestKeypair,
    recipient: &NoblePublicKey,
    amount: u64,
    fee: u64,
    timestamp: u64,
) -> (Transaction, Hash256) {
    let input_value = amount + fee + 1_000; // amount + fee + some change

    let prev_outpoint = OutPoint {
        txid: sha256(keypair.pk_bytes.as_slice()),
        vout: 0,
    };

    let change = input_value - amount - fee;
    let mut outputs = vec![
        TxOut {
            value: amount,
            address: noble_core::NobleAddress::Noble(recipient.clone()),
        },
    ];
    if change > 0 {
        outputs.push(TxOut {
            value: change,
            address: keypair.address(),
        });
    }

    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: 1, // transfer
        inputs: vec![TxIn { prev_output: prev_outpoint }],
        outputs,
        checksum: Hash256::ZERO,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: keypair.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
            expires_at: None,
    };
    let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx.issuer_sig = keypair.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
    (tx, tx_id)
}

/// Build a coinbase transaction for a given height.
///
/// Outputs carry subsidy + fees to the validator address.
pub fn make_coinbase_tx(
    validator: &TestKeypair,
    height: u64,
    total_fees: u64,
    timestamp: u64,
) -> (Transaction, Hash256) {
    let subsidy = noble_core::subsidy_at_height(height);

    let mut tx = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_COINBASE,
        inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
        outputs: vec![TxOut {
            value: subsidy + total_fees,
            address: validator.address(),
        }],
        checksum: Hash256::ZERO,
        timestamp,
        issuer_sig: SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: validator.pk_bytes.clone(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
        contract_data: None,
            expires_at: None,
    };
    let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
    tx.issuer_sig = validator.private_key.sign(&msg).unwrap();
    let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
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
            scheme_id: SCHEME_SECP256K1,
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

/// Build a block with coinbase at index 0 + user transactions.
///
/// Automatically creates the coinbase with correct subsidy + total fees.
pub fn make_block_with_coinbase(
    user_txs: Vec<(Transaction, Hash256)>,
    height: u64,
    prev_hash: Hash256,
    timestamp: u64,
    validator: &TestKeypair,
    input_values_per_tx: &[u64], // total input value for each user tx (to compute fees)
) -> (Block, Hash256, Vec<Hash256>) {
    // Compute total fees from user transactions
    let total_fees: u64 = user_txs
        .iter()
        .zip(input_values_per_tx.iter())
        .map(|((tx, _), &input_val)| {
            input_val.saturating_sub(tx.total_output_value())
        })
        .sum();

    // Build coinbase
    let (coinbase, coinbase_id) = make_coinbase_tx(validator, height, total_fees, timestamp);

    // Prepend coinbase
    let mut all_txs = vec![(coinbase, coinbase_id)];
    all_txs.extend(user_txs);

    make_signed_block_with_validator(all_txs, height, prev_hash, timestamp, validator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::MIN_TX_FEE;

    #[test]
    fn test_keypair_generates_valid_keys() {
        let kp = TestKeypair::generate();
        // secp256k1-everywhere: compressed public key is 33 bytes, secret is 32.
        assert_eq!(kp.pk_bytes.len(), 33);
        assert_eq!(kp.sk_bytes.len(), 32);
    }

    #[test]
    fn make_signed_tx_is_valid() {
        let kp = TestKeypair::generate();
        let (tx, tx_id) = make_signed_tx(&kp, b"test_doc", MIN_TX_FEE, 1_700_000_000);

        // Verify signature
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        assert!(tx.issuer_sig.verify_standalone(&msg).is_ok());

        // Verify tx_id
        let recomputed = tx.compute_tx_id(test_chain_id()).unwrap();
        assert_eq!(tx_id, recomputed);

        // UTXO structure
        assert_eq!(tx.inputs.len(), 1);
        assert!(!tx.inputs[0].prev_output.is_coinbase());
        assert_eq!(tx.outputs.len(), 1);
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
        assert_eq!(tx.checksum, Hash256::ZERO);
        // Recipient output
        assert_eq!(tx.outputs[0].value, 100_000);
        // Change output
        assert!(tx.outputs.len() >= 1);

        // Verify signature
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        assert!(tx.issuer_sig.verify_standalone(&msg).is_ok());

        // Verify tx_id
        let recomputed = tx.compute_tx_id(test_chain_id()).unwrap();
        assert_eq!(tx_id, recomputed);
    }

    #[test]
    fn make_coinbase_tx_is_valid() {
        let validator = TestKeypair::generate();
        let (tx, _) = make_coinbase_tx(&validator, 1, 5_000, 1_700_000_000);

        assert!(tx.is_coinbase());
        assert_eq!(tx.tx_type, TX_TYPE_COINBASE);
        assert_eq!(tx.inputs.len(), 1);
        assert!(tx.inputs[0].prev_output.is_coinbase());

        let expected = noble_core::subsidy_at_height(1) + 5_000;
        assert_eq!(tx.outputs[0].value, expected);
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

        let recomputed = block.header.compute_block_hash().unwrap();
        assert_eq!(block_hash, recomputed);
    }
}
