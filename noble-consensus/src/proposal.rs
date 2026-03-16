// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Block proposal: select transactions from mempool and build a valid block.

use noble_codec::NobleCbor;
use noble_core::{
    compute_merkle_root, Block, BlockHeader, NobleAddress, OutPoint, Transaction, TxIn, TxOut,
    PROTOCOL_VERSION, TX_TYPE_COINBASE, subsidy_at_height,
};
use noble_crypto::{Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};

/// Look up a UTXO's value by outpoint. Used by propose_block to compute fees.
pub trait UtxoValueLookup {
    fn utxo_value(&self, outpoint: &OutPoint) -> Option<u64>;
}

/// Propose a new block from a pre-sorted list of mempool transactions.
///
/// Automatically prepends a coinbase transaction at index 0 carrying
/// `subsidy_at_height(height) + total_fees` to the validator address.
///
/// `mempool_txs` should already be sorted by fee descending (highest first).
/// `utxo_lookup` is used to resolve input UTXO values for fee computation.
///
/// Returns the complete signed block.
#[allow(clippy::too_many_arguments)]
pub fn propose_block(
    mempool_txs: &[Transaction],
    prev_hash: Hash256,
    height: u64,
    timestamp: u64,
    chain_id: u32,
    validator_key: &NoblePrivateKey,
    validator_pubkey: &NoblePublicKey,
    max_size: usize,
    utxo_lookup: &dyn UtxoValueLookup,
) -> Result<Block, String> {
    let validator_addr = NobleAddress::Noble(validator_pubkey.clone());

    // Select transactions that fit within max_size
    let mut selected: Vec<Transaction> = Vec::new();
    let mut total_size: usize = 0;
    let mut total_fees: u64 = 0;
    // Track gateway fee shares: gateway_wire_bytes → accumulated share
    let mut gateway_shares: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();

    for tx in mempool_txs {
        let tx_bytes = tx
            .to_cbor()
            .map_err(|e| format!("failed to serialize tx: {e}"))?;
        if total_size + tx_bytes.len() > max_size {
            break;
        }
        total_size += tx_bytes.len();

        // Compute fee for this tx: sum(input values) - sum(output values)
        let input_total: u64 = tx.inputs.iter().map(|i| {
            utxo_lookup.utxo_value(&i.prev_output).unwrap_or(0)
        }).sum();
        let output_total = tx.total_output_value();
        let fee = input_total.saturating_sub(output_total);
        total_fees += fee;

        // Gateway fee split: if gateway_address is present, gateway gets 50% of fee
        if let Some(ref gw) = tx.gateway_address {
            let gw_share = fee / 2;
            if gw_share > 0 {
                *gateway_shares.entry(gw.clone()).or_default() += gw_share;
            }
        }

        selected.push(tx.clone());
    }

    // Build coinbase transaction (index 0)
    // Outputs: [0] validator gets subsidy + (total_fees - gateway_shares_sum)
    //          [1..N] one output per unique gateway with their accumulated share
    let subsidy = subsidy_at_height(height);
    let total_gateway_share: u64 = gateway_shares.values().sum();
    let validator_amount = subsidy.saturating_add(total_fees.saturating_sub(total_gateway_share));

    let mut coinbase_outputs = vec![TxOut {
        value: validator_amount,
        address: validator_addr,
    }];

    // Add gateway outputs (sorted for deterministic coinbase)
    let mut gw_entries: Vec<_> = gateway_shares.into_iter().collect();
    gw_entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (gw_wire, gw_amount) in gw_entries {
        if let Ok(gw_addr) = NobleAddress::from_wire_bytes(&gw_wire) {
            coinbase_outputs.push(TxOut {
                value: gw_amount,
                address: gw_addr,
            });
        }
    }

    let mut coinbase = Transaction {
        version: PROTOCOL_VERSION,
        tx_type: TX_TYPE_COINBASE,
        inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
        outputs: coinbase_outputs,
        checksum: Hash256::ZERO,
        timestamp,
        publisher_sig: SignatureEnvelope {
            scheme_id: validator_pubkey.scheme_id(),
            public_key: validator_pubkey.key_bytes().to_vec(),
            signature: vec![],
        },
        additional_sigs: vec![],
        metadata: vec![],
        encrypted_locator: None,
        external_attestations: vec![],
        gateway_address: None,
            contract_data: None,
    };
    let coinbase_msg = coinbase
        .compute_signing_message_for_chain(chain_id)
        .map_err(|e| format!("failed to compute coinbase signing message: {e}"))?;
    coinbase.publisher_sig = validator_key
        .sign(&coinbase_msg)
        .map_err(|e| format!("failed to sign coinbase: {e}"))?;

    // Prepend coinbase, then user transactions
    let mut all_txs = Vec::with_capacity(1 + selected.len());
    all_txs.push(coinbase);
    all_txs.extend(selected);

    // Compute tx_ids and merkle root (coinbase included)
    let tx_ids: Vec<Hash256> = all_txs
        .iter()
        .map(|tx| tx.compute_tx_id(chain_id))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to compute tx_id: {e}"))?;
    let merkle_root = compute_merkle_root(&tx_ids);



    // Build header
    let mut header = BlockHeader {
        version: PROTOCOL_VERSION,
        prev_block_hash: prev_hash,
        merkle_root,
        timestamp,
        height,
        tx_count: all_txs.len() as u32,
        validator_id: validator_pubkey.clone(),
        validator_sig: SignatureEnvelope {
            scheme_id: validator_pubkey.scheme_id(),
            public_key: validator_pubkey.key_bytes().to_vec(),
            signature: vec![],
        },
    };

    // Sign the header
    let msg = header
        .compute_signing_message()
        .map_err(|e| format!("failed to compute signing message: {e}"))?;
    header.validator_sig = validator_key
        .sign(&msg)
        .map_err(|e| format!("failed to sign block: {e}"))?;

    Ok(Block {
        header,
        transactions: all_txs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{MAX_BLOCK_SIZE, MIN_TX_FEE};
    use noble_test_utils::fixtures::test_chain_id;
    use noble_crypto::{ed25519, sha256, NoblePrivateKey, NobleSigner, SCHEME_ED25519};

    /// Test UTXO lookup that returns a fixed value for any outpoint.
    struct FixedUtxoLookup(u64);
    impl UtxoValueLookup for FixedUtxoLookup {
        fn utxo_value(&self, _outpoint: &OutPoint) -> Option<u64> {
            Some(self.0)
        }
    }

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn make_test_tx(doc: &[u8], _fee: u64) -> Transaction {
        use noble_core::{NobleAddress, OutPoint, TxIn, TxOut};
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let checksum = sha256(doc);
        let addr = NobleAddress::Noble(noble_crypto::NoblePublicKey::Ed25519(pk.clone()));
        let prev_outpoint = OutPoint {
            txid: sha256(&pk),
            vout: 0,
        };
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn { prev_output: prev_outpoint }],
            outputs: vec![TxOut { value: 1_000_000, address: addr }],
            checksum,
            timestamp: now_secs(),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk,
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
        };
        let msg = tx
            .compute_signing_message_for_chain(test_chain_id())
            .unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn propose_empty_block() {
        let (val_priv, val_pub) = make_validator();
        let block = propose_block(
            &[],
            Hash256::ZERO,
            1,
            now_secs(),
            test_chain_id(),
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
            &FixedUtxoLookup(2_000_000),
        )
        .unwrap();

        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.tx_count, 1); // coinbase only
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].is_coinbase());
        assert_eq!(block.header.validator_id, val_pub);
    }

    #[test]
    fn propose_block_with_transactions() {
        let (val_priv, val_pub) = make_validator();
        let tx1 = make_test_tx(b"doc1", MIN_TX_FEE * 10);
        let tx2 = make_test_tx(b"doc2", MIN_TX_FEE * 5);
        let txs = vec![tx1, tx2];

        let block = propose_block(
            &txs,
            Hash256::ZERO,
            1,
            now_secs(),
            test_chain_id(),
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
            &FixedUtxoLookup(2_000_000),
        )
        .unwrap();

        assert_eq!(block.header.tx_count, 3); // coinbase + 2 user txs
        assert_eq!(block.transactions.len(), 3);
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn propose_block_respects_size_limit() {
        let (val_priv, val_pub) = make_validator();
        let tx1 = make_test_tx(b"doc1", MIN_TX_FEE * 10);
        let tx2 = make_test_tx(b"doc2", MIN_TX_FEE * 5);
        let txs = vec![tx1.clone(), tx2];

        // Set max_size to only fit one transaction
        let tx1_size = tx1.to_cbor().unwrap().len();
        let block = propose_block(
            &txs,
            Hash256::ZERO,
            1,
            now_secs(),
            test_chain_id(),
            &val_priv,
            &val_pub,
            tx1_size, // exactly one tx
            &FixedUtxoLookup(2_000_000),
        )
        .unwrap();

        // coinbase + 1 user tx (second didn't fit)
        assert_eq!(
            block.header.tx_count, 2,
            "should include coinbase + one user tx due to size limit"
        );
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn proposed_block_passes_validation() {
        let (val_priv, val_pub) = make_validator();
        let tx = make_test_tx(b"validated_doc", MIN_TX_FEE);

        let now = now_secs();
        let block = propose_block(
            &[tx],
            Hash256::ZERO,
            0,
            now,
            test_chain_id(),
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
            &FixedUtxoLookup(2_000_000),
        )
        .unwrap();

        let ctx = noble_core::BlockValidationContext {
            chain_id: test_chain_id(),
            current_time: now,
            parent: None,
            validator_list: &[val_pub],
        };
        assert!(noble_core::validate_block(&block, &ctx).is_ok());
    }
}
