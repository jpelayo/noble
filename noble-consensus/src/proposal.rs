// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Block proposal: select transactions from mempool and build a valid block.

use noble_codec::NobleCbor;
use noble_core::{compute_merkle_root, Block, BlockHeader, Transaction, PROTOCOL_VERSION};
use noble_crypto::{Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};

/// Propose a new block from a pre-sorted list of mempool transactions.
///
/// `mempool_txs` should already be sorted by fee descending (highest first).
/// Transactions are included until `max_size` is reached.
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
) -> Result<Block, String> {
    // Select transactions that fit within max_size
    let mut selected: Vec<Transaction> = Vec::new();
    let mut total_size: usize = 0;

    for tx in mempool_txs {
        let tx_bytes = tx
            .to_cbor()
            .map_err(|e| format!("failed to serialize tx: {e}"))?;
        if total_size + tx_bytes.len() > max_size {
            break;
        }
        total_size += tx_bytes.len();
        selected.push(tx.clone());
    }

    // Compute tx_ids and merkle root
    let tx_ids: Vec<Hash256> = selected
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
        tx_count: selected.len() as u32,
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
        transactions: selected,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{MAINNET_CHAIN_ID, MAX_BLOCK_SIZE, MIN_TX_FEE};
    use noble_crypto::{ed25519, sha256, NoblePrivateKey, NobleSigner, SCHEME_ED25519};

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn make_test_tx(doc: &[u8], fee: u64) -> Transaction {
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let checksum = sha256(doc);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum,
            timestamp: 1_700_000_000,
            fee,
            recipient: None,
            amount: None,
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
        };
        let msg = tx.compute_signing_message().unwrap();
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
            1_700_000_000,
            MAINNET_CHAIN_ID,
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
        )
        .unwrap();

        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.tx_count, 0);
        assert!(block.transactions.is_empty());
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
            1_700_000_000,
            MAINNET_CHAIN_ID,
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
        )
        .unwrap();

        assert_eq!(block.header.tx_count, 2);
        assert_eq!(block.transactions.len(), 2);
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
            1_700_000_000,
            MAINNET_CHAIN_ID,
            &val_priv,
            &val_pub,
            tx1_size, // exactly one tx
        )
        .unwrap();

        assert_eq!(
            block.header.tx_count, 1,
            "should only include one tx due to size limit"
        );
    }

    #[test]
    fn proposed_block_passes_validation() {
        let (val_priv, val_pub) = make_validator();
        let tx = make_test_tx(b"validated_doc", MIN_TX_FEE);

        let block = propose_block(
            &[tx],
            Hash256::ZERO,
            0,
            1_700_000_000,
            MAINNET_CHAIN_ID,
            &val_priv,
            &val_pub,
            MAX_BLOCK_SIZE,
        )
        .unwrap();

        let ctx = noble_core::BlockValidationContext {
            chain_id: MAINNET_CHAIN_ID,
            current_time: 1_700_000_000,
            parent: None,
            validator_list: &[val_pub],
        };
        assert!(noble_core::validate_block(&block, &ctx).is_ok());
    }
}
