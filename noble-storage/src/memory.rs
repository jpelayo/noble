// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory storage backend for testing.
//!
//! Implements `StorageEngine` with `HashMap`-based storage. Not suitable for
//! production use — data is lost when the process exits.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::Hash256;

use crate::error::StorageError;
use crate::traits::{ChainTip, StorageEngine};
use crate::MAX_CHECKSUM_REGISTRATIONS;

/// Shared inner state behind a RwLock for thread-safe testing.
#[derive(Default)]
struct Inner {
    blocks: HashMap<Hash256, Block>,
    block_heights: HashMap<u64, Hash256>,
    transactions: HashMap<Hash256, Transaction>,
    checksum_index: HashMap<Hash256, Vec<Hash256>>,
    chain_tip: Option<ChainTip>,
    closed: bool,
}

/// In-memory `StorageEngine` implementation for unit and integration tests.
///
/// Thread-safe via `Arc<RwLock>`. Clone is cheap (shared state).
#[derive(Clone, Default)]
pub struct MemoryStorage {
    inner: Arc<RwLock<Inner>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn check_open(inner: &Inner) -> Result<(), StorageError> {
        if inner.closed {
            return Err(StorageError::NotOpen);
        }
        Ok(())
    }
}

impl StorageEngine for MemoryStorage {
    fn commit_block(
        &self,
        block: &Block,
        block_hash: &Hash256,
        tx_ids: &[Hash256],
    ) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;

        // Store block
        inner.blocks.insert(*block_hash, block.clone());
        inner.block_heights.insert(block.header.height, *block_hash);

        // Store transactions and checksum index
        for (tx, tx_id) in block.transactions.iter().zip(tx_ids.iter()) {
            inner.transactions.insert(*tx_id, tx.clone());

            let entry = inner.checksum_index.entry(tx.checksum).or_default();
            if entry.len() >= MAX_CHECKSUM_REGISTRATIONS {
                return Err(StorageError::ChecksumIndexFull {
                    checksum: tx.checksum.to_string(),
                    count: entry.len(),
                    max: MAX_CHECKSUM_REGISTRATIONS,
                });
            }
            entry.push(*tx_id);
        }

        // Update chain tip
        inner.chain_tip = Some(ChainTip {
            block_hash: *block_hash,
            height: block.header.height,
        });

        Ok(())
    }

    fn get_block(&self, block_hash: &Hash256) -> Result<Block, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .blocks
            .get(block_hash)
            .cloned()
            .ok_or_else(|| StorageError::BlockNotFound(block_hash.to_string()))
    }

    fn get_block_header(&self, block_hash: &Hash256) -> Result<BlockHeader, StorageError> {
        self.get_block(block_hash).map(|b| b.header)
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Hash256, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .block_heights
            .get(&height)
            .copied()
            .ok_or_else(|| StorageError::BlockNotFound(format!("height {height}")))
    }

    fn get_transaction(&self, tx_id: &Hash256) -> Result<Transaction, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .transactions
            .get(tx_id)
            .cloned()
            .ok_or_else(|| StorageError::TransactionNotFound(tx_id.to_string()))
    }

    fn lookup_checksum(&self, checksum: &Hash256) -> Result<Vec<Hash256>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner
            .checksum_index
            .get(checksum)
            .cloned()
            .unwrap_or_default())
    }

    fn has_transaction(&self, tx_id: &Hash256) -> Result<bool, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.transactions.contains_key(tx_id))
    }

    fn get_chain_tip(&self) -> Result<Option<ChainTip>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.chain_tip.clone())
    }

    fn close(&mut self) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        inner.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{Block, BlockHeader, Transaction, MAINNET_CHAIN_ID, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };

    fn make_signed_tx(sk: &[u8], pk: &[u8], doc: &[u8], timestamp: u64) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            checksum,
            timestamp,
            fee: 1_000,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    fn make_block(
        txs: Vec<(Transaction, Hash256)>,
        height: u64,
        prev_hash: Hash256,
        timestamp: u64,
    ) -> (Block, Hash256, Vec<Hash256>) {
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let val_priv = NoblePrivateKey::Ed25519(val_sk);
        let val_pub = NoblePublicKey::Ed25519(val_pk.clone());

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
            validator_id: val_pub,
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: val_pk,
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();

        let block_hash = header.compute_block_hash().unwrap();
        let block = Block {
            header,
            transactions,
        };
        (block, block_hash, tx_ids)
    }

    #[test]
    fn empty_store_has_no_tip() {
        let store = MemoryStorage::new();
        assert!(store.get_chain_tip().unwrap().is_none());
    }

    #[test]
    fn commit_and_retrieve_block() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx.clone(), tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        store.commit_block(&block, &block_hash, &tx_ids).unwrap();

        // Retrieve block
        let got = store.get_block(&block_hash).unwrap();
        assert_eq!(got, block);

        // Retrieve header
        let header = store.get_block_header(&block_hash).unwrap();
        assert_eq!(header, block.header);

        // Retrieve by height
        let hash = store.get_block_hash_by_height(0).unwrap();
        assert_eq!(hash, block_hash);
    }

    #[test]
    fn commit_and_retrieve_transaction() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx.clone(), tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        store.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let got = store.get_transaction(&tx_id).unwrap();
        assert_eq!(got, tx);
        assert!(store.has_transaction(&tx_id).unwrap());
    }

    #[test]
    fn checksum_lookup() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Two different txs registering the same document
        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_000);
        let (tx2, tx_id2) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_001);

        let (block, block_hash, tx_ids) = make_block(
            vec![(tx1.clone(), tx_id1), (tx2.clone(), tx_id2)],
            0,
            Hash256::ZERO,
            1_700_000_001,
        );

        store.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let checksum = sha256(b"same_doc");
        let results = store.lookup_checksum(&checksum).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&tx_id1));
        assert!(results.contains(&tx_id2));
    }

    #[test]
    fn checksum_lookup_empty() {
        let store = MemoryStorage::new();
        let missing = Hash256::from_bytes([0xFF; 32]);
        let results = store.lookup_checksum(&missing).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn chain_tip_updates() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0
        let (tx0, tx_id0) = make_signed_tx(&sk, &pk, b"doc0", 1_700_000_000);
        let (block0, hash0, ids0) =
            make_block(vec![(tx0, tx_id0)], 0, Hash256::ZERO, 1_700_000_000);
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let tip = store.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash0);
        assert_eq!(tip.height, 0);

        // Block 1
        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) = make_block(vec![(tx1, tx_id1)], 1, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let tip = store.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash1);
        assert_eq!(tip.height, 1);
    }

    #[test]
    fn not_found_errors() {
        let store = MemoryStorage::new();
        let missing = Hash256::from_bytes([0xFF; 32]);

        assert!(matches!(
            store.get_block(&missing),
            Err(StorageError::BlockNotFound(_))
        ));
        assert!(matches!(
            store.get_transaction(&missing),
            Err(StorageError::TransactionNotFound(_))
        ));
        assert!(matches!(
            store.get_block_hash_by_height(999),
            Err(StorageError::BlockNotFound(_))
        ));
        assert!(!store.has_transaction(&missing).unwrap());
    }

    #[test]
    fn closed_store_rejects_operations() {
        let mut store = MemoryStorage::new();
        store.close().unwrap();

        let missing = Hash256::ZERO;
        assert!(matches!(
            store.get_block(&missing),
            Err(StorageError::NotOpen)
        ));
        assert!(matches!(store.get_chain_tip(), Err(StorageError::NotOpen)));
    }
}
