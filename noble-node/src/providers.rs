// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Trait adapters connecting storage to network providers.
//!
//! These implementations bridge the `noble-storage::StorageEngine` trait to the
//! `noble-network::BlockProvider` / `TxProvider` traits, allowing the network
//! service to serve data from the shared storage backend.

use std::sync::Arc;

use parking_lot::RwLock;

use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::Hash256;
use noble_network::{BlockProvider, TxProvider};
use noble_storage::StorageEngine;

/// Implements [`BlockProvider`] using an `Arc<RwLock<S>>` storage backend.
pub struct StorageBlockProvider<S: StorageEngine> {
    storage: Arc<RwLock<S>>,
}

impl<S: StorageEngine> StorageBlockProvider<S> {
    /// Create a new block provider wrapping the given storage.
    pub fn new(storage: Arc<RwLock<S>>) -> Self {
        Self { storage }
    }
}

impl<S: StorageEngine + Send + Sync> BlockProvider for StorageBlockProvider<S> {
    fn get_block(&self, hash: &[u8; 32]) -> Option<Block> {
        let h = Hash256(*hash);
        let storage = self.storage.read();
        storage.get_block(&h).ok()
    }

    fn get_block_by_height(&self, height: u64) -> Option<Block> {
        let storage = self.storage.read();
        let hash = storage.get_block_hash_by_height(height).ok()?;
        storage.get_block(&hash).ok()
    }

    fn get_block_header(&self, hash: &[u8; 32]) -> Option<BlockHeader> {
        let h = Hash256(*hash);
        let storage = self.storage.read();
        storage.get_block_header(&h).ok()
    }

    fn chain_tip(&self) -> (u64, [u8; 32]) {
        let storage = self.storage.read();
        storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|tip| (tip.height, *tip.block_hash.as_bytes()))
            .unwrap_or((0, [0; 32]))
    }

    fn total_transactions(&self) -> u64 {
        let storage = self.storage.read();
        let tip = match storage.get_chain_tip().ok().flatten() {
            Some(t) => t,
            None => return 0,
        };
        let mut total: u64 = 0;
        for h in 0..=tip.height {
            if let Ok(hash) = storage.get_block_hash_by_height(h) {
                if let Ok(header) = storage.get_block_header(&hash) {
                    total += header.tx_count as u64;
                }
            }
        }
        total
    }

    fn avg_votes_per_block(&self) -> f32 {
        // Approximate: read last 100 blocks' vote counts from cycle history.
        // For now, return 0.0 — enriched once cycle history tracking is wired.
        0.0
    }
}

/// Implements [`TxProvider`] using an `Arc<RwLock<S>>` storage backend.
pub struct StorageTxProvider<S: StorageEngine> {
    storage: Arc<RwLock<S>>,
}

impl<S: StorageEngine> StorageTxProvider<S> {
    /// Create a new transaction provider wrapping the given storage.
    pub fn new(storage: Arc<RwLock<S>>) -> Self {
        Self { storage }
    }
}

impl<S: StorageEngine + Send + Sync> TxProvider for StorageTxProvider<S> {
    fn get_transaction(&self, tx_id: &[u8; 32]) -> Option<Transaction> {
        let h = Hash256(*tx_id);
        let storage = self.storage.read();
        storage.get_transaction(&h).ok()
    }

    fn has_transaction(&self, tx_id: &[u8; 32]) -> bool {
        let h = Hash256(*tx_id);
        let storage = self.storage.read();
        storage.has_transaction(&h).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_storage::MemoryStorage;

    #[test]
    fn block_provider_empty_chain_tip() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        let (height, hash) = bp.chain_tip();
        assert_eq!(height, 0);
        assert_eq!(hash, [0; 32]);
    }

    #[test]
    fn block_provider_get_block_not_found() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        assert!(bp.get_block(&[0xFF; 32]).is_none());
    }

    #[test]
    fn block_provider_get_block_by_height_not_found() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        assert!(bp.get_block_by_height(999).is_none());
    }

    #[test]
    fn block_provider_get_block_header_not_found() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        assert!(bp.get_block_header(&[0xFF; 32]).is_none());
    }

    #[test]
    fn tx_provider_get_transaction_not_found() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let tp = StorageTxProvider::new(storage);
        assert!(tp.get_transaction(&[0xFF; 32]).is_none());
    }

    #[test]
    fn tx_provider_has_transaction_not_found() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let tp = StorageTxProvider::new(storage);
        assert!(!tp.has_transaction(&[0xFF; 32]));
    }

    #[test]
    fn block_provider_with_committed_block() {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));

        // Commit genesis block.
        let genesis = noble_test_utils::fixtures::test_genesis_block();
        let block_hash = genesis.header.compute_block_hash().unwrap();
        let tx_ids: Vec<Hash256> = genesis
            .transactions
            .iter()
            .filter_map(|tx| tx.compute_tx_id(noble_test_utils::fixtures::test_chain_id()).ok())
            .collect();
        {
            let s = storage.read();
            s.commit_block(&genesis, &block_hash, &tx_ids).unwrap();
        }

        let bp = StorageBlockProvider::new(storage);

        // Chain tip should reflect genesis.
        let (height, tip_hash) = bp.chain_tip();
        assert_eq!(height, 0);
        assert_eq!(tip_hash, *block_hash.as_bytes());

        // Get block by hash should return genesis.
        let block = bp.get_block(block_hash.as_bytes()).unwrap();
        assert_eq!(block.header.height, 0);

        // Get block by height should also work.
        let block = bp.get_block_by_height(0).unwrap();
        assert_eq!(block.header.height, 0);

        // Get header should work.
        let header = bp.get_block_header(block_hash.as_bytes()).unwrap();
        assert_eq!(header.height, 0);
    }
}
