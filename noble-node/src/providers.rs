// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Trait adapters connecting storage to network providers.
//!
//! These implementations bridge the `noble-storage::StorageEngine` trait to the
//! `noble-network::BlockProvider` / `TxProvider` traits, allowing the network
//! service to serve data from the shared storage backend.

use std::sync::Arc;


use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::Hash256;
use noble_mempool::Mempool;
use noble_network::{BlockProvider, TxProvider};
use noble_storage::StorageEngine;

use noble_api::lock_order::{TrackedMutex, TrackedRwLock};

/// Implements [`BlockProvider`] using an `Arc<RwLock<S>>` storage backend.
pub struct StorageBlockProvider<S: StorageEngine> {
    storage: Arc<TrackedRwLock<S>>,
    /// H6: memo for `total_transactions` — (height counted so far, running total).
    ///
    /// `GetStatus` is served on the peer event task and is answered for every
    /// peer every 60s, but the count was recomputed by walking EVERY block and
    /// reading EVERY header each time: O(chain length) per request, growing
    /// forever, and free for a peer to trigger. Steady state is now O(1); a new
    /// block costs only the headers actually added.
    tx_count_memo: std::sync::Mutex<(u64, u64)>,
}

impl<S: StorageEngine> StorageBlockProvider<S> {
    /// Create a new block provider wrapping the given storage.
    pub fn new(storage: Arc<TrackedRwLock<S>>) -> Self {
        Self { storage, tx_count_memo: std::sync::Mutex::new((0, 0)) }
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

    fn get_block_hash_by_height(&self, height: u64) -> Option<[u8; 32]> {
        let storage = self.storage.read();
        storage.get_block_hash_by_height(height).ok().map(|h| *h.as_bytes())
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

        let mut memo = match self.tx_count_memo.lock() {
            Ok(m) => m,
            // A poisoned memo is a cache problem, not a correctness one — fall
            // back to the honest full scan rather than propagating a panic.
            Err(poisoned) => poisoned.into_inner(),
        };
        let (counted_to, mut total) = *memo;

        // Rollback (or first call): the memo describes a chain that no longer
        // exists, so recount. Correctness first — this is the rare path.
        let start = if counted_to > tip.height || (counted_to == 0 && total == 0) {
            total = 0;
            0
        } else if counted_to == tip.height {
            return total; // steady state: nothing new
        } else {
            counted_to + 1
        };

        for h in start..=tip.height {
            if let Ok(hash) = storage.get_block_hash_by_height(h) {
                if let Ok(header) = storage.get_block_header(&hash) {
                    total += header.tx_count as u64;
                }
            }
        }
        *memo = (tip.height, total);
        total
    }

    fn avg_votes_per_block(&self) -> f32 {
        // Approximate: read last 100 blocks' vote counts from cycle history.
        // For now, return 0.0 — enriched once cycle history tracking is wired.
        0.0
    }

    fn get_block_votes(&self, height: u64) -> Option<Vec<u8>> {
        let storage = self.storage.read();
        match storage.get_block_votes(height) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("get_block_votes({height}) storage error: {e}");
                None
            }
        }
    }
}

/// Implements [`TxProvider`] using storage + mempool.
///
/// Searches the mempool first (pending txs), then committed storage.
/// This is critical for transaction relay: when a peer requests a tx
/// after receiving a `TxAnnounce`, the tx is typically still in the
/// mempool (not yet committed to a block).
pub struct StorageTxProvider<S: StorageEngine> {
    storage: Arc<TrackedRwLock<S>>,
    mempool: Arc<TrackedMutex<Mempool>>,
}

impl<S: StorageEngine> StorageTxProvider<S> {
    /// Create a new transaction provider wrapping storage and mempool.
    pub fn new(storage: Arc<TrackedRwLock<S>>, mempool: Arc<TrackedMutex<Mempool>>) -> Self {
        Self { storage, mempool }
    }
}

impl<S: StorageEngine + Send + Sync> TxProvider for StorageTxProvider<S> {
    fn get_transaction(&self, tx_id: &[u8; 32]) -> Option<Transaction> {
        let h = Hash256(*tx_id);
        // Check mempool first (pending txs not yet in a block).
        // LOCK ORDER: this mempool(5) block MUST stay closed before the
        // storage(2) read below — merging them is a 5→2 descending acquisition.
        // This runs on the network service thread, so an inversion here
        // collides cross-thread with the event loop's storage→mempool order.
        {
            let pool = self.mempool.lock();
            if let Some(entry) = pool.get(&h) {
                return Some(entry.tx.clone());
            }
        }
        // Fall back to committed storage.
        let storage = self.storage.read();
        storage.get_transaction(&h).ok()
    }

    fn has_transaction(&self, tx_id: &[u8; 32]) -> bool {
        let h = Hash256(*tx_id);
        // LOCK ORDER: same as get_transaction — mempool(5) block must close
        // before storage(2) is read.
        {
            let pool = self.mempool.lock();
            if pool.contains(&h) {
                return true;
            }
        }
        let storage = self.storage.read();
        storage.has_transaction(&h).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_api::lock_order::LockOrder;
    use noble_mempool::MempoolConfig;
    use noble_storage::MemoryStorage;

    fn test_mempool() -> Arc<TrackedMutex<Mempool>> {
        Arc::new(TrackedMutex::new(LockOrder::Mempool, Mempool::new(MempoolConfig::default())))
    }

    #[test]
    fn block_provider_empty_chain_tip() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        let (height, hash) = bp.chain_tip();
        assert_eq!(height, 0);
        assert_eq!(hash, [0; 32]);
    }

    #[test]
    fn block_provider_get_block_not_found() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        assert!(bp.get_block(&[0xFF; 32]).is_none());
    }

    #[test]
    fn block_provider_get_block_by_height_not_found() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        assert!(bp.get_block_by_height(999).is_none());
    }

    #[test]
    fn block_provider_get_block_header_not_found() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let bp = StorageBlockProvider::new(storage);
        assert!(bp.get_block_header(&[0xFF; 32]).is_none());
    }

    #[test]
    fn tx_provider_get_transaction_not_found() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let tp = StorageTxProvider::new(storage, test_mempool());
        assert!(tp.get_transaction(&[0xFF; 32]).is_none());
    }

    #[test]
    fn tx_provider_has_transaction_not_found() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let tp = StorageTxProvider::new(storage, test_mempool());
        assert!(!tp.has_transaction(&[0xFF; 32]));
    }

    #[test]
    fn block_provider_with_committed_block() {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));

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
