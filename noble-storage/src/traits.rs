// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! StorageEngine trait — the abstract interface for block/transaction persistence.
//!
//! All storage backends (RocksDB, in-memory mock) implement this trait.

use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::Hash256;

use crate::error::StorageError;

/// Chain tip metadata persisted in the `chain_state` column family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainTip {
    /// Hash of the current tip block.
    pub block_hash: Hash256,
    /// Height of the current tip block.
    pub height: u64,
}

/// Abstract storage interface for the NOBLE blockchain.
///
/// Implementors must guarantee that `commit_block` is atomic — either all
/// updates for a block (block data, indexes, chain state) succeed together,
/// or none are visible.
pub trait StorageEngine {
    /// Atomically commit a block and all its indexes.
    ///
    /// This writes the block to the `blocks` CF, updates the `block_hashes`
    /// height→hash index, inserts all transactions into `tx_index`, appends
    /// checksum registrations to `checksum_index`, and updates `chain_state`.
    fn commit_block(
        &self,
        block: &Block,
        block_hash: &Hash256,
        tx_ids: &[Hash256],
    ) -> Result<(), StorageError>;

    /// Retrieve a full block by its hash.
    fn get_block(&self, block_hash: &Hash256) -> Result<Block, StorageError>;

    /// Retrieve only the block header by its hash.
    fn get_block_header(&self, block_hash: &Hash256) -> Result<BlockHeader, StorageError>;

    /// Retrieve a block hash by height.
    fn get_block_hash_by_height(&self, height: u64) -> Result<Hash256, StorageError>;

    /// Retrieve a transaction by its tx_id.
    fn get_transaction(&self, tx_id: &Hash256) -> Result<Transaction, StorageError>;

    /// Look up all transaction IDs that registered a given document checksum.
    fn lookup_checksum(&self, checksum: &Hash256) -> Result<Vec<Hash256>, StorageError>;

    /// Check whether a transaction exists in the store.
    fn has_transaction(&self, tx_id: &Hash256) -> Result<bool, StorageError>;

    /// Get the current chain tip, or None if the chain is empty (pre-genesis).
    fn get_chain_tip(&self) -> Result<Option<ChainTip>, StorageError>;

    /// Close the database (for graceful shutdown). Subsequent calls should
    /// return `StorageError::NotOpen`.
    fn close(&mut self) -> Result<(), StorageError>;
}
