// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! StorageEngine trait — the abstract interface for block/transaction persistence.
//!
//! All storage backends (RocksDB, in-memory mock) implement this trait.

use noble_core::{Block, BlockHeader, PeerRecord, Transaction};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::StorageError;

/// Pending key rotation record: `(old_key_wire, new_key_wire, rotation_cycle)`.
pub type KeyRotationRecord = (Vec<u8>, Vec<u8>, u64);

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

    /// Get the block location of a confirmed transaction: (height, offset_in_block).
    fn get_transaction_location(&self, tx_id: &Hash256) -> Result<(u64, u32), StorageError>;

    /// Get the current chain tip, or None if the chain is empty (pre-genesis).
    fn get_chain_tip(&self) -> Result<Option<ChainTip>, StorageError>;

    /// Get the balance of an address in atomic units. Returns 0 for unknown addresses.
    fn get_balance(&self, pubkey: &NoblePublicKey) -> Result<u64, StorageError>;

    /// Get paginated transaction history for an address.
    ///
    /// Returns tx_ids in chronological order (earliest first).
    /// `page` is 0-indexed, `limit` is the maximum number of entries per page.
    fn get_address_history(
        &self,
        pubkey: &NoblePublicKey,
        page: u32,
        limit: u32,
    ) -> Result<Vec<Hash256>, StorageError>;

    /// Get the timestamps of the most recent `count` blocks (newest first).
    ///
    /// Used for median-of-11 timestamp validation (B13).
    fn get_recent_timestamps(&self, count: usize) -> Result<Vec<u64>, StorageError>;

    /// Store a peer ban (peer_id bytes → banned_until unix timestamp).
    fn store_ban(&self, peer_id: &[u8], banned_until: u64) -> Result<(), StorageError>;

    /// Remove a peer ban.
    fn remove_ban(&self, peer_id: &[u8]) -> Result<(), StorageError>;

    /// Load all persisted bans. Returns (peer_id_bytes, banned_until_unix).
    fn load_bans(&self) -> Result<Vec<(Vec<u8>, u64)>, StorageError>;

    /// Roll back the chain to a specific height, removing all blocks above it.
    /// Recalculates balances by replaying from genesis.
    /// Returns the new chain tip after rollback.
    fn rollback_to_height(
        &self,
        target_height: u64,
        chain_id: u32,
    ) -> Result<ChainTip, StorageError>;

    /// Store a pending key rotation.
    ///
    /// Key: old_key wire bytes, Value: CBOR(new_key_wire, rotation_cycle).
    fn store_key_rotation(
        &self,
        old_key: &NoblePublicKey,
        new_key: &NoblePublicKey,
        rotation_cycle: u64,
    ) -> Result<(), StorageError>;

    /// Remove a pending key rotation (after grace period expires).
    fn remove_key_rotation(&self, old_key: &NoblePublicKey) -> Result<(), StorageError>;

    /// Load all pending key rotations.
    fn load_key_rotations(&self) -> Result<Vec<KeyRotationRecord>, StorageError>;

    // ── Peer Memory ──

    /// Store or update a peer record, keyed by identity_key wire bytes.
    fn store_peer_record(&self, record: &PeerRecord) -> Result<(), StorageError>;

    /// Get a peer record by identity_key wire bytes.
    fn get_peer_record(&self, identity_key: &[u8]) -> Result<PeerRecord, StorageError>;

    /// List all stored peer records.
    fn list_peer_records(&self) -> Result<Vec<PeerRecord>, StorageError>;

    /// Remove a specific peer record by identity_key wire bytes.
    fn remove_peer_record(&self, identity_key: &[u8]) -> Result<(), StorageError>;

    /// Remove all peer records whose `last_seen` is older than `max_age_secs` from `now`.
    /// Returns the number of pruned records.
    fn prune_peer_records(&self, now: u64, max_age_secs: u64) -> Result<u32, StorageError>;

    /// Close the database (for graceful shutdown). Subsequent calls should
    /// return `StorageError::NotOpen`.
    fn close(&mut self) -> Result<(), StorageError>;
}
