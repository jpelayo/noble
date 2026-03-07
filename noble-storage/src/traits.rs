// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! StorageEngine trait — the abstract interface for block/transaction persistence.
//!
//! All storage backends (RocksDB, in-memory mock) implement this trait.

use noble_core::{Block, BlockHeader, NobleAddress, PeerRecord, Transaction};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::StorageError;

/// Pending key rotation record: `(old_key_wire, new_key_wire, rotation_cycle)`.
pub type KeyRotationRecord = (Vec<u8>, Vec<u8>, u64);

/// Per-column-family size and key count estimates.
#[derive(Debug, Clone, Default)]
pub struct CfStats {
    pub name: String,
    pub estimated_bytes: u64,
    pub estimated_keys: u64,
}

/// Aggregated storage statistics across all column families.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    pub column_families: Vec<CfStats>,
}

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
    /// Accepts both native NOBLE public keys and Bitcoin-format addresses.
    fn get_balance(&self, address: &NobleAddress) -> Result<u64, StorageError>;

    /// Get paginated transaction history for an address.
    ///
    /// Returns tx_ids in chronological order (earliest first).
    /// `page` is 0-indexed, `limit` is the maximum number of entries per page.
    /// Accepts both native NOBLE public keys and Bitcoin-format addresses.
    fn get_address_history(
        &self,
        address: &NobleAddress,
        page: u32,
        limit: u32,
    ) -> Result<Vec<Hash256>, StorageError>;

    /// Count total transaction history entries for an address.
    ///
    /// More efficient than `get_address_history` with limit=0 for counting purposes.
    fn count_address_history(&self, address: &NobleAddress) -> Result<u64, StorageError>;

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

    /// Reset chain to genesis (height 0), removing all blocks above genesis.
    /// Unlike `rollback_to_height`, this bypasses the MAX_REORG_DEPTH safety limit.
    /// Used for fork recovery ("blockchain hop") when the node needs to re-sync.
    fn force_reset_to_genesis(&self, chain_id: u32) -> Result<ChainTip, StorageError>;

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

    // ── Version Chain ──

    /// Look up all tx_ids that are next-versions referencing a given prev_checksum.
    /// Returns empty vec if no successors exist.
    fn lookup_version_successors(
        &self,
        prev_checksum: &Hash256,
    ) -> Result<Vec<Hash256>, StorageError>;

    /// Check whether at least one notarization exists for this checksum on-chain.
    fn has_checksum(&self, checksum: &Hash256) -> Result<bool, StorageError> {
        self.lookup_checksum(checksum).map(|v| !v.is_empty())
    }

    // ── Publisher Index ──

    /// Look up all tx_ids published (notarizations) by a given public key.
    /// `pubkey_wire` is the wire-format key bytes ([scheme_id || raw_key]).
    /// Returns empty vec if no documents exist for this publisher.
    fn lookup_by_publisher(&self, pubkey_wire: &[u8]) -> Result<Vec<Hash256>, StorageError>;

    // ── Cycle History (H-002) ──

    /// Store a cycle history entry, keyed by cycle number.
    fn store_cycle_history(&self, cycle: u64, data: &[u8]) -> Result<(), StorageError>;

    /// Retrieve the most recent `count` cycle history entries (newest first).
    fn get_recent_cycle_history(&self, count: usize) -> Result<Vec<Vec<u8>>, StorageError>;

    /// Remove all cycle history entries. Used during bootstrap to clear stale
    /// data from previous runs that used a different cycle epoch.
    fn clear_cycle_history(&self) -> Result<(), StorageError> {
        Ok(()) // default no-op
    }

    // ── Finality State ──

    /// Store finality state (height, hash, cycle) in chain_state CF.
    fn store_finality_state(&self, data: &[u8]) -> Result<(), StorageError> {
        let _ = data;
        Ok(()) // default no-op for backends that don't support it
    }

    /// Load finality state from chain_state CF. Returns None if never stored.
    fn load_finality_state(&self) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None) // default no-op
    }

    // ── Per-Block Vote Witness ──

    /// Store per-block vote witness data, keyed by block height.
    /// Separate from cycle history — survives `clear_cycle_history`.
    fn store_block_votes(&self, height: u64, data: &[u8]) -> Result<(), StorageError>;

    /// Retrieve vote witness data for a specific block height.
    fn get_block_votes(&self, height: u64) -> Result<Option<Vec<u8>>, StorageError>;

    // ── Pruning Support ──

    /// Remove the block body (transactions) for a given block hash,
    /// but keep the header in place. Used by moderate pruning.
    fn prune_block_body(&self, _block_hash: &noble_crypto::Hash256) -> Result<(), StorageError> {
        Ok(()) // default no-op for backends that don't support pruning
    }

    /// Delete all data for a block at the given height: block body, header,
    /// and height→hash index. Used by aggressive pruning.
    fn delete_block_data(
        &self,
        _block_hash: &noble_crypto::Hash256,
        _height: u64,
    ) -> Result<(), StorageError> {
        Ok(()) // default no-op
    }

    /// Get the "pruned up to" marker — the highest height that has been pruned.
    /// Returns 0 if no pruning has occurred.
    fn get_pruning_marker(&self) -> Result<u64, StorageError> {
        Ok(0)
    }

    /// Set the "pruned up to" marker after a pruning pass.
    fn set_pruning_marker(&self, _height: u64) -> Result<(), StorageError> {
        Ok(())
    }

    /// Return per-column-family size and key count estimates.
    ///
    /// The default implementation returns empty stats (for backends that don't
    /// support introspection, e.g. `MemoryStorage`).
    fn get_storage_stats(&self) -> Result<StorageStats, StorageError> {
        Ok(StorageStats::default())
    }

    // ── Badge State ──

    /// Store a badge for a pubkey (CBOR-encoded VoteBadge).
    fn store_badge(&self, pubkey_wire: &[u8], badge_cbor: &[u8]) -> Result<(), StorageError> {
        let _ = (pubkey_wire, badge_cbor);
        Ok(()) // default no-op
    }

    /// Get a badge by pubkey wire bytes (returns CBOR bytes).
    fn get_badge(&self, pubkey_wire: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let _ = pubkey_wire;
        Ok(None) // default no-op
    }

    /// Remove a badge.
    fn remove_badge(&self, pubkey_wire: &[u8]) -> Result<(), StorageError> {
        let _ = pubkey_wire;
        Ok(()) // default no-op
    }

    /// List all badges: (pubkey_wire, cbor_bytes).
    fn list_badges(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Ok(Vec::new()) // default no-op
    }

    /// Store a badge proposal (keyed by proposal hash).
    fn store_badge_proposal(&self, proposal_hash: &[u8], proposal_cbor: &[u8]) -> Result<(), StorageError> {
        let _ = (proposal_hash, proposal_cbor);
        Ok(()) // default no-op
    }

    /// Get a badge proposal by hash.
    fn get_badge_proposal(&self, proposal_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let _ = proposal_hash;
        Ok(None) // default no-op
    }

    /// Remove a badge proposal.
    fn remove_badge_proposal(&self, proposal_hash: &[u8]) -> Result<(), StorageError> {
        let _ = proposal_hash;
        Ok(()) // default no-op
    }

    /// List all badge proposals: (proposal_hash, cbor_bytes).
    fn list_badge_proposals(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Ok(Vec::new()) // default no-op
    }

    // ── Evidence Storage ──

    /// Store misbehavior evidence, keyed by evidence hash (SHA-256 of CBOR).
    fn store_evidence(&self, evidence_hash: &[u8], evidence_cbor: &[u8]) -> Result<(), StorageError> {
        let _ = (evidence_hash, evidence_cbor);
        Ok(()) // default no-op
    }

    /// Get evidence by hash.
    fn get_evidence(&self, evidence_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let _ = evidence_hash;
        Ok(None)
    }

    /// List all stored evidence: (evidence_hash, cbor_bytes).
    fn list_evidence(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        Ok(Vec::new())
    }

    /// Close the database (for graceful shutdown). Subsequent calls should
    /// return `StorageError::NotOpen`.
    fn close(&mut self) -> Result<(), StorageError>;
}
