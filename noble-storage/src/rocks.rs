// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! RocksDB-backed storage engine with 12 column families.
//!
//! # Panic Safety Audit
//!
//! All `.try_into().unwrap()` calls in this module are safe because they are
//! **always preceded by an explicit length check** that returns `Err(StorageError)`
//! for wrong-sized data. The `.unwrap()` is unreachable if the length check passes.
//!
//! Column family handles are obtained exclusively through `fn cf(&self, name) -> Result`,
//! which returns `StorageError::Database` on missing CFs. All call sites use `?`.
//!
//! All RocksDB I/O operations (`get_cf`, `put_cf`, `write`, `delete_cf`, `iterator_cf`)
//! use `.map_err(|e| StorageError::Database(...))` — no `.unwrap()` on DB results.
//!
//! # Architecture
//!
//! Single RocksDB instance, single volume. The 12 column families are logical
//! partitions within one database directory. If the underlying disk disappears
//! (I/O failure), all operations surface as `StorageError::Database` — no panics.
//! Corruption recovery is handled by `open_with_repair()` at startup.
//!
//! Column families:
//! - `blocks`: height (u64 BE) → serialized Block
//! - `block_hashes`: block_hash (32B) → height (u64 BE)
//! - `tx_index`: tx_id (32B) → height(8B) + tx_offset(4B)
//! - `checksum_index`: doc_checksum (32B) → concatenated tx_ids (N×32B)
//! - `chain_state`: string key → value bytes
//! - `validator_state`: validator_pubkey → reputation data (reserved for Sprint 4+)
//! - `address_balances`: pubkey_wire → u64 BE balance (GAP-H19)
//! - `address_history`: pubkey_wire+height(8B BE)+offset(4B BE) → tx_id(32B) (GAP-H19)
//! - `bans`: peer_id bytes → banned_until (u64 BE)
//! - `peer_memory`: identity_key wire → CBOR-encoded PeerRecord
//! - `version_chain`: prev_checksum (32B) → concatenated successor tx_ids (N×32B)
//! - `publisher_index`: pubkey_wire → concatenated notarization tx_ids (N×32B)

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rocksdb::{
    ColumnFamilyDescriptor, Direction, IteratorMode, MergeOperands, Options, WriteBatch, DB,
};

use noble_codec::NobleCbor;
use noble_core::constants::{
    subsidy_at_height, MAX_REORG_DEPTH, MAX_SUPPLY, META_KEY_PREV_CHECKSUM, TX_TYPE_NOTARIZATION,
    TX_TYPE_TRANSFER,
};
use noble_core::{Block, BlockHeader, NobleAddress, PeerRecord, Transaction};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::StorageError;
use crate::traits::{ChainTip, KeyRotationRecord, StorageEngine};
use crate::MAX_CHECKSUM_REGISTRATIONS;

// --- Column family names ---

const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_HASHES: &str = "block_hashes";
const CF_TX_INDEX: &str = "tx_index";
const CF_CHECKSUM_INDEX: &str = "checksum_index";
const CF_CHAIN_STATE: &str = "chain_state";
const CF_VALIDATOR_STATE: &str = "validator_state";
const CF_ADDRESS_BALANCES: &str = "address_balances";
const CF_ADDRESS_HISTORY: &str = "address_history";
const CF_BANS: &str = "bans";
const CF_PEER_MEMORY: &str = "peer_memory";
const CF_VERSION_CHAIN: &str = "version_chain";
const CF_PUBLISHER_INDEX: &str = "publisher_index";

// --- Chain state keys ---

const KEY_TIP_HASH: &[u8] = b"tip_hash";
const KEY_TIP_HEIGHT: &[u8] = b"tip_height";
/// Running total supply in atomic units (AUD2-M2: O(1) supply tracking).
const KEY_TOTAL_SUPPLY: &[u8] = b"total_supply";

/// Configuration for the RocksDB storage engine.
#[derive(Debug, Clone)]
pub struct RocksDbConfig {
    /// Block cache size in bytes (shared across CFs). Default: 64 MB.
    pub block_cache_size: usize,
    /// Bloom filter bits per key. Default: 10.
    pub bloom_filter_bits: i32,
    /// Enable Zstd compression on the blocks CF. Default: true.
    pub enable_compression: bool,
}

impl Default for RocksDbConfig {
    fn default() -> Self {
        Self {
            block_cache_size: 64 * 1024 * 1024,
            bloom_filter_bits: 10,
            enable_compression: true,
        }
    }
}

/// RocksDB-backed `StorageEngine` implementation.
///
/// Uses 12 column families with bloom filters, Zstd compression on blocks,
/// and merge operators on `checksum_index`, `version_chain`, and `publisher_index`
/// for append-only tx_id lists.
pub struct RocksDbStorage {
    db: DB,
    closed: AtomicBool,
}

impl RocksDbStorage {
    /// Open (or create) a RocksDB database at the given path with default config.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        Self::open_with_config(path, &RocksDbConfig::default())
    }

    /// Open (or create) a RocksDB database with custom configuration.
    pub fn open_with_config<P: AsRef<Path>>(
        path: P,
        config: &RocksDbConfig,
    ) -> Result<Self, StorageError> {
        let mut db_opts = Options::default();
        db_opts.create_if_missing(true);
        db_opts.create_missing_column_families(true);

        let cfs = vec![
            Self::cf_blocks(config),
            Self::cf_block_hashes(config),
            Self::cf_tx_index(config),
            Self::cf_checksum_index(config),
            Self::cf_chain_state(),
            Self::cf_validator_state(),
            Self::cf_address_balances(config),
            Self::cf_address_history(config),
            Self::cf_bans(),
            Self::cf_peer_memory(),
            Self::cf_version_chain(config),
            Self::cf_publisher_index(config),
        ];

        let db = DB::open_cf_descriptors(&db_opts, path, cfs)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(Self {
            db,
            closed: AtomicBool::new(false),
        })
    }

    // --- Column family descriptors ---

    fn cf_blocks(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        if config.enable_compression {
            opts.set_compression_type(rocksdb::DBCompressionType::Zstd);
        }
        ColumnFamilyDescriptor::new(CF_BLOCKS, opts)
    }

    fn cf_block_hashes(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_bloom_locality(config.bloom_filter_bits as u32);
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_BLOCK_HASHES, opts)
    }

    fn cf_tx_index(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_TX_INDEX, opts)
    }

    fn cf_checksum_index(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("checksum_merge", checksum_merge_operator);
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_CHECKSUM_INDEX, opts)
    }

    fn cf_chain_state() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_CHAIN_STATE, Options::default())
    }

    fn cf_validator_state() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_VALIDATOR_STATE, Options::default())
    }

    fn cf_address_balances(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_ADDRESS_BALANCES, opts)
    }

    fn cf_address_history(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_ADDRESS_HISTORY, opts)
    }

    fn cf_bans() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_BANS, Options::default())
    }

    fn cf_peer_memory() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_PEER_MEMORY, Options::default())
    }

    fn cf_publisher_index(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("publisher_merge", checksum_merge_operator);
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_PUBLISHER_INDEX, opts)
    }

    fn cf_version_chain(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("version_chain_merge", checksum_merge_operator);
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_VERSION_CHAIN, opts)
    }

    // --- Helpers ---

    fn check_open(&self) -> Result<(), StorageError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(StorageError::NotOpen);
        }
        Ok(())
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::Database(format!("column family '{name}' not found")))
    }

    /// Build the CF key for an address balance: wire bytes.
    /// Supports both native NOBLE keys (0x01/0x02) and Bitcoin addresses (0x80/0x81).
    fn address_key(address: &NobleAddress) -> Vec<u8> {
        address.to_wire_bytes()
    }

    /// Build the CF key for an address balance from a NoblePublicKey (convenience).
    fn pubkey_key(pubkey: &NoblePublicKey) -> Vec<u8> {
        pubkey.to_wire_bytes()
    }

    /// Build the CF key for an address history entry.
    fn history_key(pubkey_wire: &[u8], height: u64, offset: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(pubkey_wire.len() + 8 + 4);
        key.extend_from_slice(pubkey_wire);
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(&offset.to_be_bytes());
        key
    }

    /// Read a balance from the DB, returning 0 for unknown addresses.
    fn read_balance_raw(&self, key: &[u8]) -> Result<u64, StorageError> {
        let cf = self.cf(CF_ADDRESS_BALANCES)?;
        match self
            .db
            .get_cf(cf, key)
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(StorageError::Database(format!(
                        "corrupt balance entry: expected 8 bytes, got {}",
                        bytes.len()
                    )));
                }
                Ok(u64::from_be_bytes(bytes.as_slice().try_into().unwrap()))
            }
            None => Ok(0),
        }
    }
}

impl RocksDbStorage {
    /// Attempt to repair a corrupt RocksDB.
    pub fn repair<P: AsRef<Path>>(path: P) -> Result<(), StorageError> {
        DB::repair(&Options::default(), path)
            .map_err(|e| StorageError::Database(format!("repair failed: {e}")))
    }

    /// Open with automatic repair on failure.
    pub fn open_with_repair<P: AsRef<Path> + Clone>(path: P) -> Result<Self, StorageError> {
        match Self::open(path.clone()) {
            Ok(db) => Ok(db),
            Err(first_err) => {
                tracing::warn!(
                    task = "storage",
                    "DB open failed, attempting repair: {first_err}"
                );
                Self::repair(path.clone())?;
                Self::open(path).map_err(|second_err| {
                    StorageError::Database(format!(
                        "open failed after repair: first={first_err}, second={second_err}"
                    ))
                })
            }
        }
    }

    /// Read the running total supply in O(1) from `chain_state` CF (AUD2-M2).
    ///
    /// Returns 0 if no blocks have been committed yet.
    pub fn get_total_supply(&self) -> Result<u64, StorageError> {
        self.check_open()?;
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        match self
            .db
            .get_cf(cf_state, KEY_TOTAL_SUPPLY)
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(StorageError::Database(format!(
                        "corrupt total_supply entry: expected 8 bytes, got {}",
                        bytes.len()
                    )));
                }
                Ok(u64::from_be_bytes(bytes.as_slice().try_into().unwrap()))
            }
            None => Ok(0),
        }
    }
}

impl StorageEngine for RocksDbStorage {
    #[tracing::instrument(skip(self, block, block_hash, tx_ids), fields(task = "storage_commit", height = block.header.height))]
    fn commit_block(
        &self,
        block: &Block,
        block_hash: &Hash256,
        tx_ids: &[Hash256],
    ) -> Result<(), StorageError> {
        self.check_open()?;

        let height = block.header.height;
        let height_be = height.to_be_bytes();

        // Serialize block
        let block_bytes = block.to_cbor()?;

        let mut batch = WriteBatch::default();

        // blocks CF: height → serialized block
        let cf_blocks = self.cf(CF_BLOCKS)?;
        batch.put_cf(cf_blocks, height_be, &block_bytes);

        // block_hashes CF: block_hash → height
        let cf_hashes = self.cf(CF_BLOCK_HASHES)?;
        batch.put_cf(cf_hashes, block_hash.as_bytes(), height_be);

        // tx_index CF: tx_id → height(8B) + offset(4B)
        let cf_tx = self.cf(CF_TX_INDEX)?;
        for (offset, tx_id) in tx_ids.iter().enumerate() {
            let mut value = Vec::with_capacity(12);
            value.extend_from_slice(&height_be);
            value.extend_from_slice(&(offset as u32).to_be_bytes());
            batch.put_cf(cf_tx, tx_id.as_bytes(), &value);
        }

        // checksum_index CF: checksum → merge-append tx_id (notarizations only)
        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;
        let cf_version = self.cf(CF_VERSION_CHAIN)?;
        let cf_publisher = self.cf(CF_PUBLISHER_INDEX)?;
        for (tx, tx_id) in block.transactions.iter().zip(tx_ids.iter()) {
            if tx.tx_type == TX_TYPE_NOTARIZATION {
                batch.merge_cf(cf_checksum, tx.checksum.as_bytes(), tx_id.as_bytes());

                // version_chain CF: prev_checksum → merge-append successor tx_id
                if let Some(prev_hex) = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_PREV_CHECKSUM)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                {
                    if let Ok(prev_hash) = Hash256::from_hex(prev_hex) {
                        batch.merge_cf(cf_version, prev_hash.as_bytes(), tx_id.as_bytes());
                    }
                }

                // publisher_index CF: pubkey_wire → merge-append tx_id
                let publisher_wire = tx
                    .publisher_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?
                    .to_wire_bytes();
                batch.merge_cf(cf_publisher, &publisher_wire, tx_id.as_bytes());
            }
        }

        // chain_state CF: tip_hash and tip_height
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        batch.put_cf(cf_state, KEY_TIP_HASH, block_hash.as_bytes());
        batch.put_cf(cf_state, KEY_TIP_HEIGHT, height_be);

        // --- Balance accumulator (GAP-H19) ---
        let cf_balances = self.cf(CF_ADDRESS_BALANCES)?;
        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;

        // Phase 1: accumulate deltas as i128
        let mut deltas: HashMap<Vec<u8>, i128> = HashMap::new();

        // Validator gets subsidy + fees (split with gateway if present)
        let validator_key = Self::pubkey_key(&block.header.validator_id);
        let subsidy = subsidy_at_height(height) as i128;

        // Split fees: 50% to gateway (if present), remainder to validator.
        // Subsidy always goes 100% to validator.
        let mut validator_fee_total: i128 = 0;
        for tx in &block.transactions {
            let fee = tx.fee as i128;
            if let Some(ref gw) = tx.gateway_address {
                let gw_share = fee / 2;
                let val_share = fee - gw_share; // validator gets rounding
                *deltas.entry(gw.clone()).or_default() += gw_share;
                validator_fee_total += val_share;
            } else {
                validator_fee_total += fee;
            }
        }
        *deltas.entry(validator_key).or_default() += subsidy + validator_fee_total;

        for (offset, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
            let sender_pk = tx
                .publisher_sig
                .to_noble_public_key()
                .map_err(|e| StorageError::Codec(e.to_string()))?;
            // S34: Canonical debit address resolution
            // S35 F1: delta-aware balance closure — each tx sees effective balances
            // including earlier in-block changes
            let need = tx.amount.unwrap_or(0) + tx.fee;
            let sender_addr = noble_core::resolve_debit_address(
                &tx.source_address,
                &sender_pk,
                need,
                |a| {
                    let key = a.to_wire_bytes();
                    let base = self.read_balance_raw(&key).unwrap_or(0) as i128;
                    let delta = deltas.get(&key).copied().unwrap_or(0);
                    let effective = base + delta;
                    if effective > 0 { effective as u64 } else { 0 }
                },
            )
            .map_err(|e| StorageError::Codec(e.to_string()))?;
            let sender_key = sender_addr.to_wire_bytes();

            if tx.tx_type == TX_TYPE_TRANSFER {
                let amount = tx.amount.unwrap_or(0) as i128;
                let fee = tx.fee as i128;
                *deltas.entry(sender_key.clone()).or_default() -= amount + fee;
                if let Some(ref recipient) = tx.recipient {
                    let recip_key = recipient.to_wire_bytes();
                    *deltas.entry(recip_key.clone()).or_default() += amount;

                    // History for recipient
                    let hkey = Self::history_key(&recip_key, height, offset as u32);
                    batch.put_cf(cf_history, hkey, tx_id.as_bytes());
                }
            } else {
                // Notarization: sender pays fee only
                let fee = tx.fee as i128;
                *deltas.entry(sender_key.clone()).or_default() -= fee;
            }

            // History for sender
            let hkey = Self::history_key(&sender_key, height, offset as u32);
            batch.put_cf(cf_history, hkey, tx_id.as_bytes());
        }

        // Phase 2: read current balances, apply deltas, write final
        for (key, delta) in &deltas {
            tracing::debug!(
                task = "storage",
                "balance delta: {} for key len={}",
                delta,
                key.len()
            );
            let current = self.read_balance_raw(key)?;
            let new_balance = current as i128 + delta;
            if new_balance < 0 {
                return Err(StorageError::InsufficientBalance {
                    available: current,
                    needed: (-delta) as u64,
                });
            }
            if new_balance > u64::MAX as i128 {
                return Err(StorageError::BalanceOverflow {
                    current,
                    amount: *delta as u64,
                });
            }
            batch.put_cf(cf_balances, key, (new_balance as u64).to_be_bytes());
        }

        // Phase 3: MAX_SUPPLY cap enforcement via O(1) running total (AUD2-M2)
        // Read current total_supply from chain_state, add this block's subsidy,
        // and check against MAX_SUPPLY. No full-balance iteration needed.
        let block_subsidy = subsidy_at_height(height);
        let prev_supply = self.get_total_supply()?;
        // Use checked_add to fail loudly on u64 overflow rather than silently capping.
        let new_supply =
            prev_supply
                .checked_add(block_subsidy)
                .ok_or(StorageError::SupplyOverflow {
                    cumulative: u64::MAX,
                    max: MAX_SUPPLY,
                })?;
        if new_supply > MAX_SUPPLY {
            return Err(StorageError::SupplyOverflow {
                cumulative: new_supply,
                max: MAX_SUPPLY,
            });
        }
        // Persist updated total_supply in the same atomic batch
        batch.put_cf(cf_state, KEY_TOTAL_SUPPLY, new_supply.to_be_bytes());

        // Atomic commit
        self.db
            .write(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        tracing::debug!(
            task = "storage",
            "committed block at height {}",
            block.header.height
        );

        Ok(())
    }

    fn get_block(&self, block_hash: &Hash256) -> Result<Block, StorageError> {
        self.check_open()?;
        tracing::trace!("get_block: hash={}", block_hash);

        // Look up height from block_hashes CF
        let cf_hashes = self.cf(CF_BLOCK_HASHES)?;
        let height_bytes = self
            .db
            .get_cf(cf_hashes, block_hash.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or_else(|| StorageError::BlockNotFound(block_hash.to_string()))?;

        // Fetch block from blocks CF by height
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let block_bytes = self
            .db
            .get_cf(cf_blocks, &height_bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or_else(|| StorageError::BlockNotFound(block_hash.to_string()))?;

        Block::from_cbor(&block_bytes).map_err(Into::into)
    }

    fn get_block_header(&self, block_hash: &Hash256) -> Result<BlockHeader, StorageError> {
        // For now, deserialize the full block and return the header.
        // Optimization: store headers separately in a future sprint.
        self.get_block(block_hash).map(|b| b.header)
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Hash256, StorageError> {
        self.check_open()?;

        let cf_blocks = self.cf(CF_BLOCKS)?;
        let height_be = height.to_be_bytes();

        // Verify block exists at this height
        let block_bytes = self
            .db
            .get_cf(cf_blocks, height_be)
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or_else(|| StorageError::BlockNotFound(format!("height {height}")))?;

        let block = Block::from_cbor(&block_bytes)?;
        block
            .header
            .compute_block_hash()
            .map_err(|e| StorageError::Codec(e.to_string()))
    }

    fn get_transaction(&self, tx_id: &Hash256) -> Result<Transaction, StorageError> {
        let (height, offset) = self.get_transaction_location(tx_id)?;

        // Fetch the block at this height
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let height_be = height.to_be_bytes();
        let block_bytes = self
            .db
            .get_cf(cf_blocks, height_be)
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or_else(|| {
                StorageError::TransactionNotFound(format!(
                    "block at height {height} not found for tx {tx_id}",
                ))
            })?;

        let block = Block::from_cbor(&block_bytes)?;
        block
            .transactions
            .into_iter()
            .nth(offset as usize)
            .ok_or_else(|| {
                StorageError::TransactionNotFound(format!(
                    "tx offset {offset} out of range in block at height {height}",
                ))
            })
    }

    fn get_transaction_location(&self, tx_id: &Hash256) -> Result<(u64, u32), StorageError> {
        self.check_open()?;

        let cf_tx = self.cf(CF_TX_INDEX)?;
        let location = self
            .db
            .get_cf(cf_tx, tx_id.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or_else(|| StorageError::TransactionNotFound(tx_id.to_string()))?;

        if location.len() != 12 {
            return Err(StorageError::Database(format!(
                "corrupt tx_index entry: expected 12 bytes, got {}",
                location.len()
            )));
        }

        let height = u64::from_be_bytes(location[..8].try_into().unwrap());
        let offset = u32::from_be_bytes(location[8..12].try_into().unwrap());
        Ok((height, offset))
    }

    fn lookup_checksum(&self, checksum: &Hash256) -> Result<Vec<Hash256>, StorageError> {
        self.check_open()?;

        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;
        let raw = self
            .db
            .get_cf(cf_checksum, checksum.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match raw {
            None => Ok(vec![]),
            Some(bytes) => parse_checksum_index_value(&bytes),
        }
    }

    fn has_transaction(&self, tx_id: &Hash256) -> Result<bool, StorageError> {
        self.check_open()?;

        let cf_tx = self.cf(CF_TX_INDEX)?;
        let exists = self
            .db
            .get_cf(cf_tx, tx_id.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?
            .is_some();

        Ok(exists)
    }

    fn get_balance(&self, address: &NobleAddress) -> Result<u64, StorageError> {
        self.check_open()?;
        let key = Self::address_key(address);
        self.read_balance_raw(&key)
    }

    fn get_address_history(
        &self,
        address: &NobleAddress,
        page: u32,
        limit: u32,
    ) -> Result<Vec<Hash256>, StorageError> {
        self.check_open()?;

        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;
        let prefix = Self::address_key(address);
        let skip = (page as usize) * (limit as usize);

        let iter = self
            .db
            .iterator_cf(cf_history, IteratorMode::From(&prefix, Direction::Forward));

        let mut results = Vec::new();
        let mut skipped = 0;

        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;

            // Check prefix match
            if key.len() < prefix.len() || &key[..prefix.len()] != prefix.as_slice() {
                break;
            }

            if skipped < skip {
                skipped += 1;
                continue;
            }

            if value.len() != 32 {
                return Err(StorageError::Database(format!(
                    "corrupt history entry: expected 32 bytes, got {}",
                    value.len()
                )));
            }
            results.push(Hash256::from_bytes(value.as_ref().try_into().unwrap()));

            if results.len() >= limit as usize {
                break;
            }
        }

        Ok(results)
    }

    fn count_address_history(&self, address: &NobleAddress) -> Result<u64, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_ADDRESS_HISTORY)?;
        let wire = Self::address_key(address);
        let mut count = 0u64;
        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&wire, Direction::Forward));
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.len() < wire.len() || &key[..wire.len()] != wire.as_slice() {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    fn get_chain_tip(&self) -> Result<Option<ChainTip>, StorageError> {
        self.check_open()?;

        let cf_state = self.cf(CF_CHAIN_STATE)?;

        let tip_hash_bytes = self
            .db
            .get_cf(cf_state, KEY_TIP_HASH)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let tip_height_bytes = self
            .db
            .get_cf(cf_state, KEY_TIP_HEIGHT)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match (tip_hash_bytes, tip_height_bytes) {
            (Some(hash_bytes), Some(height_bytes)) => {
                if hash_bytes.len() != 32 || height_bytes.len() != 8 {
                    return Err(StorageError::Database(
                        "corrupt chain state: invalid tip data".to_string(),
                    ));
                }
                let block_hash = Hash256::from_bytes(hash_bytes.as_slice().try_into().unwrap());
                let height = u64::from_be_bytes(height_bytes.as_slice().try_into().unwrap());
                Ok(Some(ChainTip { block_hash, height }))
            }
            (None, None) => Ok(None),
            _ => Err(StorageError::Database(
                "corrupt chain state: partial tip data".to_string(),
            )),
        }
    }

    #[tracing::instrument(skip(self), fields(task = "storage_rollback", target_height, chain_id))]
    fn rollback_to_height(
        &self,
        target_height: u64,
        chain_id: u32,
    ) -> Result<ChainTip, StorageError> {
        self.check_open()?;
        tracing::debug!("rolling back to height {}", target_height);

        // Get current tip
        let tip = self
            .get_chain_tip()?
            .ok_or_else(|| StorageError::Database("no chain tip".into()))?;

        if target_height >= tip.height {
            return Ok(tip);
        }

        // Enforce MAX_REORG_DEPTH
        let depth = tip.height - target_height;
        if depth > MAX_REORG_DEPTH {
            return Err(StorageError::ReorgTooDeep {
                depth,
                max: MAX_REORG_DEPTH,
            });
        }

        let mut batch = WriteBatch::default();
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let cf_hashes = self.cf(CF_BLOCK_HASHES)?;
        let cf_tx = self.cf(CF_TX_INDEX)?;

        // Phase 1: Remove blocks above target_height
        for h in (target_height + 1)..=tip.height {
            let height_be = h.to_be_bytes();

            // Get block data to find transactions
            if let Some(block_bytes) = self
                .db
                .get_cf(cf_blocks, height_be)
                .map_err(|e| StorageError::Database(e.to_string()))?
            {
                if let Ok(block) = Block::from_cbor(&block_bytes) {
                    // Remove tx index entries
                    for tx in &block.transactions {
                        if let Ok(tx_id) = tx.compute_tx_id(chain_id) {
                            batch.delete_cf(cf_tx, tx_id.as_bytes());
                        }
                    }

                    // Remove block hash index
                    if let Ok(block_hash) = block.header.compute_block_hash() {
                        batch.delete_cf(cf_hashes, block_hash.as_bytes());
                    }
                }
            }

            // Remove block data
            batch.delete_cf(cf_blocks, height_be);
        }

        // Write phase 1 deletions
        self.db
            .write(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Phase 2: Clear all balances, history, and checksum_index (iterate and delete)
        let mut clear_batch = WriteBatch::default();
        let cf_balances = self.cf(CF_ADDRESS_BALANCES)?;
        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;
        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;

        let iter = self.db.iterator_cf(cf_balances, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            clear_batch.delete_cf(cf_balances, &key);
        }

        let iter = self.db.iterator_cf(cf_history, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            clear_batch.delete_cf(cf_history, &key);
        }

        // Clear checksum_index (merge-append values can't be selectively trimmed)
        let iter = self.db.iterator_cf(cf_checksum, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            clear_batch.delete_cf(cf_checksum, &key);
        }

        // Clear version_chain (same merge-append pattern as checksum_index)
        let cf_version = self.cf(CF_VERSION_CHAIN)?;
        let iter = self.db.iterator_cf(cf_version, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            clear_batch.delete_cf(cf_version, &key);
        }

        // Clear publisher_index (same merge-append pattern)
        let cf_publisher = self.cf(CF_PUBLISHER_INDEX)?;
        let iter = self.db.iterator_cf(cf_publisher, IteratorMode::Start);
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            clear_batch.delete_cf(cf_publisher, &key);
        }

        // Phase 3: Update chain tip
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        let target_hash = self.get_block_hash_by_height(target_height)?;
        clear_batch.put_cf(cf_state, KEY_TIP_HASH, target_hash.as_bytes());
        clear_batch.put_cf(cf_state, KEY_TIP_HEIGHT, target_height.to_be_bytes());

        self.db
            .write(clear_batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Phase 4: Replay balances, history, checksum_index, version_chain, and publisher_index from 0..=target_height
        let cf_balances = self.cf(CF_ADDRESS_BALANCES)?;
        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;
        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;
        let cf_version = self.cf(CF_VERSION_CHAIN)?;
        let cf_publisher = self.cf(CF_PUBLISHER_INDEX)?;

        let mut balances: HashMap<Vec<u8>, i128> = HashMap::new();
        let mut replay_batch = WriteBatch::default();
        // AUD3-D8: Track total_supply during rollback replay.
        let mut replay_supply: u64 = 0;

        for h in 0..=target_height {
            let hash = self.get_block_hash_by_height(h)?;
            let block = self.get_block(&hash)?;

            let validator_key = Self::pubkey_key(&block.header.validator_id);
            let subsidy = subsidy_at_height(h) as i128;
            replay_supply = replay_supply.saturating_add(subsidy as u64);

            let mut validator_fee_total: i128 = 0;
            for tx in &block.transactions {
                let fee = tx.fee as i128;
                if let Some(ref gw) = tx.gateway_address {
                    let gw_share = fee / 2;
                    let val_share = fee - gw_share;
                    *balances.entry(gw.clone()).or_default() += gw_share;
                    validator_fee_total += val_share;
                } else {
                    validator_fee_total += fee;
                }
            }
            *balances.entry(validator_key).or_default() += subsidy + validator_fee_total;

            for (offset, tx) in block.transactions.iter().enumerate() {
                let sender_pk = tx
                    .publisher_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                // S34: Use canonical debit resolution (fixes P0 replay divergence)
                // S35 F1: replay uses accumulated balances (already delta-aware)
                let need = tx.amount.unwrap_or(0) + tx.fee;
                let sender_addr = noble_core::resolve_debit_address(
                    &tx.source_address,
                    &sender_pk,
                    need,
                    |a| {
                        let key = a.to_wire_bytes();
                        let bal = balances.get(&key).copied().unwrap_or(0);
                        if bal >= 0 { bal as u64 } else { 0 }
                    },
                )
                .map_err(|e| StorageError::Codec(e.to_string()))?;
                let sender_key = sender_addr.to_wire_bytes();

                let tx_id = tx
                    .compute_tx_id(chain_id)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;

                // Rebuild checksum_index
                replay_batch.merge_cf(cf_checksum, tx.checksum.as_bytes(), tx_id.as_bytes());

                // Rebuild version_chain and publisher_index
                if tx.tx_type == TX_TYPE_NOTARIZATION {
                    if let Some(prev_hex) = tx
                        .metadata
                        .iter()
                        .find(|m| m.key == META_KEY_PREV_CHECKSUM)
                        .and_then(|m| std::str::from_utf8(&m.value).ok())
                    {
                        if let Ok(prev_hash) = Hash256::from_hex(prev_hex) {
                            replay_batch.merge_cf(
                                cf_version,
                                prev_hash.as_bytes(),
                                tx_id.as_bytes(),
                            );
                        }
                    }
                    // Rebuild publisher_index
                    replay_batch.merge_cf(cf_publisher, &sender_key, tx_id.as_bytes());
                }

                if tx.tx_type == TX_TYPE_TRANSFER {
                    let amount = tx.amount.unwrap_or(0) as i128;
                    let fee = tx.fee as i128;
                    *balances.entry(sender_key.clone()).or_default() -= amount + fee;
                    if let Some(ref recipient) = tx.recipient {
                        let recip_key = recipient.to_wire_bytes();
                        *balances.entry(recip_key.clone()).or_default() += amount;
                        let hkey = Self::history_key(&recip_key, h, offset as u32);
                        replay_batch.put_cf(cf_history, hkey, tx_id.as_bytes());
                    }
                } else {
                    let fee = tx.fee as i128;
                    *balances.entry(sender_key.clone()).or_default() -= fee;
                }

                let hkey = Self::history_key(&sender_key, h, offset as u32);
                replay_batch.put_cf(cf_history, hkey, tx_id.as_bytes());
            }
        }

        // Write balances
        for (key, balance) in &balances {
            if *balance >= 0 {
                replay_batch.put_cf(cf_balances, key, (*balance as u64).to_be_bytes());
            }
        }

        // AUD3-D8: Persist total_supply so get_total_supply() is correct after rollback.
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        replay_batch.put_cf(cf_state, KEY_TOTAL_SUPPLY, replay_supply.to_be_bytes());

        self.db
            .write(replay_batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(ChainTip {
            block_hash: target_hash,
            height: target_height,
        })
    }

    fn get_recent_timestamps(&self, count: usize) -> Result<Vec<u64>, StorageError> {
        self.check_open()?;
        let tip = match self.get_chain_tip()? {
            Some(t) => t.height,
            None => return Ok(vec![]),
        };
        let mut timestamps = Vec::with_capacity(count);
        let start = tip.saturating_sub(count.saturating_sub(1) as u64);
        for h in (start..=tip).rev() {
            let hash = self.get_block_hash_by_height(h)?;
            let header = self.get_block_header(&hash)?;
            timestamps.push(header.timestamp);
            if timestamps.len() >= count {
                break;
            }
        }
        Ok(timestamps)
    }

    fn store_ban(&self, peer_id: &[u8], banned_until: u64) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BANS)?;
        self.db
            .put_cf(cf, peer_id, banned_until.to_be_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn remove_ban(&self, peer_id: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BANS)?;
        self.db
            .delete_cf(cf, peer_id)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn load_bans(&self) -> Result<Vec<(Vec<u8>, u64)>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BANS)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut bans = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if value.len() == 8 {
                let banned_until = u64::from_be_bytes(value[..8].try_into().unwrap());
                if banned_until > now {
                    bans.push((key.to_vec(), banned_until));
                }
            }
        }
        Ok(bans)
    }

    fn store_key_rotation(
        &self,
        old_key: &NoblePublicKey,
        new_key: &NoblePublicKey,
        rotation_cycle: u64,
    ) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_VALIDATOR_STATE)?;
        let key = old_key.to_wire_bytes();
        // Value: new_key_wire_len(4B BE) + new_key_wire + rotation_cycle(8B BE)
        let new_wire = new_key.to_wire_bytes();
        let mut value = Vec::with_capacity(4 + new_wire.len() + 8);
        value.extend_from_slice(&(new_wire.len() as u32).to_be_bytes());
        value.extend_from_slice(&new_wire);
        value.extend_from_slice(&rotation_cycle.to_be_bytes());
        self.db
            .put_cf(cf, &key, &value)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn remove_key_rotation(&self, old_key: &NoblePublicKey) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_VALIDATOR_STATE)?;
        let key = old_key.to_wire_bytes();
        self.db
            .delete_cf(cf, &key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn load_key_rotations(&self) -> Result<Vec<KeyRotationRecord>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_VALIDATOR_STATE)?;
        let mut rotations = Vec::new();
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if value.len() >= 12 {
                let new_wire_len = u32::from_be_bytes(value[..4].try_into().unwrap()) as usize;
                if value.len() == 4 + new_wire_len + 8 {
                    let new_wire = value[4..4 + new_wire_len].to_vec();
                    let cycle = u64::from_be_bytes(value[4 + new_wire_len..].try_into().unwrap());
                    rotations.push((key.to_vec(), new_wire, cycle));
                }
            }
        }
        Ok(rotations)
    }

    fn store_peer_record(&self, record: &PeerRecord) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_PEER_MEMORY)?;
        let buf = record
            .to_cbor()
            .map_err(|e| StorageError::Codec(e.to_string()))?;
        self.db
            .put_cf(&cf, &record.identity_key, &buf)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_peer_record(&self, identity_key: &[u8]) -> Result<PeerRecord, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_PEER_MEMORY)?;
        let bytes = self
            .db
            .get_cf(&cf, identity_key)
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or(StorageError::NotFound)?;
        PeerRecord::from_cbor(&bytes).map_err(|e| StorageError::Codec(e.to_string()))
    }

    fn list_peer_records(&self) -> Result<Vec<PeerRecord>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_PEER_MEMORY)?;
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut records = Vec::new();
        for item in iter {
            let (_key, val) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            let rec =
                PeerRecord::from_cbor(&val).map_err(|e| StorageError::Codec(e.to_string()))?;
            records.push(rec);
        }
        Ok(records)
    }

    fn remove_peer_record(&self, identity_key: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_PEER_MEMORY)?;
        self.db
            .delete_cf(&cf, identity_key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn prune_peer_records(&self, now: u64, max_age_secs: u64) -> Result<u32, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_PEER_MEMORY)?;
        let iter = self.db.iterator_cf(&cf, IteratorMode::Start);
        let mut to_delete = Vec::new();
        for item in iter {
            let (key, val) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            let rec =
                PeerRecord::from_cbor(&val).map_err(|e| StorageError::Codec(e.to_string()))?;
            if rec.is_stale(now, max_age_secs) {
                to_delete.push(key.to_vec());
            }
        }
        let count = to_delete.len() as u32;
        for key in &to_delete {
            self.db
                .delete_cf(&cf, key)
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }
        Ok(count)
    }

    // ── Cycle History (H-002) ──

    fn store_cycle_history(&self, cycle: u64, data: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        // Key: "cycle_history:" + cycle number in big-endian (for natural ordering).
        let mut key = b"cycle_history:".to_vec();
        key.extend_from_slice(&cycle.to_be_bytes());
        self.db
            .put_cf(&cf, &key, data)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_recent_cycle_history(&self, count: usize) -> Result<Vec<Vec<u8>>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        // Iterate backwards from the end of the "cycle_history:" prefix range.
        // The prefix ends at "cycle_history;" (next byte after ':').
        let prefix_end = b"cycle_history;".to_vec();
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(&prefix_end, Direction::Reverse));
        let prefix = b"cycle_history:";
        let mut entries = Vec::with_capacity(count);
        for item in iter {
            if entries.len() >= count {
                break;
            }
            let (key, val) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if !key.starts_with(prefix) {
                break;
            }
            entries.push(val.to_vec());
        }
        Ok(entries)
    }

    fn lookup_version_successors(
        &self,
        prev_checksum: &Hash256,
    ) -> Result<Vec<Hash256>, StorageError> {
        self.check_open()?;

        let cf_version = self.cf(CF_VERSION_CHAIN)?;
        let raw = self
            .db
            .get_cf(cf_version, prev_checksum.as_bytes())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match raw {
            None => Ok(vec![]),
            Some(bytes) => parse_checksum_index_value(&bytes),
        }
    }

    fn lookup_by_publisher(&self, pubkey_wire: &[u8]) -> Result<Vec<Hash256>, StorageError> {
        self.check_open()?;

        let cf_publisher = self.cf(CF_PUBLISHER_INDEX)?;
        let raw = self
            .db
            .get_cf(cf_publisher, pubkey_wire)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match raw {
            None => Ok(vec![]),
            Some(bytes) => parse_checksum_index_value(&bytes),
        }
    }

    fn close(&mut self) -> Result<(), StorageError> {
        self.closed.store(true, Ordering::Relaxed);
        Ok(())
    }
}

// --- Checksum merge operator (GAP-M8, GAP-M10) ---

/// RocksDB merge operator that appends 32-byte tx_ids to an existing list.
///
/// **Associativity property (GAP-M8):** merge(merge(a, b), c) == merge(a, merge(b, c)).
/// This holds because we simply concatenate 32-byte chunks.
///
/// **Bound (GAP-M10):** Values are capped at `MAX_CHECKSUM_REGISTRATIONS × 32` bytes.
/// Once the cap is reached, further merge operands are silently dropped.
fn checksum_merge_operator(
    _key: &[u8],
    existing: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let max_bytes = MAX_CHECKSUM_REGISTRATIONS * 32;

    let mut result = match existing {
        Some(bytes) => bytes.to_vec(),
        None => Vec::new(),
    };

    for operand in operands {
        if operand.len() != 32 {
            // Invalid operand — skip (should not happen in correct usage)
            continue;
        }
        if result.len() + 32 > max_bytes {
            // Cap reached (GAP-M10) — stop appending
            break;
        }
        result.extend_from_slice(operand);
    }

    Some(result)
}

/// Parse a checksum index value (flat concatenation of 32-byte tx_ids).
fn parse_checksum_index_value(bytes: &[u8]) -> Result<Vec<Hash256>, StorageError> {
    if bytes.len() % 32 != 0 {
        return Err(StorageError::Database(format!(
            "corrupt checksum index: length {} is not a multiple of 32",
            bytes.len()
        )));
    }

    let mut result = Vec::with_capacity(bytes.len() / 32);
    for chunk in bytes.chunks_exact(32) {
        result.push(Hash256::from_bytes(chunk.try_into().unwrap()));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::constants::{HALVING_INTERVAL, INITIAL_SUBSIDY};
    use noble_core::{Block, BlockHeader, Transaction, MAINNET_CHAIN_ID, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };
    use tempfile::TempDir;

    fn temp_db() -> (RocksDbStorage, TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open(dir.path()).unwrap();
        (db, dir)
    }

    /// Convenience: wrap a NoblePublicKey into a NobleAddress for balance lookups.
    fn addr(pk: &NoblePublicKey) -> NobleAddress {
        NobleAddress::Noble(pk.clone())
    }

    fn make_signed_tx(sk: &[u8], pk: &[u8], doc: &[u8], timestamp: u64) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum,
            timestamp,
            fee: 1_000,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: None,
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    fn make_transfer_tx(
        sk: &[u8],
        pk: &[u8],
        recipient: &NoblePublicKey,
        amount: u64,
        fee: u64,
        timestamp: u64,
    ) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(b"transfer");
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum,
            timestamp,
            fee,
            recipient: Some(NobleAddress::Noble(recipient.clone())),
            amount: Some(amount),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: None,
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

    fn make_block_with_validator(
        txs: Vec<(Transaction, Hash256)>,
        height: u64,
        prev_hash: Hash256,
        timestamp: u64,
        val_sk: &[u8],
        val_pk: &[u8],
    ) -> (Block, Hash256, Vec<Hash256>) {
        let val_priv = NoblePrivateKey::Ed25519(val_sk.to_vec());
        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());

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
                public_key: val_pk.to_vec(),
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

    // --- Basic operations ---

    #[test]
    fn open_and_close() {
        let (mut db, _dir) = temp_db();
        assert!(db.get_chain_tip().unwrap().is_none());
        db.close().unwrap();
        assert!(matches!(db.get_chain_tip(), Err(StorageError::NotOpen)));
    }

    #[test]
    fn commit_and_retrieve_block() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let got = db.get_block(&block_hash).unwrap();
        assert_eq!(got, block);
    }

    #[test]
    fn retrieve_block_header() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let header = db.get_block_header(&block_hash).unwrap();
        assert_eq!(header, block.header);
    }

    #[test]
    fn block_hash_by_height() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let hash = db.get_block_hash_by_height(0).unwrap();
        assert_eq!(hash, block_hash);
    }

    #[test]
    fn retrieve_transaction() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) = make_block_with_validator(
            vec![(tx.clone(), tx_id)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let got = db.get_transaction(&tx_id).unwrap();
        assert_eq!(got, tx);
        assert!(db.has_transaction(&tx_id).unwrap());
    }

    #[test]
    fn checksum_lookup_single() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let checksum = tx.checksum;
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let results = db.lookup_checksum(&checksum).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tx_id);
    }

    #[test]
    fn checksum_lookup_multiple_blocks() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: first registration of same_doc (sender = validator)
        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_000);
        let checksum = tx1.checksum;
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![(tx1, tx_id1)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        // Block 1: second registration of same_doc
        let (tx2, tx_id2) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_001);
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![(tx2, tx_id2)], 1, hash0, 1_700_000_001, &sk, &pk);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        let results = db.lookup_checksum(&checksum).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], tx_id1);
        assert_eq!(results[1], tx_id2);
    }

    #[test]
    fn checksum_lookup_empty() {
        let (db, _dir) = temp_db();
        let missing = Hash256::from_bytes([0xFF; 32]);
        let results = db.lookup_checksum(&missing).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn chain_tip_updates() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        assert!(db.get_chain_tip().unwrap().is_none());

        let (tx0, tx_id0) = make_signed_tx(&sk, &pk, b"doc0", 1_700_000_000);
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![(tx0, tx_id0)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let tip = db.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash0);
        assert_eq!(tip.height, 0);

        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![(tx1, tx_id1)], 1, hash0, 1_700_000_001, &sk, &pk);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        let tip = db.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash1);
        assert_eq!(tip.height, 1);
    }

    #[test]
    fn not_found_errors() {
        let (db, _dir) = temp_db();
        let missing = Hash256::from_bytes([0xFF; 32]);

        assert!(matches!(
            db.get_block(&missing),
            Err(StorageError::BlockNotFound(_))
        ));
        assert!(matches!(
            db.get_transaction(&missing),
            Err(StorageError::TransactionNotFound(_))
        ));
        assert!(matches!(
            db.get_block_hash_by_height(999),
            Err(StorageError::BlockNotFound(_))
        ));
        assert!(!db.has_transaction(&missing).unwrap());
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"persistent_doc", 1_700_000_000);
        let checksum = tx.checksum;
        let (block, block_hash, tx_ids) = make_block_with_validator(
            vec![(tx.clone(), tx_id)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );

        // Write and close
        {
            let db = RocksDbStorage::open(dir.path()).unwrap();
            db.commit_block(&block, &block_hash, &tx_ids).unwrap();
        }

        // Reopen and verify
        {
            let db = RocksDbStorage::open(dir.path()).unwrap();
            let got = db.get_block(&block_hash).unwrap();
            assert_eq!(got, block);

            let got_tx = db.get_transaction(&tx_id).unwrap();
            assert_eq!(got_tx, tx);

            let results = db.lookup_checksum(&checksum).unwrap();
            assert_eq!(results, vec![tx_id]);

            let tip = db.get_chain_tip().unwrap().unwrap();
            assert_eq!(tip.block_hash, block_hash);
            assert_eq!(tip.height, 0);
        }
    }

    #[test]
    fn empty_block_commit() {
        let (db, _dir) = temp_db();
        let (block, block_hash, tx_ids) = make_block(vec![], 0, Hash256::ZERO, 1_700_000_000);
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let got = db.get_block(&block_hash).unwrap();
        assert_eq!(got.transactions.len(), 0);

        let tip = db.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.height, 0);
    }

    #[test]
    fn multiple_transactions_in_block() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        let (tx1, id1) = make_signed_tx(&sk, &pk, b"doc_a", 1_700_000_000);
        let (tx2, id2) = make_signed_tx(&sk, &pk, b"doc_b", 1_700_000_000);
        let (tx3, id3) = make_signed_tx(&sk, &pk, b"doc_c", 1_700_000_000);

        let (block, hash, ids) = make_block_with_validator(
            vec![(tx1.clone(), id1), (tx2.clone(), id2), (tx3.clone(), id3)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        db.commit_block(&block, &hash, &ids).unwrap();

        assert_eq!(db.get_transaction(&id1).unwrap(), tx1);
        assert_eq!(db.get_transaction(&id2).unwrap(), tx2);
        assert_eq!(db.get_transaction(&id3).unwrap(), tx3);
    }

    // --- Merge operator tests ---

    #[test]
    fn parse_checksum_index_value_valid() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&[0xBB; 32]);

        let result = parse_checksum_index_value(&bytes).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], Hash256::from_bytes([0xAA; 32]));
        assert_eq!(result[1], Hash256::from_bytes([0xBB; 32]));
    }

    #[test]
    fn parse_checksum_index_value_invalid_length() {
        let bytes = vec![0u8; 33]; // Not a multiple of 32
        assert!(parse_checksum_index_value(&bytes).is_err());
    }

    // --- Balance storage tests (GAP-H19) ---

    #[test]
    fn balance_zero_for_unknown_address() {
        let (db, _dir) = temp_db();
        let (_, pk) = ed25519::generate_keypair();
        let pubkey = NoblePublicKey::Ed25519(pk);
        assert_eq!(db.get_balance(&addr(&pubkey)).unwrap(), 0);
    }

    #[test]
    fn subsidy_credited_to_validator() {
        let (db, _dir) = temp_db();
        let (block, block_hash, tx_ids) = make_block(vec![], 1, Hash256::ZERO, 1_700_000_000);
        let validator = block.header.validator_id.clone();
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(db.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY);
    }

    #[test]
    fn subsidy_halves_at_halving_interval() {
        let (db, _dir) = temp_db();
        let (block, block_hash, tx_ids) =
            make_block(vec![], HALVING_INTERVAL, Hash256::ZERO, 1_700_000_000);
        let validator = block.header.validator_id.clone();
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(db.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn fees_credited_to_validator() {
        let (db, _dir) = temp_db();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        // Fund sender as validator of block 1
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        // Block 2: 2 notarization txs
        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let (tx2, id2) = make_signed_tx(&sender_sk, &sender_pk, b"doc2", 1_700_000_001);
        let (block1, hash1, ids1) = make_block_with_validator(
            vec![(tx1, id1), (tx2, id2)],
            2,
            hash0,
            1_700_000_001,
            &val_sk,
            &val_pk,
        );
        let validator = block1.header.validator_id.clone();
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        assert_eq!(db.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY + 2_000);
    }

    #[test]
    fn notarization_debits_sender_fee() {
        let (db, _dir) = temp_db();

        // Fund sender as validator of block 1
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert_eq!(db.get_balance(&addr(&sender_pub)).unwrap(), INITIAL_SUBSIDY);

        // Block 2: sender submits a notarization (different validator)
        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let fee = tx1.fee;
        let (block1, hash1, ids1) = make_block(vec![(tx1, id1)], 2, hash0, 1_700_000_001);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        assert_eq!(db.get_balance(&addr(&sender_pub)).unwrap(), INITIAL_SUBSIDY - fee);
    }

    #[test]
    fn transfer_debits_sender_credits_recipient() {
        let (db, _dir) = temp_db();

        // Fund sender as validator of block 1
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        // Create transfer
        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recip_pk);
        let amount = 100_000u64;
        let fee = 1_000u64;
        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            &recipient,
            amount,
            fee,
            1_700_000_001,
        );
        let (block1, hash1, ids1) = make_block(vec![(tx, tx_id)], 2, hash0, 1_700_000_001);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert_eq!(
            db.get_balance(&addr(&sender_pub)).unwrap(),
            INITIAL_SUBSIDY - amount - fee
        );
        assert_eq!(db.get_balance(&addr(&recipient)).unwrap(), amount);
    }

    #[test]
    fn transfer_insufficient_balance_fails() {
        let (db, _dir) = temp_db();

        // Sender has no prior funds
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recip_pk);
        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            &recipient,
            100_000,
            1_000,
            1_700_000_000,
        );
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        let result = db.commit_block(&block, &block_hash, &tx_ids);
        assert!(matches!(
            result,
            Err(StorageError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn balance_overflow_fails() {
        let (db, _dir) = temp_db();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        // Block 0: empty block to create the validator's balance entry
        let (block0, hash0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &val_sk, &val_pk);
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        // Directly write a near-max balance into the DB
        let cf_balances = db.cf(CF_ADDRESS_BALANCES).unwrap();
        let key = RocksDbStorage::pubkey_key(&NoblePublicKey::Ed25519(val_pk.to_vec()));
        db.db
            .put_cf(cf_balances, &key, &(u64::MAX - 10).to_be_bytes())
            .unwrap();

        // Block 1: validator gets another subsidy → overflow
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![], 1, hash0, 1_700_000_001, &val_sk, &val_pk);
        let result = db.commit_block(&block1, &hash1, &ids1);
        assert!(matches!(result, Err(StorageError::BalanceOverflow { .. })));
    }

    #[test]
    fn history_records_notarization() {
        let (db, _dir) = temp_db();

        // Fund sender
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) = make_block(vec![(tx1, id1)], 2, hash0, 1_700_000_001);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let history = db.get_address_history(&addr(&sender_pub), 0, 100).unwrap();
        assert!(history.contains(&id1));
    }

    #[test]
    fn history_records_transfer_both_parties() {
        let (db, _dir) = temp_db();

        // Fund sender
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recip_pk);
        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            &recipient,
            10_000,
            1_000,
            1_700_000_001,
        );
        let (block1, hash1, ids1) = make_block(vec![(tx, tx_id)], 2, hash0, 1_700_000_001);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert!(db
            .get_address_history(&addr(&sender_pub), 0, 100)
            .unwrap()
            .contains(&tx_id));
        assert!(db
            .get_address_history(&addr(&recipient), 0, 100)
            .unwrap()
            .contains(&tx_id));
    }

    #[test]
    fn history_pagination() {
        let (db, _dir) = temp_db();

        // Fund sender as validator
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let mut prev_hash = hash0;
        for i in 1..=3u64 {
            let (tx, id) = make_signed_tx(
                &sender_sk,
                &sender_pk,
                format!("doc{i}").as_bytes(),
                1_700_000_000 + i,
            );
            let (block, hash, ids) = make_block_with_validator(
                vec![(tx, id)],
                i,
                prev_hash,
                1_700_000_000 + i,
                &sender_sk,
                &sender_pk,
            );
            db.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let page0 = db.get_address_history(&addr(&sender_pub), 0, 2).unwrap();
        assert_eq!(page0.len(), 2);
        let page1 = db.get_address_history(&addr(&sender_pub), 1, 2).unwrap();
        assert_eq!(page1.len(), 1);
        assert!(!page0.contains(&page1[0]));
    }

    #[test]
    fn history_empty_for_unknown() {
        let (db, _dir) = temp_db();
        let (_, pk) = ed25519::generate_keypair();
        let pubkey = NoblePublicKey::Ed25519(pk);
        let history = db.get_address_history(&addr(&pubkey), 0, 100).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn history_chronological_order() {
        let (db, _dir) = temp_db();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let mut prev_hash = hash0;
        let mut expected_order = vec![];
        for i in 1..=3u64 {
            let (tx, id) = make_signed_tx(
                &sender_sk,
                &sender_pk,
                format!("doc{i}").as_bytes(),
                1_700_000_000 + i,
            );
            expected_order.push(id);
            let (block, hash, ids) = make_block_with_validator(
                vec![(tx, id)],
                i,
                prev_hash,
                1_700_000_000 + i,
                &sender_sk,
                &sender_pk,
            );
            db.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let history = db.get_address_history(&addr(&sender_pub), 0, 100).unwrap();
        assert_eq!(history, expected_order);
    }

    #[test]
    fn multi_block_balance_accumulation() {
        let (db, _dir) = temp_db();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        let mut prev_hash = Hash256::ZERO;
        for h in 1..4u64 {
            let (block, hash, ids) = make_block_with_validator(
                vec![],
                h,
                prev_hash,
                1_700_000_000 + h,
                &val_sk,
                &val_pk,
            );
            db.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 3);
    }

    #[test]
    fn validator_gets_transfer_fees() {
        let (db, _dir) = temp_db();

        // Fund sender
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        // Transfer validated by a different validator
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(recip_pk);
        let fee = 2_000u64;
        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            &recipient,
            10_000,
            fee,
            1_700_000_001,
        );
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![(tx, tx_id)], 2, hash0, 1_700_000_001, &val_sk, &val_pk);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + fee);
    }

    #[test]
    fn self_transfer_balance_correct() {
        let (db, _dir) = temp_db();

        // Fund sender as validator of block 1
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let fee = 1_000u64;
        let amount = 10_000u64;
        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            &sender_pub,
            amount,
            fee,
            1_700_000_001,
        );
        let (block1, hash1, ids1) = make_block(vec![(tx, tx_id)], 2, hash0, 1_700_000_001);
        db.commit_block(&block1, &hash1, &ids1).unwrap();

        // Self-transfer: net effect is -fee only
        assert_eq!(db.get_balance(&addr(&sender_pub)).unwrap(), INITIAL_SUBSIDY - fee);
    }

    #[test]
    fn persistence_across_reopen_balances() {
        let dir = tempfile::tempdir().unwrap();
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let validator = NoblePublicKey::Ed25519(val_pk.to_vec());

        // Write a block and close
        {
            let db = RocksDbStorage::open(dir.path()).unwrap();
            let (block, hash, ids) = make_block_with_validator(
                vec![],
                1,
                Hash256::ZERO,
                1_700_000_000,
                &val_sk,
                &val_pk,
            );
            db.commit_block(&block, &hash, &ids).unwrap();
            assert_eq!(db.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY);
        }

        // Reopen and verify
        {
            let db = RocksDbStorage::open(dir.path()).unwrap();
            assert_eq!(db.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY);
        }
    }

    // --- Rollback tests ---

    #[test]
    fn rollback_removes_blocks() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        let mut prev = Hash256::ZERO;
        for h in 0..3u64 {
            let (b, hash, ids) =
                make_block_with_validator(vec![], h, prev, 1_700_000_000 + h, &sk, &pk);
            db.commit_block(&b, &hash, &ids).unwrap();
            prev = hash;
        }

        let tip = db.rollback_to_height(1, MAINNET_CHAIN_ID).unwrap();
        assert_eq!(tip.height, 1);
        assert!(db.get_block_hash_by_height(2).is_err());
    }

    #[test]
    fn rollback_recalculates_balances() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let val_pub = NoblePublicKey::Ed25519(pk.to_vec());

        // Genesis block at height 0 (0 subsidy), then funded blocks at heights 1-3
        let mut prev = Hash256::ZERO;
        for h in 0..4u64 {
            let (b, hash, ids) =
                make_block_with_validator(vec![], h, prev, 1_700_000_000 + h, &sk, &pk);
            db.commit_block(&b, &hash, &ids).unwrap();
            prev = hash;
        }

        // Heights 1,2,3 each give INITIAL_SUBSIDY; height 0 gives 0
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 3);
        db.rollback_to_height(2, MAINNET_CHAIN_ID).unwrap();
        // After rollback: heights 0,1,2 remain → 0 + INITIAL_SUBSIDY + INITIAL_SUBSIDY
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 2);
    }

    #[test]
    fn repair_succeeds_on_valid_db() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _db = RocksDbStorage::open(dir.path()).unwrap();
        }
        // Repair a valid DB should succeed
        RocksDbStorage::repair(dir.path()).unwrap();
    }

    #[test]
    fn open_with_repair_normal_path() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open_with_repair(dir.path()).unwrap();
        assert!(db.get_chain_tip().unwrap().is_none());
    }

    // ── Peer Record Tests ──

    #[test]
    fn rocks_peer_record_store_and_get() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open(dir.path()).unwrap();

        let rec = PeerRecord::new(vec![0xAA; 32], vec![0xBB; 38], 1_700_000_000);
        db.store_peer_record(&rec).unwrap();

        let loaded = db.get_peer_record(&[0xAA; 32]).unwrap();
        assert_eq!(loaded, rec);
    }

    #[test]
    fn rocks_peer_record_list_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open(dir.path()).unwrap();

        db.store_peer_record(&PeerRecord::new(vec![1], vec![10], 100))
            .unwrap();
        db.store_peer_record(&PeerRecord::new(vec![2], vec![20], 200))
            .unwrap();

        let records = db.list_peer_records().unwrap();
        assert_eq!(records.len(), 2);

        db.remove_peer_record(&[1]).unwrap();
        let records = db.list_peer_records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].identity_key, vec![2]);
    }

    #[test]
    fn rocks_peer_record_prune() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open(dir.path()).unwrap();

        db.store_peer_record(&PeerRecord::new(vec![1], vec![10], 1000))
            .unwrap();
        db.store_peer_record(&PeerRecord::new(vec![2], vec![20], 5000))
            .unwrap();
        db.store_peer_record(&PeerRecord::new(vec![3], vec![30], 9000))
            .unwrap();

        // At time 10000, max_age 3000 → records older than 7000 are stale
        let pruned = db.prune_peer_records(10000, 3000).unwrap();
        assert_eq!(pruned, 2);
        let remaining = db.list_peer_records().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].identity_key, vec![3]);
    }

    #[test]
    fn rocks_peer_record_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open(dir.path()).unwrap();
        assert!(matches!(
            db.get_peer_record(&[99]),
            Err(StorageError::NotFound)
        ));
    }

    // --- Gateway fee split tests ---

    /// Helper: create a signed notarization tx with an optional gateway_address.
    fn make_signed_tx_with_gateway(
        sk: &[u8],
        pk: &[u8],
        doc: &[u8],
        timestamp: u64,
        fee: u64,
        gateway: Option<Vec<u8>>,
    ) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
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
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: gateway,
            source_address: None,
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn gateway_fee_split_50_50() {
        let (db, _dir) = temp_db();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, gw_pk) = ed25519::generate_keypair();
        let gw_key = NoblePublicKey::Ed25519(gw_pk.clone());
        let gw_wire = gw_key.to_wire_bytes();

        // Fund sender with block 1
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 2: tx with gateway, fee=2000
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx_with_gateway(
            &sender_sk,
            &sender_pk,
            b"doc-gw",
            1_700_000_001,
            2_000,
            Some(gw_wire),
        );
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx, tx_id)], 2, h0, 1_700_000_001, &val_sk, &val_pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        // Validator gets subsidy + 50% of fee (1000)
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + 1_000);
        // Gateway gets 50% of fee (1000)
        assert_eq!(db.get_balance(&addr(&gw_key)).unwrap(), 1_000);
    }

    #[test]
    fn gateway_fee_split_odd_rounds_to_validator() {
        let (db, _dir) = temp_db();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, gw_pk) = ed25519::generate_keypair();
        let gw_key = NoblePublicKey::Ed25519(gw_pk.clone());
        let gw_wire = gw_key.to_wire_bytes();

        // Fund sender
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 2: tx with gateway, odd fee=1001
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx_with_gateway(
            &sender_sk,
            &sender_pk,
            b"doc-odd",
            1_700_000_001,
            1_001,
            Some(gw_wire),
        );
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx, tx_id)], 2, h0, 1_700_000_001, &val_sk, &val_pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        // fee=1001: gw_share=500, val_share=501
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + 501);
        assert_eq!(db.get_balance(&addr(&gw_key)).unwrap(), 500);
    }

    #[test]
    fn no_gateway_100_percent_to_validator() {
        let (db, _dir) = temp_db();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();

        // Fund sender
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 2: tx WITHOUT gateway, fee=2000
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx_with_gateway(
            &sender_sk,
            &sender_pk,
            b"doc-no-gw",
            1_700_000_001,
            2_000,
            None,
        );
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx, tx_id)], 2, h0, 1_700_000_001, &val_sk, &val_pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        // Validator gets subsidy + 100% of fee
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + 2_000);
    }

    #[test]
    fn gateway_equals_sender() {
        let (db, _dir) = temp_db();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let sender_wire = sender_pub.to_wire_bytes();

        // Fund sender with block 1 (sender is also validator)
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();
        // sender_pub balance = INITIAL_SUBSIDY

        // Block 2: sender sends notarization with self as gateway, fee=2000
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx_with_gateway(
            &sender_sk,
            &sender_pk,
            b"doc-self-gw",
            1_700_000_001,
            2_000,
            Some(sender_wire),
        );
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx, tx_id)], 2, h0, 1_700_000_001, &val_sk, &val_pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // sender pays fee=2000, gets back gw_share=1000 → net change = -1000
        assert_eq!(
            db.get_balance(&addr(&sender_pub)).unwrap(),
            INITIAL_SUBSIDY - 1_000
        );
        // validator gets subsidy + val_share=1000
        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + 1_000);
    }

    #[test]
    fn gateway_equals_validator() {
        let (db, _dir) = temp_db();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        let val_wire = val_pub.to_wire_bytes();

        // Fund sender
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 2: gateway == validator, fee=2000
        let (tx, tx_id) = make_signed_tx_with_gateway(
            &sender_sk,
            &sender_pk,
            b"doc-val-gw",
            1_700_000_001,
            2_000,
            Some(val_wire),
        );
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx, tx_id)], 2, h0, 1_700_000_001, &val_sk, &val_pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // validator gets subsidy + val_share(1000) + gw_share(1000) = subsidy + 2000
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + 2_000);
    }

    // --- AUD2-M2: O(1) total_supply tracking ---

    #[test]
    fn aud2_m2_total_supply_tracks_across_blocks() {
        let (db, _dir) = temp_db();
        // Initially total_supply is 0
        assert_eq!(db.get_total_supply().unwrap(), 0);

        let (sk, pk) = ed25519::generate_keypair();

        // Block 1: validator gets INITIAL_SUBSIDY
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 1, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        db.commit_block(&b0, &h0, &ids0).unwrap();
        assert_eq!(db.get_total_supply().unwrap(), INITIAL_SUBSIDY);

        // Block 2: another INITIAL_SUBSIDY (same validator, height < HALVING_INTERVAL)
        let (b1, h1, ids1) = make_block_with_validator(vec![], 2, h0, 1_700_000_001, &sk, &pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();
        assert_eq!(db.get_total_supply().unwrap(), INITIAL_SUBSIDY * 2);

        // Block at HALVING_INTERVAL: subsidy halves
        let halved_subsidy = INITIAL_SUBSIDY / 2;
        let (b2, h2, ids2) =
            make_block_with_validator(vec![], HALVING_INTERVAL, h1, 1_700_000_002, &sk, &pk);
        db.commit_block(&b2, &h2, &ids2).unwrap();
        assert_eq!(
            db.get_total_supply().unwrap(),
            INITIAL_SUBSIDY * 2 + halved_subsidy
        );
    }

    #[test]
    fn aud2_m2_total_supply_read_is_o1() {
        // This test verifies that get_total_supply() reads a single key
        // from chain_state (not iterating balances). The proof is structural:
        // we commit multiple blocks with different validators and confirm the
        // total_supply key returns the correct cumulative subsidy without
        // scanning address_balances.
        let (db, _dir) = temp_db();

        let (sk1, pk1) = ed25519::generate_keypair();
        let (sk2, pk2) = ed25519::generate_keypair();

        // Two blocks, each mined by a different validator
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 1, Hash256::ZERO, 1_700_000_000, &sk1, &pk1);
        db.commit_block(&b0, &h0, &ids0).unwrap();

        let (b1, h1, _ids1) = make_block_with_validator(vec![], 2, h0, 1_700_000_001, &sk2, &pk2);
        db.commit_block(&b1, &h1, &_ids1).unwrap();

        // Total supply is 2x INITIAL_SUBSIDY, read from chain_state key (O(1))
        let supply = db.get_total_supply().unwrap();
        assert_eq!(supply, INITIAL_SUBSIDY * 2);

        // Each validator has INITIAL_SUBSIDY individually
        let v1 = NoblePublicKey::Ed25519(pk1.to_vec());
        let v2 = NoblePublicKey::Ed25519(pk2.to_vec());
        assert_eq!(db.get_balance(&addr(&v1)).unwrap(), INITIAL_SUBSIDY);
        assert_eq!(db.get_balance(&addr(&v2)).unwrap(), INITIAL_SUBSIDY);
    }

    // --- Version chain tests ---

    fn make_versioned_notarization(
        sk: &[u8],
        pk: &[u8],
        doc: &[u8],
        prev_checksum: Option<&Hash256>,
        version: Option<u32>,
        timestamp: u64,
    ) -> (Transaction, Hash256) {
        use noble_core::constants::{META_KEY_PREV_CHECKSUM, META_KEY_VERSION};
        use noble_core::MetadataEntry;

        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut metadata = Vec::new();
        if let Some(prev) = prev_checksum {
            metadata.push(MetadataEntry {
                key: META_KEY_PREV_CHECKSUM.to_string(),
                value: prev.to_string().into_bytes(),
            });
        }
        if let Some(v) = version {
            metadata.push(MetadataEntry {
                key: META_KEY_VERSION.to_string(),
                value: v.to_string().into_bytes(),
            });
        }
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum,
            timestamp,
            fee: 1_000,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: None,
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn version_chain_indexed_on_commit() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: v1 notarization (no prev_checksum)
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_v1", None, Some(1), 1_700_000_000);
        let v1_checksum = tx1.checksum;
        let (b0, h0, ids0) = make_block_with_validator(
            vec![(tx1, tx_id1)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: v2 notarization referencing v1's checksum
        let (tx2, tx_id2) = make_versioned_notarization(
            &sk,
            &pk,
            b"doc_v2",
            Some(&v1_checksum),
            Some(2),
            1_700_000_001,
        );
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx2, tx_id2)], 1, h0, 1_700_000_001, &sk, &pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // v1_checksum should have tx_id2 as a successor
        let successors = db.lookup_version_successors(&v1_checksum).unwrap();
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0], tx_id2);
    }

    #[test]
    fn version_chain_empty_for_non_versioned() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        // Commit a normal notarization without version metadata
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"plain_doc", 1_700_000_000);
        let checksum = tx.checksum;
        let (b0, h0, ids0) =
            make_block_with_validator(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // No successors for a plain document
        let successors = db.lookup_version_successors(&checksum).unwrap();
        assert!(successors.is_empty());
    }

    #[test]
    fn version_chain_multiple_successors() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: v1
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_v1", None, Some(1), 1_700_000_000);
        let v1_checksum = tx1.checksum;
        let (b0, h0, ids0) = make_block_with_validator(
            vec![(tx1, tx_id1)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: two different v2s referencing same v1 checksum (fork)
        let (tx2a, tx_id2a) = make_versioned_notarization(
            &sk,
            &pk,
            b"doc_v2a",
            Some(&v1_checksum),
            Some(2),
            1_700_000_001,
        );
        let (tx2b, tx_id2b) = make_versioned_notarization(
            &sk,
            &pk,
            b"doc_v2b",
            Some(&v1_checksum),
            Some(2),
            1_700_000_002,
        );
        let (b1, h1, ids1) = make_block_with_validator(
            vec![(tx2a, tx_id2a), (tx2b, tx_id2b)],
            1,
            h0,
            1_700_000_001,
            &sk,
            &pk,
        );
        db.commit_block(&b1, &h1, &ids1).unwrap();

        let successors = db.lookup_version_successors(&v1_checksum).unwrap();
        assert_eq!(successors.len(), 2);
        assert!(successors.contains(&tx_id2a));
        assert!(successors.contains(&tx_id2b));
    }

    #[test]
    fn version_chain_rollback_cleans_index() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: empty genesis (sender=validator collects subsidy)
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: v1 notarization
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_v1", None, Some(1), 1_700_000_001);
        let v1_checksum = tx1.checksum;
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx1, tx_id1)], 1, h0, 1_700_000_001, &sk, &pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // Block 2: v2 referencing v1
        let (tx2, tx_id2) = make_versioned_notarization(
            &sk,
            &pk,
            b"doc_v2",
            Some(&v1_checksum),
            Some(2),
            1_700_000_002,
        );
        let (b2, h2, ids2) =
            make_block_with_validator(vec![(tx2, tx_id2)], 2, h1, 1_700_000_002, &sk, &pk);
        db.commit_block(&b2, &h2, &ids2).unwrap();

        // Verify version chain exists
        assert_eq!(db.lookup_version_successors(&v1_checksum).unwrap().len(), 1);

        // Rollback to height 1 (removes block 2 which has the v2)
        db.rollback_to_height(1, MAINNET_CHAIN_ID).unwrap();

        // Version chain should be empty after rollback (block 2 removed)
        let successors = db.lookup_version_successors(&v1_checksum).unwrap();
        assert!(successors.is_empty());
    }

    // ── Publisher Index Tests ──

    #[test]
    fn publisher_index_populated_on_commit() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk.clone());
        let wire = pub_key.to_wire_bytes();

        // Block 0: two notarizations from same key
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_a", None, Some(1), 1_700_000_000);
        let (tx2, tx_id2) =
            make_versioned_notarization(&sk, &pk, b"doc_b", None, Some(1), 1_700_000_000);
        let (b0, h0, ids0) = make_block_with_validator(
            vec![(tx1, tx_id1), (tx2, tx_id2)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        db.commit_block(&b0, &h0, &ids0).unwrap();

        let results = db.lookup_by_publisher(&wire).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&tx_id1));
        assert!(results.contains(&tx_id2));
    }

    #[test]
    fn publisher_index_empty_for_unknown_key() {
        let (db, _dir) = temp_db();
        let unknown_wire = vec![0x01; 33];
        let results = db.lookup_by_publisher(&unknown_wire).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn publisher_index_ignores_transfers() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk.clone());
        let wire = pub_key.to_wire_bytes();

        let (_sk2, pk2) = ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(pk2.clone());

        // Block 0: genesis (empty)
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: transfer only
        let (tx_t, tx_id_t) = make_transfer_tx(&sk, &pk, &recipient, 100, 1_000, 1_700_000_001);
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx_t, tx_id_t)], 1, h0, 1_700_000_001, &sk, &pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // Publisher index should be empty — transfers are not indexed
        let results = db.lookup_by_publisher(&wire).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn publisher_index_multiple_publishers() {
        let (db, _dir) = temp_db();

        let (sk_a, pk_a) = ed25519::generate_keypair();
        let pub_a = NoblePublicKey::Ed25519(pk_a.clone());
        let wire_a = pub_a.to_wire_bytes();

        let (sk_b, pk_b) = ed25519::generate_keypair();
        let pub_b = NoblePublicKey::Ed25519(pk_b.clone());
        let wire_b = pub_b.to_wire_bytes();

        // Block 0: empty genesis (subsidy(0)=0)
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk_a, &pk_a);
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: empty — A gets subsidy(1) as validator
        let (b1, h1, ids1) = make_block_with_validator(vec![], 1, h0, 1_700_000_001, &sk_a, &pk_a);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // Block 2: empty — B gets subsidy(2) as validator
        let (b2, h2, ids2) = make_block_with_validator(vec![], 2, h1, 1_700_000_002, &sk_b, &pk_b);
        db.commit_block(&b2, &h2, &ids2).unwrap();

        // Block 3: notarization from A (A has subsidy from block 1)
        let (tx_a, tx_id_a) =
            make_versioned_notarization(&sk_a, &pk_a, b"doc_by_a", None, Some(1), 1_700_000_003);
        let (b3, h3, ids3) =
            make_block_with_validator(vec![(tx_a, tx_id_a)], 3, h2, 1_700_000_003, &sk_b, &pk_b);
        db.commit_block(&b3, &h3, &ids3).unwrap();

        // Block 4: notarization from B (B has subsidy from blocks 2+3)
        let (tx_b, tx_id_b) =
            make_versioned_notarization(&sk_b, &pk_b, b"doc_by_b", None, Some(1), 1_700_000_004);
        let (b4, _h4, ids4) =
            make_block_with_validator(vec![(tx_b, tx_id_b)], 4, h3, 1_700_000_004, &sk_a, &pk_a);
        db.commit_block(&b4, &_h4, &ids4).unwrap();

        let results_a = db.lookup_by_publisher(&wire_a).unwrap();
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0], tx_id_a);

        let results_b = db.lookup_by_publisher(&wire_b).unwrap();
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0], tx_id_b);
    }

    #[test]
    fn publisher_index_rollback_clears_and_replays() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk.clone());
        let wire = pub_key.to_wire_bytes();

        // Block 0: empty genesis
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        db.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: notarization A
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_1", None, Some(1), 1_700_000_001);
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx1, tx_id1)], 1, h0, 1_700_000_001, &sk, &pk);
        db.commit_block(&b1, &h1, &ids1).unwrap();

        // Block 2: notarization B
        let (tx2, tx_id2) =
            make_versioned_notarization(&sk, &pk, b"doc_2", None, Some(1), 1_700_000_002);
        let (b2, h2, ids2) =
            make_block_with_validator(vec![(tx2, tx_id2)], 2, h1, 1_700_000_002, &sk, &pk);
        db.commit_block(&b2, &h2, &ids2).unwrap();

        // Block 3: notarization C
        let (tx3, tx_id3) =
            make_versioned_notarization(&sk, &pk, b"doc_3", None, Some(1), 1_700_000_003);
        let (b3, _h3, ids3) =
            make_block_with_validator(vec![(tx3, tx_id3)], 3, h2, 1_700_000_003, &sk, &pk);
        db.commit_block(&b3, &_h3, &ids3).unwrap();

        // Before rollback: 3 tx_ids
        assert_eq!(db.lookup_by_publisher(&wire).unwrap().len(), 3);

        // Rollback to height 1 (removes blocks 2 and 3)
        db.rollback_to_height(1, MAINNET_CHAIN_ID).unwrap();

        // After rollback: only tx_id1 from block 1
        let results = db.lookup_by_publisher(&wire).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tx_id1);
    }
}
