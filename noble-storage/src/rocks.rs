// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! RocksDB-backed storage engine with UTXO-model column families.
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
//! Single RocksDB instance, single volume. Column families are logical
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
//! - `validator_state`: validator_pubkey → reputation data
//! - `utxo_set`: outpoint (36B) → encoded UtxoEntry
//! - `address_utxos`: address_wire || outpoint (36B) → empty (presence index)
//! - `undo_data`: height (8B BE) → CBOR-encoded spent UTXOs
//! - `address_history`: pubkey_wire+height(8B BE)+offset(4B BE) → tx_id(32B)
//! - `bans`: peer_id bytes → banned_until (u64 BE)
//! - `peer_memory`: identity_key wire → CBOR-encoded PeerRecord
//! - `version_chain`: prev_checksum (32B) → concatenated successor tx_ids (N×32B)
//! - `issuer_index`: pubkey_wire → concatenated notarization tx_ids (N×32B)

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rocksdb::{
    ColumnFamilyDescriptor, Direction, IteratorMode, MergeOperands, Options, WriteBatch, DB,
};

use noble_codec::NobleCbor;
use noble_core::constants::{
    subsidy_at_height, COINBASE_MATURITY, MAX_REORG_DEPTH, MAX_SUPPLY, META_KEY_PREV_CHECKSUM,
};
use noble_core::{Block, BlockHeader, NobleAddress, OutPoint, PeerRecord, Transaction, UtxoEntry};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::StorageError;
use crate::traits::{CfStats, ChainTip, KeyRotationRecord, StorageEngine, StorageStats};
use crate::MAX_CHECKSUM_REGISTRATIONS;

// --- Column family names ---

const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_HASHES: &str = "block_hashes";
const CF_TX_INDEX: &str = "tx_index";
const CF_CHECKSUM_INDEX: &str = "checksum_index";
const CF_CHAIN_STATE: &str = "chain_state";
const CF_VALIDATOR_STATE: &str = "validator_state";
const CF_UTXO_SET: &str = "utxo_set";
const CF_ADDRESS_UTXOS: &str = "address_utxos";
const CF_UNDO_DATA: &str = "undo_data";
const CF_ADDRESS_HISTORY: &str = "address_history";
const CF_BANS: &str = "bans";
const CF_PEER_MEMORY: &str = "peer_memory";
const CF_VERSION_CHAIN: &str = "version_chain";
const CF_ISSUER_INDEX: &str = "issuer_index";
const CF_BADGE_STATE: &str = "badge_state";
const CF_EVIDENCE: &str = "evidence";
const CF_METADATA_INDEX: &str = "metadata_index";

/// All column family names, for introspection (storage stats).
const ALL_CF_NAMES: &[&str] = &[
    CF_BLOCKS, CF_BLOCK_HASHES, CF_TX_INDEX, CF_CHECKSUM_INDEX,
    CF_CHAIN_STATE, CF_VALIDATOR_STATE, CF_UTXO_SET, CF_ADDRESS_UTXOS,
    CF_UNDO_DATA, CF_ADDRESS_HISTORY, CF_BANS, CF_PEER_MEMORY,
    CF_VERSION_CHAIN, CF_ISSUER_INDEX, CF_BADGE_STATE, CF_EVIDENCE,
    CF_METADATA_INDEX,
];

// --- Chain state keys ---

const KEY_TIP_HASH: &[u8] = b"tip_hash";
const KEY_TIP_HEIGHT: &[u8] = b"tip_height";
const KEY_FINALITY_STATE: &[u8] = b"finality_state";
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
/// Uses 13 column families with bloom filters, Zstd compression on blocks,
/// and merge operators on `checksum_index`, `version_chain`, and `issuer_index`
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
            Self::cf_utxo_set(config),
            Self::cf_address_utxos(config),
            Self::cf_undo_data(),
            Self::cf_address_history(config),
            Self::cf_bans(),
            Self::cf_peer_memory(),
            Self::cf_version_chain(config),
            Self::cf_issuer_index(config),
            Self::cf_badge_state(),
            Self::cf_evidence(),
            Self::cf_metadata_index(),
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

    fn cf_utxo_set(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_UTXO_SET, opts)
    }

    fn cf_address_utxos(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_ADDRESS_UTXOS, opts)
    }

    fn cf_undo_data() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_UNDO_DATA, Options::default())
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

    fn cf_issuer_index(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("issuer_merge", checksum_merge_operator);
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_ISSUER_INDEX, opts)
    }

    fn cf_version_chain(config: &RocksDbConfig) -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("version_chain_merge", checksum_merge_operator);
        let mut table_opts = rocksdb::BlockBasedOptions::default();
        table_opts.set_bloom_filter(config.bloom_filter_bits as f64, false);
        opts.set_block_based_table_factory(&table_opts);
        ColumnFamilyDescriptor::new(CF_VERSION_CHAIN, opts)
    }

    fn cf_badge_state() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_BADGE_STATE, Options::default())
    }

    fn cf_evidence() -> ColumnFamilyDescriptor {
        ColumnFamilyDescriptor::new(CF_EVIDENCE, Options::default())
    }

    fn cf_metadata_index() -> ColumnFamilyDescriptor {
        let mut opts = Options::default();
        opts.set_merge_operator_associative("metadata_merge", checksum_merge_operator);
        ColumnFamilyDescriptor::new(CF_METADATA_INDEX, opts)
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

    /// Build the CF key for an address balance/history: wire bytes.
    /// Supports both native NOBLE keys (0x01/0x02) and Bitcoin addresses (0x80/0x81).
    fn address_key(address: &NobleAddress) -> Vec<u8> {
        address.to_wire_bytes()
    }

    /// Build the CF key for an address history entry.
    fn history_key(pubkey_wire: &[u8], height: u64, offset: u32) -> Vec<u8> {
        let mut key = Vec::with_capacity(pubkey_wire.len() + 8 + 4);
        key.extend_from_slice(pubkey_wire);
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(&offset.to_be_bytes());
        key
    }

    // --- UTXO encoding/decoding helpers ---

    /// Build the CF_UTXO_SET key: outpoint bytes (txid 32B || vout 4B LE).
    fn outpoint_key(outpoint: &OutPoint) -> [u8; 36] {
        outpoint.to_bytes()
    }

    /// Decode an OutPoint from 36 bytes.
    fn decode_outpoint_key(bytes: &[u8]) -> OutPoint {
        let mut arr = [0u8; 36];
        arr.copy_from_slice(&bytes[..36]);
        OutPoint::from_bytes(&arr)
    }

    /// Build the CF_ADDRESS_UTXOS key: address_wire || outpoint bytes.
    fn address_utxo_key(address_wire: &[u8], outpoint: &OutPoint) -> Vec<u8> {
        let op_bytes = outpoint.to_bytes();
        let mut key = Vec::with_capacity(address_wire.len() + 36);
        key.extend_from_slice(address_wire);
        key.extend_from_slice(&op_bytes);
        key
    }

    /// Encode a UtxoEntry to bytes for CF_UTXO_SET value.
    /// Format: value(8B BE) || height(8B BE) || is_coinbase(1B) || address_wire(var)
    fn encode_utxo_entry(entry: &UtxoEntry) -> Vec<u8> {
        let addr_wire = entry.address.to_wire_bytes();
        let mut buf = Vec::with_capacity(8 + 8 + 1 + addr_wire.len());
        buf.extend_from_slice(&entry.value.to_be_bytes());
        buf.extend_from_slice(&entry.height.to_be_bytes());
        buf.push(if entry.is_coinbase { 1 } else { 0 });
        buf.extend_from_slice(&addr_wire);
        buf
    }

    /// Decode a UtxoEntry from bytes stored in CF_UTXO_SET.
    fn decode_utxo_entry(bytes: &[u8]) -> Result<UtxoEntry, StorageError> {
        // Minimum: 8 (value) + 8 (height) + 1 (is_coinbase) + 1 (min address) = 18
        if bytes.len() < 18 {
            return Err(StorageError::Database(format!(
                "corrupt UTXO entry: expected at least 18 bytes, got {}",
                bytes.len()
            )));
        }
        let value = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let height = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let is_coinbase = bytes[16] != 0;
        let address = NobleAddress::from_wire_bytes(&bytes[17..])
            .map_err(|e| StorageError::Database(format!("corrupt UTXO address: {e}")))?;
        Ok(UtxoEntry {
            value,
            address,
            height,
            is_coinbase,
        })
    }

    /// Encode a list of spent UtxoEntries with their outpoints for undo data.
    /// Format: count(4B BE) || (outpoint(36B) || entry_len(4B BE) || entry_bytes)*
    fn encode_undo_data(spent: &[(OutPoint, UtxoEntry)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(spent.len() as u32).to_be_bytes());
        for (outpoint, entry) in spent {
            buf.extend_from_slice(&outpoint.to_bytes());
            let entry_bytes = Self::encode_utxo_entry(entry);
            buf.extend_from_slice(&(entry_bytes.len() as u32).to_be_bytes());
            buf.extend_from_slice(&entry_bytes);
        }
        buf
    }

    /// Decode undo data back into (OutPoint, UtxoEntry) pairs.
    fn decode_undo_data(bytes: &[u8]) -> Result<Vec<(OutPoint, UtxoEntry)>, StorageError> {
        if bytes.len() < 4 {
            return Err(StorageError::Database("corrupt undo data: too short".into()));
        }
        let count = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let mut pos = 4;
        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 36 + 4 > bytes.len() {
                return Err(StorageError::Database("corrupt undo data: truncated".into()));
            }
            let op_bytes: [u8; 36] = bytes[pos..pos + 36].try_into().unwrap();
            let outpoint = OutPoint::from_bytes(&op_bytes);
            pos += 36;
            let entry_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + entry_len > bytes.len() {
                return Err(StorageError::Database("corrupt undo data: truncated entry".into()));
            }
            let entry = Self::decode_utxo_entry(&bytes[pos..pos + entry_len])?;
            pos += entry_len;
            result.push((outpoint, entry));
        }
        Ok(result)
    }

    /// Read a UTXO entry from the UTXO set by outpoint.
    fn read_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, StorageError> {
        let cf = self.cf(CF_UTXO_SET)?;
        let key = Self::outpoint_key(outpoint);
        match self
            .db
            .get_cf(cf, key)
            .map_err(|e| StorageError::Database(e.to_string()))?
        {
            Some(bytes) => Ok(Some(Self::decode_utxo_entry(&bytes)?)),
            None => Ok(None),
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

    /// Query per-CF size and key count estimates from RocksDB properties.
    fn query_cf_stats(&self) -> Vec<CfStats> {
        ALL_CF_NAMES
            .iter()
            .filter_map(|&name| {
                let cf = self.db.cf_handle(name)?;
                let estimated_bytes = self
                    .db
                    .property_int_value_cf(cf, "rocksdb.estimate-live-data-size")
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                let estimated_keys = self
                    .db
                    .property_int_value_cf(cf, "rocksdb.estimate-num-keys")
                    .ok()
                    .flatten()
                    .unwrap_or(0);
                Some(CfStats {
                    name: name.to_string(),
                    estimated_bytes,
                    estimated_keys,
                })
            })
            .collect()
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
        let cf_issuer = self.cf(CF_ISSUER_INDEX)?;
        let cf_meta = self.cf(CF_METADATA_INDEX)?;
        for (tx, tx_id) in block.transactions.iter().zip(tx_ids.iter()) {
            let handler = noble_core::tx_types::handler_for(tx.tx_type);
            if handler.map_or(false, |h| h.needs_notarization_indexing()) {
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

                // issuer_index CF: pubkey_wire → merge-append tx_id
                let issuer_wire = tx
                    .issuer_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?
                    .to_wire_bytes();
                batch.merge_cf(cf_issuer, &issuer_wire, tx_id.as_bytes());

                // metadata_index CF: [key_len:u16 || key || value] → merge-append tx_id
                for entry in &tx.metadata {
                    let mut idx_key = Vec::with_capacity(2 + entry.key.len() + entry.value.len());
                    idx_key.extend_from_slice(&(entry.key.len() as u16).to_be_bytes());
                    idx_key.extend_from_slice(entry.key.as_bytes());
                    idx_key.extend_from_slice(&entry.value);
                    batch.merge_cf(cf_meta, &idx_key, tx_id.as_bytes());
                }
            }
        }


        // chain_state CF: tip_hash and tip_height
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        batch.put_cf(cf_state, KEY_TIP_HASH, block_hash.as_bytes());
        batch.put_cf(cf_state, KEY_TIP_HEIGHT, height_be);

        // --- UTXO processing ---
        let cf_utxo = self.cf(CF_UTXO_SET)?;
        let cf_addr_utxo = self.cf(CF_ADDRESS_UTXOS)?;
        let cf_undo = self.cf(CF_UNDO_DATA)?;
        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;

        // Collect all spent UTXOs for undo data
        let mut spent_utxos: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        let mut total_fees: u64 = 0;

        // Track outpoints deleted within this block (double-spend within same block)
        let mut deleted_in_block: HashMap<[u8; 36], UtxoEntry> = HashMap::new();
        // Track outpoints created within this block (for spending in-block outputs)
        let mut created_in_block: HashMap<[u8; 36], UtxoEntry> = HashMap::new();

        for (offset, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
            let is_coinbase = tx.is_coinbase();

            // --- Process inputs (consume UTXOs) for non-coinbase ---
            let mut input_sum: u64 = 0;
            if !is_coinbase {
                for input in &tx.inputs {
                    let op_key = Self::outpoint_key(&input.prev_output);

                    // Check double-spend within block
                    if deleted_in_block.contains_key(&op_key) {
                        return Err(StorageError::Database(format!(
                            "double-spend within block: txid={}, vout={}",
                            input.prev_output.txid, input.prev_output.vout
                        )));
                    }

                    // Try in-block created outputs first, then DB
                    let entry = if let Some(e) = created_in_block.remove(&op_key) {
                        e
                    } else {
                        self.read_utxo(&input.prev_output)?
                            .ok_or_else(|| StorageError::UtxoNotFound {
                                txid: input.prev_output.txid.to_string(),
                                vout: input.prev_output.vout,
                            })?
                    };

                    // Check coinbase maturity
                    if entry.is_coinbase && !entry.is_mature(height) {
                        return Err(StorageError::ImmatureCoinbase {
                            created_height: entry.height,
                            current_height: height,
                            maturity: COINBASE_MATURITY,
                        });
                    }

                    input_sum += entry.value;

                    // Delete from UTXO set and address index
                    let addr_wire = entry.address.to_wire_bytes();
                    batch.delete_cf(cf_utxo, op_key);
                    batch.delete_cf(cf_addr_utxo, Self::address_utxo_key(&addr_wire, &input.prev_output));

                    // Record for undo data
                    spent_utxos.push((input.prev_output.clone(), entry.clone()));
                    deleted_in_block.insert(op_key, entry);
                }
                let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
                if input_sum >= output_sum {
                    total_fees += input_sum - output_sum;
                }
            }

            // --- Process outputs (create new UTXOs) ---
            for (vout, output) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: *tx_id,
                    vout: vout as u32,
                };
                let entry = UtxoEntry {
                    value: output.value,
                    address: output.address.clone(),
                    height,
                    is_coinbase,
                };
                let op_key = Self::outpoint_key(&outpoint);
                let entry_bytes = Self::encode_utxo_entry(&entry);
                let addr_wire = output.address.to_wire_bytes();

                batch.put_cf(cf_utxo, op_key, &entry_bytes);
                batch.put_cf(cf_addr_utxo, Self::address_utxo_key(&addr_wire, &outpoint), &[]);

                created_in_block.insert(op_key, entry);
            }

            // --- Address history for all involved addresses ---
            // Record history for each unique address touched by this tx
            let mut history_addresses: Vec<Vec<u8>> = Vec::new();

            if !is_coinbase {
                for input in &tx.inputs {
                    let op_key = Self::outpoint_key(&input.prev_output);
                    if let Some(spent_entry) = deleted_in_block.get(&op_key) {
                        let wire = spent_entry.address.to_wire_bytes();
                        if !history_addresses.contains(&wire) {
                            history_addresses.push(wire);
                        }
                    }
                }
            }
            for output in &tx.outputs {
                let wire = output.address.to_wire_bytes();
                if !history_addresses.contains(&wire) {
                    history_addresses.push(wire);
                }
            }
            for addr_wire in &history_addresses {
                let hkey = Self::history_key(addr_wire, height, offset as u32);
                batch.put_cf(cf_history, hkey, tx_id.as_bytes());
            }
        }

        // Store undo data for this block
        let undo_bytes = Self::encode_undo_data(&spent_utxos);
        batch.put_cf(cf_undo, height_be, &undo_bytes);

        // Verify coinbase output value matches subsidy + collected fees
        let subsidy = subsidy_at_height(height);
        if let Some(coinbase_tx) = block.transactions.first() {
            if coinbase_tx.is_coinbase() {
                let coinbase_total: u64 = coinbase_tx.outputs.iter().map(|o| o.value).sum();
                let expected = subsidy + total_fees;
                if coinbase_total != expected {
                    return Err(StorageError::Database(format!(
                        "coinbase output mismatch: got {coinbase_total}, expected {expected} (subsidy {subsidy} + fees {total_fees})"
                    )));
                }
            }
        }

        // MAX_SUPPLY cap enforcement via O(1) running total
        let block_subsidy = subsidy;
        let prev_supply = self.get_total_supply()?;
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

        let cf_addr_utxo = self.cf(CF_ADDRESS_UTXOS)?;
        let cf_utxo = self.cf(CF_UTXO_SET)?;
        let prefix = Self::address_key(address);

        let iter = self
            .db
            .iterator_cf(cf_addr_utxo, IteratorMode::From(&prefix, Direction::Forward));

        let mut total: u64 = 0;
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;

            // Check prefix match
            if key.len() < prefix.len() || &key[..prefix.len()] != prefix.as_slice() {
                break;
            }

            // Extract outpoint bytes from the key (last 36 bytes)
            if key.len() < prefix.len() + 36 {
                continue; // malformed key, skip
            }
            let op_bytes = &key[prefix.len()..prefix.len() + 36];

            // Look up the UTXO value
            if let Some(entry_bytes) = self
                .db
                .get_cf(cf_utxo, op_bytes)
                .map_err(|e| StorageError::Database(e.to_string()))?
            {
                let entry = Self::decode_utxo_entry(&entry_bytes)?;
                total = total.saturating_add(entry.value);
            }
        }

        Ok(total)
    }

    fn get_address_utxos(
        &self,
        address: &NobleAddress,
    ) -> Result<Vec<(noble_core::OutPoint, noble_core::UtxoEntry)>, StorageError> {
        self.check_open()?;

        let cf_addr_utxo = self.cf(CF_ADDRESS_UTXOS)?;
        let cf_utxo = self.cf(CF_UTXO_SET)?;
        let prefix = Self::address_key(address);

        let iter = self
            .db
            .iterator_cf(cf_addr_utxo, IteratorMode::From(&prefix, Direction::Forward));

        let mut result = Vec::new();
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.len() < prefix.len() || &key[..prefix.len()] != prefix.as_slice() {
                break;
            }
            if key.len() < prefix.len() + 36 {
                continue;
            }
            let op_bytes = &key[prefix.len()..prefix.len() + 36];
            if let Some(entry_bytes) = self
                .db
                .get_cf(cf_utxo, op_bytes)
                .map_err(|e| StorageError::Database(e.to_string()))?
            {
                let entry = Self::decode_utxo_entry(&entry_bytes)?;
                let outpoint = Self::decode_outpoint_key(op_bytes);
                result.push((outpoint, entry));
            }
        }

        Ok(result)
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

        let cf_blocks = self.cf(CF_BLOCKS)?;
        let cf_hashes = self.cf(CF_BLOCK_HASHES)?;
        let cf_tx = self.cf(CF_TX_INDEX)?;
        let cf_utxo = self.cf(CF_UTXO_SET)?;
        let cf_addr_utxo = self.cf(CF_ADDRESS_UTXOS)?;
        let cf_undo = self.cf(CF_UNDO_DATA)?;

        // Process blocks in reverse order using undo data
        for h in (target_height + 1..=tip.height).rev() {
            let height_be = h.to_be_bytes();
            let mut batch = WriteBatch::default();

            // Load undo data for this height
            let undo_bytes = self
                .db
                .get_cf(cf_undo, height_be)
                .map_err(|e| StorageError::Database(e.to_string()))?
                .ok_or(StorageError::UndoDataNotFound { height: h })?;
            let spent_utxos = Self::decode_undo_data(&undo_bytes)?;

            // Load block to find outputs to remove and tx_ids to unindex
            if let Some(block_bytes) = self
                .db
                .get_cf(cf_blocks, height_be)
                .map_err(|e| StorageError::Database(e.to_string()))?
            {
                match Block::from_cbor(&block_bytes) {
                    Ok(block) => {
                    // Remove tx index entries and delete created UTXOs
                    for (offset, tx) in block.transactions.iter().enumerate() {
                        match tx.compute_tx_id(chain_id) {
                            Ok(tx_id) => {
                            batch.delete_cf(cf_tx, tx_id.as_bytes());

                            // Remove outputs created by this tx
                            for (vout, output) in tx.outputs.iter().enumerate() {
                                let outpoint = OutPoint {
                                    txid: tx_id,
                                    vout: vout as u32,
                                };
                                let op_key = Self::outpoint_key(&outpoint);
                                let addr_wire = output.address.to_wire_bytes();
                                batch.delete_cf(cf_utxo, op_key);
                                batch.delete_cf(cf_addr_utxo, Self::address_utxo_key(&addr_wire, &outpoint));
                            }

                            // Remove history entries for this tx
                            // Collect unique addresses
                            let mut addrs: Vec<Vec<u8>> = Vec::new();
                            for output in &tx.outputs {
                                let wire = output.address.to_wire_bytes();
                                if !addrs.contains(&wire) {
                                    addrs.push(wire);
                                }
                            }
                            // Input addresses from undo data — handled below
                            for addr_wire in &addrs {
                                let hkey = Self::history_key(addr_wire, h, offset as u32);
                                let cf_history = self.cf(CF_ADDRESS_HISTORY)?;
                                batch.delete_cf(cf_history, hkey);
                            }
                            }
                            Err(e) => {
                                tracing::error!("corrupt tx during rollback at height {h}: {e}");
                            }
                        }
                    }

                    // Remove block hash index
                    if let Ok(block_hash) = block.header.compute_block_hash() {
                        batch.delete_cf(cf_hashes, block_hash.as_bytes());
                    }
                    }
                    Err(e) => {
                        tracing::error!("corrupt block during rollback at height {h}: {e}");
                    }
                }
            }

            // Restore spent UTXOs
            for (outpoint, entry) in &spent_utxos {
                let op_key = Self::outpoint_key(outpoint);
                let entry_bytes = Self::encode_utxo_entry(entry);
                let addr_wire = entry.address.to_wire_bytes();
                batch.put_cf(cf_utxo, op_key, &entry_bytes);
                batch.put_cf(cf_addr_utxo, Self::address_utxo_key(&addr_wire, outpoint), &[]);
            }

            // Remove block data and undo data
            batch.delete_cf(cf_blocks, height_be);
            batch.delete_cf(cf_undo, height_be);

            self.db
                .write(batch)
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }

        // Clear and rebuild merge-append indexes (checksum, version_chain, issuer, metadata)
        let mut clear_batch = WriteBatch::default();
        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;
        let cf_version = self.cf(CF_VERSION_CHAIN)?;
        let cf_issuer = self.cf(CF_ISSUER_INDEX)?;
        let cf_meta = self.cf(CF_METADATA_INDEX)?;
        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;

        for cf in [cf_checksum, cf_version, cf_issuer, cf_meta, cf_history] {
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);
            for item in iter {
                let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
                clear_batch.delete_cf(cf, &key);
            }
        }

        // Update chain tip
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        let target_hash = self.get_block_hash_by_height(target_height)?;
        clear_batch.put_cf(cf_state, KEY_TIP_HASH, target_hash.as_bytes());
        clear_batch.put_cf(cf_state, KEY_TIP_HEIGHT, target_height.to_be_bytes());

        self.db
            .write(clear_batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Replay checksum_index, version_chain, issuer_index, metadata_index, and history from 0..=target_height
        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;
        let cf_version = self.cf(CF_VERSION_CHAIN)?;
        let cf_issuer = self.cf(CF_ISSUER_INDEX)?;
        let cf_meta = self.cf(CF_METADATA_INDEX)?;
        let cf_history = self.cf(CF_ADDRESS_HISTORY)?;

        let mut replay_batch = WriteBatch::default();
        let mut replay_supply: u64 = 0;

        for h in 0..=target_height {
            let hash = self.get_block_hash_by_height(h)?;
            let block = self.get_block(&hash)?;

            replay_supply = replay_supply.saturating_add(subsidy_at_height(h));

            for (offset, tx) in block.transactions.iter().enumerate() {
                let tx_id = tx
                    .compute_tx_id(chain_id)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;

                // Rebuild checksum_index for notarizations
                if noble_core::tx_types::handler_for(tx.tx_type).map_or(false, |h| h.needs_notarization_indexing()) {
                    replay_batch.merge_cf(cf_checksum, tx.checksum.as_bytes(), tx_id.as_bytes());

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

                    let issuer_wire = tx
                        .issuer_sig
                        .to_noble_public_key()
                        .map_err(|e| StorageError::Codec(e.to_string()))?
                        .to_wire_bytes();
                    replay_batch.merge_cf(cf_issuer, &issuer_wire, tx_id.as_bytes());

                    // metadata_index replay
                    for entry in &tx.metadata {
                        let mut idx_key = Vec::with_capacity(2 + entry.key.len() + entry.value.len());
                        idx_key.extend_from_slice(&(entry.key.len() as u16).to_be_bytes());
                        idx_key.extend_from_slice(entry.key.as_bytes());
                        idx_key.extend_from_slice(&entry.value);
                        replay_batch.merge_cf(cf_meta, &idx_key, tx_id.as_bytes());
                    }
                }

                // Rebuild address history
                let mut history_addresses: Vec<Vec<u8>> = Vec::new();
                if !tx.is_coinbase() {
                    // We don't have the spent UTXO addresses at replay time easily,
                    // but we can get them from the issuer_sig for simple cases.
                    // For a complete solution, use the issuer's key.
                    let sender_pk = tx
                        .issuer_sig
                        .to_noble_public_key()
                        .map_err(|e| StorageError::Codec(e.to_string()))?;
                    let sender_wire = NobleAddress::Noble(sender_pk).to_wire_bytes();
                    if !history_addresses.contains(&sender_wire) {
                        history_addresses.push(sender_wire);
                    }
                }
                for output in &tx.outputs {
                    let wire = output.address.to_wire_bytes();
                    if !history_addresses.contains(&wire) {
                        history_addresses.push(wire);
                    }
                }
                for addr_wire in &history_addresses {
                    let hkey = Self::history_key(addr_wire, h, offset as u32);
                    replay_batch.put_cf(cf_history, hkey, tx_id.as_bytes());
                }
            }
        }

        // Persist total_supply
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

    fn force_reset_to_genesis(&self, chain_id: u32) -> Result<ChainTip, StorageError> {
        self.check_open()?;
        let tip = self
            .get_chain_tip()?
            .ok_or_else(|| StorageError::Database("no chain tip".into()))?;

        if tip.height == 0 {
            return Ok(tip);
        }

        tracing::warn!(
            "force_reset_to_genesis: wiping {} blocks (bypasses MAX_REORG_DEPTH)",
            tip.height
        );

        // Remove blocks and tx indexes
        let mut batch = WriteBatch::default();
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let cf_hashes = self.cf(CF_BLOCK_HASHES)?;
        let cf_tx = self.cf(CF_TX_INDEX)?;

        for h in 1..=tip.height {
            let height_be = h.to_be_bytes();
            if let Some(block_bytes) = self
                .db
                .get_cf(cf_blocks, height_be)
                .map_err(|e| StorageError::Database(e.to_string()))?
            {
                match Block::from_cbor(&block_bytes) {
                    Ok(block) => {
                        for tx in &block.transactions {
                            match tx.compute_tx_id(chain_id) {
                                Ok(tx_id) => {
                                    batch.delete_cf(cf_tx, tx_id.as_bytes());
                                }
                                Err(e) => {
                                    tracing::error!("corrupt tx during force_reset at height {h}: {e}");
                                }
                            }
                        }
                        if let Ok(block_hash) = block.header.compute_block_hash() {
                            batch.delete_cf(cf_hashes, block_hash.as_bytes());
                        }
                    }
                    Err(e) => {
                        tracing::error!("corrupt block during force_reset at height {h}: {e}");
                    }
                }
            }
            batch.delete_cf(cf_blocks, height_be);
        }

        self.db
            .write(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Clear UTXO set, address UTXOs, undo data, history, checksum, version_chain, issuer_index
        let mut clear_batch = WriteBatch::default();
        for cf_name in [
            CF_UTXO_SET,
            CF_ADDRESS_UTXOS,
            CF_UNDO_DATA,
            CF_ADDRESS_HISTORY,
            CF_CHECKSUM_INDEX,
            CF_VERSION_CHAIN,
            CF_ISSUER_INDEX,
            CF_METADATA_INDEX,
        ] {
            let cf = self.cf(cf_name)?;
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);
            for item in iter {
                let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
                clear_batch.delete_cf(cf, &key);
            }
        }

        // Update chain tip to genesis
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        let genesis_hash = self.get_block_hash_by_height(0)?;
        clear_batch.put_cf(cf_state, KEY_TIP_HASH, genesis_hash.as_bytes());
        clear_batch.put_cf(cf_state, KEY_TIP_HEIGHT, 0u64.to_be_bytes());

        self.db
            .write(clear_batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        // Replay genesis block (height 0) for UTXOs
        let block = self.get_block(&genesis_hash)?;
        let mut replay_batch = WriteBatch::default();
        let cf_utxo = self.cf(CF_UTXO_SET)?;
        let cf_addr_utxo = self.cf(CF_ADDRESS_UTXOS)?;

        // Genesis block: re-create UTXOs from coinbase outputs
        for tx in &block.transactions {
            match tx.compute_tx_id(chain_id) {
                Ok(tx_id) => {
                    for (vout, output) in tx.outputs.iter().enumerate() {
                        let outpoint = OutPoint { txid: tx_id, vout: vout as u32 };
                        let entry = UtxoEntry {
                            value: output.value,
                            address: output.address.clone(),
                            height: 0,
                            is_coinbase: tx.is_coinbase(),
                        };
                        let op_key = Self::outpoint_key(&outpoint);
                        let entry_bytes = Self::encode_utxo_entry(&entry);
                        let addr_wire = output.address.to_wire_bytes();
                        replay_batch.put_cf(cf_utxo, op_key, &entry_bytes);
                        replay_batch.put_cf(cf_addr_utxo, Self::address_utxo_key(&addr_wire, &outpoint), &[]);
                    }
                }
                Err(e) => {
                    tracing::error!("corrupt genesis tx during force_reset: {e}");
                }
            }
        }

        let subsidy = subsidy_at_height(0);
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        replay_batch.put_cf(cf_state, KEY_TOTAL_SUPPLY, subsidy.to_be_bytes());

        self.db
            .write(replay_batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(ChainTip {
            block_hash: genesis_hash,
            height: 0,
        })
    }

    fn wipe_all_chain_data(&self) -> Result<(), StorageError> {
        self.check_open()?;

        tracing::warn!("wipe_all_chain_data: clearing ALL column families (cross-chain adoption)");

        // Clear every column family completely.
        let all_cfs = [
            CF_BLOCKS,
            CF_BLOCK_HASHES,
            CF_TX_INDEX,
            CF_CHECKSUM_INDEX,
            CF_CHAIN_STATE,
            CF_VALIDATOR_STATE,
            CF_UTXO_SET,
            CF_ADDRESS_UTXOS,
            CF_UNDO_DATA,
            CF_ADDRESS_HISTORY,
            CF_BANS,
            CF_PEER_MEMORY,
            CF_VERSION_CHAIN,
            CF_ISSUER_INDEX,
            CF_METADATA_INDEX,
            CF_BADGE_STATE,
            CF_EVIDENCE,
        ];

        for cf_name in all_cfs {
            let cf = self.cf(cf_name)?;
            let mut batch = WriteBatch::default();
            let iter = self.db.iterator_cf(cf, IteratorMode::Start);
            for item in iter {
                let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
                batch.delete_cf(cf, &key);
            }
            self.db
                .write(batch)
                .map_err(|e| StorageError::Database(e.to_string()))?;
        }

        tracing::warn!("wipe_all_chain_data: all data cleared — node is in pre-genesis state");
        Ok(())
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

    fn store_ban(&self, peer_id: &[u8], banned_until: u64, category_code: u8, evidence_hash: Option<&[u8; 32]>) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BANS)?;
        // Value: 8 bytes banned_until (BE) + 1 byte category_code + optional 32 bytes evidence_hash
        match evidence_hash {
            Some(hash) => {
                let mut value = [0u8; 41];
                value[..8].copy_from_slice(&banned_until.to_be_bytes());
                value[8] = category_code;
                value[9..41].copy_from_slice(hash);
                self.db
                    .put_cf(cf, peer_id, value)
                    .map_err(|e| StorageError::Database(e.to_string()))
            }
            None => {
                let mut value = [0u8; 9];
                value[..8].copy_from_slice(&banned_until.to_be_bytes());
                value[8] = category_code;
                self.db
                    .put_cf(cf, peer_id, value)
                    .map_err(|e| StorageError::Database(e.to_string()))
            }
        }
    }

    fn remove_ban(&self, peer_id: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BANS)?;
        self.db
            .delete_cf(cf, peer_id)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn load_bans(&self) -> Result<Vec<(Vec<u8>, u64, u8, Option<[u8; 32]>)>, StorageError> {
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
            if value.len() >= 8 {
                let banned_until = u64::from_be_bytes(value[..8].try_into().unwrap());
                // Category code: byte 9 if present, else 0x0C (ManualBan) for legacy 8-byte entries.
                let category_code = if value.len() >= 9 { value[8] } else { 0x0C };
                // Evidence hash: bytes 9..41 if present (41-byte entries).
                let evidence_hash = if value.len() >= 41 {
                    let mut h = [0u8; 32];
                    h.copy_from_slice(&value[9..41]);
                    Some(h)
                } else {
                    None
                };
                if banned_until > now {
                    bans.push((key.to_vec(), banned_until, category_code, evidence_hash));
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

    fn clear_cycle_history(&self) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        let prefix = b"cycle_history:";
        let prefix_end = b"cycle_history;";
        let iter = self
            .db
            .iterator_cf(&cf, IteratorMode::From(prefix, Direction::Forward));
        let mut batch = rocksdb::WriteBatch::default();
        for item in iter {
            let (key, _) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if !key.starts_with(prefix) || key.as_ref() >= prefix_end.as_slice() {
                break;
            }
            batch.delete_cf(&cf, &key);
        }
        self.db
            .write(batch)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    // ── Per-Block Vote Witness ──

    fn store_block_votes(&self, height: u64, data: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        let mut key = b"block_votes:".to_vec();
        key.extend_from_slice(&height.to_be_bytes());
        self.db
            .put_cf(&cf, &key, data)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_block_votes(&self, height: u64) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        let mut key = b"block_votes:".to_vec();
        key.extend_from_slice(&height.to_be_bytes());
        self.db
            .get_cf(&cf, &key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_utxo(&self, outpoint: &OutPoint) -> Result<Option<UtxoEntry>, StorageError> {
        self.check_open()?;
        self.read_utxo(outpoint)
    }

    fn store_finality_state(&self, data: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        self.db
            .put_cf(&cf, KEY_FINALITY_STATE, data)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn load_finality_state(&self) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        self.db
            .get_cf(&cf, KEY_FINALITY_STATE)
            .map_err(|e| StorageError::Database(e.to_string()))
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

    fn lookup_by_issuer(&self, pubkey_wire: &[u8]) -> Result<Vec<Hash256>, StorageError> {
        self.check_open()?;

        let cf_issuer = self.cf(CF_ISSUER_INDEX)?;
        let raw = self
            .db
            .get_cf(cf_issuer, pubkey_wire)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match raw {
            None => Ok(vec![]),
            Some(bytes) => parse_checksum_index_value(&bytes),
        }
    }

    fn lookup_by_metadata(&self, key: &str, value: &[u8]) -> Result<Vec<Hash256>, StorageError> {
        self.check_open()?;

        let cf_meta = self.cf(CF_METADATA_INDEX)?;
        let mut idx_key = Vec::with_capacity(2 + key.len() + value.len());
        idx_key.extend_from_slice(&(key.len() as u16).to_be_bytes());
        idx_key.extend_from_slice(key.as_bytes());
        idx_key.extend_from_slice(value);

        let raw = self
            .db
            .get_cf(cf_meta, &idx_key)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match raw {
            None => Ok(vec![]),
            Some(bytes) => parse_checksum_index_value(&bytes),
        }
    }

    // ── Badge State ──

    fn store_badge(&self, pubkey_wire: &[u8], badge_cbor: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        // Prefix with "b:" to separate badges from proposals
        let mut key = Vec::with_capacity(2 + pubkey_wire.len());
        key.extend_from_slice(b"b:");
        key.extend_from_slice(pubkey_wire);
        self.db.put_cf(cf, &key, badge_cbor)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_badge(&self, pubkey_wire: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let mut key = Vec::with_capacity(2 + pubkey_wire.len());
        key.extend_from_slice(b"b:");
        key.extend_from_slice(pubkey_wire);
        self.db.get_cf(cf, &key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn remove_badge(&self, pubkey_wire: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let mut key = Vec::with_capacity(2 + pubkey_wire.len());
        key.extend_from_slice(b"b:");
        key.extend_from_slice(pubkey_wire);
        self.db.delete_cf(cf, &key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn list_badges(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let prefix = b"b:";
        let mut badges = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf, prefix);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.starts_with(prefix) {
                badges.push((key[2..].to_vec(), value.to_vec()));
            } else {
                break;
            }
        }
        Ok(badges)
    }

    fn store_badge_proposal(&self, proposal_hash: &[u8], proposal_cbor: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let mut key = Vec::with_capacity(2 + proposal_hash.len());
        key.extend_from_slice(b"p:");
        key.extend_from_slice(proposal_hash);
        self.db.put_cf(cf, &key, proposal_cbor)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_badge_proposal(&self, proposal_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let mut key = Vec::with_capacity(2 + proposal_hash.len());
        key.extend_from_slice(b"p:");
        key.extend_from_slice(proposal_hash);
        self.db.get_cf(cf, &key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn remove_badge_proposal(&self, proposal_hash: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let mut key = Vec::with_capacity(2 + proposal_hash.len());
        key.extend_from_slice(b"p:");
        key.extend_from_slice(proposal_hash);
        self.db.delete_cf(cf, &key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn list_badge_proposals(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_BADGE_STATE)?;
        let prefix = b"p:";
        let mut proposals = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf, prefix);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.starts_with(prefix) {
                proposals.push((key[2..].to_vec(), value.to_vec()));
            } else {
                break;
            }
        }
        Ok(proposals)
    }

    fn get_storage_stats(&self) -> Result<StorageStats, StorageError> {
        self.check_open()?;
        Ok(StorageStats {
            column_families: self.query_cf_stats(),
        })
    }

    // ── Evidence Storage ──

    fn store_evidence(&self, evidence_hash: &[u8], evidence_cbor: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_EVIDENCE)?;
        self.db
            .put_cf(cf, evidence_hash, evidence_cbor)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn get_evidence(&self, evidence_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_EVIDENCE)?;
        self.db
            .get_cf(cf, evidence_hash)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn list_evidence(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_EVIDENCE)?;
        let mut result = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            result.push((key.to_vec(), value.to_vec()));
        }
        Ok(result)
    }

    // ── Checkpoint State ──

    fn store_checkpoint(&self, height: u64, data: &[u8]) -> Result<(), StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        let key = format!("checkpoint:{:010}", height);
        self.db
            .put_cf(cf, key.as_bytes(), data)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    fn load_checkpoints(&self) -> Result<Vec<(u64, Vec<u8>)>, StorageError> {
        self.check_open()?;
        let cf = self.cf(CF_CHAIN_STATE)?;
        let prefix = b"checkpoint:";
        let mut result = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf, prefix);
        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            if key.starts_with(prefix) {
                // Key format: "checkpoint:0000000030" → parse height from after ":"
                if let Ok(key_str) = std::str::from_utf8(&key[prefix.len()..]) {
                    if let Ok(height) = key_str.parse::<u64>() {
                        result.push((height, value.to_vec()));
                    }
                }
            } else {
                break;
            }
        }
        Ok(result)
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
    use noble_core::constants::{HALVING_INTERVAL, INITIAL_SUBSIDY, TX_TYPE_COINBASE, TX_TYPE_TRANSFER};
    use noble_core::utxo::{OutPoint, TxIn, TxOut};
    use noble_core::{Block, BlockHeader, Transaction, PROTOCOL_VERSION};
    use noble_test_utils::fixtures::test_chain_id;
    use noble_crypto::{
        secp256k1, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_SECP256K1,
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

    /// Create a coinbase transaction paying `value` to `address`.
    fn make_coinbase_tx(
        sk: &[u8],
        pk: &[u8],
        address: &NobleAddress,
        value: u64,
        timestamp: u64,
    ) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_COINBASE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut { value, address: address.clone() }],
            checksum: Hash256::ZERO,
            timestamp,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    /// Create a notarization tx that spends a UTXO (input) and returns change.
    /// Fee = input_value - change_value.
    fn make_signed_tx(
        sk: &[u8],
        pk: &[u8],
        doc: &[u8],
        timestamp: u64,
    ) -> (Transaction, Hash256) {
        // This creates a notarization with a dummy input outpoint.
        // Tests that use this must ensure the input UTXO exists.
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let checksum = sha256(doc);
        let sender_addr = NobleAddress::Noble(NoblePublicKey::Secp256k1(pk.to_vec()));
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![TxIn {
                prev_output: OutPoint {
                    txid: Hash256::from_bytes([0xDD; 32]), // dummy, overridden by caller
                    vout: 0,
                },
            }],
            outputs: vec![TxOut {
                value: 0, // will be set by caller or use default
                address: sender_addr,
            }],
            checksum,
            timestamp,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    /// Create a transfer tx: spends `input_outpoint` and sends `amount` to `recipient`,
    /// with change back to sender. Fee = input_value - amount - change.
    fn make_transfer_tx_utxo(
        sk: &[u8],
        pk: &[u8],
        recipient: &NobleAddress,
        input_outpoint: OutPoint,
        input_value: u64,
        amount: u64,
        fee: u64,
        timestamp: u64,
    ) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let sender_addr = NobleAddress::Noble(NoblePublicKey::Secp256k1(pk.to_vec()));
        let change = input_value - amount - fee;
        let mut outputs = vec![TxOut { value: amount, address: recipient.clone() }];
        if change > 0 {
            outputs.push(TxOut { value: change, address: sender_addr });
        }
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: vec![TxIn { prev_output: input_outpoint }],
            outputs,
            checksum: Hash256::ZERO,
            timestamp,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    fn make_block(
        txs: Vec<(Transaction, Hash256)>,
        height: u64,
        prev_hash: Hash256,
        timestamp: u64,
    ) -> (Block, Hash256, Vec<Hash256>) {
        let (val_sk, val_pk) = secp256k1::generate_keypair();
        let val_priv = NoblePrivateKey::Secp256k1(val_sk);
        let val_pub = NoblePublicKey::Secp256k1(val_pk.clone());

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
                scheme_id: SCHEME_SECP256K1,
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
        let val_priv = NoblePrivateKey::Secp256k1(val_sk.to_vec());
        let val_pub = NoblePublicKey::Secp256k1(val_pk.to_vec());

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
                scheme_id: SCHEME_SECP256K1,
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

    /// Helper: commit an empty block with a coinbase paying subsidy to the validator.
    fn commit_block_with_coinbase(
        db: &RocksDbStorage,
        height: u64,
        prev_hash: Hash256,
        timestamp: u64,
        val_sk: &[u8],
        val_pk: &[u8],
    ) -> (Hash256, Hash256) {
        let val_addr = NobleAddress::Noble(NoblePublicKey::Secp256k1(val_pk.to_vec()));
        let subsidy = subsidy_at_height(height);
        let (coinbase_tx, coinbase_id) =
            make_coinbase_tx(val_sk, val_pk, &val_addr, subsidy, timestamp);
        let (block, block_hash, tx_ids) = make_block_with_validator(
            vec![(coinbase_tx, coinbase_id)],
            height,
            prev_hash,
            timestamp,
            val_sk,
            val_pk,
        );
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();
        (block_hash, coinbase_id)
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
    fn commit_and_retrieve_empty_block() {
        let (db, _dir) = temp_db();
        let (block, block_hash, tx_ids) = make_block(vec![], 0, Hash256::ZERO, 1_700_000_000);
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let got = db.get_block(&block_hash).unwrap();
        assert_eq!(got, block);
    }

    #[test]
    fn commit_block_with_coinbase_and_retrieve() {
        let (db, _dir) = temp_db();
        let (val_sk, val_pk) = secp256k1::generate_keypair();
        let (hash, _coinbase_id) =
            commit_block_with_coinbase(&db, 1, Hash256::ZERO, 1_700_000_000, &val_sk, &val_pk);

        let tip = db.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash);
        assert_eq!(tip.height, 1);
    }

    #[test]
    fn block_hash_by_height() {
        let (db, _dir) = temp_db();
        let (block, block_hash, tx_ids) = make_block(vec![], 0, Hash256::ZERO, 1_700_000_000);
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let hash = db.get_block_hash_by_height(0).unwrap();
        assert_eq!(hash, block_hash);
    }

    #[test]
    fn chain_tip_updates() {
        let (db, _dir) = temp_db();
        assert!(db.get_chain_tip().unwrap().is_none());

        let (block0, hash0, ids0) = make_block(vec![], 0, Hash256::ZERO, 1_700_000_000);
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let tip = db.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash0);
        assert_eq!(tip.height, 0);

        let (block1, hash1, ids1) = make_block(vec![], 1, hash0, 1_700_000_001);
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

    // --- UTXO Balance tests ---

    #[test]
    fn balance_zero_for_unknown_address() {
        let (db, _dir) = temp_db();
        let (_, pk) = secp256k1::generate_keypair();
        let pubkey = NoblePublicKey::Secp256k1(pk);
        assert_eq!(db.get_balance(&addr(&pubkey)).unwrap(), 0);
    }

    #[test]
    fn coinbase_creates_utxo() {
        let (db, _dir) = temp_db();
        let (val_sk, val_pk) = secp256k1::generate_keypair();
        let val_pub = NoblePublicKey::Secp256k1(val_pk.to_vec());

        let (_hash, _coinbase_id) =
            commit_block_with_coinbase(&db, 1, Hash256::ZERO, 1_700_000_000, &val_sk, &val_pk);

        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY);
    }

    #[test]
    fn multi_block_balance_accumulation() {
        let (db, _dir) = temp_db();
        let (val_sk, val_pk) = secp256k1::generate_keypair();
        let val_pub = NoblePublicKey::Secp256k1(val_pk.to_vec());

        let mut prev_hash = Hash256::ZERO;
        for h in 1..4u64 {
            let (hash, _) = commit_block_with_coinbase(
                &db, h, prev_hash, 1_700_000_000 + h, &val_sk, &val_pk,
            );
            prev_hash = hash;
        }

        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 3);
    }

    #[test]
    fn transfer_debits_sender_credits_recipient() {
        let (db, _dir) = temp_db();
        let (sender_sk, sender_pk) = secp256k1::generate_keypair();
        let sender_pub = NoblePublicKey::Secp256k1(sender_pk.to_vec());

        // Block 1: coinbase funds sender
        let (hash0, coinbase_id) = commit_block_with_coinbase(
            &db, 1, Hash256::ZERO, 1_700_000_000, &sender_sk, &sender_pk,
        );

        // Wait for maturity (block at height 1 + COINBASE_MATURITY = 7)
        let mut prev = hash0;
        for h in 2..=7u64 {
            let (hash, _) = commit_block_with_coinbase(
                &db, h, prev, 1_700_000_000 + h, &sender_sk, &sender_pk,
            );
            prev = hash;
        }

        // Block 8: transfer from sender to recipient
        let (_, recip_pk) = secp256k1::generate_keypair();
        let recipient = NoblePublicKey::Secp256k1(recip_pk);
        let recip_addr = NobleAddress::Noble(recipient.clone());
        let amount = 100_000u64;
        let fee = 1_000u64;
        // Spend coinbase from block 1
        let input_outpoint = OutPoint { txid: coinbase_id, vout: 0 };
        let (tx, tx_id) = make_transfer_tx_utxo(
            &sender_sk, &sender_pk, &recip_addr, input_outpoint, INITIAL_SUBSIDY,
            amount, fee, 1_700_000_008,
        );
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![(tx, tx_id)], 8, prev, 1_700_000_008, &sender_sk, &sender_pk);
        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        assert_eq!(db.get_balance(&addr(&recipient)).unwrap(), amount);
        // Sender has: coinbase from blocks 2-7 (6 UTXOs) + change from transfer
        let sender_balance = db.get_balance(&addr(&sender_pub)).unwrap();
        let expected_change = INITIAL_SUBSIDY - amount - fee;
        // Block 8 has no coinbase, only the transfer tx
        let expected = INITIAL_SUBSIDY * 6 + expected_change;
        assert_eq!(sender_balance, expected);
    }

    #[test]
    fn spending_nonexistent_utxo_fails() {
        let (db, _dir) = temp_db();
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip_pk) = secp256k1::generate_keypair();
        let recip_addr = NobleAddress::Noble(NoblePublicKey::Secp256k1(recip_pk));

        // Try to spend a UTXO that doesn't exist
        let fake_outpoint = OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout: 0,
        };
        let (tx, tx_id) = make_transfer_tx_utxo(
            &sk, &pk, &recip_addr, fake_outpoint, 100_000, 50_000, 1_000, 1_700_000_000,
        );
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        let result = db.commit_block(&block, &block_hash, &tx_ids);
        assert!(matches!(result, Err(StorageError::UtxoNotFound { .. })));
    }

    // --- Total supply tests ---

    #[test]
    fn total_supply_tracks_across_blocks() {
        let (db, _dir) = temp_db();
        assert_eq!(db.get_total_supply().unwrap(), 0);

        let (sk, pk) = secp256k1::generate_keypair();

        let (h0, _) = commit_block_with_coinbase(&db, 1, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        assert_eq!(db.get_total_supply().unwrap(), INITIAL_SUBSIDY);

        let (h1, _) = commit_block_with_coinbase(&db, 2, h0, 1_700_000_001, &sk, &pk);
        assert_eq!(db.get_total_supply().unwrap(), INITIAL_SUBSIDY * 2);

        let halved = INITIAL_SUBSIDY / 2;
        let (_h2, _) = commit_block_with_coinbase(&db, HALVING_INTERVAL, h1, 1_700_000_002, &sk, &pk);
        assert_eq!(db.get_total_supply().unwrap(), INITIAL_SUBSIDY * 2 + halved);
    }

    // --- UTXO encoding/decoding tests ---

    #[test]
    fn utxo_entry_encode_decode_roundtrip() {
        let (_, pk) = secp256k1::generate_keypair();
        let entry = UtxoEntry {
            value: 42_000_000,
            address: NobleAddress::Noble(NoblePublicKey::Secp256k1(pk)),
            height: 123,
            is_coinbase: true,
        };
        let encoded = RocksDbStorage::encode_utxo_entry(&entry);
        let decoded = RocksDbStorage::decode_utxo_entry(&encoded).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn undo_data_encode_decode_roundtrip() {
        let (_, pk) = secp256k1::generate_keypair();
        let entry = UtxoEntry {
            value: 100_000,
            address: NobleAddress::Noble(NoblePublicKey::Secp256k1(pk)),
            height: 5,
            is_coinbase: false,
        };
        let outpoint = OutPoint {
            txid: Hash256::from_bytes([0xAB; 32]),
            vout: 2,
        };
        let spent = vec![(outpoint.clone(), entry.clone())];
        let encoded = RocksDbStorage::encode_undo_data(&spent);
        let decoded = RocksDbStorage::decode_undo_data(&encoded).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].0, outpoint);
        assert_eq!(decoded[0].1, entry);
    }

    // --- Rollback tests ---

    #[test]
    fn rollback_removes_blocks() {
        let (db, _dir) = temp_db();
        let (sk, pk) = secp256k1::generate_keypair();

        let mut prev = Hash256::ZERO;
        for h in 0..3u64 {
            let (b, hash, ids) =
                make_block_with_validator(vec![], h, prev, 1_700_000_000 + h, &sk, &pk);
            db.commit_block(&b, &hash, &ids).unwrap();
            prev = hash;
        }

        let tip = db.rollback_to_height(1, test_chain_id()).unwrap();
        assert_eq!(tip.height, 1);
        assert!(db.get_block_hash_by_height(2).is_err());
    }

    #[test]
    fn rollback_restores_utxos() {
        let (db, _dir) = temp_db();
        let (sk, pk) = secp256k1::generate_keypair();
        let val_pub = NoblePublicKey::Secp256k1(pk.to_vec());

        let mut prev = Hash256::ZERO;
        for h in 0..4u64 {
            let (hash, _) = commit_block_with_coinbase(&db, h, prev, 1_700_000_000 + h, &sk, &pk);
            prev = hash;
        }

        // Heights 1,2,3 each give INITIAL_SUBSIDY; height 0 gives 0
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 3);

        db.rollback_to_height(2, test_chain_id()).unwrap();
        // After rollback: heights 0,1,2 remain → 0 + INITIAL_SUBSIDY + INITIAL_SUBSIDY
        assert_eq!(db.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 2);
    }

    #[test]
    fn repair_succeeds_on_valid_db() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _db = RocksDbStorage::open(dir.path()).unwrap();
        }
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
        let bytes = vec![0u8; 33];
        assert!(parse_checksum_index_value(&bytes).is_err());
    }

    // --- Storage stats tests ---

    #[test]
    fn rocks_get_storage_stats_returns_all_cfs() {
        let dir = tempfile::tempdir().unwrap();
        let db = RocksDbStorage::open(dir.path()).unwrap();
        let stats = db.get_storage_stats().unwrap();
        assert_eq!(stats.column_families.len(), ALL_CF_NAMES.len());
        let names: Vec<&str> = stats.column_families.iter().map(|cf| cf.name.as_str()).collect();
        assert!(names.contains(&"blocks"));
        assert!(names.contains(&"block_hashes"));
        assert!(names.contains(&"tx_index"));
        assert!(names.contains(&"checksum_index"));
        assert!(names.contains(&"chain_state"));
        assert!(names.contains(&"validator_state"));
        assert!(names.contains(&"utxo_set"));
        assert!(names.contains(&"address_utxos"));
        assert!(names.contains(&"undo_data"));
        assert!(names.contains(&"address_history"));
        assert!(names.contains(&"bans"));
        assert!(names.contains(&"peer_memory"));
        assert!(names.contains(&"version_chain"));
        assert!(names.contains(&"issuer_index"));
        assert!(names.contains(&"badge_state"));
        assert!(names.contains(&"evidence"));
    }
}
