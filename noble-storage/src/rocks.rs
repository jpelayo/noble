// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! RocksDB-backed storage engine with 6 column families.
//!
//! Column families:
//! - `blocks`: height (u64 BE) → serialized Block
//! - `block_hashes`: block_hash (32B) → height (u64 BE)
//! - `tx_index`: tx_id (32B) → height(8B) + tx_offset(4B)
//! - `checksum_index`: doc_checksum (32B) → concatenated tx_ids (N×32B)
//! - `chain_state`: string key → value bytes
//! - `validator_state`: validator_pubkey → reputation data (reserved for Sprint 4+)

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rocksdb::{ColumnFamilyDescriptor, MergeOperands, Options, WriteBatch, DB};

use noble_codec::NobleCbor;
use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::Hash256;

use crate::error::StorageError;
use crate::traits::{ChainTip, StorageEngine};
use crate::MAX_CHECKSUM_REGISTRATIONS;

// --- Column family names ---

const CF_BLOCKS: &str = "blocks";
const CF_BLOCK_HASHES: &str = "block_hashes";
const CF_TX_INDEX: &str = "tx_index";
const CF_CHECKSUM_INDEX: &str = "checksum_index";
const CF_CHAIN_STATE: &str = "chain_state";
const CF_VALIDATOR_STATE: &str = "validator_state";

// --- Chain state keys ---

const KEY_TIP_HASH: &[u8] = b"tip_hash";
const KEY_TIP_HEIGHT: &[u8] = b"tip_height";

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
/// Uses 6 column families with bloom filters, Zstd compression on blocks,
/// and a merge operator on `checksum_index` for append-only tx_id lists.
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
}

impl StorageEngine for RocksDbStorage {
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

        // checksum_index CF: checksum → merge-append tx_id
        let cf_checksum = self.cf(CF_CHECKSUM_INDEX)?;
        for (tx, tx_id) in block.transactions.iter().zip(tx_ids.iter()) {
            batch.merge_cf(cf_checksum, tx.checksum.as_bytes(), tx_id.as_bytes());
        }

        // chain_state CF: tip_hash and tip_height
        let cf_state = self.cf(CF_CHAIN_STATE)?;
        batch.put_cf(cf_state, KEY_TIP_HASH, block_hash.as_bytes());
        batch.put_cf(cf_state, KEY_TIP_HEIGHT, height_be);

        // Atomic commit
        self.db
            .write(batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    fn get_block(&self, block_hash: &Hash256) -> Result<Block, StorageError> {
        self.check_open()?;

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

        let height_be: [u8; 8] = location[..8].try_into().unwrap();
        let offset = u32::from_be_bytes(location[8..12].try_into().unwrap()) as usize;

        // Fetch the block at this height
        let cf_blocks = self.cf(CF_BLOCKS)?;
        let block_bytes = self
            .db
            .get_cf(cf_blocks, height_be)
            .map_err(|e| StorageError::Database(e.to_string()))?
            .ok_or_else(|| {
                StorageError::TransactionNotFound(format!(
                    "block at height {} not found for tx {}",
                    u64::from_be_bytes(height_be),
                    tx_id
                ))
            })?;

        let block = Block::from_cbor(&block_bytes)?;
        block.transactions.into_iter().nth(offset).ok_or_else(|| {
            StorageError::TransactionNotFound(format!(
                "tx offset {offset} out of range in block at height {}",
                u64::from_be_bytes(height_be)
            ))
        })
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
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

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
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

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
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let hash = db.get_block_hash_by_height(0).unwrap();
        assert_eq!(hash, block_hash);
    }

    #[test]
    fn retrieve_transaction() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx.clone(), tx_id)], 0, Hash256::ZERO, 1_700_000_000);

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
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        db.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let results = db.lookup_checksum(&checksum).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tx_id);
    }

    #[test]
    fn checksum_lookup_multiple_blocks() {
        let (db, _dir) = temp_db();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: first registration of same_doc
        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_000);
        let checksum = tx1.checksum;
        let (block0, hash0, ids0) =
            make_block(vec![(tx1, tx_id1)], 0, Hash256::ZERO, 1_700_000_000);
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        // Block 1: second registration of same_doc
        let (tx2, tx_id2) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_001);
        let (block1, hash1, ids1) = make_block(vec![(tx2, tx_id2)], 1, hash0, 1_700_000_001);
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
        let (block0, hash0, ids0) =
            make_block(vec![(tx0, tx_id0)], 0, Hash256::ZERO, 1_700_000_000);
        db.commit_block(&block0, &hash0, &ids0).unwrap();

        let tip = db.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash0);
        assert_eq!(tip.height, 0);

        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) = make_block(vec![(tx1, tx_id1)], 1, hash0, 1_700_000_001);
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
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx.clone(), tx_id)], 0, Hash256::ZERO, 1_700_000_000);

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

        let (block, hash, ids) = make_block(
            vec![(tx1.clone(), id1), (tx2.clone(), id2), (tx3.clone(), id3)],
            0,
            Hash256::ZERO,
            1_700_000_000,
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
}
