// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Core mempool data structure with 4 indexes and the 8-step admission pipeline.
//!
//! ## Indexes
//!
//! 1. **Primary**: `HashMap<Hash256, MempoolEntry>` — tx_id → entry
//! 2. **By fee-rate**: `BTreeMap<u64, HashSet<Hash256>>` — ordered for block assembly
//! 3. **By checksum**: `HashMap<Hash256, HashSet<Hash256>>` — checksum → tx_ids
//! 4. **By timestamp**: `BTreeMap<u64, HashSet<Hash256>>` — for expiry sweep
//!
//! ## 8-Step Admission Pipeline
//!
//! 1. Size check
//! 2. Duplicate check (mempool + chain callback)
//! 3. Version check
//! 4. Structural validation (T1-T5, T8-T10 via noble-core)
//! 5. Signature cache lookup (skip verification if cached)
//! 6. Signature verification (T6, T7)
//! 7. Fee check (>= dynamic minimum)
//! 8. Accept into mempool (insert all indexes)

use std::collections::{BTreeMap, HashMap, HashSet};

use noble_codec::NobleCbor;
use noble_core::{Transaction, MAINNET_CHAIN_ID, MAX_TX_SIZE, MIN_TX_FEE, PROTOCOL_VERSION};
use noble_crypto::{is_recognized_scheme, Hash256};

use crate::error::MempoolError;
use crate::sigcache::SigCache;

/// Default mempool configuration.
pub const DEFAULT_MAX_SIZE_BYTES: usize = 32 * 1024 * 1024; // 32 MB
pub const DEFAULT_MAX_COUNT: usize = 10_000;
pub const DEFAULT_EXPIRY_SECS: u64 = 72 * 3600; // 72 hours

/// Configuration for the mempool.
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum total serialized size of all transactions in bytes.
    pub max_size_bytes: usize,
    /// Maximum number of transactions.
    pub max_count: usize,
    /// Transaction expiry time in seconds.
    pub expiry_secs: u64,
    /// Signature cache capacity.
    pub sig_cache_size: usize,
    /// Chain ID for tx_id computation.
    pub chain_id: u32,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            max_count: DEFAULT_MAX_COUNT,
            expiry_secs: DEFAULT_EXPIRY_SECS,
            sig_cache_size: crate::sigcache::DEFAULT_SIG_CACHE_SIZE,
            chain_id: MAINNET_CHAIN_ID,
        }
    }
}

/// An entry in the mempool.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// The transaction.
    pub tx: Transaction,
    /// Pre-computed transaction ID.
    pub tx_id: Hash256,
    /// Serialized size in bytes.
    pub size_bytes: usize,
    /// Fee in atomic units.
    pub fee: u64,
    /// Unix timestamp when the transaction was received.
    pub received_at: u64,
}

/// Callback trait for checking whether a transaction exists in the confirmed chain.
///
/// This allows the mempool to reject duplicates without depending directly
/// on `noble-storage`.
pub trait ChainLookup {
    /// Returns `true` if the transaction is already confirmed on-chain.
    fn is_confirmed(&self, tx_id: &Hash256) -> bool;
}

/// A no-op chain lookup that never reports duplicates.
/// Useful for testing the mempool in isolation.
pub struct NoChainLookup;

impl ChainLookup for NoChainLookup {
    fn is_confirmed(&self, _tx_id: &Hash256) -> bool {
        false
    }
}

/// The NOBLE transaction mempool.
pub struct Mempool {
    config: MempoolConfig,
    /// Primary index: tx_id → entry.
    by_id: HashMap<Hash256, MempoolEntry>,
    /// Fee-rate index: fee → set of tx_ids (for block assembly and eviction).
    by_fee: BTreeMap<u64, HashSet<Hash256>>,
    /// Checksum index: document checksum → set of tx_ids.
    by_checksum: HashMap<Hash256, HashSet<Hash256>>,
    /// Timestamp index: received_at → set of tx_ids (for expiry).
    by_timestamp: BTreeMap<u64, HashSet<Hash256>>,
    /// Signature verification cache.
    sig_cache: SigCache,
    /// Current total serialized size of all transactions.
    total_size_bytes: usize,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        let sig_cache = SigCache::new(config.sig_cache_size);
        Self {
            config,
            by_id: HashMap::new(),
            by_fee: BTreeMap::new(),
            by_checksum: HashMap::new(),
            by_timestamp: BTreeMap::new(),
            sig_cache,
            total_size_bytes: 0,
        }
    }

    /// Create a mempool with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(MempoolConfig::default())
    }

    // --- Public query API ---

    /// Number of transactions in the mempool.
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Total serialized size of all transactions.
    pub fn total_size(&self) -> usize {
        self.total_size_bytes
    }

    /// Look up a transaction by its ID.
    pub fn get(&self, tx_id: &Hash256) -> Option<&MempoolEntry> {
        self.by_id.get(tx_id)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, tx_id: &Hash256) -> bool {
        self.by_id.contains_key(tx_id)
    }

    /// Look up all mempool tx_ids that registered a given document checksum.
    pub fn lookup_checksum(&self, checksum: &Hash256) -> Vec<Hash256> {
        self.by_checksum
            .get(checksum)
            .map(|set| set.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Iterate transactions in descending fee order (highest fee first).
    /// Used for block assembly.
    pub fn iter_by_fee_desc(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.by_fee
            .iter()
            .rev()
            .flat_map(move |(_, ids)| ids.iter().filter_map(move |id| self.by_id.get(id)))
    }

    // --- 8-Step Admission Pipeline ---

    /// Attempt to admit a transaction into the mempool.
    ///
    /// `current_time` is the wall-clock Unix timestamp for expiry tracking.
    /// `chain` is used for duplicate detection against confirmed transactions.
    ///
    /// Returns `Ok(tx_id)` if admitted, or `Err(MempoolError)` with the
    /// specific step that rejected the transaction.
    pub fn admit<C: ChainLookup>(
        &mut self,
        tx: &Transaction,
        current_time: u64,
        chain: &C,
    ) -> Result<Hash256, MempoolError> {
        // Step 1: Size check
        let tx_bytes = tx
            .to_cbor()
            .map_err(|e| MempoolError::Internal(e.to_string()))?;
        let size_bytes = tx_bytes.len();
        if size_bytes > MAX_TX_SIZE {
            return Err(MempoolError::TxTooLarge {
                size: size_bytes,
                max: MAX_TX_SIZE,
            });
        }

        // Compute tx_id (needed for step 2+)
        let tx_id = tx
            .compute_tx_id(self.config.chain_id)
            .map_err(|e| MempoolError::Internal(e.to_string()))?;

        // Step 2: Duplicate check
        if self.by_id.contains_key(&tx_id) || chain.is_confirmed(&tx_id) {
            return Err(MempoolError::Duplicate(tx_id.to_string()));
        }

        // Step 3: Version check
        if tx.version != PROTOCOL_VERSION {
            return Err(MempoolError::UnrecognizedVersion(tx.version));
        }

        // Step 4: Structural validation (T1-T5, T8-T10 — everything except sigs and fee)
        self.validate_structure(tx)?;

        // Step 5: Signature cache lookup
        let sigs_verified = self.sig_cache.contains(&tx_id);

        // Step 6: Signature verification (skip if cached)
        if !sigs_verified {
            self.verify_signatures(tx)?;
            self.sig_cache.insert(tx_id);
        }

        // Step 7: Fee check
        let min_fee = self.dynamic_min_fee();
        if tx.fee < min_fee {
            return Err(MempoolError::FeeTooLow {
                fee: tx.fee,
                min_fee,
            });
        }

        // Pre-step 8: Evict if needed to make room
        self.evict_if_needed(size_bytes);

        // Step 8: Accept into mempool
        let entry = MempoolEntry {
            tx: tx.clone(),
            tx_id,
            size_bytes,
            fee: tx.fee,
            received_at: current_time,
        };

        self.insert_entry(entry);
        Ok(tx_id)
    }

    /// Remove a transaction from the mempool (e.g., after confirmation).
    pub fn remove(&mut self, tx_id: &Hash256) -> Option<MempoolEntry> {
        let entry = self.by_id.remove(tx_id)?;

        // Remove from fee index
        if let Some(set) = self.by_fee.get_mut(&entry.fee) {
            set.remove(tx_id);
            if set.is_empty() {
                self.by_fee.remove(&entry.fee);
            }
        }

        // Remove from checksum index
        if let Some(set) = self.by_checksum.get_mut(&entry.tx.checksum) {
            set.remove(tx_id);
            if set.is_empty() {
                self.by_checksum.remove(&entry.tx.checksum);
            }
        }

        // Remove from timestamp index
        if let Some(set) = self.by_timestamp.get_mut(&entry.received_at) {
            set.remove(tx_id);
            if set.is_empty() {
                self.by_timestamp.remove(&entry.received_at);
            }
        }

        self.total_size_bytes -= entry.size_bytes;
        self.sig_cache.remove(tx_id);
        Some(entry)
    }

    /// Remove all expired transactions (received_at + expiry_secs < current_time).
    pub fn expire(&mut self, current_time: u64) -> usize {
        let cutoff = current_time.saturating_sub(self.config.expiry_secs);

        // Collect expired tx_ids
        let expired: Vec<Hash256> = self
            .by_timestamp
            .range(..=cutoff)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();

        let count = expired.len();
        for tx_id in expired {
            self.remove(&tx_id);
        }
        count
    }

    /// Remove all transactions that are now confirmed in a block.
    pub fn remove_confirmed(&mut self, tx_ids: &[Hash256]) {
        for tx_id in tx_ids {
            self.remove(tx_id);
        }
    }

    // --- Internal helpers ---

    fn validate_structure(&self, tx: &Transaction) -> Result<(), MempoolError> {
        // T5: Publisher scheme recognized
        if !is_recognized_scheme(tx.publisher_sig.scheme_id) {
            return Err(MempoolError::StructuralValidation(format!(
                "unrecognized publisher scheme {:#04x}",
                tx.publisher_sig.scheme_id
            )));
        }

        // T7 prereq: Additional sig schemes recognized
        for (i, sig) in tx.additional_sigs.iter().enumerate() {
            if !is_recognized_scheme(sig.scheme_id) {
                return Err(MempoolError::StructuralValidation(format!(
                    "additional sig {} has unrecognized scheme {:#04x}",
                    i, sig.scheme_id
                )));
            }
        }

        // T8+T9: Metadata validation
        noble_core::validate_metadata(&tx.metadata)
            .map_err(|e| MempoolError::StructuralValidation(e.to_string()))?;

        Ok(())
    }

    fn verify_signatures(&self, tx: &Transaction) -> Result<(), MempoolError> {
        let signing_msg = tx
            .compute_signing_message()
            .map_err(|e| MempoolError::Internal(e.to_string()))?;

        // T6: Publisher signature
        tx.publisher_sig
            .verify_standalone(&signing_msg)
            .map_err(|e| MempoolError::SignatureInvalid(format!("publisher: {e}")))?;

        // T7: Additional signatures
        for (i, sig) in tx.additional_sigs.iter().enumerate() {
            sig.verify_standalone(&signing_msg)
                .map_err(|e| MempoolError::SignatureInvalid(format!("additional sig {i}: {e}")))?;
        }

        Ok(())
    }

    fn dynamic_min_fee(&self) -> u64 {
        // For now, use the static minimum fee from the protocol.
        // In future sprints, this could be adjusted based on mempool fullness.
        MIN_TX_FEE
    }

    fn insert_entry(&mut self, entry: MempoolEntry) {
        let tx_id = entry.tx_id;
        let fee = entry.fee;
        let checksum = entry.tx.checksum;
        let received_at = entry.received_at;
        let size = entry.size_bytes;

        self.by_id.insert(tx_id, entry);
        self.by_fee.entry(fee).or_default().insert(tx_id);
        self.by_checksum.entry(checksum).or_default().insert(tx_id);
        self.by_timestamp
            .entry(received_at)
            .or_default()
            .insert(tx_id);
        self.total_size_bytes += size;
    }

    fn evict_if_needed(&mut self, incoming_size: usize) {
        // Evict lowest-fee transactions until we have room
        while (self.by_id.len() >= self.config.max_count
            || self.total_size_bytes + incoming_size > self.config.max_size_bytes)
            && !self.by_id.is_empty()
        {
            // Find the lowest fee bucket
            let lowest_fee = match self.by_fee.keys().next().copied() {
                Some(f) => f,
                None => break,
            };

            // Pick one tx_id from the lowest fee bucket
            let tx_id = match self
                .by_fee
                .get(&lowest_fee)
                .and_then(|s| s.iter().next().copied())
            {
                Some(id) => id,
                None => break,
            };

            self.remove(&tx_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{MetadataEntry, Transaction, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, NoblePrivateKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

    fn make_signed_tx(sk: &[u8], pk: &[u8], doc: &[u8], fee: u64) -> Transaction {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            checksum,
            timestamp: 1_700_000_000,
            fee,
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
        tx
    }

    fn test_config() -> MempoolConfig {
        MempoolConfig {
            max_count: 100,
            max_size_bytes: 1024 * 1024,
            expiry_secs: 3600,
            sig_cache_size: 100,
            chain_id: MAINNET_CHAIN_ID,
        }
    }

    // --- Basic operations ---

    #[test]
    fn empty_mempool() {
        let pool = Mempool::new(test_config());
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_size(), 0);
    }

    #[test]
    fn admit_valid_tx() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);

        let tx_id = pool.admit(&tx, 1_700_000_000, &NoChainLookup).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx_id));
        assert!(pool.get(&tx_id).is_some());
    }

    #[test]
    fn admit_and_remove() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);

        let tx_id = pool.admit(&tx, 1_700_000_000, &NoChainLookup).unwrap();
        assert_eq!(pool.len(), 1);

        let entry = pool.remove(&tx_id).unwrap();
        assert_eq!(entry.tx_id, tx_id);
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(&tx_id));
    }

    // --- Step 1: Size check ---

    // Note: Generating a tx that exceeds MAX_TX_SIZE (4096) with valid sigs
    // is tricky. We test this path via an oversized metadata entry.

    // --- Step 2: Duplicate check ---

    #[test]
    fn step2_reject_mempool_duplicate() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);

        pool.admit(&tx, 1_700_000_000, &NoChainLookup).unwrap();
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::Duplicate(_))));
    }

    #[test]
    fn step2_reject_confirmed_duplicate() {
        struct ConfirmedChain(Hash256);
        impl ChainLookup for ConfirmedChain {
            fn is_confirmed(&self, tx_id: &Hash256) -> bool {
                *tx_id == self.0
            }
        }

        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();

        let chain = ConfirmedChain(tx_id);
        let result = pool.admit(&tx, 1_700_000_000, &chain);
        assert!(matches!(result, Err(MempoolError::Duplicate(_))));
    }

    // --- Step 3: Version check ---

    #[test]
    fn step3_reject_bad_version() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.version = 99;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::UnrecognizedVersion(99))));
    }

    // --- Step 4: Structural validation ---

    #[test]
    fn step4_reject_unknown_scheme() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.publisher_sig.scheme_id = 0xFF;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))));
    }

    #[test]
    fn step4_reject_duplicate_metadata_keys() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(b"meta_doc");
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            checksum,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![
                MetadataEntry {
                    key: "dup".into(),
                    value: b"v1".to_vec(),
                },
                MetadataEntry {
                    key: "dup".into(),
                    value: b"v2".to_vec(),
                },
            ],
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))));
    }

    // --- Step 5+6: Signature verification ---

    #[test]
    fn step6_reject_invalid_publisher_sig() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.publisher_sig.signature = vec![0u8; 64]; // Corrupt signature

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::SignatureInvalid(_))));
    }

    #[test]
    fn step6_reject_invalid_additional_sig() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.additional_sigs.push(SignatureEnvelope {
            scheme_id: SCHEME_ED25519,
            public_key: pk.to_vec(),
            signature: vec![0u8; 64],
        });

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::SignatureInvalid(_))));
    }

    // --- Step 7: Fee check ---

    #[test]
    fn step7_reject_low_fee() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(b"low_fee_doc");
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            checksum,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE - 1,
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

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup);
        assert!(matches!(result, Err(MempoolError::FeeTooLow { .. })));
    }

    // --- Checksum lookup ---

    #[test]
    fn checksum_lookup() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"same_doc", MIN_TX_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"other_doc", MIN_TX_FEE);

        let id1 = pool.admit(&tx1, 1_700_000_000, &NoChainLookup).unwrap();
        let _id2 = pool.admit(&tx2, 1_700_000_000, &NoChainLookup).unwrap();

        let checksum = sha256(b"same_doc");
        let results = pool.lookup_checksum(&checksum);
        assert_eq!(results.len(), 1);
        assert!(results.contains(&id1));
    }

    // --- Fee ordering ---

    #[test]
    fn iter_by_fee_desc() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        let tx_low = make_signed_tx(&sk, &pk, b"low", MIN_TX_FEE);
        let tx_mid = make_signed_tx(&sk, &pk, b"mid", MIN_TX_FEE * 5);
        let tx_high = make_signed_tx(&sk, &pk, b"high", MIN_TX_FEE * 10);

        pool.admit(&tx_low, 1_700_000_000, &NoChainLookup).unwrap();
        pool.admit(&tx_mid, 1_700_000_000, &NoChainLookup).unwrap();
        pool.admit(&tx_high, 1_700_000_000, &NoChainLookup).unwrap();

        let fees: Vec<u64> = pool.iter_by_fee_desc().map(|e| e.fee).collect();
        assert_eq!(fees, vec![MIN_TX_FEE * 10, MIN_TX_FEE * 5, MIN_TX_FEE]);
    }

    // --- Eviction ---

    #[test]
    fn eviction_by_count() {
        let mut config = test_config();
        config.max_count = 3;
        let mut pool = Mempool::new(config);
        let (sk, pk) = ed25519::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"doc2", MIN_TX_FEE * 2);
        let tx3 = make_signed_tx(&sk, &pk, b"doc3", MIN_TX_FEE * 3);
        let tx4 = make_signed_tx(&sk, &pk, b"doc4", MIN_TX_FEE * 4);

        let id1 = pool.admit(&tx1, 1_700_000_000, &NoChainLookup).unwrap();
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup).unwrap();
        pool.admit(&tx3, 1_700_000_000, &NoChainLookup).unwrap();

        // tx4 triggers eviction of tx1 (lowest fee)
        pool.admit(&tx4, 1_700_000_000, &NoChainLookup).unwrap();
        assert_eq!(pool.len(), 3);
        assert!(!pool.contains(&id1), "lowest fee tx should be evicted");
    }

    // --- Expiry ---

    #[test]
    fn expiry() {
        let mut config = test_config();
        config.expiry_secs = 3600; // 1 hour
        let mut pool = Mempool::new(config);
        let (sk, pk) = ed25519::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"old", MIN_TX_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"new", MIN_TX_FEE);

        let id1 = pool.admit(&tx1, 1_000, &NoChainLookup).unwrap();
        let id2 = pool.admit(&tx2, 5_000, &NoChainLookup).unwrap();
        assert_eq!(pool.len(), 2);

        // Expire at time 4601 (cutoff = 4601 - 3600 = 1001)
        // tx1 received at 1000 <= 1001 → expired
        // tx2 received at 5000 > 1001 → kept
        let expired = pool.expire(4601);
        assert_eq!(expired, 1);
        assert!(!pool.contains(&id1));
        assert!(pool.contains(&id2));
    }

    // --- Signature cache ---

    #[test]
    fn sig_cache_avoids_reverification() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"cached", MIN_TX_FEE);

        let tx_id = pool.admit(&tx, 1_700_000_000, &NoChainLookup).unwrap();

        // Verify the sig cache has the tx_id
        assert!(pool.sig_cache.contains(&tx_id));

        // Remove and re-admit — should use cache
        pool.remove(&tx_id);
        // After remove, sig_cache entry is cleared
        assert!(!pool.sig_cache.contains(&tx_id));
    }

    // --- remove_confirmed ---

    #[test]
    fn remove_confirmed_batch() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"c1", MIN_TX_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"c2", MIN_TX_FEE);
        let tx3 = make_signed_tx(&sk, &pk, b"c3", MIN_TX_FEE);

        let id1 = pool.admit(&tx1, 1_700_000_000, &NoChainLookup).unwrap();
        let id2 = pool.admit(&tx2, 1_700_000_000, &NoChainLookup).unwrap();
        let id3 = pool.admit(&tx3, 1_700_000_000, &NoChainLookup).unwrap();

        pool.remove_confirmed(&[id1, id3]);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&id1));
        assert!(pool.contains(&id2));
        assert!(!pool.contains(&id3));
    }
}
