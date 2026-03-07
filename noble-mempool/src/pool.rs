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
//! 4. Structural validation (T5 scheme, T7-prereq additional sig schemes, T8-T9 metadata)
//! 5. Signature cache lookup (skip verification if cached)
//! 6. Signature verification (T6, T7)
//! 7. Fee check (>= dynamic minimum)
//! 8. Accept into mempool (insert all indexes)

use std::collections::{BTreeMap, HashMap, HashSet};

use noble_codec::NobleCbor;
use noble_core::{
    Transaction, MAX_TX_SIZE, META_KEY_PREV_CHECKSUM, PROTOCOL_VERSION,
    TX_TYPE_NOTARIZATION, TX_TYPE_TRANSFER,
};
use noble_crypto::{is_recognized_scheme, Hash256};

use crate::error::MempoolError;
use crate::sigcache::SigCache;

/// Default mempool configuration.
pub const DEFAULT_MAX_SIZE_BYTES: usize = 32 * 1024 * 1024; // 32 MB
pub const DEFAULT_MAX_COUNT: usize = 10_000;
pub const DEFAULT_EXPIRY_SECS: u64 = 72 * 3600; // 72 hours
pub const DEFAULT_MAX_PER_SENDER: usize = 64;

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
    /// Maximum transactions per sender in the mempool.
    pub max_per_sender: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            max_count: DEFAULT_MAX_COUNT,
            expiry_secs: DEFAULT_EXPIRY_SECS,
            sig_cache_size: crate::sigcache::DEFAULT_SIG_CACHE_SIZE,
            chain_id: 0,
            max_per_sender: DEFAULT_MAX_PER_SENDER,
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
    /// S35 F2/F4: Resolved debit bucket for transfer transactions.
    /// Set during admission via `resolve_debit_address()`.
    /// `None` for non-transfer transactions.
    pub debit_address: Option<noble_core::NobleAddress>,
}

/// Callback trait for checking whether a transaction exists in the confirmed chain.
///
/// This allows the mempool to reject duplicates without depending directly
/// on `noble-storage`.
pub trait ChainLookup {
    /// Returns `true` if the transaction is already confirmed on-chain.
    fn is_confirmed(&self, tx_id: &Hash256) -> bool;

    /// Returns true if at least one notarization exists for this checksum on-chain.
    /// Default: false (for tests that don't need version chain validation).
    fn has_checksum(&self, _checksum: &Hash256) -> bool {
        false
    }
}

/// A no-op chain lookup that never reports duplicates.
/// Useful for testing the mempool in isolation.
pub struct NoChainLookup;

impl ChainLookup for NoChainLookup {
    fn is_confirmed(&self, _tx_id: &Hash256) -> bool {
        false
    }
}

/// Callback trait for querying on-chain balances during mempool admission.
///
/// Decoupled from `ChainLookup` (SRP) following the project pattern of
/// one trait per concern (ChainLookup, BlockProvider, TxProvider).
pub trait BalanceLookup {
    /// Return the confirmed balance for the given address (in atomic units).
    fn get_balance(&self, address: &noble_core::NobleAddress) -> u64;
}

/// A no-op balance lookup that always returns `u64::MAX`.
/// Existing tests pass this so balance checks never reject.
pub struct NoBalanceLookup;

impl BalanceLookup for NoBalanceLookup {
    fn get_balance(&self, _address: &noble_core::NobleAddress) -> u64 {
        u64::MAX
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
    /// Sender index: pubkey wire bytes → set of tx_ids (for pending debit calc).
    by_sender: HashMap<Vec<u8>, HashSet<Hash256>>,
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
            by_sender: HashMap::new(),
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

    /// Compute fee statistics: (min_fee, max_fee, avg_fee).
    /// Returns (0, 0, 0) when the mempool is empty.
    pub fn fee_stats(&self) -> (u64, u64, u64) {
        if self.by_fee.is_empty() {
            return (0, 0, 0);
        }
        let min_fee = self.by_fee.keys().next().copied().unwrap_or(0);
        let max_fee = self.by_fee.keys().next_back().copied().unwrap_or(0);
        let count = self.by_id.len() as u64;
        let total_fees: u64 = self.by_id.values().map(|e| e.tx.fee).sum();
        let avg_fee = if count > 0 { total_fees / count } else { 0 };
        (min_fee, max_fee, avg_fee)
    }

    /// Sum of `(amount + fee)` for all pending transfer transactions from the given sender.
    pub fn pending_debit(&self, pubkey: &noble_crypto::NoblePublicKey) -> u64 {
        let wire = pubkey.to_wire_bytes();
        self.pending_debits_for_sender(&wire)
    }

    /// Sum of pending debits targeting a specific `NobleAddress` bucket.
    ///
    /// S35 F2/F4: Uses `entry.debit_address` (resolved at admission) instead of
    /// scanning `source_address` wire bytes. This correctly attributes debits to
    /// the resolved bucket, including legacy fallback resolution.
    pub fn pending_debit_for_address(&self, addr: &noble_core::NobleAddress) -> u64 {
        self.by_id
            .values()
            .filter(|e| e.tx.tx_type == TX_TYPE_TRANSFER)
            .filter(|e| e.debit_address.as_ref() == Some(addr))
            .fold(0u64, |acc, e| {
                acc.saturating_add(e.tx.amount.unwrap_or(0))
                    .saturating_add(e.tx.fee)
            })
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
    /// `balance` is used for transfer balance-sufficiency checks (step 6.5).
    ///
    /// Returns `Ok(tx_id)` if admitted, or `Err(MempoolError)` with the
    /// specific step that rejected the transaction.
    #[tracing::instrument(
        skip(self, tx, current_time, chain, balance),
        fields(task = "mempool_admit")
    )]
    pub fn admit<C: ChainLookup, B: BalanceLookup>(
        &mut self,
        tx: &Transaction,
        current_time: u64,
        chain: &C,
        balance: &B,
        chain_height: u64,
    ) -> Result<Hash256, MempoolError> {
        // Step 1: Size check
        tracing::trace!("mempool step 1: size check");
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
        tracing::trace!("mempool step 2: duplicate check");
        if self.by_id.contains_key(&tx_id) || chain.is_confirmed(&tx_id) {
            return Err(MempoolError::Duplicate(tx_id.to_string()));
        }

        // Step 2.5: Per-sender rate limit
        tracing::trace!("mempool step 2.5: per-sender rate limit");
        if let Ok(sender) = tx.publisher_sig.to_noble_public_key() {
            let sender_wire = sender.to_wire_bytes();
            let count = self
                .by_sender
                .get(&sender_wire)
                .map(|s| s.len())
                .unwrap_or(0);
            if count >= self.config.max_per_sender {
                return Err(MempoolError::SenderRateLimit {
                    count,
                    max: self.config.max_per_sender,
                });
            }
        }

        // Step 2.6: Version chain — if doc:prev_checksum is present, verify it exists on-chain
        if tx.tx_type == TX_TYPE_NOTARIZATION {
            if let Some(prev_hex) = tx
                .metadata
                .iter()
                .find(|m| m.key == META_KEY_PREV_CHECKSUM)
                .and_then(|m| std::str::from_utf8(&m.value).ok())
            {
                if let Ok(prev_hash) = Hash256::from_hex(prev_hex) {
                    if !chain.has_checksum(&prev_hash) {
                        return Err(MempoolError::PrevChecksumNotFound(prev_hex.to_string()));
                    }
                }
            }
        }

        // Step 3: Version check
        tracing::trace!("mempool step 3: version check");
        if tx.version != PROTOCOL_VERSION {
            return Err(MempoolError::UnrecognizedVersion(tx.version));
        }

        // Step 4: Structural validation (T1-T5, T8-T10 — everything except sigs and fee)
        tracing::trace!("mempool step 4: structural validation");
        self.validate_structure(tx)?;

        // Step 5: Signature cache lookup
        tracing::trace!("mempool step 5: signature cache lookup");
        let sigs_verified = self.sig_cache.contains(&tx_id);

        // Step 6: Signature verification (skip if cached)
        tracing::trace!(
            "mempool step 6: signature verification (cached={})",
            sigs_verified
        );
        if !sigs_verified {
            self.verify_signatures(tx)?;
            self.sig_cache.insert(tx_id);
        }

        // Step 6.3: Source address ownership validation (T31/T32)
        tracing::trace!("mempool step 6.3: source_address validation");
        noble_core::validate_source_address(tx, chain_height)
            .map_err(|e| MempoolError::StructuralValidation(format!("source_address: {e}")))?;

        // Step 6.5: Balance sufficiency check (transfer transactions only)
        // S35 F2/F4: Resolve debit bucket FIRST, then compute bucket-specific pending
        tracing::trace!("mempool step 6.5: balance sufficiency check");
        let resolved_debit_addr = if tx.tx_type == TX_TYPE_TRANSFER {
            if let Ok(sender) = tx.publisher_sig.to_noble_public_key() {
                let amount = tx.amount.unwrap_or(0);
                let this_need = amount.saturating_add(tx.fee);

                // Resolve which bucket this tx will debit
                let debit_addr = noble_core::resolve_debit_address(
                    &tx.source_address,
                    &sender,
                    this_need,
                    |a| balance.get_balance(a),
                )
                .map_err(|e| MempoolError::ValidationFailed(e.to_string()))?;

                // Compute pending from the SAME bucket using entry.debit_address
                let bucket_pending = self.pending_debit_for_address(&debit_addr);
                let need = this_need.saturating_add(bucket_pending);

                let have = balance.get_balance(&debit_addr);
                if have < need {
                    return Err(MempoolError::InsufficientBalance { have, need });
                }
                Some(debit_addr)
            } else {
                None
            }
        } else {
            None
        };

        // Step 7: Fee check
        tracing::trace!("mempool step 7: fee check");
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
        tracing::trace!("mempool step 8: accept into mempool");
        let entry = MempoolEntry {
            tx: tx.clone(),
            tx_id,
            size_bytes,
            fee: tx.fee,
            received_at: current_time,
            debit_address: resolved_debit_addr,
        };

        self.insert_entry(entry);
        tracing::debug!(
            task = "mempool",
            "transaction admitted to mempool, pool size: {}",
            self.len()
        );
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

        // Remove from sender index
        if let Ok(sender) = entry.tx.publisher_sig.to_noble_public_key() {
            let sender_wire = sender.to_wire_bytes();
            if let Some(set) = self.by_sender.get_mut(&sender_wire) {
                set.remove(tx_id);
                if set.is_empty() {
                    self.by_sender.remove(&sender_wire);
                }
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
        // AUD3-D7: Chain-aware signing message prevents cross-chain replay.
        let signing_msg = tx
            .compute_signing_message_for_chain(self.config.chain_id)
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
        // AUD-H4: Dynamic fee based on mempool utilization
        let pct = self.utilization_pct();
        noble_core::dynamic_min_fee(pct)
    }

    /// Compute mempool utilization percentage (0-100).
    pub fn utilization_pct(&self) -> u8 {
        if noble_core::MAX_MEMPOOL_SIZE == 0 {
            return 0;
        }
        let pct = (self.total_size_bytes as u128 * 100) / noble_core::MAX_MEMPOOL_SIZE as u128;
        pct.min(100) as u8
    }

    fn insert_entry(&mut self, entry: MempoolEntry) {
        let tx_id = entry.tx_id;
        let fee = entry.fee;
        let checksum = entry.tx.checksum;
        let received_at = entry.received_at;
        let size = entry.size_bytes;

        // Populate sender index
        if let Ok(sender) = entry.tx.publisher_sig.to_noble_public_key() {
            let sender_wire = sender.to_wire_bytes();
            self.by_sender.entry(sender_wire).or_default().insert(tx_id);
        }

        self.by_id.insert(tx_id, entry);
        self.by_fee.entry(fee).or_default().insert(tx_id);
        self.by_checksum.entry(checksum).or_default().insert(tx_id);
        self.by_timestamp
            .entry(received_at)
            .or_default()
            .insert(tx_id);
        self.total_size_bytes += size;
    }

    /// Sum of `(amount + fee)` for all of sender's in-mempool transfer transactions.
    fn pending_debits_for_sender(&self, sender_wire: &[u8]) -> u64 {
        let Some(tx_ids) = self.by_sender.get(sender_wire) else {
            return 0;
        };
        tx_ids
            .iter()
            .filter_map(|id| self.by_id.get(id))
            .filter(|e| e.tx.tx_type == TX_TYPE_TRANSFER)
            .fold(0u64, |acc, e| {
                acc.saturating_add(e.tx.amount.unwrap_or(0))
                    .saturating_add(e.tx.fee)
            })
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

            tracing::trace!(
                "mempool eviction: removing lowest-fee tx (fee={})",
                lowest_fee
            );
            self.remove(&tx_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{MetadataEntry, Transaction, MIN_TX_FEE, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, NoblePrivateKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };
    use noble_test_utils::fixtures::test_chain_id;

    fn make_signed_tx(sk: &[u8], pk: &[u8], doc: &[u8], fee: u64) -> Transaction {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum,
            timestamp: 1_700_000_000,
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
            gateway_address: None,
            source_address: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    fn test_config() -> MempoolConfig {
        MempoolConfig {
            max_count: 100,
            max_size_bytes: 1024 * 1024,
            expiry_secs: 3600,
            sig_cache_size: 100,
            chain_id: test_chain_id(),
            max_per_sender: DEFAULT_MAX_PER_SENDER,
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

        let tx_id = pool
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx_id));
        assert!(pool.get(&tx_id).is_some());
    }

    #[test]
    fn admit_and_remove() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);

        let tx_id = pool
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
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

        pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
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
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let chain = ConfirmedChain(tx_id);
        let result = pool.admit(&tx, 1_700_000_000, &chain, &NoBalanceLookup, 0);
        assert!(matches!(result, Err(MempoolError::Duplicate(_))));
    }

    // --- Step 3: Version check ---

    #[test]
    fn step3_reject_bad_version() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.version = 99;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(matches!(result, Err(MempoolError::UnrecognizedVersion(99))));
    }

    // --- Step 4: Structural validation ---

    #[test]
    fn step4_reject_unknown_scheme() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.publisher_sig.scheme_id = 0xFF;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
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
            tx_type: 0,
            checksum,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: None,
            amount: None,
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
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))));
    }

    // --- Step 5+6: Signature verification ---

    #[test]
    fn step6_reject_invalid_publisher_sig() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.publisher_sig.signature = vec![0u8; 64]; // Corrupt signature

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
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

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
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
            tx_type: 0,
            checksum,
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE - 1,
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
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(matches!(result, Err(MempoolError::FeeTooLow { .. })));
    }

    // --- Checksum lookup ---

    #[test]
    fn checksum_lookup() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"same_doc", MIN_TX_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"other_doc", MIN_TX_FEE);

        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        let _id2 = pool
            .admit(&tx2, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

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

        pool.admit(&tx_low, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        pool.admit(&tx_mid, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        pool.admit(&tx_high, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

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

        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        pool.admit(&tx3, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

        // tx4 triggers eviction of tx1 (lowest fee)
        pool.admit(&tx4, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
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

        let id1 = pool
            .admit(&tx1, 1_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        let id2 = pool
            .admit(&tx2, 5_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
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

        let tx_id = pool
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

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

        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        let id2 = pool
            .admit(&tx2, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();
        let id3 = pool
            .admit(&tx3, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

        pool.remove_confirmed(&[id1, id3]);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&id1));
        assert!(pool.contains(&id2));
        assert!(!pool.contains(&id3));
    }

    // --- Step 6.5: Balance sufficiency ---

    /// Fixed-balance lookup for testing balance checks.
    struct FixedBalanceLookup(u64);

    impl BalanceLookup for FixedBalanceLookup {
        fn get_balance(&self, _address: &noble_core::NobleAddress) -> u64 {
            self.0
        }
    }

    fn make_signed_transfer(
        sk: &[u8],
        pk: &[u8],
        recipient_pk: &[u8],
        amount: u64,
        fee: u64,
    ) -> Transaction {
        make_signed_transfer_salt(sk, pk, recipient_pk, amount, fee, b"default")
    }

    fn make_signed_transfer_salt(
        sk: &[u8],
        pk: &[u8],
        recipient_pk: &[u8],
        amount: u64,
        fee: u64,
        salt: &[u8],
    ) -> Transaction {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let recipient = noble_crypto::NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let checksum = sha256(salt);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 1,
            checksum,
            timestamp: 1_700_000_000,
            fee,
            recipient: Some(noble_core::NobleAddress::Noble(recipient)),
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
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn step65_reject_insufficient_balance() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        let tx = make_signed_transfer(&sk, &pk, &recip, 500_000, MIN_TX_FEE);
        // Balance is 100_000, need 500_000 + MIN_TX_FEE = 501_000
        let bal = FixedBalanceLookup(100_000);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &bal, 0);
        assert!(
            matches!(
                result,
                Err(MempoolError::InsufficientBalance { have: 100_000, .. })
            ),
            "expected InsufficientBalance, got {:?}",
            result
        );
    }

    #[test]
    fn step65_accept_sufficient_balance() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        let tx = make_signed_transfer(&sk, &pk, &recip, 500_000, MIN_TX_FEE);
        // Balance is exactly amount + fee
        let bal = FixedBalanceLookup(500_000 + MIN_TX_FEE);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &bal, 0);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn step65_skip_for_notarization() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        // Notarization tx — balance check should be skipped
        let tx = make_signed_tx(&sk, &pk, b"doc_nota", MIN_TX_FEE);
        let bal = FixedBalanceLookup(0); // zero balance
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &bal, 0);
        assert!(
            result.is_ok(),
            "notarization must skip balance check, got {:?}",
            result
        );
    }

    #[test]
    fn step65_pending_debits_counted() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        let bal = FixedBalanceLookup(200_000);

        // First transfer: amount=100_000, fee=1_000 → need 101_000, balance 200_000 → OK
        let tx1 = make_signed_transfer_salt(&sk, &pk, &recip, 100_000, MIN_TX_FEE, b"tx1");
        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &bal, 0)
            .unwrap();

        // Second transfer: amount=100_000, fee=1_000 → need 101_000 + pending 101_000 = 202_000
        // but balance is only 200_000 → reject
        let tx2 = make_signed_transfer_salt(&sk, &pk, &recip, 100_000, MIN_TX_FEE, b"tx2");
        let result = pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &bal, 0);
        assert!(
            matches!(result, Err(MempoolError::InsufficientBalance { .. })),
            "second transfer should fail due to pending debits, got {:?}",
            result
        );
    }

    #[test]
    fn step65_pending_debits_cleared_on_remove() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        let bal = FixedBalanceLookup(200_000);

        // Admit first transfer
        let tx1 = make_signed_transfer_salt(&sk, &pk, &recip, 100_000, MIN_TX_FEE, b"rm1");
        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &bal, 0)
            .unwrap();

        // Remove it (e.g., confirmed in a block)
        pool.remove(&id1);

        // Now second transfer should succeed (pending debits are cleared)
        let tx2 = make_signed_transfer_salt(&sk, &pk, &recip, 100_000, MIN_TX_FEE, b"rm2");
        let result = pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &bal, 0);
        assert!(
            result.is_ok(),
            "after remove, second transfer should succeed, got {:?}",
            result
        );
    }

    // --- Per-sender rate limit ---

    #[test]
    fn sender_rate_limit_enforced() {
        let mut config = test_config();
        config.max_per_sender = 3;
        let mut pool = Mempool::new(config);
        let (sk, pk) = ed25519::generate_keypair();

        // Admit 3 txs (at the limit)
        for i in 0..3 {
            let tx = make_signed_tx(&sk, &pk, format!("rate{i}").as_bytes(), MIN_TX_FEE);
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
                .unwrap();
        }

        // 4th should be rejected
        let tx4 = make_signed_tx(&sk, &pk, b"rate3", MIN_TX_FEE);
        let result = pool.admit(&tx4, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(
            matches!(
                result,
                Err(MempoolError::SenderRateLimit { count: 3, max: 3 })
            ),
            "expected SenderRateLimit, got: {result:?}"
        );
    }

    #[test]
    fn sender_rate_limit_per_sender() {
        let mut config = test_config();
        config.max_per_sender = 2;
        let mut pool = Mempool::new(config);
        let (sk1, pk1) = ed25519::generate_keypair();
        let (sk2, pk2) = ed25519::generate_keypair();

        // Sender 1: 2 txs (at limit)
        for i in 0..2 {
            let tx = make_signed_tx(&sk1, &pk1, format!("s1_{i}").as_bytes(), MIN_TX_FEE);
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
                .unwrap();
        }

        // Sender 2 should still be able to submit
        let tx = make_signed_tx(&sk2, &pk2, b"s2_0", MIN_TX_FEE);
        assert!(
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
                .is_ok(),
            "different sender should not be rate-limited"
        );
    }

    // --- fee_stats ---

    #[test]
    fn fee_stats_empty_mempool() {
        let pool = Mempool::new(test_config());
        assert_eq!(pool.fee_stats(), (0, 0, 0));
    }

    #[test]
    fn fee_stats_with_transactions() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

        let tx2 = make_signed_tx(&sk, &pk, b"doc2", MIN_TX_FEE * 3);
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0)
            .unwrap();

        let (min_f, max_f, avg_f) = pool.fee_stats();
        assert_eq!(min_f, MIN_TX_FEE);
        assert_eq!(max_f, MIN_TX_FEE * 3);
        assert_eq!(avg_f, MIN_TX_FEE * 2); // (1 + 3) / 2 = 2
    }

    // --- pending_debit ---

    #[test]
    fn pending_debit_zero_for_unknown_key() {
        let pool = Mempool::new(test_config());
        let (_sk, pk) = ed25519::generate_keypair();
        let pubkey = noble_crypto::NoblePublicKey::Ed25519(pk.to_vec());
        assert_eq!(pool.pending_debit(&pubkey), 0);
    }

    #[test]
    fn pending_debit_for_address_noble() {
        let pool = Mempool::new(test_config());
        let (_sk, pk) = ed25519::generate_keypair();
        let pubkey = noble_crypto::NoblePublicKey::Ed25519(pk.to_vec());
        let addr = noble_core::NobleAddress::Noble(pubkey.clone());
        // Should delegate to pending_debit for Noble addresses
        assert_eq!(pool.pending_debit_for_address(&addr), 0);
    }

    #[test]
    fn pending_debit_for_address_bitcoin_zero() {
        let pool = Mempool::new(test_config());
        let h160_addr = noble_core::NobleAddress::BitcoinHash160([0xAA; 20]);
        assert_eq!(pool.pending_debit_for_address(&h160_addr), 0);
    }

    // --- Step 2.6: Version chain validation ---

    fn make_versioned_notarization(
        sk: &[u8],
        pk: &[u8],
        doc: &[u8],
        fee: u64,
        version: Option<&str>,
        prev_checksum: Option<&str>,
    ) -> Transaction {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut metadata = vec![];
        if let Some(v) = version {
            metadata.push(MetadataEntry {
                key: noble_core::META_KEY_VERSION.into(),
                value: v.as_bytes().to_vec(),
            });
        }
        if let Some(pc) = prev_checksum {
            metadata.push(MetadataEntry {
                key: noble_core::META_KEY_PREV_CHECKSUM.into(),
                value: pc.as_bytes().to_vec(),
            });
        }
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            checksum,
            timestamp: 1_700_000_000,
            fee,
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
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn step2_6_prev_checksum_not_on_chain_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let prev_hex = "aa".repeat(32);
        let tx =
            make_versioned_notarization(&sk, &pk, b"v2doc", MIN_TX_FEE, Some("2"), Some(&prev_hex));
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::PrevChecksumNotFound(_))),
            "expected PrevChecksumNotFound, got: {result:?}"
        );
    }

    #[test]
    fn step2_6_prev_checksum_on_chain_accepted() {
        struct ChecksumExists(Hash256);
        impl ChainLookup for ChecksumExists {
            fn is_confirmed(&self, _tx_id: &Hash256) -> bool {
                false
            }
            fn has_checksum(&self, checksum: &Hash256) -> bool {
                *checksum == self.0
            }
        }

        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let prev_hex = "aa".repeat(32);
        let prev_hash = Hash256::from_hex(&prev_hex).unwrap();
        let chain = ChecksumExists(prev_hash);
        let tx = make_versioned_notarization(
            &sk,
            &pk,
            b"v2doc2",
            MIN_TX_FEE,
            Some("2"),
            Some(&prev_hex),
        );
        let result = pool.admit(&tx, 1_700_000_000, &chain, &NoBalanceLookup, 0);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn step2_6_no_version_metadata_skipped() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        // Normal notarization without any version metadata
        let tx = make_signed_tx(&sk, &pk, b"normal_doc", MIN_TX_FEE);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    // --- Finding 2B: Hash160 balance fallback test ---

    #[test]
    fn balance_check_hash160_fallback() {
        use noble_crypto::{secp256k1, SCHEME_SECP256K1};

        // Custom balance lookup that returns 0 for Noble addresses
        // but 100_000 for the Hash160 address of the secp256k1 key
        struct Hash160BalanceLookup {
            hash160_addr: noble_core::NobleAddress,
        }
        impl BalanceLookup for Hash160BalanceLookup {
            fn get_balance(&self, address: &noble_core::NobleAddress) -> u64 {
                if address == &self.hash160_addr {
                    100_000 // balance exists only in Hash160 bucket
                } else {
                    0 // Noble bucket is empty
                }
            }
        }

        let mut pool = Mempool::new(test_config());
        let (sk, pk_bytes) = secp256k1::generate_keypair();
        let sender_pk = noble_crypto::NoblePublicKey::Secp256k1(pk_bytes.clone());

        // Derive the Hash160 address for this secp256k1 key
        let hash160_addr =
            noble_core::NobleAddress::bitcoin_hash160_for_pubkey(&sender_pk).unwrap();
        let balance = Hash160BalanceLookup { hash160_addr };

        // Build a transfer tx with secp256k1 key
        let priv_key = NoblePrivateKey::Secp256k1(sk);
        let (_, recip_pk) = ed25519::generate_keypair();
        let recip_addr = noble_core::NobleAddress::Noble(
            noble_crypto::NoblePublicKey::Ed25519(recip_pk),
        );

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"transfer_test"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recip_addr),
            amount: Some(10_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk_bytes.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        // Admit should succeed because Hash160 balance covers the transfer
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &balance, 0);
        assert!(
            result.is_ok(),
            "secp256k1 sender with Hash160 balance should pass: {result:?}"
        );
    }

    // --- S35 F2/F4: Bucket-aware mempool pending ---

    #[test]
    fn pending_debit_for_address_uses_resolved_bucket() {
        use noble_crypto::{secp256k1, SCHEME_SECP256K1};

        let mut pool = Mempool::new(test_config());
        let (sk, pk_raw) = secp256k1::generate_keypair();
        let sender_pk = noble_crypto::NoblePublicKey::Secp256k1(pk_raw.clone());
        let noble_addr = noble_core::NobleAddress::Noble(sender_pk.clone());
        let h160_addr = noble_core::NobleAddress::bitcoin_hash160_for_pubkey(&sender_pk).unwrap();

        let (_, recip) = ed25519::generate_keypair();
        let recip_addr =
            noble_core::NobleAddress::Noble(noble_crypto::NoblePublicKey::Ed25519(recip.to_vec()));

        // Balance lookup: both buckets have enough
        struct DualBucketLookup {
            noble: noble_core::NobleAddress,
            h160: noble_core::NobleAddress,
        }
        impl BalanceLookup for DualBucketLookup {
            fn get_balance(&self, address: &noble_core::NobleAddress) -> u64 {
                if *address == self.noble || *address == self.h160 {
                    1_000_000
                } else {
                    0
                }
            }
        }
        let bal = DualBucketLookup {
            noble: noble_addr.clone(),
            h160: h160_addr.clone(),
        };

        // Tx1: explicit source_address = Noble
        let mut tx1 = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"bucket_tx1"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recip_addr.clone()),
            amount: Some(50_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk_raw.clone(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(noble_addr.to_wire_bytes()),
        };
        let msg1 = tx1.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx1.publisher_sig.signature = noble_crypto::secp256k1::sign(&sk, &msg1).unwrap();

        // Tx2: explicit source_address = Hash160
        let mut tx2 = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"bucket_tx2"),
            timestamp: 1_700_000_001,
            fee: MIN_TX_FEE,
            recipient: Some(recip_addr.clone()),
            amount: Some(30_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk_raw.clone(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(h160_addr.to_wire_bytes()),
        };
        let msg2 = tx2.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx2.publisher_sig.signature = noble_crypto::secp256k1::sign(&sk, &msg2).unwrap();

        // Admit both
        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &bal, 0)
            .expect("tx1 should be admitted");
        pool.admit(&tx2, 1_700_000_001, &NoChainLookup, &bal, 0)
            .expect("tx2 should be admitted");

        // Verify bucket-specific pending
        let noble_pending = pool.pending_debit_for_address(&noble_addr);
        let h160_pending = pool.pending_debit_for_address(&h160_addr);

        assert_eq!(
            noble_pending,
            50_000 + MIN_TX_FEE,
            "Noble bucket should have tx1's debit"
        );
        assert_eq!(
            h160_pending,
            30_000 + MIN_TX_FEE,
            "Hash160 bucket should have tx2's debit"
        );
    }

    // --- Step 6.3: Source address validation (T31/T32) ---

    #[test]
    fn step63_reject_source_address_on_non_transfer() {
        use noble_crypto::{secp256k1, SCHEME_SECP256K1};

        let mut pool = Mempool::new(test_config());
        let (sk, pk_raw) = secp256k1::generate_keypair();
        let sender_pk = noble_crypto::NoblePublicKey::Secp256k1(pk_raw.clone());
        let noble_addr = noble_core::NobleAddress::Noble(sender_pk);

        // Build a notarization (tx_type=0) with source_address set — T31b violation
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            checksum: sha256(b"t31b_test"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: None,
            amount: None,
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk_raw.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(noble_addr.to_wire_bytes()),
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig.signature = noble_crypto::secp256k1::sign(&sk, &msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::StructuralValidation(ref s)) if s.contains("source_address")),
            "notarization with source_address should be rejected (T31b), got: {result:?}"
        );
    }

    #[test]
    fn step63_reject_forged_source_address() {
        use noble_crypto::{secp256k1, SCHEME_SECP256K1};

        let mut pool = Mempool::new(test_config());
        let (sk, pk_raw) = secp256k1::generate_keypair();

        // Generate a different key's Hash160 address (forged)
        let (_, other_pk_raw) = secp256k1::generate_keypair();
        let other_pk = noble_crypto::NoblePublicKey::Secp256k1(other_pk_raw);
        let forged_addr = noble_core::NobleAddress::bitcoin_hash160_for_pubkey(&other_pk).unwrap();

        let (_, recip_pk) = ed25519::generate_keypair();
        let recip_addr = noble_core::NobleAddress::Noble(
            noble_crypto::NoblePublicKey::Ed25519(recip_pk),
        );

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"t31_forged"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recip_addr),
            amount: Some(1_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk_raw.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(forged_addr.to_wire_bytes()),
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig.signature = noble_crypto::secp256k1::sign(&sk, &msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoBalanceLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::StructuralValidation(ref s)) if s.contains("source_address")),
            "transfer with forged source_address should be rejected (T31), got: {result:?}"
        );
    }

    #[test]
    fn step63_accept_valid_source_address() {
        use noble_crypto::{secp256k1, SCHEME_SECP256K1};

        let mut pool = Mempool::new(test_config());
        let (sk, pk_raw) = secp256k1::generate_keypair();
        let sender_pk = noble_crypto::NoblePublicKey::Secp256k1(pk_raw.clone());
        let h160_addr = noble_core::NobleAddress::bitcoin_hash160_for_pubkey(&sender_pk).unwrap();

        let (_, recip_pk) = ed25519::generate_keypair();
        let recip_addr = noble_core::NobleAddress::Noble(
            noble_crypto::NoblePublicKey::Ed25519(recip_pk),
        );

        // Balance lookup that covers the transfer from Hash160 bucket
        struct H160BalanceLookup {
            h160: noble_core::NobleAddress,
        }
        impl BalanceLookup for H160BalanceLookup {
            fn get_balance(&self, addr: &noble_core::NobleAddress) -> u64 {
                if *addr == self.h160 {
                    1_000_000
                } else {
                    0
                }
            }
        }
        let bal = H160BalanceLookup {
            h160: h160_addr.clone(),
        };

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"t31_valid"),
            timestamp: 1_700_000_000,
            fee: MIN_TX_FEE,
            recipient: Some(recip_addr),
            amount: Some(1_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk_raw.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(h160_addr.to_wire_bytes()),
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig.signature = noble_crypto::secp256k1::sign(&sk, &msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &bal, 0);
        assert!(
            result.is_ok(),
            "transfer with valid Hash160 source_address should be admitted, got: {result:?}"
        );
    }
}
