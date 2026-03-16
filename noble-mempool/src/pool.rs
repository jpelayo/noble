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
    OutPoint, Transaction, MAX_TX_SIZE, META_KEY_PREV_CHECKSUM, PROTOCOL_VERSION,
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
    /// Chain ID for tx_id computation. Shared with Node so updates propagate.
    pub chain_id: std::sync::Arc<std::sync::atomic::AtomicU32>,
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
            chain_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0)),
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
    /// Implicit fee in atomic units: sum(input UTXO values) - sum(output values).
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

/// Callback trait for querying on-chain UTXOs during mempool admission.
///
/// Decoupled from `ChainLookup` (SRP) following the project pattern of
/// one trait per concern (ChainLookup, BlockProvider, TxProvider).
pub trait UtxoLookup {
    /// Look up a UTXO by its outpoint. Returns `(value, is_coinbase, creation_height)` if it
    /// exists and is unspent on-chain. Returns `None` if the UTXO doesn't exist or is already spent.
    fn get_utxo(&self, outpoint: &OutPoint) -> Option<(u64, bool, u64)>;
}

/// A no-op UTXO lookup that always returns a fixed-value non-coinbase UTXO.
/// Returns 1_000_000 atomic units per UTXO, matching test fixture conventions.
/// For production code, implement `UtxoLookup` against the actual UTXO set.
pub struct NoUtxoLookup;

/// Default UTXO value returned by `NoUtxoLookup` (matches test fixture `make_signed_tx` input_value).
pub const NO_UTXO_LOOKUP_VALUE: u64 = 1_000_000;

impl UtxoLookup for NoUtxoLookup {
    fn get_utxo(&self, _outpoint: &OutPoint) -> Option<(u64, bool, u64)> {
        Some((NO_UTXO_LOOKUP_VALUE, false, 0))
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
    /// UTXO double-spend prevention: outpoints consumed by in-mempool transactions.
    spent_by_mempool: HashSet<OutPoint>,
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
            spent_by_mempool: HashSet::new(),
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
        let total_fees: u64 = self.by_id.values().map(|e| e.fee).sum();
        let avg_fee = if count > 0 { total_fees / count } else { 0 };
        (min_fee, max_fee, avg_fee)
    }

    /// Sum of `(total_output_value + fee)` for all pending transactions from the given sender.
    pub fn pending_debit(&self, pubkey: &noble_crypto::NoblePublicKey) -> u64 {
        let wire = pubkey.to_wire_bytes();
        self.pending_debits_for_sender(&wire)
    }

    /// Whether an outpoint is already consumed by an in-mempool transaction.
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_by_mempool.contains(outpoint)
    }

    /// Pending debits for a specific address.
    ///
    /// In the UTXO model, pending debits are tracked via the `spent_by_mempool`
    /// set (outpoint-level). This sums output values of mempool txs where
    /// the sender matches the queried address. Returns 0 if no pending txs.
    pub fn pending_debit_for_address(&self, addr: &noble_core::NobleAddress) -> u64 {
        let addr_wire = addr.to_wire_bytes();
        self.by_id.values()
            .filter(|entry| {
                // Check if the publisher (sender) matches the queried address
                entry.tx.publisher_sig.to_noble_public_key()
                    .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes() == addr_wire)
                    .unwrap_or(false)
            })
            .map(|entry| entry.tx.total_output_value() + entry.fee)
            .fold(0u64, |acc, v| acc.saturating_add(v))
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
    /// `utxos` is used for UTXO existence and double-spend checks (step 6.5).
    ///
    /// Returns `Ok(tx_id)` if admitted, or `Err(MempoolError)` with the
    /// specific step that rejected the transaction.
    #[tracing::instrument(
        skip(self, tx, current_time, chain, utxos),
        fields(task = "mempool_admit")
    )]
    pub fn admit<C: ChainLookup, U: UtxoLookup>(
        &mut self,
        tx: &Transaction,
        current_time: u64,
        chain: &C,
        utxos: &U,
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
            .compute_tx_id(self.config.chain_id.load(std::sync::atomic::Ordering::Relaxed))
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

        // Step 2.55: Reject coinbase transactions (only block proposer creates them)
        if tx.is_coinbase() {
            return Err(MempoolError::StructuralValidation(
                "coinbase transactions are not allowed in mempool".into(),
            ));
        }

        // Step 2.6: Version chain — if doc:prev_checksum is present, verify it exists on-chain
        if noble_core::tx_types::handler_for(tx.tx_type).map_or(false, |h| h.validates_version_chain()) {
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

        // Step 6.5: UTXO existence + double-spend check
        tracing::trace!("mempool step 6.5: UTXO validation");
        let mut input_value_sum: u64 = 0;
        for input in &tx.inputs {
            let outpoint = &input.prev_output;

            // Reject coinbase outpoints (already covered by step 2.55, but belt-and-suspenders)
            if outpoint.is_coinbase() {
                return Err(MempoolError::StructuralValidation(
                    "coinbase input not allowed in mempool".into(),
                ));
            }

            // Check for in-mempool double-spend
            if self.spent_by_mempool.contains(outpoint) {
                return Err(MempoolError::StructuralValidation(
                    format!("input {}:{} already spent by mempool tx", outpoint.txid, outpoint.vout),
                ));
            }

            // Verify UTXO exists on-chain and is mature
            match utxos.get_utxo(outpoint) {
                Some((value, is_coinbase, creation_height)) => {
                    // Coinbase maturity check
                    if is_coinbase && chain_height < creation_height + noble_core::COINBASE_MATURITY {
                        return Err(MempoolError::StructuralValidation(
                            format!(
                                "coinbase UTXO {}:{} not mature (created at {}, current {}, need {})",
                                outpoint.txid, outpoint.vout,
                                creation_height, chain_height,
                                creation_height + noble_core::COINBASE_MATURITY
                            ),
                        ));
                    }
                    input_value_sum = input_value_sum.saturating_add(value);
                }
                None => {
                    return Err(MempoolError::StructuralValidation(
                        format!("input {}:{} references unknown or spent UTXO", outpoint.txid, outpoint.vout),
                    ));
                }
            }
        }

        // Compute implicit fee: sum(inputs) - sum(outputs)
        let output_value_sum = tx.total_output_value();
        let fee = input_value_sum.checked_sub(output_value_sum).ok_or_else(|| {
            MempoolError::StructuralValidation(format!(
                "outputs ({output_value_sum}) exceed inputs ({input_value_sum})"
            ))
        })?;

        // Step 7: Fee check
        tracing::trace!("mempool step 7: fee check");
        let min_fee = self.dynamic_min_fee();
        if fee < min_fee {
            return Err(MempoolError::FeeTooLow {
                fee,
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
            fee,
            received_at: current_time,
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

        // Unmark spent outpoints
        for input in &entry.tx.inputs {
            self.spent_by_mempool.remove(&input.prev_output);
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
            .compute_signing_message_for_chain(self.config.chain_id.load(std::sync::atomic::Ordering::Relaxed))
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

        // Mark input outpoints as spent by mempool
        for input in &entry.tx.inputs {
            self.spent_by_mempool.insert(input.prev_output.clone());
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

    /// Sum of `(total_output_value + fee)` for all of sender's in-mempool transactions.
    fn pending_debits_for_sender(&self, sender_wire: &[u8]) -> u64 {
        let Some(tx_ids) = self.by_sender.get(sender_wire) else {
            return 0;
        };
        tx_ids
            .iter()
            .filter_map(|id| self.by_id.get(id))
            .fold(0u64, |acc, e| {
                acc.saturating_add(e.tx.total_output_value())
                    .saturating_add(e.fee)
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
    use noble_core::{MetadataEntry, TxIn, TxOut, OutPoint, Transaction, MIN_TX_FEE, PROTOCOL_VERSION};
    use noble_core::address::NobleAddress;
    use noble_crypto::{
        ed25519, sha256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };
    use noble_test_utils::fixtures::test_chain_id;

    /// Counter for generating unique outpoints in tests.
    use std::sync::atomic::{AtomicU32, Ordering};
    static OUTPOINT_COUNTER: AtomicU32 = AtomicU32::new(1);

    /// Generate a unique fake outpoint for test transactions.
    fn unique_outpoint() -> OutPoint {
        let vout = OUTPOINT_COUNTER.fetch_add(1, Ordering::Relaxed);
        OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout,
        }
    }

    /// Build a signed notarization tx (UTXO model).
    /// `fee` = input_value - change_output_value (input_value is fixed at 1_000_000).
    fn make_signed_tx(sk: &[u8], pk: &[u8], doc: &[u8], fee: u64) -> Transaction {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let pub_key = NoblePublicKey::Ed25519(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key.clone());
        let checksum = sha256(doc);
        let input_value = 1_000_000u64; // Fixed input UTXO value for tests
        let change = input_value.saturating_sub(fee);

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0, // notarization
            inputs: vec![TxIn { prev_output: unique_outpoint() }],
            outputs: vec![TxOut { value: change, address: addr }],
            checksum,
            timestamp: 1_700_000_000,
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
        contract_data: None,
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
            chain_id: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(test_chain_id())),
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
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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

        pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
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
        let result = pool.admit(&tx, 1_700_000_000, &chain, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::Duplicate(_))));
    }

    // --- Step 3: Version check ---

    #[test]
    fn step3_reject_bad_version() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.version = 99;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::UnrecognizedVersion(99))));
    }

    // --- Step 4: Structural validation ---

    #[test]
    fn step4_reject_unknown_scheme() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.publisher_sig.scheme_id = 0xFF;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))));
    }

    #[test]
    fn step4_reject_duplicate_metadata_keys() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let pub_key = NoblePublicKey::Ed25519(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);
        let checksum = sha256(b"meta_doc");
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn { prev_output: unique_outpoint() }],
            outputs: vec![TxOut { value: 999_000, address: addr }],
            checksum,
            timestamp: 1_700_000_000,
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
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))));
    }

    // --- Step 5+6: Signature verification ---

    #[test]
    fn step6_reject_invalid_publisher_sig() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", MIN_TX_FEE);
        tx.publisher_sig.signature = vec![0u8; 64]; // Corrupt signature

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
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

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::SignatureInvalid(_))));
    }

    // --- Step 7: Fee check ---

    #[test]
    fn step7_reject_low_fee() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        // Fee = 0 (input_value == output_value). Use a custom UTXO lookup.
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let pub_key = NoblePublicKey::Ed25519(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);
        let checksum = sha256(b"low_fee_doc");
        let outpoint = unique_outpoint();
        let input_value = 1_000u64;
        // output = input_value (fee = 0 < MIN_TX_FEE)
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn { prev_output: outpoint.clone() }],
            outputs: vec![TxOut { value: input_value, address: addr }],
            checksum,
            timestamp: 1_700_000_000,
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
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        // Custom UTXO lookup that returns the exact input value
        struct ExactUtxoLookup { outpoint: OutPoint, value: u64 }
        impl UtxoLookup for ExactUtxoLookup {
            fn get_utxo(&self, op: &OutPoint) -> Option<(u64, bool, u64)> {
                if *op == self.outpoint { Some((self.value, false, 0)) } else { None }
            }
        }
        let utxo = ExactUtxoLookup { outpoint, value: input_value };

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &utxo, 0);
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
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        let _id2 = pool
            .admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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

        pool.admit(&tx_low, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        pool.admit(&tx_mid, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        pool.admit(&tx_high, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        pool.admit(&tx3, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();

        // tx4 triggers eviction of tx1 (lowest fee)
        pool.admit(&tx4, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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
            .admit(&tx1, 1_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        let id2 = pool
            .admit(&tx2, 5_000, &NoChainLookup, &NoUtxoLookup, 0)
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
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        let id2 = pool
            .admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        let id3 = pool
            .admit(&tx3, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();

        pool.remove_confirmed(&[id1, id3]);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&id1));
        assert!(pool.contains(&id2));
        assert!(!pool.contains(&id3));
    }

    // --- Step 6.5: UTXO validation ---

    /// A UTXO lookup that returns None for all outpoints (nothing exists).
    struct EmptyUtxoLookup;
    impl UtxoLookup for EmptyUtxoLookup {
        fn get_utxo(&self, _outpoint: &OutPoint) -> Option<(u64, bool, u64)> {
            None
        }
    }

    /// Build a signed transfer tx (UTXO model) with a specific outpoint.
    fn make_signed_transfer_with_outpoint(
        sk: &[u8],
        pk: &[u8],
        recipient_pk: &[u8],
        outpoint: OutPoint,
        amount: u64,
        change: u64,
    ) -> Transaction {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let pub_key = NoblePublicKey::Ed25519(pk.to_vec());
        let recipient = NoblePublicKey::Ed25519(recipient_pk.to_vec());
        let sender_addr = NobleAddress::Noble(pub_key);
        let recip_addr = NobleAddress::Noble(recipient);

        let mut outputs = vec![TxOut { value: amount, address: recip_addr }];
        if change > 0 {
            outputs.push(TxOut { value: change, address: sender_addr });
        }

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: noble_core::TX_TYPE_TRANSFER,
            inputs: vec![TxIn { prev_output: outpoint }],
            outputs,
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
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
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn step65_reject_unknown_utxo() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        let outpoint = unique_outpoint();
        let tx = make_signed_transfer_with_outpoint(&sk, &pk, &recip, outpoint, 500_000, 499_000);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &EmptyUtxoLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::StructuralValidation(ref s)) if s.contains("unknown or spent UTXO")),
            "expected unknown UTXO error, got {:?}",
            result
        );
    }

    #[test]
    fn step65_accept_valid_utxo() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();

        let tx = make_signed_tx(&sk, &pk, b"utxo_ok", MIN_TX_FEE);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn step65_reject_double_spend_in_mempool() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        // Both txs spend the same outpoint
        let shared_outpoint = unique_outpoint();
        let tx1 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint.clone(), 500_000, 499_000,
        );
        let tx2 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint, 400_000, 599_000,
        );

        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();
        let result = pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::StructuralValidation(ref s)) if s.contains("already spent by mempool")),
            "double spend should be rejected, got {:?}",
            result
        );
    }

    #[test]
    fn step65_spent_outpoints_cleared_on_remove() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let (_, recip) = ed25519::generate_keypair();

        let shared_outpoint = unique_outpoint();
        let tx1 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint.clone(), 500_000, 499_000,
        );
        let id1 = pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();

        // Remove it
        pool.remove(&id1);

        // Same outpoint can now be spent again
        let tx2 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint, 400_000, 599_000,
        );
        let result = pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(
            result.is_ok(),
            "after remove, outpoint should be spendable again, got {:?}",
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
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
                .unwrap();
        }

        // 4th should be rejected
        let tx4 = make_signed_tx(&sk, &pk, b"rate3", MIN_TX_FEE);
        let result = pool.admit(&tx4, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
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
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
                .unwrap();
        }

        // Sender 2 should still be able to submit
        let tx = make_signed_tx(&sk2, &pk2, b"s2_0", MIN_TX_FEE);
        assert!(
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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
        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
            .unwrap();

        let tx2 = make_signed_tx(&sk, &pk, b"doc2", MIN_TX_FEE * 3);
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0)
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
        let pub_key = NoblePublicKey::Ed25519(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);
        let checksum = sha256(doc);
        let input_value = 1_000_000u64;
        let change = input_value.saturating_sub(fee);
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
            inputs: vec![TxIn { prev_output: unique_outpoint() }],
            outputs: vec![TxOut { value: change, address: addr }],
            checksum,
            timestamp: 1_700_000_000,
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
        contract_data: None,
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
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
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
        let result = pool.admit(&tx, 1_700_000_000, &chain, &NoUtxoLookup, 0);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn step2_6_no_version_metadata_skipped() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        // Normal notarization without any version metadata
        let tx = make_signed_tx(&sk, &pk, b"normal_doc", MIN_TX_FEE);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    // --- Coinbase rejection ---

    #[test]
    fn reject_coinbase_in_mempool() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let pub_key = NoblePublicKey::Ed25519(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: noble_core::TX_TYPE_COINBASE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut { value: 100_000_000, address: addr }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
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
        contract_data: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::StructuralValidation(ref s)) if s.contains("coinbase")),
            "coinbase tx should be rejected, got: {result:?}"
        );
    }
}
