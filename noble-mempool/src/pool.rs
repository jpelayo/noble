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

use noble_core::{
    OutPoint, Transaction, MAX_TX_SIZE, META_KEY_PREV_CHECKSUM,
    wire::WireFormat,
};
use noble_crypto::Hash256;

use crate::error::MempoolError;
use crate::sigcache::SigCache;

/// Default mempool configuration.
pub const DEFAULT_MAX_SIZE_BYTES: usize = 32 * 1024 * 1024; // 32 MB
pub const DEFAULT_MAX_COUNT: usize = 10_000;
pub const DEFAULT_EXPIRY_SECS: u64 = 72 * 3600; // 72 hours
pub const DEFAULT_MAX_PER_SENDER: usize = 64;
/// Max txs in an unconfirmed ancestor chain INCLUDING the candidate
/// (Bitcoin's `-limitancestorcount`, default 25). Bounds proposal/template CPU.
pub const DEFAULT_MAX_ANCESTORS: usize = 25;
/// Max txs in an unconfirmed descendant set of any tx INCLUDING that tx
/// (Bitcoin's `-limitdescendantcount`, default 25).
pub const DEFAULT_MAX_DESCENDANTS: usize = 25;
/// Rolling min-fee: increment added above an evicted feerate (groat/byte).
pub const ROLLING_FEE_INCREMENT: u64 = 1;
/// Rolling min-fee: halflife of the decay back toward MIN_RELAY_FEE_RATE.
pub const ROLLING_FEE_HALFLIFE_SECS: u64 = 12 * 3600;

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
    /// Max unconfirmed ancestor chain length (incl. candidate).
    pub max_ancestors: usize,
    /// Max unconfirmed descendant set size of any tx (incl. that tx).
    pub max_descendants: usize,
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
            max_ancestors: DEFAULT_MAX_ANCESTORS,
            max_descendants: DEFAULT_MAX_DESCENDANTS,
        }
    }
}

/// Pending transaction summary for a specific address — UTXO-level breakdown.
#[derive(Debug, Clone)]
pub struct PendingTxSummary {
    pub tx_id: Hash256,
    pub outputs_to_self: u64,
    pub outputs_to_others: u64,
    pub fee: u64,
    pub net_debit: u64,
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
    /// Fee rate in atomic units per byte (fee / size_bytes). Used for prioritization.
    pub fee_rate: u64,
    /// Unix timestamp when the transaction was received.
    pub received_at: u64,
}

/// Single source of truth for protocol-level transaction expiry (K3-03).
/// A tx is expired when `now > expires_at` — the exact boundary the admission
/// check has always used. Admission, the periodic sweep, and the
/// block-proposal iterator all call this one helper so the boundary can
/// never drift between them.
#[inline]
pub fn tx_is_expired(tx: &Transaction, now: u64) -> bool {
    tx.expires_at.is_some_and(|e| now > e)
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
/// Returns 100_000_000 atomic units per UTXO (1 NOBLE), matching test fixture conventions.
/// For production code, implement `UtxoLookup` against the actual UTXO set.
pub struct NoUtxoLookup;

/// Default UTXO value returned by `NoUtxoLookup` (matches test fixture `make_signed_tx` input_value).
pub const NO_UTXO_LOOKUP_VALUE: u64 = 100_000_000;

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
    by_fee_rate: BTreeMap<u64, HashSet<Hash256>>,
    /// Checksum index: document checksum → set of tx_ids.
    by_checksum: HashMap<Hash256, HashSet<Hash256>>,
    /// Timestamp index: received_at → set of tx_ids (for expiry).
    by_timestamp: BTreeMap<u64, HashSet<Hash256>>,
    /// Protocol-expiry index: tx.expires_at → set of tx_ids (K3-03). Only
    /// txs that carry `expires_at` appear here. Lets `expire()` sweep
    /// protocol-expired entries without a full-pool scan.
    by_expiry: BTreeMap<u64, HashSet<Hash256>>,
    /// Sender index: pubkey wire bytes → set of tx_ids (for pending debit calc).
    by_sender: HashMap<Vec<u8>, HashSet<Hash256>>,
    /// UTXO double-spend prevention: outpoint → the in-mempool tx spending it
    /// (Bitcoin's `mapNextTx`). The reverse index lets `remove_for_block`
    /// find conflicting txs in O(1) when a block consumes an outpoint.
    spent_by_mempool: HashMap<OutPoint, Hash256>,
    /// Outputs created by mempool transactions — spendable as inputs by other mempool txs.
    /// Mirrors Bitcoin's unconfirmed transaction chaining (CPFP).
    mempool_outputs: HashMap<OutPoint, (u64, Vec<u8>)>, // (value, address_wire)
    /// Which mempool tx created each mempool output (for cascade eviction).
    output_creator: HashMap<OutPoint, Hash256>,
    /// Dependency graph: child_tx_id → set of parent tx_ids it spends from.
    depends_on: HashMap<Hash256, HashSet<Hash256>>,
    /// Reverse dependency graph: parent_tx_id → set of child tx_ids spending
    /// its outputs. Exact mirror of `depends_on`, maintained in lockstep —
    /// makes cascade eviction and descendant counting O(children) instead of
    /// O(whole map).
    children_of: HashMap<Hash256, HashSet<Hash256>>,
    /// Signature verification cache.
    sig_cache: SigCache,
    /// Current total serialized size of all transactions.
    total_size_bytes: usize,
    /// Rolling dynamic min-fee floor (groat/byte), raised when txs are evicted
    /// under size pressure and decayed back toward MIN_RELAY_FEE_RATE over time.
    /// Mirrors Bitcoin's mempool `GetMinFee`.
    rolling_min_fee_rate: u64,
    /// Unix-seconds timestamp of the last rolling-fee update (for decay).
    rolling_updated_at: u64,
}

impl Mempool {
    /// Create a new empty mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        let sig_cache = SigCache::new(config.sig_cache_size);
        Self {
            config,
            by_id: HashMap::new(),
            by_fee_rate: BTreeMap::new(),
            by_checksum: HashMap::new(),
            by_timestamp: BTreeMap::new(),
            by_expiry: BTreeMap::new(),
            by_sender: HashMap::new(),
            spent_by_mempool: HashMap::new(),
            mempool_outputs: HashMap::new(),
            output_creator: HashMap::new(),
            depends_on: HashMap::new(),
            children_of: HashMap::new(),
            sig_cache,
            total_size_bytes: 0,
            rolling_min_fee_rate: noble_core::MIN_RELAY_FEE_RATE,
            rolling_updated_at: 0,
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

    /// Compute fee rate statistics: (min_fee_rate, max_fee_rate, avg_fee_rate) in groats/byte.
    /// Returns (0, 0, 0) when the mempool is empty.
    pub fn fee_stats(&self) -> (u64, u64, u64) {
        if self.by_fee_rate.is_empty() {
            return (0, 0, 0);
        }
        let min_rate = self.by_fee_rate.keys().next().copied().unwrap_or(0);
        let max_rate = self.by_fee_rate.keys().next_back().copied().unwrap_or(0);
        let count = self.by_id.len() as u64;
        let total_rates: u64 = self.by_id.values().map(|e| e.fee_rate).sum();
        let avg_rate = if count > 0 { total_rates / count } else { 0 };
        (min_rate, max_rate, avg_rate)
    }

    /// Sum of `(total_output_value + fee)` for all pending transactions from the given sender.
    pub fn pending_debit(&self, pubkey: &noble_crypto::NoblePublicKey) -> u64 {
        let wire = pubkey.to_wire_bytes();
        self.pending_debits_for_sender(&wire)
    }

    /// Return all unspent mempool outputs for a given address (wire bytes).
    /// These are change outputs from pending transactions — spendable by subsequent txs.
    pub fn outputs_for_address(&self, addr_wire: &[u8]) -> Vec<(OutPoint, u64)> {
        self.mempool_outputs.iter()
            .filter(|(op, (_, wire))| wire == addr_wire && !self.spent_by_mempool.contains_key(op))
            .map(|(op, (value, _))| (op.clone(), *value))
            .collect()
    }

    /// Whether an outpoint is already consumed by an in-mempool transaction.
    pub fn is_outpoint_spent(&self, outpoint: &OutPoint) -> bool {
        self.spent_by_mempool.contains_key(outpoint)
    }

    /// Pending debits for a specific address.
    ///
    /// In the UTXO model, pending debits are tracked via the `spent_by_mempool`
    /// set (outpoint-level). This sums output values of mempool txs where
    /// the sender matches the queried address. Returns 0 if no pending txs.
    /// Net pending debit for an address: outputs going to OTHER addresses + fees.
    /// Change outputs returning to the sender are NOT counted as debit.
    pub fn pending_debit_for_address(&self, addr: &noble_core::NobleAddress) -> u64 {
        let addr_wire = addr.to_wire_bytes();
        self.by_id.values()
            .filter(|entry| {
                entry.tx.issuer_sig.to_noble_public_key()
                    .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes() == addr_wire)
                    .unwrap_or(false)
            })
            .map(|entry| {
                let outgoing: u64 = entry.tx.outputs.iter()
                    .filter(|o| o.address.to_wire_bytes() != addr_wire)
                    .map(|o| o.value)
                    .sum();
                outgoing.saturating_add(entry.fee)
            })
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// Net pending credit for an address: outputs going TO `addr` from txs
    /// whose signer is NOT in `exclude_signers_wire`. Caller passes the
    /// wire-bytes of every key it owns, so self-transfers between own
    /// buckets (Noble → my-Hash160 change, etc.) are correctly classified
    /// as outflow-with-self-change rather than incoming credit.
    pub fn pending_credit_for_address(
        &self,
        addr: &noble_core::NobleAddress,
        exclude_signers_wire: &[Vec<u8>],
    ) -> u64 {
        let addr_wire = addr.to_wire_bytes();
        self.by_id.values()
            .filter(|entry| {
                entry.tx.issuer_sig.to_noble_public_key()
                    .map(|pk| {
                        let s = noble_core::NobleAddress::Noble(pk).to_wire_bytes();
                        !exclude_signers_wire.iter().any(|w| w == &s)
                    })
                    .unwrap_or(true)
            })
            .map(|entry| entry.tx.outputs.iter()
                .filter(|o| o.address.to_wire_bytes() == addr_wire)
                .map(|o| o.value)
                .sum::<u64>())
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// Pending change returning to an address from its own mempool txs.
    /// These are outputs in the sender's txs that go BACK to the sender.
    pub fn pending_change_for_address(&self, addr: &noble_core::NobleAddress) -> u64 {
        let addr_wire = addr.to_wire_bytes();
        self.by_id.values()
            .filter(|entry| {
                entry.tx.issuer_sig.to_noble_public_key()
                    .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes() == addr_wire)
                    .unwrap_or(false)
            })
            .map(|entry| {
                entry.tx.outputs.iter()
                    .filter(|o| o.address.to_wire_bytes() == addr_wire)
                    .map(|o| o.value)
                    .sum::<u64>()
            })
            .fold(0u64, |acc, v| acc.saturating_add(v))
    }

    /// Full pending tx breakdown for an address.
    pub fn pending_tx_summaries(&self, addr: &noble_core::NobleAddress) -> Vec<PendingTxSummary> {
        let addr_wire = addr.to_wire_bytes();
        self.by_id.values()
            .filter(|entry| {
                entry.tx.issuer_sig.to_noble_public_key()
                    .map(|pk| noble_core::NobleAddress::Noble(pk).to_wire_bytes() == addr_wire)
                    .unwrap_or(false)
            })
            .map(|entry| {
                let outputs_to_self: u64 = entry.tx.outputs.iter()
                    .filter(|o| o.address.to_wire_bytes() == addr_wire)
                    .map(|o| o.value)
                    .sum();
                let outputs_to_others: u64 = entry.tx.outputs.iter()
                    .filter(|o| o.address.to_wire_bytes() != addr_wire)
                    .map(|o| o.value)
                    .sum();
                PendingTxSummary {
                    tx_id: entry.tx_id,
                    outputs_to_self,
                    outputs_to_others,
                    fee: entry.fee,
                    net_debit: outputs_to_others.saturating_add(entry.fee),
                }
            })
            .collect()
    }

    /// Iterate transactions in descending fee order (highest fee first).
    /// Used for block assembly.
    pub fn iter_by_fee_rate_desc(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.by_fee_rate
            .iter()
            .rev()
            .flat_map(move |(_, ids)| ids.iter().filter_map(move |id| self.by_id.get(id)))
    }

    /// Iterate transactions in dependency-safe order for block proposal.
    /// Parents always appear before their children. Within independent groups,
    /// higher fee-rate transactions come first.
    ///
    /// `min_fee_rate` is the proposer's policy floor (groats/byte); pass `0`
    /// for no filtering. The filter is **package-aware**: excluding a
    /// below-floor parent also excludes all of its descendants — a child whose
    /// parent isn't in the feed can never be built into the block (the builder
    /// would just skip it for a missing input, wasting the slot). Sound
    /// because cascade eviction guarantees every pooled tx's `depends_on`
    /// parents are still pooled: an excluded parent simply never enters
    /// `emitted`, so its descendants never become ready and drop out at the
    /// no-progress break.
    pub fn iter_for_block_proposal(&self, min_fee_rate: u64, now: u64) -> Vec<&MempoolEntry> {
        let mut result: Vec<&MempoolEntry> = Vec::with_capacity(self.by_id.len());
        let mut emitted: HashSet<Hash256> = HashSet::new();

        // Collect entries meeting the fee floor, sorted by fee rate desc
        // (default priority). Defensively exclude protocol-expired entries
        // (K3-03): a tx can expire between admission and the next expire()
        // sweep — proposing it would make our own block invalid at every
        // other validator. An excluded parent keeps its descendants out via
        // the topo gate below (they never become ready).
        let all_by_fee: Vec<&MempoolEntry> = self
            .iter_by_fee_rate_desc()
            .filter(|e| e.fee_rate >= min_fee_rate && !tx_is_expired(&e.tx, now))
            .collect();

        // Repeatedly scan: emit entries whose parents are all emitted (or have no parents).
        // Bounded by max_ancestors+1 passes: a topo layer is emitted each pass,
        // and chain depth is capped at the ancestor limit, so this also breaks
        // on no-progress (defensive against an unexpected cycle).
        let max_passes = self.config.max_ancestors + 1;
        let mut remaining: Vec<&MempoolEntry> = all_by_fee;
        for _ in 0..max_passes {
            if remaining.is_empty() {
                break;
            }
            let before = result.len();
            let mut still_blocked = Vec::new();
            for entry in remaining {
                let parents = self.depends_on.get(&entry.tx_id);
                let ready = match parents {
                    None => true,
                    Some(deps) => deps.iter().all(|p| emitted.contains(p)),
                };
                if ready {
                    emitted.insert(entry.tx_id);
                    result.push(entry);
                } else {
                    still_blocked.push(entry);
                }
            }
            remaining = still_blocked;
            if remaining.is_empty() || result.len() == before {
                break; // all emitted or stuck (circular — shouldn't happen)
            }
        }
        result
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
        self.admit_with_size(tx, current_time, chain, utxos, chain_height, None)
    }

    /// Admit a transaction with an explicit CBOR byte size.
    ///
    /// When `submitted_size` is `Some(len)`, fee validation uses that length
    /// instead of re-encoding via serde. This ensures the fee rate check
    /// matches the exact bytes the client produced — no encoder divergence.
    pub fn admit_with_size<C: ChainLookup, U: UtxoLookup>(
        &mut self,
        tx: &Transaction,
        current_time: u64,
        chain: &C,
        utxos: &U,
        chain_height: u64,
        submitted_size: Option<usize>,
    ) -> Result<Hash256, MempoolError> {
        // Step 1: Size check
        // Uses the submitted byte count when available (RPC path), or the
        // frozen wire format encoder (noble-core::wire::WireFormat) otherwise.
        tracing::trace!("mempool step 1: size check");
        let size_bytes = if let Some(sz) = submitted_size {
            sz
        } else {
            tx.wire_bytes().len()
        };
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
        if let Ok(sender) = tx.issuer_sig.to_noble_public_key() {
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

        // Step 2.58: Protocol expiry check (shared boundary — see tx_is_expired).
        // Runs BEFORE the core structural validator so an expired tx yields the
        // typed `Expired` variant; the core T-EXPIRY check (which reports via
        // ValidationError::Internal) never fires for mempool admission.
        if tx_is_expired(tx, current_time) {
            return Err(MempoolError::Expired);
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

        // Step 3-6: Stateless STRUCTURE validation via the shared core
        // validator — the same rules block validation enforces, minus
        // signatures: T1 size/counts, T2 version, T4 timestamp skew, T5
        // issuer scheme, T8 metadata, T10 tx_id, T15 duplicate inputs in same
        // tx, T29-T32 type-specific metadata, T-EXPIRY (RealTime).
        //
        // Signatures (T6/T7/T26) are deliberately deferred to step 7.5 —
        // AFTER the UTXO and fee-floor checks — so below-floor / bogus-input
        // spam is rejected without paying for secp256k1 verification
        // (Bitcoin's ordering: cheap policy first, expensive crypto last).
        //
        // Stateful checks (T11 fee, UTXO existence, double-spend across
        // mempool, maturity) remain below — they are NOT in noble_core's
        // stateless validators.
        tracing::trace!("mempool steps 3-6: stateless structure validation via noble_core");
        let validation_ctx = noble_core::TxValidationContext {
            chain_id: self.config.chain_id.load(std::sync::atomic::Ordering::Relaxed),
            // RealTime is the ONLY correct context for live mempool admission.
            // Historical would relax the T4 skew check, which is wrong here.
            time_context: noble_core::TimeContext::RealTime {
                wall_clock: current_time,
            },
            chain_height,
        };
        noble_core::validate_transaction_structure(tx, &tx_id, &validation_ctx).map_err(|e| {
            match e {
                // T4 is clock-dependent — never objective peer misbehavior (K3-01).
                noble_core::ValidationError::TimestampOutOfRange { .. } => {
                    MempoolError::TimestampOutOfRange(e.to_string())
                }
                other => MempoolError::StructuralValidation(other.to_string()),
            }
        })?;

        // Step 6.5: UTXO existence + double-spend check
        tracing::trace!("mempool step 6.5: UTXO validation");
        let mut input_value_sum: u64 = 0;
        let mut parent_deps: HashSet<Hash256> = HashSet::new();
        for input in &tx.inputs {
            let outpoint = &input.prev_output;

            // Reject coinbase outpoints (already covered by step 2.55, but belt-and-suspenders)
            if outpoint.is_coinbase() {
                return Err(MempoolError::StructuralValidation(
                    "coinbase input not allowed in mempool".into(),
                ));
            }

            // Check for in-mempool double-spend
            if self.spent_by_mempool.contains_key(outpoint) {
                return Err(MempoolError::DoubleSpend);
            }

            // Verify UTXO exists: check on-chain first, then mempool outputs
            match utxos.get_utxo(outpoint) {
                Some((value, _is_coinbase, creation_height)) => {
                    // Maturity check — ALL UTXOs need COINBASE_MATURITY confirmations.
                    if chain_height < creation_height + noble_core::COINBASE_MATURITY {
                        let blocks_remaining = (creation_height + noble_core::COINBASE_MATURITY).saturating_sub(chain_height);
                        return Err(MempoolError::ImmatureInput {
                            available_at: creation_height + noble_core::COINBASE_MATURITY,
                            blocks_remaining,
                        });
                    }
                    input_value_sum = input_value_sum.saturating_add(value);
                }
                None => {
                    // Not on-chain — check mempool outputs (unconfirmed tx chaining)
                    if let Some((value, _addr_wire)) = self.mempool_outputs.get(outpoint) {
                        input_value_sum = input_value_sum.saturating_add(*value);
                        // Record dependency on the tx that created this output
                        if let Some(parent_id) = self.output_creator.get(outpoint) {
                            parent_deps.insert(*parent_id);
                        }
                    } else {
                        return Err(MempoolError::MissingInput);
                    }
                }
            }
        }

        // Chain limits (DoS): bound the unconfirmed ancestor/descendant graph
        // this tx would join (Bitcoin's limitancestorcount/limitdescendantcount).
        // `parent_deps` (this tx's direct in-mempool parents) is now final.
        self.check_chain_limits(&parent_deps)?;

        // Compute implicit fee: sum(inputs) - sum(outputs)
        let output_value_sum = tx.total_output_value();
        let fee = input_value_sum.checked_sub(output_value_sum).ok_or(
            MempoolError::InsufficientBalance {
                have: input_value_sum,
                need: output_value_sum,
            },
        )?;

        // Step 7: Fee rate check (Bitcoin-style free market)

        tracing::trace!("mempool step 7: fee rate check");
        let fee_rate = if size_bytes > 0 { fee / size_bytes as u64 } else { 0 };
        // Effective floor = max(protocol floor, rolling dynamic floor). The
        // rolling floor only exceeds the protocol floor while the pool is
        // shedding load under size pressure, decaying back over time — so under
        // normal load this is exactly MIN_RELAY_FEE_RATE.
        let effective_floor = self.current_min_fee_rate(current_time);
        if fee_rate < effective_floor {
            return Err(MempoolError::FeeTooLow {
                fee,
                min_fee: effective_floor * size_bytes as u64,
            });
        }

        // Step 7.5: Signature verification (T6/T7/T26) — the expensive part,
        // run LAST among the checks so all cheap policy rejections above never
        // pay for secp256k1, but BEFORE make_room so an invalid-sig tx can
        // never evict residents. tx_id commits to the full wire bytes
        // (signatures included), so a cache hit proves these exact signature
        // bytes verified before — safe to skip re-verification on re-admission
        // after expiry/eviction.
        tracing::trace!("mempool step 7.5: signature verification");
        if !self.sig_cache.contains(&tx_id) {
            // K3-01: signature failures use the dedicated typed variant
            // (previously funneled into StructuralValidation, leaving
            // SignatureInvalid dead).
            noble_core::validate_transaction_signatures(tx, &validation_ctx)
                .map_err(|e| MempoolError::SignatureInvalid(e.to_string()))?;
            self.sig_cache.insert(tx_id);
        }

        // Pre-step 8: Make room (admission-aware eviction). Refuses rather than
        // evict a higher-fee resident for this lower-fee newcomer, rejects an
        // oversize tx outright, and raises the rolling floor from everything it
        // sheds (incl. cascade descendants).
        self.make_room(size_bytes, fee_rate, current_time)?;

        // Step 8: Accept into mempool
        tracing::trace!("mempool step 8: accept into mempool");
        let entry = MempoolEntry {
            tx: tx.clone(),
            tx_id,
            size_bytes,
            fee,
            fee_rate,
            received_at: current_time,
        };

        self.insert_entry(entry, parent_deps);
        tracing::debug!(
            task = "mempool",
            "transaction admitted to mempool, pool size: {}",
            self.len()
        );
        Ok(tx_id)
    }

    /// Remove a transaction from the mempool (e.g., after confirmation).
    /// Cascade-evicts any tx that depends on it. Returns the primary entry.
    pub fn remove(&mut self, tx_id: &Hash256) -> Option<MempoolEntry> {
        let mut removed = Vec::new();
        self.remove_collecting(tx_id, &mut removed);
        // The primary tx is pushed first; descendants follow.
        removed.into_iter().next()
    }

    /// Like `remove`, but appends every removed entry — the primary AND all
    /// cascade-evicted descendants — to `out`. Lets callers (eviction) see the
    /// full removed set, e.g. to raise the rolling fee floor from descendants
    /// that the plain `remove` would otherwise hide.
    fn remove_collecting(&mut self, tx_id: &Hash256, out: &mut Vec<MempoolEntry>) {
        let entry = match self.by_id.remove(tx_id) {
            Some(e) => e,
            None => return,
        };

        // Remove from fee-rate index
        if let Some(set) = self.by_fee_rate.get_mut(&entry.fee_rate) {
            set.remove(tx_id);
            if set.is_empty() {
                self.by_fee_rate.remove(&entry.fee_rate);
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

        // Remove from protocol-expiry index (K3-03)
        if let Some(expires_at) = entry.tx.expires_at {
            if let Some(set) = self.by_expiry.get_mut(&expires_at) {
                set.remove(tx_id);
                if set.is_empty() {
                    self.by_expiry.remove(&expires_at);
                }
            }
        }

        // Remove from sender index
        if let Ok(sender) = entry.tx.issuer_sig.to_noble_public_key() {
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

        // Remove mempool outputs created by this tx
        for (vout, _) in entry.tx.outputs.iter().enumerate() {
            let outpoint = OutPoint { txid: *tx_id, vout: vout as u32 };
            self.mempool_outputs.remove(&outpoint);
            self.output_creator.remove(&outpoint);
        }

        // Remove dependency records — both directions. Unlink this tx from
        // each parent's children_of set (using its own depends_on parents),
        // keeping the two graphs exact mirrors.
        if let Some(parents) = self.depends_on.remove(tx_id) {
            for parent in parents {
                if let Some(children) = self.children_of.get_mut(&parent) {
                    children.remove(tx_id);
                    if children.is_empty() {
                        self.children_of.remove(&parent);
                    }
                }
            }
        }

        self.total_size_bytes -= entry.size_bytes;
        // NOTE: the sig_cache entry is intentionally KEPT — tx_id commits to
        // the exact signature bytes, so if this tx is re-admitted after
        // expiry/eviction the cached verification is still valid and the
        // secp256k1 work is skipped. The LRU bounds cache memory.
        out.push(entry); // record the primary before cascading

        // Cascade-evict any tx that depends on this one — O(direct children)
        // via the reverse index (was a full depends_on scan).
        //
        // NOTE (maturity=finality property): when a parent confirms and is
        // removed via `remove_for_block`, this cascade evicts its in-mempool
        // children too. Because ALL outputs require COINBASE_MATURITY
        // confirmations before they can be spent INTO a block, such a child
        // cannot re-enter the mempool until the (now on-chain) parent output
        // matures — so a CPFP / fast change re-spend is unavailable for
        // COINBASE_MATURITY blocks after the parent confirms. Intentional.
        if let Some(children) = self.children_of.remove(tx_id) {
            for child_id in children {
                tracing::debug!(task = "mempool", "cascade-evicting dependent tx {:?}", child_id);
                self.remove_collecting(&child_id, out);
            }
        }
    }

    /// Remove all expired transactions — by mempool residence TTL
    /// (received_at + expiry_secs < current_time) AND by protocol-level
    /// `tx.expires_at` (K3-03: a tx valid at admission can expire while
    /// resident; without this sweep it stayed proposal-eligible).
    /// Returns the TOTAL number of removed entries, including any fresher
    /// descendants cascade-evicted along with an expired parent.
    pub fn expire(&mut self, current_time: u64) -> usize {
        let cutoff = current_time.saturating_sub(self.config.expiry_secs);

        // Collect TTL-expired tx_ids
        let mut expired: Vec<Hash256> = self
            .by_timestamp
            .range(..=cutoff)
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect();

        // Collect protocol-expired tx_ids (expired ⟺ now > expires_at,
        // i.e. keys strictly below current_time — same boundary as
        // tx_is_expired / admission).
        expired.extend(
            self.by_expiry
                .range(..current_time)
                .flat_map(|(_, ids)| ids.iter().copied()),
        );

        let mut removed = Vec::new();
        for tx_id in expired {
            self.remove_collecting(&tx_id, &mut removed);
        }
        removed.len()
    }

    /// Drop every entry and reset all internal state to empty. Called on
    /// chain rollback / wipe / blockchain hop: pooled txs were validated
    /// against a chain state that no longer exists (after a hop even their
    /// tx_ids are stale — tx_id commits to the chain_id), so the conservative
    /// correct move is a full purge; origin wallets re-relay. The rolling fee
    /// floor and sig cache reset too — they describe the old chain's load.
    pub fn clear(&mut self) {
        self.by_id.clear();
        self.by_fee_rate.clear();
        self.by_checksum.clear();
        self.by_timestamp.clear();
        self.by_expiry.clear();
        self.by_sender.clear();
        self.spent_by_mempool.clear();
        self.mempool_outputs.clear();
        self.output_creator.clear();
        self.depends_on.clear();
        self.children_of.clear();
        self.sig_cache = SigCache::new(self.config.sig_cache_size);
        self.total_size_bytes = 0;
        self.rolling_min_fee_rate = noble_core::MIN_RELAY_FEE_RATE;
        self.rolling_updated_at = 0;
    }

    /// Test-only visibility into the signature cache (retention across
    /// eviction) and the dependency-graph mirror invariant.
    #[cfg(test)]
    fn sig_cache_contains(&self, tx_id: &Hash256) -> bool {
        self.sig_cache.contains(tx_id)
    }
    #[cfg(test)]
    fn dep_graphs_len(&self) -> (usize, usize) {
        (self.depends_on.len(), self.children_of.len())
    }

    /// Remove all transactions that are now confirmed in a block.
    pub fn remove_confirmed(&mut self, tx_ids: &[Hash256]) {
        for tx_id in tx_ids {
            self.remove(tx_id);
        }
    }

    /// Remove the confirmed txs **and** every *conflicting* mempool tx that
    /// spends an outpoint a confirmed tx just consumed on-chain. Mirrors
    /// Bitcoin Core's `removeForBlock` + `removeConflicts`.
    ///
    /// `confirmed_tx_ids` are the block's tx_ids precomputed by the caller
    /// under the block's chain_id — they are NOT recomputed here, because the
    /// node's chain_id may already have advanced after commit.
    ///
    /// Without this, a tx that spends an outpoint a block consumed (e.g. a
    /// different proposer's block included a conflicting tx) would linger in
    /// the mempool referencing a now-spent UTXO — mis-priced in fee accounting
    /// and re-selected into proposal after proposal.
    pub fn remove_for_block(&mut self, block_txs: &[Transaction], confirmed_tx_ids: &[Hash256]) {
        // 1. Conflicts: any mempool tx spending an input a block tx consumed is
        //    now permanently invalid. Dedup — the same spender can be found via
        //    multiple inputs; cascade removal is idempotent but we avoid the
        //    repeated walks.
        let mut conflicts: HashSet<Hash256> = HashSet::new();
        for tx in block_txs {
            for input in &tx.inputs {
                if let Some(&holder) = self.spent_by_mempool.get(&input.prev_output) {
                    conflicts.insert(holder);
                }
            }
        }
        for id in conflicts {
            self.remove(&id); // cascade-evicts descendants
        }
        // 2. The confirmed txs themselves (idempotent if already gone via step 1).
        for id in confirmed_tx_ids {
            self.remove(id);
        }
    }

    // --- Internal helpers ---
    //
    // The previous `validate_structure` and `verify_signatures` helpers were
    // removed: their work is now done by `noble_core::validate_transaction`
    // (called from `admit_with_size`), which runs the full stateless pass
    // including the metadata and signature checks they implemented.

    // Fee rate is checked at admission time (step 7) against MIN_RELAY_FEE_RATE.
    // No dynamic fee scaling — the market decides via fee rate competition.

    fn insert_entry(&mut self, entry: MempoolEntry, parent_deps: HashSet<Hash256>) {
        let tx_id = entry.tx_id;
        let fee_rate = entry.fee_rate;
        let checksum = entry.tx.checksum;
        let received_at = entry.received_at;
        let size = entry.size_bytes;

        // Populate sender index
        if let Ok(sender) = entry.tx.issuer_sig.to_noble_public_key() {
            let sender_wire = sender.to_wire_bytes();
            self.by_sender.entry(sender_wire).or_default().insert(tx_id);
        }

        // Mark input outpoints as spent by mempool (outpoint → spender tx_id)
        for input in &entry.tx.inputs {
            self.spent_by_mempool.insert(input.prev_output.clone(), tx_id);
        }

        // Register this tx's outputs as spendable mempool outputs
        for (vout, output) in entry.tx.outputs.iter().enumerate() {
            let outpoint = OutPoint { txid: tx_id, vout: vout as u32 };
            let addr_wire = output.address.to_wire_bytes();
            self.mempool_outputs.insert(outpoint.clone(), (output.value, addr_wire));
            self.output_creator.insert(outpoint, tx_id);
        }

        // Record dependency graph — both directions (for cascade eviction +
        // topo ordering + O(children) descendant walks).
        if !parent_deps.is_empty() {
            for parent in &parent_deps {
                self.children_of.entry(*parent).or_default().insert(tx_id);
            }
            self.depends_on.insert(tx_id, parent_deps);
        }

        // Protocol-expiry index (K3-03): only txs carrying expires_at.
        if let Some(expires_at) = entry.tx.expires_at {
            self.by_expiry.entry(expires_at).or_default().insert(tx_id);
        }
        self.by_id.insert(tx_id, entry);
        self.by_fee_rate.entry(fee_rate).or_default().insert(tx_id);
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

    /// Distinct transitive in-mempool ancestor closure of a tx whose direct
    /// parents are `parents` (does not include the candidate itself).
    fn ancestor_closure(&self, parents: &HashSet<Hash256>) -> HashSet<Hash256> {
        let mut closure: HashSet<Hash256> = HashSet::new();
        let mut stack: Vec<Hash256> = parents.iter().copied().collect();
        while let Some(id) = stack.pop() {
            if closure.insert(id) {
                if let Some(grandparents) = self.depends_on.get(&id) {
                    for &g in grandparents {
                        if !closure.contains(&g) {
                            stack.push(g);
                        }
                    }
                }
            }
        }
        closure
    }

    /// Count of distinct transitive descendants of `a` currently in the
    /// mempool (NOT counting `a`). A descendant is any tx that transitively
    /// depends on `a` — walked O(descendants) via the `children_of` mirror.
    fn descendant_count(&self, a: &Hash256) -> usize {
        let mut descendants: HashSet<Hash256> = HashSet::new();
        let mut frontier: Vec<Hash256> = vec![*a];
        while let Some(node) = frontier.pop() {
            if let Some(children) = self.children_of.get(&node) {
                for &child in children {
                    if descendants.insert(child) {
                        frontier.push(child);
                    }
                }
            }
        }
        descendants.len()
    }

    /// Enforce ancestor/descendant chain limits for an incoming tx with the
    /// given direct in-mempool parents. Counts are candidate-inclusive
    /// (Bitcoin convention): candidate + ancestors ≤ max_ancestors, and for
    /// every ancestor `a`, `a` + its existing descendants + the candidate ≤
    /// max_descendants.
    fn check_chain_limits(&self, parent_deps: &HashSet<Hash256>) -> Result<(), MempoolError> {
        if parent_deps.is_empty() {
            return Ok(()); // no in-mempool ancestors → trivially within limits
        }
        let closure = self.ancestor_closure(parent_deps);
        if closure.len() + 1 > self.config.max_ancestors {
            return Err(MempoolError::ChainTooLong {
                kind: "ancestor",
                limit: self.config.max_ancestors,
            });
        }
        for a in &closure {
            // a (1) + existing descendants D(a) + the new candidate (1).
            if self.descendant_count(a) + 2 > self.config.max_descendants {
                return Err(MempoolError::ChainTooLong {
                    kind: "descendant",
                    limit: self.config.max_descendants,
                });
            }
        }
        Ok(())
    }

    /// True if a tx of `incoming_size` bytes fits without exceeding either cap.
    fn has_room(&self, incoming_size: usize) -> bool {
        self.by_id.len() < self.config.max_count
            && self.total_size_bytes + incoming_size <= self.config.max_size_bytes
    }

    /// The effective minimum fee rate right now: `max(MIN_RELAY_FEE_RATE,
    /// decayed rolling floor)`. The rolling floor halves its excess over the
    /// protocol floor every `ROLLING_FEE_HALFLIFE_SECS`. Pure read.
    fn current_min_fee_rate(&self, now: u64) -> u64 {
        let floor = noble_core::MIN_RELAY_FEE_RATE;
        if self.rolling_min_fee_rate <= floor {
            return floor;
        }
        let elapsed = now.saturating_sub(self.rolling_updated_at);
        let halvings = elapsed / ROLLING_FEE_HALFLIFE_SECS;
        if halvings >= 64 {
            return floor; // fully decayed (guard against u64 shift overflow)
        }
        let excess = self.rolling_min_fee_rate - floor;
        floor + (excess >> halvings)
    }

    /// Raise the rolling floor to at least `target`, first decaying the stored
    /// value to `now` so repeated bumps don't compound a stale-high floor.
    fn bump_rolling_fee(&mut self, target: u64, now: u64) {
        let decayed = self.current_min_fee_rate(now);
        self.rolling_min_fee_rate = decayed.max(target);
        self.rolling_updated_at = now;
    }

    /// Admission-aware eviction: free room for an incoming tx of `incoming_size`
    /// bytes paying `incoming_fee_rate`. Returns all entries evicted (incl.
    /// cascade descendants).
    ///
    /// Guarantees (Bitcoin-parity):
    /// - Rejects a tx larger than the whole pool budget outright (R5).
    /// - Never evicts a resident whose fee rate is ≥ the incoming rate to make
    ///   room for it (R3): feasibility is decided read-only over the strictly
    ///   cheaper txs BEFORE anything is removed, so admission never mutates the
    ///   pool and then fails.
    /// - Raises the rolling fee floor from the highest evicted fee rate (R4),
    ///   including cascade-evicted descendants.
    fn make_room(
        &mut self,
        incoming_size: usize,
        incoming_fee_rate: u64,
        now: u64,
    ) -> Result<Vec<MempoolEntry>, MempoolError> {
        if incoming_size > self.config.max_size_bytes {
            return Err(MempoolError::TxTooLarge {
                size: incoming_size,
                max: self.config.max_size_bytes,
            });
        }
        if self.has_room(incoming_size) {
            return Ok(Vec::new());
        }

        // Feasibility (read-only): can we get under both caps by evicting ONLY
        // txs strictly cheaper than the incoming? Count their own sizes/counts;
        // cascade only frees more, so this is a conservative lower bound.
        let cheaper: Vec<&MempoolEntry> = self
            .by_fee_rate
            .range(..incoming_fee_rate)
            .flat_map(|(_, ids)| ids.iter())
            .filter_map(|id| self.by_id.get(id))
            .collect();
        let freeable_bytes: usize = cheaper.iter().map(|e| e.size_bytes).sum();
        let freeable_count = cheaper.len();
        let need_bytes = (self.total_size_bytes + incoming_size)
            .saturating_sub(self.config.max_size_bytes);
        let need_count = (self.by_id.len() + 1).saturating_sub(self.config.max_count);
        if freeable_bytes < need_bytes || freeable_count < need_count {
            let cheapest = self.by_fee_rate.keys().next().copied().unwrap_or(0);
            return Err(MempoolError::FeeTooLowToEvict {
                incoming: incoming_fee_rate,
                resident: cheapest,
            });
        }

        // Feasible — evict cheapest-first until there's room. Feasibility
        // guarantees we stay strictly below `incoming_fee_rate`.
        let mut removed = Vec::new();
        while !self.has_room(incoming_size) {
            let lowest = match self.by_fee_rate.keys().next().copied() {
                Some(f) if f < incoming_fee_rate => f,
                _ => break, // unreachable given feasibility; defensive
            };
            let victim = self
                .by_fee_rate
                .get(&lowest)
                .and_then(|s| s.iter().next().copied());
            let Some(id) = victim else { break };
            self.remove_collecting(&id, &mut removed);
        }

        // R4: raise the rolling floor from the highest evicted fee rate.
        if let Some(max_evicted) = removed.iter().map(|e| e.fee_rate).max() {
            self.bump_rolling_fee(max_evicted + ROLLING_FEE_INCREMENT, now);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{MetadataEntry, TxIn, TxOut, OutPoint, Transaction, MIN_TX_FEE, PROTOCOL_VERSION};
    use noble_core::address::NobleAddress;
    use noble_crypto::{
        secp256k1, sha256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_SECP256K1,
    };
    use noble_test_utils::fixtures::test_chain_id;

    /// Test fee that passes the fee_rate floor (MIN_RELAY_FEE_RATE=1 groat/byte).
    /// A typical test tx is ~250 bytes, so fee=1000 gives fee_rate=4 groats/byte.
    const TEST_FEE: u64 = 1_000;

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
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let pub_key = NoblePublicKey::Secp256k1(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key.clone());
        let checksum = sha256(doc);
        let input_value = noble_core::GROATS_PER_NOBLE; // 1 NOBLE per test UTXO
        let change = input_value.saturating_sub(fee);

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0, // notarization
            inputs: vec![TxIn { prev_output: unique_outpoint() }],
            outputs: vec![TxOut { value: change, address: addr }],
            checksum,
            timestamp: 1_700_000_000,
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
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
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
            max_ancestors: DEFAULT_MAX_ANCESTORS,
            max_descendants: DEFAULT_MAX_DESCENDANTS,
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
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);

        let tx_id = pool
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx_id));
        assert!(pool.get(&tx_id).is_some());
    }

    #[test]
    fn admit_and_remove() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);

        let tx_id = pool
            .admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        assert_eq!(pool.len(), 1);

        let entry = pool.remove(&tx_id).unwrap();
        assert_eq!(entry.tx_id, tx_id);
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(&tx_id));
    }

    // --- Step 1: Size check ---

    // Note: Generating a tx that exceeds MAX_TX_SIZE (8192) with valid sigs
    // is tricky. We test this path via an oversized metadata entry.

    // --- Step 2: Duplicate check ---

    #[test]
    fn step2_reject_mempool_duplicate() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);

        pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
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
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();

        let chain = ConfirmedChain(tx_id);
        let result = pool.admit(&tx, 1_700_000_000, &chain, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::Duplicate(_))));
    }

    // --- Step 3-6: noble_core stateless validation (audit follow-up) ---

    #[test]
    fn step3_reject_bad_version() {
        // After the audit fix, the version check is part of noble_core::
        // validate_transaction. The error becomes StructuralValidation with
        // the version number in the message instead of the dedicated
        // UnrecognizedVersion variant.
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.version = 99;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        match result {
            Err(MempoolError::StructuralValidation(msg)) => {
                assert!(msg.contains("99") || msg.to_lowercase().contains("version"),
                    "expected version-related error, got: {msg}");
            }
            other => panic!("expected StructuralValidation, got {other:?}"),
        }
    }

    // === Audit follow-up: mempool admission == block validation ===
    //
    // Six regression tests guarding the unification: each constructs a tx
    // that would be rejected at block validation, and asserts mempool
    // admission rejects it at the same gate — not later, at proposal time.
    //
    // All use chain_height=100 to bypass the unrelated COINBASE_MATURITY
    // check on the test-fixture UTXO (creation_height=0); the focus is
    // on the new stateless validators.

    #[test]
    fn audit_unknown_tx_type_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.tx_type = 0xFF; // unknown
        // Re-sign with new tx_type (signing payload changes)
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 100);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))),
            "unknown tx_type 0xFF must be rejected at admission, got {result:?}");
    }

    #[test]
    fn audit_future_timestamp_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        // Set tx.timestamp far in the future relative to current_time.
        let current_time: u64 = 1_700_000_000;
        tx.timestamp = current_time + noble_core::MAX_TX_TIMESTAMP_SKEW + 100;
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, current_time, &NoChainLookup, &NoUtxoLookup, 100);
        assert!(matches!(result, Err(MempoolError::TimestampOutOfRange(_))),
            "future timestamp must be rejected at admission, got {result:?}");
    }

    #[test]
    fn audit_past_timestamp_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        let current_time: u64 = 1_700_000_000;
        tx.timestamp = current_time
            .saturating_sub(noble_core::MAX_TX_TIMESTAMP_SKEW)
            .saturating_sub(100);
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, current_time, &NoChainLookup, &NoUtxoLookup, 100);
        assert!(matches!(result, Err(MempoolError::TimestampOutOfRange(_))),
            "stale timestamp must be rejected at admission, got {result:?}");
    }

    #[test]
    fn audit_duplicate_inputs_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        // Add a SECOND copy of the same input outpoint.
        let dup = tx.inputs[0].prev_output.clone();
        tx.inputs.push(TxIn { prev_output: dup });
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 100);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))),
            "duplicate inputs must be rejected at admission, got {result:?}");
    }

    #[test]
    fn audit_locked_tx_missing_metadata_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.tx_type = noble_core::TX_TYPE_LOCKED; // 0x06
        // Intentionally omit locked:checksum / locked:salt / locked:nonce.
        tx.metadata.clear();
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 100);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))),
            "locked tx without required metadata must be rejected, got {result:?}");
    }

    #[test]
    fn audit_unlocking_tx_missing_metadata_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.tx_type = noble_core::TX_TYPE_UNLOCKING; // 0x07
        // No unlock:txid / unlock:password metadata.
        tx.metadata.clear();
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 100);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))),
            "unlocking tx without required metadata must be rejected, got {result:?}");
    }

    // --- Step 4: Structural validation ---

    #[test]
    fn step4_reject_unknown_scheme() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.issuer_sig.scheme_id = 0xFF;

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(matches!(result, Err(MempoolError::StructuralValidation(_))));
    }

    #[test]
    fn duplicate_metadata_keys_allowed_by_decree() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let pub_key = NoblePublicKey::Secp256k1(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);
        let checksum = sha256(b"meta_doc");
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: 0,
            inputs: vec![TxIn { prev_output: unique_outpoint() }],
            outputs: vec![TxOut { value: 999_000, address: addr }],
            checksum,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
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
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        // T9 was removed by decree (2026-04-01, noble-core/src/metadata.rs):
        // duplicate metadata keys are ALLOWED. The old expectation only ever
        // "passed" because the height-0 maturity error masked it (both were
        // StructuralValidation strings before the K3-01 typed variants).
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(result.is_ok(), "duplicate metadata keys are legal: {result:?}");
    }

    // --- Step 5+6: Signature verification ---

    #[test]
    fn step6_reject_invalid_issuer_sig() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.issuer_sig.signature = vec![0u8; 64]; // Corrupt signature

        // chain_height 10: clears the COINBASE_MATURITY(3) gate so admission
        // actually REACHES the signature check (at height 0 the maturity
        // error fired first and masked it — exposed by the K3-01 typed
        // variants).
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
        // K3-01: signature failures now surface through the dedicated
        // SignatureInvalid variant (typed rejection classes).
        assert!(matches!(result, Err(MempoolError::SignatureInvalid(_))));
    }

    #[test]
    fn step6_reject_invalid_additional_sig() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        tx.additional_sigs.push(SignatureEnvelope {
            scheme_id: SCHEME_SECP256K1,
            public_key: pk.to_vec(),
            signature: vec![0u8; 64],
        });

        // chain_height 10: see step6_reject_invalid_issuer_sig.
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
        // K3-01: signature failures now surface through the dedicated
        // SignatureInvalid variant (typed rejection classes).
        assert!(matches!(result, Err(MempoolError::SignatureInvalid(_))));
    }

    // --- Step 7: Fee check ---

    #[test]
    fn step7_reject_low_fee() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        // Fee = 0 (input_value == output_value). Use a custom UTXO lookup.
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let pub_key = NoblePublicKey::Secp256k1(pk.to_vec());
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
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        // Custom UTXO lookup that returns the exact input value
        struct ExactUtxoLookup { outpoint: OutPoint, value: u64 }
        impl UtxoLookup for ExactUtxoLookup {
            fn get_utxo(&self, op: &OutPoint) -> Option<(u64, bool, u64)> {
                if *op == self.outpoint { Some((self.value, false, 0)) } else { None }
            }
        }
        let utxo = ExactUtxoLookup { outpoint, value: input_value };

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &utxo, 10);
        assert!(matches!(result, Err(MempoolError::FeeTooLow { .. })));
    }

    // --- Checksum lookup ---

    #[test]
    fn checksum_lookup() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"same_doc", TEST_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"other_doc", TEST_FEE);

        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        let _id2 = pool
            .admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();

        let checksum = sha256(b"same_doc");
        let results = pool.lookup_checksum(&checksum);
        assert_eq!(results.len(), 1);
        assert!(results.contains(&id1));
    }

    // --- Fee ordering ---

    #[test]
    fn iter_by_fee_rate_desc() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();

        let tx_low = make_signed_tx(&sk, &pk, b"low", TEST_FEE);
        let tx_mid = make_signed_tx(&sk, &pk, b"mid", TEST_FEE * 5);
        let tx_high = make_signed_tx(&sk, &pk, b"high", TEST_FEE * 10);

        pool.admit(&tx_low, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        pool.admit(&tx_mid, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        pool.admit(&tx_high, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();

        let fees: Vec<u64> = pool.iter_by_fee_rate_desc().map(|e| e.fee).collect();
        assert_eq!(fees, vec![TEST_FEE * 10, TEST_FEE * 5, TEST_FEE]);
    }

    // --- Eviction ---

    #[test]
    fn eviction_by_count() {
        let mut config = test_config();
        config.max_count = 3;
        let mut pool = Mempool::new(config);
        let (sk, pk) = secp256k1::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"doc2", TEST_FEE * 2);
        let tx3 = make_signed_tx(&sk, &pk, b"doc3", TEST_FEE * 3);
        let tx4 = make_signed_tx(&sk, &pk, b"doc4", TEST_FEE * 4);

        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        pool.admit(&tx3, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();

        // tx4 triggers eviction of tx1 (lowest fee)
        pool.admit(&tx4, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
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
        let (sk, pk) = secp256k1::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"old", TEST_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"new", TEST_FEE);

        // Admit near the tx timestamp (1_700_000_000) so the T4 skew check
        // (±3600s in RealTime context) passes; relative receipt times drive expiry.
        let base: u64 = 1_700_000_000;
        let id1 = pool
            .admit(&tx1, base, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        let id2 = pool
            .admit(&tx2, base + 3000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        assert_eq!(pool.len(), 2);

        // Expire at base+3601 (cutoff = base+3601 - 3600 = base+1)
        // tx1 received at base <= base+1 → expired
        // tx2 received at base+3000 > base+1 → kept
        let expired = pool.expire(base + 3601);
        assert_eq!(expired, 1);
        assert!(!pool.contains(&id1));
        assert!(pool.contains(&id2));
    }

    // --- Signature cache ---
    // (Cache-retention-across-eviction and the cached re-admission flow are
    // covered by `sig_cache_retained_after_eviction` below — the old
    // `sig_cache_avoids_reverification` test asserted the pre-audit behavior
    // of purging the cache entry on removal, which defeated the cache.)

    // --- remove_confirmed ---

    #[test]
    fn remove_confirmed_batch() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"c1", TEST_FEE);
        let tx2 = make_signed_tx(&sk, &pk, b"c2", TEST_FEE);
        let tx3 = make_signed_tx(&sk, &pk, b"c3", TEST_FEE);

        let id1 = pool
            .admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        let id2 = pool
            .admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        let id3 = pool
            .admit(&tx3, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
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
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let pub_key = NoblePublicKey::Secp256k1(pk.to_vec());
        let recipient = NoblePublicKey::Secp256k1(recipient_pk.to_vec());
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
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn step65_reject_unknown_utxo() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        let outpoint = unique_outpoint();
        let tx = make_signed_transfer_with_outpoint(&sk, &pk, &recip, outpoint, 500_000, 499_000);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &EmptyUtxoLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::MissingInput)),
            "expected unknown UTXO error, got {:?}",
            result
        );
    }

    #[test]
    fn step65_accept_valid_utxo() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();

        let tx = make_signed_tx(&sk, &pk, b"utxo_ok", TEST_FEE);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn step65_reject_double_spend_in_mempool() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        // Both txs spend the same outpoint
        let shared_outpoint = unique_outpoint();
        let tx1 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint.clone(), 500_000, 499_000,
        );
        let tx2 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint, 400_000, 599_000,
        );

        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        let result = pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(
            matches!(result, Err(MempoolError::DoubleSpend)),
            "double spend should be rejected, got {:?}",
            result
        );
    }

    #[test]
    fn step65_spent_outpoints_cleared_on_remove() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        let shared_outpoint = unique_outpoint();
        let tx1 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint.clone(), 500_000, 499_000,
        );
        let id1 = pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();

        // Remove it
        pool.remove(&id1);

        // Same outpoint can now be spent again
        let tx2 = make_signed_transfer_with_outpoint(
            &sk, &pk, &recip, shared_outpoint, 400_000, 599_000,
        );
        let result = pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
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
        let (sk, pk) = secp256k1::generate_keypair();

        // Admit 3 txs (at the limit)
        for i in 0..3 {
            let tx = make_signed_tx(&sk, &pk, format!("rate{i}").as_bytes(), TEST_FEE);
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
                .unwrap();
        }

        // 4th should be rejected
        let tx4 = make_signed_tx(&sk, &pk, b"rate3", TEST_FEE);
        let result = pool.admit(&tx4, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
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
        let (sk1, pk1) = secp256k1::generate_keypair();
        let (sk2, pk2) = secp256k1::generate_keypair();

        // Sender 1: 2 txs (at limit)
        for i in 0..2 {
            let tx = make_signed_tx(&sk1, &pk1, format!("s1_{i}").as_bytes(), TEST_FEE);
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
                .unwrap();
        }

        // Sender 2 should still be able to submit
        let tx = make_signed_tx(&sk2, &pk2, b"s2_0", TEST_FEE);
        assert!(
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
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
        let (sk, pk) = secp256k1::generate_keypair();

        let tx1 = make_signed_tx(&sk, &pk, b"doc1", TEST_FEE);
        pool.admit(&tx1, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();

        let tx2 = make_signed_tx(&sk, &pk, b"doc2", TEST_FEE * 3);
        pool.admit(&tx2, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();

        let (min_r, max_r, avg_r) = pool.fee_stats();
        // fee_stats now returns fee_rates (groats/byte), not absolute fees.
        // Exact values depend on tx serialized size, but ordering must hold.
        assert!(min_r > 0, "min_fee_rate should be > 0");
        assert!(max_r > min_r, "max_fee_rate should be > min_fee_rate");
        assert!(avg_r >= min_r && avg_r <= max_r, "avg should be between min and max");
    }

    // --- pending_debit ---

    #[test]
    fn pending_debit_zero_for_unknown_key() {
        let pool = Mempool::new(test_config());
        let (_sk, pk) = secp256k1::generate_keypair();
        let pubkey = noble_crypto::NoblePublicKey::Secp256k1(pk.to_vec());
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
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let pub_key = NoblePublicKey::Secp256k1(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);
        let checksum = sha256(doc);
        let input_value = 100_000_000u64;
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
            issuer_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
                public_key: pk.to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata,
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn step2_6_prev_checksum_not_on_chain_rejected() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let prev_hex = "aa".repeat(32);
        let tx =
            make_versioned_notarization(&sk, &pk, b"v2doc", TEST_FEE, Some("2"), Some(&prev_hex));
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
        let (sk, pk) = secp256k1::generate_keypair();
        let prev_hex = "aa".repeat(32);
        let prev_hash = Hash256::from_hex(&prev_hex).unwrap();
        let chain = ChecksumExists(prev_hash);
        let tx = make_versioned_notarization(
            &sk,
            &pk,
            b"v2doc2",
            TEST_FEE,
            Some("2"),
            Some(&prev_hex),
        );
        let result = pool.admit(&tx, 1_700_000_000, &chain, &NoUtxoLookup, 10);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn step2_6_no_version_metadata_skipped() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        // Normal notarization without any version metadata
        let tx = make_signed_tx(&sk, &pk, b"normal_doc", TEST_FEE);
        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    // --- Coinbase rejection ---

    #[test]
    fn reject_coinbase_in_mempool() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let pub_key = NoblePublicKey::Secp256k1(pk.to_vec());
        let addr = NobleAddress::Noble(pub_key);

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: noble_core::TX_TYPE_COINBASE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut { value: 100_000_000, address: addr }],
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
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
            expires_at: None,
        };
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();

        let result = pool.admit(&tx, 1_700_000_000, &NoChainLookup, &NoUtxoLookup, 0);
        assert!(
            matches!(result, Err(MempoolError::StructuralValidation(ref s)) if s.contains("coinbase")),
            "coinbase tx should be rejected, got: {result:?}"
        );
    }

    // --- Stage 1a: remove_for_block (conflict removal) ---

    /// Lookup returning a mature on-chain UTXO for any registered outpoint.
    struct MapUtxoLookup(std::collections::HashMap<OutPoint, u64>);
    impl UtxoLookup for MapUtxoLookup {
        fn get_utxo(&self, op: &OutPoint) -> Option<(u64, bool, u64)> {
            // (value, is_coinbase=false, creation_height=0) → mature at any height ≥ 3.
            self.0.get(op).map(|&v| (v, false, 0))
        }
    }

    /// A confirmed block tx (spending `op`) that was NOT in this node's mempool
    /// — e.g. it arrived in another proposer's block.
    fn block_tx_spending(op: OutPoint) -> Transaction {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        make_signed_transfer_with_outpoint(&sk, &pk, &recip, op, 400_000, 599_000)
    }

    #[test]
    fn remove_for_block_drops_conflicting_tx() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), 1_000_000)].into_iter().collect());

        // B (in our mempool) spends X.
        let b = make_signed_transfer_with_outpoint(&sk, &pk, &recip, x.clone(), 500_000, 499_000);
        pool.admit(&b, 1_700_000_000, &NoChainLookup, &lookup, 10).unwrap();
        let b_id = b.compute_tx_id(test_chain_id()).unwrap();
        assert!(pool.get(&b_id).is_some());

        // A different tx A (from a committed block) also spends X.
        let a = block_tx_spending(x.clone());
        let a_id = a.compute_tx_id(test_chain_id()).unwrap();
        pool.remove_for_block(&[a], &[a_id]);

        assert!(pool.get(&b_id).is_none(), "conflicting tx B must be evicted");
        assert!(!pool.is_outpoint_spent(&x), "X must no longer be marked spent");
    }

    #[test]
    fn remove_for_block_removes_confirmed_and_dependents() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), 1_000_000)].into_iter().collect());

        // Parent P spends on-chain X; its change (vout 1) goes back to the sender.
        let p = make_signed_transfer_with_outpoint(&sk, &pk, &recip, x, 500_000, 499_000);
        pool.admit(&p, 1_700_000_000, &NoChainLookup, &lookup, 10).unwrap();
        let p_id = p.compute_tx_id(test_chain_id()).unwrap();

        // Child C spends P's change output (a mempool output — CPFP chaining).
        let p_change = OutPoint { txid: p_id, vout: 1 };
        let c = make_signed_transfer_with_outpoint(&sk, &pk, &recip, p_change, 200_000, 298_000);
        pool.admit(&c, 1_700_000_000, &NoChainLookup, &lookup, 10).unwrap();
        let c_id = c.compute_tx_id(test_chain_id()).unwrap();
        assert!(pool.get(&c_id).is_some());

        // P confirms → P removed and its dependent C cascade-evicted.
        pool.remove_for_block(&[p], &[p_id]);
        assert!(pool.get(&p_id).is_none(), "confirmed P removed");
        assert!(pool.get(&c_id).is_none(), "dependent C cascade-evicted");
    }

    #[test]
    fn remove_for_block_dedups_repeated_conflict() {
        // A single mempool tx B spends two outpoints X and Y; a confirmed block
        // tx A spends both. B is discovered twice — dedup must remove it once,
        // without panic.
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());

        let x = unique_outpoint();
        let y = unique_outpoint();
        let lookup = MapUtxoLookup(
            [(x.clone(), 600_000), (y.clone(), 600_000)].into_iter().collect(),
        );

        // Build a 2-input B inline (the single-input helper can't express this).
        let build_two_in = |inputs: Vec<OutPoint>, amount: u64, change: u64| {
            let mut tx = Transaction {
                version: PROTOCOL_VERSION,
                tx_type: noble_core::TX_TYPE_TRANSFER,
                inputs: inputs.into_iter().map(|prev_output| TxIn { prev_output }).collect(),
                outputs: vec![
                    TxOut { value: amount, address: NobleAddress::Noble(NoblePublicKey::Secp256k1(recip.to_vec())) },
                    TxOut { value: change, address: NobleAddress::Noble(NoblePublicKey::Secp256k1(pk.to_vec())) },
                ],
                checksum: Hash256::ZERO,
                timestamp: 1_700_000_000,
                issuer_sig: SignatureEnvelope { scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![] },
                additional_sigs: vec![],
                metadata: vec![],
                encrypted_locator: None,
                external_attestations: vec![],
                gateway_address: None,
                contract_data: None,
                expires_at: None,
            };
            let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
            tx.issuer_sig = priv_key.sign(&msg).unwrap();
            tx
        };

        let b = build_two_in(vec![x.clone(), y.clone()], 600_000, 599_000); // fee = 1_200_000 - 1_199_000 = 1000
        pool.admit(&b, 1_700_000_000, &NoChainLookup, &lookup, 10).unwrap();
        let b_id = b.compute_tx_id(test_chain_id()).unwrap();

        // Confirmed block tx A also spends both X and Y.
        let a = build_two_in(vec![x, y], 700_000, 499_000);
        let a_id = a.compute_tx_id(test_chain_id()).unwrap();
        pool.remove_for_block(&[a], &[a_id]); // must not panic on the double-discovery

        assert!(pool.get(&b_id).is_none(), "B removed once, cleanly");
        assert!(pool.is_empty());
    }

    // --- Stage 2a: ancestor/descendant chain limits ---

    #[test]
    fn ancestor_limit_accepts_25_rejects_26() {
        let mut pool = Mempool::new(test_config()); // max_ancestors = 25
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        // On-chain seed UTXO.
        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), 100_000_000)].into_iter().collect());

        // Build a linear chain: each tx spends the previous tx's change output
        // (vout 1, paid back to `pk`). tx0 spends the on-chain seed.
        let mut prev_op = x;
        let mut prev_val: u64 = 100_000_000;
        // 25 txs = candidate(25th) + 24 ancestors → all accepted.
        for i in 0..25u64 {
            let change = prev_val - 2_000; // amount 1000 + fee 1000
            let tx = make_signed_transfer_with_outpoint(&sk, &pk, &recip, prev_op.clone(), 1_000, change);
            pool.admit(&tx, 1_700_000_000, &NoChainLookup, &lookup, 10)
                .unwrap_or_else(|e| panic!("chain tx {i} must admit: {e:?}"));
            let id = tx.compute_tx_id(test_chain_id()).unwrap();
            prev_op = OutPoint { txid: id, vout: 1 }; // the change output
            prev_val = change;
        }

        // The 26th (candidate + 25 ancestors) must be rejected.
        let change = prev_val - 2_000;
        let tx26 = make_signed_transfer_with_outpoint(&sk, &pk, &recip, prev_op, 1_000, change);
        let res = pool.admit(&tx26, 1_700_000_000, &NoChainLookup, &lookup, 10);
        assert!(
            matches!(res, Err(MempoolError::ChainTooLong { kind: "ancestor", .. })),
            "26-deep chain must be rejected as ancestor-too-long, got {res:?}"
        );
    }

    #[test]
    fn descendant_limit_accepts_24_children_rejects_25th() {
        let mut pool = Mempool::new(test_config()); // max_descendants = 25
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());

        // Parent P spends an on-chain UTXO and fans out into 25 self-owned outputs.
        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), 100_000_000)].into_iter().collect());
        let self_addr = NobleAddress::Noble(NoblePublicKey::Secp256k1(pk.to_vec()));
        let mut p = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: noble_core::TX_TYPE_TRANSFER,
            inputs: vec![TxIn { prev_output: x }],
            outputs: (0..25).map(|_| TxOut { value: 1_000_000, address: self_addr.clone() }).collect(),
            checksum: Hash256::ZERO,
            timestamp: 1_700_000_000,
            issuer_sig: SignatureEnvelope { scheme_id: SCHEME_SECP256K1, public_key: pk.to_vec(), signature: vec![] },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
            expires_at: None,
        };
        // fee = 100_000_000 - 25*1_000_000 = 75_000_000 ≫ floor.
        let msg = p.compute_signing_message_for_chain(test_chain_id()).unwrap();
        p.issuer_sig = priv_key.sign(&msg).unwrap();
        pool.admit(&p, 1_700_000_000, &NoChainLookup, &lookup, 10).unwrap();
        let p_id = p.compute_tx_id(test_chain_id()).unwrap();

        // 24 children, each spending one of P's outputs → P + 24 + candidate would
        // be 25 on the 24th, which is the max; all 24 accepted.
        for vout in 0..24u32 {
            let op = OutPoint { txid: p_id, vout };
            let child = make_signed_transfer_with_outpoint(&sk, &pk, &recip, op, 1_000, 998_000);
            pool.admit(&child, 1_700_000_000, &NoChainLookup, &lookup, 10)
                .unwrap_or_else(|e| panic!("child {vout} must admit: {e:?}"));
        }

        // The 25th child pushes P's descendant set (P + 24 + candidate = 26) over 25.
        let op = OutPoint { txid: p_id, vout: 24 };
        let child25 = make_signed_transfer_with_outpoint(&sk, &pk, &recip, op, 1_000, 998_000);
        let res = pool.admit(&child25, 1_700_000_000, &NoChainLookup, &lookup, 10);
        assert!(
            matches!(res, Err(MempoolError::ChainTooLong { kind: "descendant", .. })),
            "25th child must be rejected as descendant-too-long, got {res:?}"
        );
    }

    // --- Stage 2b: admission-aware make_room + rolling min-fee floor ---

    fn tiny_config(max_count: usize, max_size_bytes: usize) -> MempoolConfig {
        let mut c = test_config();
        c.max_count = max_count;
        c.max_size_bytes = max_size_bytes;
        c
    }

    /// A transfer spending a fresh outpoint of value `NO_UTXO_LOOKUP_VALUE`,
    /// paying `NO_UTXO_LOOKUP_VALUE - fee` to a recipient → implicit fee = `fee`.
    /// Used with `NoUtxoLookup` (resolves every input to NO_UTXO_LOOKUP_VALUE).
    fn tx_with_fee(fee: u64) -> Transaction {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        let amount = NO_UTXO_LOOKUP_VALUE - fee;
        make_signed_transfer_with_outpoint(&sk, &pk, &recip, unique_outpoint(), amount, 0)
    }

    const NOW: u64 = 1_700_000_000;

    #[test]
    fn make_room_refuses_lower_fee_incoming() {
        // Pool (cap 2) full of HIGH-fee txs; a LOW-fee incoming can't displace
        // them and is refused — the pool is left untouched.
        let mut pool = Mempool::new(tiny_config(2, 10 * 1024 * 1024));
        for _ in 0..2 {
            pool.admit(&tx_with_fee(20_000), NOW, &NoChainLookup, &NoUtxoLookup, 10).unwrap();
        }
        assert_eq!(pool.len(), 2);
        let res = pool.admit(&tx_with_fee(500), NOW, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(
            matches!(res, Err(MempoolError::FeeTooLowToEvict { .. })),
            "low-fee incoming must be refused, got {res:?}"
        );
        assert_eq!(pool.len(), 2, "pool must be untouched on refusal");
    }

    #[test]
    fn make_room_evicts_for_higher_fee_incoming() {
        let mut pool = Mempool::new(tiny_config(2, 10 * 1024 * 1024));
        for _ in 0..2 {
            pool.admit(&tx_with_fee(500), NOW, &NoChainLookup, &NoUtxoLookup, 10).unwrap();
        }
        // High-fee incoming out-bids the cheap residents → admitted, one evicted.
        pool.admit(&tx_with_fee(20_000), NOW, &NoChainLookup, &NoUtxoLookup, 10).unwrap();
        assert_eq!(pool.len(), 2, "stayed at capacity (one low-fee evicted)");
    }

    #[test]
    fn make_room_rejects_oversize_tx() {
        // Pool budget smaller than a single tx → reject outright, pool untouched.
        let mut pool = Mempool::new(tiny_config(100, 100)); // 100-byte budget
        let res = pool.admit(&tx_with_fee(500), NOW, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(
            matches!(res, Err(MempoolError::TxTooLarge { .. })),
            "tx larger than the pool budget must be rejected, got {res:?}"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn rolling_fee_rises_from_cascade_descendant() {
        // A low-fee parent with a HIGH-fee child: evicting the parent cascades
        // the child, and the rolling floor must reflect the child's higher rate
        // (review #4) — observable as a subsequent mid-fee tx being rejected.
        let mut pool = Mempool::new(tiny_config(2, 10 * 1024 * 1024));
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();

        // MapUtxoLookup resolves ONLY the explicit seed outpoints (x for P, y for
        // D, z for mid). Crucially it returns None for P's change output, so the
        // child resolves via mempool_outputs and records its dependency on P —
        // NoUtxoLookup would resolve everything as on-chain and hide that edge.
        let v = NO_UTXO_LOOKUP_VALUE;
        let x = unique_outpoint();
        let y = unique_outpoint();
        let z = unique_outpoint();
        let lookup = MapUtxoLookup(
            [(x.clone(), v), (y.clone(), v), (z.clone(), v)].into_iter().collect(),
        );

        // Parent P (low fee 500 → rate ~1) spends seed x, change to SELF (vout 1).
        let p = make_signed_transfer_with_outpoint(&sk, &pk, &recip, x, 1_000, v - 1_500);
        pool.admit(&p, NOW, &NoChainLookup, &lookup, 10).unwrap();
        let p_id = p.compute_tx_id(test_chain_id()).unwrap();
        // Child C (HIGH fee 20_000 → rate ~57) spends P's change (vout 1) — a
        // mempool output (not in the lookup) → C depends on P.
        let p_change = OutPoint { txid: p_id, vout: 1 };
        let c_in = v - 1_500;
        let c = make_signed_transfer_with_outpoint(&sk, &pk, &recip, p_change, c_in - 20_000, 0);
        pool.admit(&c, NOW, &NoChainLookup, &lookup, 10).unwrap();
        assert_eq!(pool.len(), 2);

        // Admit D (fee 30_000, spends seed y) → evicts P (cheapest) + cascades C;
        // floor rises to child_rate + 1 (the child's high rate, not P's low one).
        let d = make_signed_transfer_with_outpoint(&sk, &pk, &recip, y, v - 30_000, 0);
        pool.admit(&d, NOW, &NoChainLookup, &lookup, 10).unwrap();

        // A mid-fee tx (rate ~5, spends seed z) must now be rejected by the
        // raised rolling floor at the fee check.
        let mid = make_signed_transfer_with_outpoint(&sk, &pk, &recip, z, v - 2_000, 0);
        let res = pool.admit(&mid, NOW, &NoChainLookup, &lookup, 10);
        assert!(
            matches!(res, Err(MempoolError::FeeTooLow { .. })),
            "rolling floor (raised by the cascade-evicted child) must reject a mid-fee tx, got {res:?}"
        );
    }

    #[test]
    fn rolling_fee_noop_under_normal_load() {
        // No size pressure → the floor stays at MIN_RELAY_FEE_RATE, so even a
        // rate-1 tx is admitted (regression anchor: no congestion pricing idle).
        let mut pool = Mempool::new(test_config());
        // ~250-byte tx, fee 300 → rate ~1.
        let res = pool.admit(&tx_with_fee(500), NOW, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(res.is_ok(), "min-rate tx must admit under normal load, got {res:?}");
    }

    // --- Audit fixes: admission ordering, sig cache, clear(), package filter,
    // --- dependency-graph mirror, expire cascade count ---

    #[test]
    fn below_floor_fee_rejected_before_sig_work() {
        // A tx with BOTH a below-floor fee and a corrupt signature must be
        // rejected as FeeTooLow — proving the fee check runs before the
        // expensive signature verification (spam never pays for secp256k1).
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"cheap", 100); // ~330B → rate 0
        tx.issuer_sig.signature = vec![0u8; 64]; // corrupt
        let res = pool.admit(&tx, NOW, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(
            matches!(res, Err(MempoolError::FeeTooLow { .. })),
            "below-floor must reject at the fee check, before signatures: {res:?}"
        );
    }

    #[test]
    fn valid_fee_corrupt_sig_still_rejected() {
        // Signatures are deferred, NOT skipped: a fee-passing tx with a bad
        // signature must never be inserted.
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let mut tx = make_signed_tx(&sk, &pk, b"badsig", TEST_FEE);
        tx.issuer_sig.signature = vec![0u8; 64];
        let res = pool.admit(&tx, NOW, &NoChainLookup, &NoUtxoLookup, 10);
        assert!(
            matches!(res, Err(MempoolError::SignatureInvalid(_))),
            "corrupt sig must be rejected at step 7.5: {res:?}"
        );
        assert!(pool.is_empty());
    }

    #[test]
    fn sig_cache_retained_after_eviction() {
        // Cache entries survive removal so a re-admitted identical tx skips
        // the secp256k1 work (tx_id commits to the signature bytes).
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let tx = make_signed_tx(&sk, &pk, b"cached", TEST_FEE);
        let tx_id = pool.admit(&tx, NOW, &NoChainLookup, &NoUtxoLookup, 10).unwrap();
        assert!(pool.sig_cache_contains(&tx_id));
        pool.remove(&tx_id);
        assert!(
            pool.sig_cache_contains(&tx_id),
            "eviction must keep the sig-cache entry for cheap re-admission"
        );
        // Re-admission (cache-hit path) still works end-to-end.
        pool.admit(&tx, NOW, &NoChainLookup, &NoUtxoLookup, 10).unwrap();
        assert_eq!(pool.len(), 1);
    }

    /// Build a low-fee parent (rate ~1) + high-fee chained child (rate ~57)
    /// where the child spends the parent's in-mempool change output.
    fn admit_parent_child_chain(pool: &mut Mempool) -> (Hash256, Hash256, OutPoint) {
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        let v = NO_UTXO_LOOKUP_VALUE;
        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), v)].into_iter().collect());

        // Parent: fee 500 → rate ~1; change to self at vout 1.
        let p = make_signed_transfer_with_outpoint(&sk, &pk, &recip, x.clone(), 1_000, v - 1_500);
        let p_id = pool.admit(&p, NOW, &NoChainLookup, &lookup, 10).unwrap();
        // Child spends the parent's change (a mempool output): fee 20_000 → rate ~57.
        let p_change = OutPoint { txid: p_id, vout: 1 };
        let c_in = v - 1_500;
        let c = make_signed_transfer_with_outpoint(&sk, &pk, &recip, p_change, c_in - 20_000, 0);
        let c_id = pool.admit(&c, NOW, &NoChainLookup, &lookup, 10).unwrap();
        (p_id, c_id, x)
    }

    #[test]
    fn clear_resets_everything() {
        let mut pool = Mempool::new(test_config());
        let (_, _, seed) = admit_parent_child_chain(&mut pool);
        assert_eq!(pool.len(), 2);
        assert!(pool.is_outpoint_spent(&seed));
        assert_ne!(pool.dep_graphs_len(), (0, 0));

        pool.clear();

        assert_eq!(pool.len(), 0);
        assert_eq!(pool.total_size(), 0);
        assert!(!pool.is_outpoint_spent(&seed));
        assert_eq!(pool.dep_graphs_len(), (0, 0));
        assert!(pool.fee_stats() == (0, 0, 0) || pool.is_empty());

        // The pool is fully usable after clear (fresh chain state).
        let (sk, pk) = secp256k1::generate_keypair();
        pool.admit(&make_signed_tx(&sk, &pk, b"post-clear", TEST_FEE), NOW, &NoChainLookup, &NoUtxoLookup, 10)
            .unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn package_filter_excludes_below_floor_parent_and_its_child() {
        let mut pool = Mempool::new(test_config());
        let (p_id, c_id, _) = admit_parent_child_chain(&mut pool);

        // No floor: both included, parent strictly before child.
        let all: Vec<Hash256> = pool.iter_for_block_proposal(0, NOW).iter().map(|e| e.tx_id).collect();
        let pi = all.iter().position(|id| *id == p_id).expect("parent in feed");
        let ci = all.iter().position(|id| *id == c_id).expect("child in feed");
        assert!(pi < ci, "parent must precede child");

        // Floor 10: parent (rate ~1) excluded → child (rate ~57) must be
        // excluded too, even though it clears the floor on its own — a child
        // without its parent is unbuildable and would only waste a slot.
        let filtered = pool.iter_for_block_proposal(10, NOW);
        assert!(
            filtered.is_empty(),
            "below-floor parent must exclude the whole package, got {} entries",
            filtered.len()
        );
    }

    #[test]
    fn cascade_removes_chain_and_keeps_graph_mirrors_clean() {
        let mut pool = Mempool::new(test_config());
        let (p_id, _c_id, seed) = admit_parent_child_chain(&mut pool);

        // Removing the parent cascades the child; both graphs end empty.
        pool.remove(&p_id);
        assert!(pool.is_empty(), "cascade must remove the dependent child");
        assert_eq!(pool.dep_graphs_len(), (0, 0), "depends_on/children_of must mirror to empty");
        assert!(!pool.is_outpoint_spent(&seed));
    }

    #[test]
    fn expire_counts_cascaded_children() {
        let mut config = test_config();
        config.expiry_secs = 3600;
        let mut pool = Mempool::new(config);
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        let v = NO_UTXO_LOOKUP_VALUE;
        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), v)].into_iter().collect());

        // Parent received at NOW; chained child received at NOW+3000 (fresh).
        let p = make_signed_transfer_with_outpoint(&sk, &pk, &recip, x, 1_000, v - 1_500);
        let p_id = pool.admit(&p, NOW, &NoChainLookup, &lookup, 10).unwrap();
        let p_change = OutPoint { txid: p_id, vout: 1 };
        let c_in = v - 1_500;
        let c = make_signed_transfer_with_outpoint(&sk, &pk, &recip, p_change, c_in - 20_000, 0);
        pool.admit(&c, NOW + 3000, &NoChainLookup, &lookup, 10).unwrap();

        // At NOW+3601 only the parent is past expiry (cutoff = NOW+1), but the
        // child cascades with it — the return value must count BOTH.
        let removed = pool.expire(NOW + 3601);
        assert_eq!(removed, 2, "expire must count cascade-evicted children");
        assert!(pool.is_empty());
    }

    // --- K3-03: protocol-level expires_at enforcement ---

    /// Like make_signed_tx but with a protocol expiry set BEFORE signing.
    fn make_signed_tx_expiring(
        sk: &[u8],
        pk: &[u8],
        doc: &[u8],
        fee: u64,
        expires_at: u64,
    ) -> Transaction {
        let priv_key = NoblePrivateKey::Secp256k1(sk.to_vec());
        let mut tx = make_signed_tx(sk, pk, doc, fee);
        tx.expires_at = Some(expires_at);
        let msg = tx.compute_signing_message_for_chain(test_chain_id()).unwrap();
        tx.issuer_sig = priv_key.sign(&msg).unwrap();
        tx
    }

    #[test]
    fn protocol_expiry_sweep_and_proposal_filter() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let exp = NOW + 100;
        let tx = make_signed_tx_expiring(&sk, &pk, b"expiring", TEST_FEE, exp);

        // Valid at admission (NOW < expires_at).
        let tx_id = pool.admit(&tx, NOW, &NoChainLookup, &NoUtxoLookup, 10).unwrap();

        // Boundary: at now == expires_at the tx is NOT yet expired
        // (admission boundary is `now > expires_at`) — still proposable,
        // and the sweep must not remove it.
        assert_eq!(pool.iter_for_block_proposal(0, exp).len(), 1);
        assert_eq!(pool.expire(exp), 0, "not expired at now == expires_at");
        assert_eq!(pool.len(), 1);

        // One second past: excluded from proposal BEFORE any sweep runs.
        assert!(
            pool.iter_for_block_proposal(0, exp + 1).is_empty(),
            "expired tx must never be proposed, even pre-sweep"
        );
        // Still resident (mempool TTL not reached) until the sweep…
        assert_eq!(pool.len(), 1);
        // …which now removes it by protocol expiry, long before the TTL.
        assert_eq!(pool.expire(exp + 1), 1);
        assert!(pool.is_empty());
        assert!(!pool.contains(&tx_id));
    }

    #[test]
    fn expired_parent_excludes_child_from_proposal_and_sweep_cascades() {
        let mut pool = Mempool::new(test_config());
        let (sk, pk) = secp256k1::generate_keypair();
        let (_, recip) = secp256k1::generate_keypair();
        let v = NO_UTXO_LOOKUP_VALUE;
        let x = unique_outpoint();
        let lookup = MapUtxoLookup([(x.clone(), v)].into_iter().collect());
        let exp = NOW + 100;

        // Parent expires at `exp`; child (spending parent's change) does not.
        let mut p = make_signed_transfer_with_outpoint(&sk, &pk, &recip, x, 1_000, v - 1_500);
        p.expires_at = Some(exp);
        let msg = p.compute_signing_message_for_chain(test_chain_id()).unwrap();
        p.issuer_sig = NoblePrivateKey::Secp256k1(sk.to_vec()).sign(&msg).unwrap();
        let p_id = pool.admit(&p, NOW, &NoChainLookup, &lookup, 10).unwrap();
        let p_change = OutPoint { txid: p_id, vout: 1 };
        let c = make_signed_transfer_with_outpoint(&sk, &pk, &recip, p_change, v - 1_500 - 20_000, 0);
        let c_id = pool.admit(&c, NOW, &NoChainLookup, &lookup, 10).unwrap();

        // Past parent expiry: parent excluded → child (unexpired but
        // unbuildable without its parent) excluded via the topo gate.
        assert!(
            pool.iter_for_block_proposal(0, exp + 1).is_empty(),
            "expired parent must exclude the whole package from proposal"
        );

        // Sweep removes the parent by protocol expiry and cascades the child.
        assert_eq!(pool.expire(exp + 1), 2, "sweep must cascade to descendants");
        assert!(pool.is_empty());
        assert!(!pool.contains(&p_id) && !pool.contains(&c_id));
    }
}
