// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory storage backend for testing.
//!
//! Implements `StorageEngine` with `HashMap`-based storage. Not suitable for
//! production use — data is lost when the process exits.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, RwLock};

use noble_core::constants::{
    subsidy_at_height, COINBASE_MATURITY, MAX_REORG_DEPTH, MAX_SUPPLY, META_KEY_PREV_CHECKSUM,
};
use noble_core::{Block, BlockHeader, NobleAddress, OutPoint, PeerRecord, Transaction, UtxoEntry};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::StorageError;
use crate::traits::{ChainTip, KeyRotationRecord, StorageEngine};
use crate::MAX_CHECKSUM_REGISTRATIONS;

/// Shared inner state behind a RwLock for thread-safe testing.
#[derive(Default)]
struct Inner {
    blocks: HashMap<Hash256, Block>,
    block_heights: HashMap<u64, Hash256>,
    transactions: HashMap<Hash256, Transaction>,
    checksum_index: HashMap<Hash256, Vec<Hash256>>,
    tx_locations: HashMap<Hash256, (u64, u32)>,
    chain_tip: Option<ChainTip>,
    /// UTXO set: OutPoint → UtxoEntry.
    utxo_set: HashMap<OutPoint, UtxoEntry>,
    /// Reverse index: address → set of OutPoints owned by that address.
    address_utxos: HashMap<NobleAddress, HashSet<OutPoint>>,
    /// Undo data for rollback: height → list of (OutPoint, UtxoEntry) that were spent at that height.
    undo_data: HashMap<u64, Vec<(OutPoint, UtxoEntry)>>,
    /// Outputs created at each height, for rollback removal.
    created_outputs: HashMap<u64, Vec<(OutPoint, NobleAddress)>>,
    /// Address history: (wire_bytes, height, offset) → tx_id (GAP-H19).
    address_history: BTreeMap<(Vec<u8>, u64, u32), Hash256>,
    /// Persisted peer bans: peer_id_bytes → (banned_until_unix, category_code, evidence_hash).
    bans: HashMap<Vec<u8>, (u64, u8, Option<[u8; 32]>)>,
    /// Pending key rotations: old_key_wire → (new_key_wire, rotation_cycle).
    key_rotations: HashMap<Vec<u8>, (Vec<u8>, u64)>,
    /// Peer memory: identity_key_wire → PeerRecord.
    peer_records: HashMap<Vec<u8>, PeerRecord>,
    /// Cycle history: cycle_number → CBOR-encoded CycleHistoryEntry (H-002).
    cycle_history: BTreeMap<u64, Vec<u8>>,
    /// Version chain: prev_checksum → list of tx_ids that reference it via doc:prev_checksum.
    version_chain: HashMap<Hash256, Vec<Hash256>>,
    /// Publisher index: pubkey_wire_bytes → list of notarization tx_ids.
    publisher_index: HashMap<Vec<u8>, Vec<Hash256>>,
    /// Badge state: pubkey_wire → CBOR-encoded VoteBadge.
    badges: HashMap<Vec<u8>, Vec<u8>>,
    /// Badge proposals: proposal_hash → CBOR-encoded BadgeProposal.
    badge_proposals: HashMap<Vec<u8>, Vec<u8>>,
    /// Per-block vote witness: height → CBOR-encoded BlockVotes.
    block_votes: BTreeMap<u64, Vec<u8>>,
    /// Finality state persistence.
    finality_state: Option<Vec<u8>>,
    /// Misbehavior evidence: evidence_hash → CBOR-encoded MisbehaviorEvidence.
    evidence: HashMap<Vec<u8>, Vec<u8>>,
    /// Checkpoint state: height → CBOR-encoded Checkpoint.
    checkpoints: BTreeMap<u64, Vec<u8>>,
    closed: bool,
}

/// In-memory `StorageEngine` implementation for unit and integration tests.
///
/// Thread-safe via `Arc<RwLock>`. Clone is cheap (shared state).
#[derive(Clone, Default)]
pub struct MemoryStorage {
    inner: Arc<RwLock<Inner>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    fn check_open(inner: &Inner) -> Result<(), StorageError> {
        if inner.closed {
            return Err(StorageError::NotOpen);
        }
        Ok(())
    }
}

impl StorageEngine for MemoryStorage {
    #[tracing::instrument(skip(self, block, block_hash, tx_ids), fields(task = "memory_storage_commit", height = block.header.height))]
    fn commit_block(
        &self,
        block: &Block,
        block_hash: &Hash256,
        tx_ids: &[Hash256],
    ) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;

        // Store block
        inner.blocks.insert(*block_hash, block.clone());
        inner.block_heights.insert(block.header.height, *block_hash);

        // Store transactions, locations, and checksum index
        let height = block.header.height;
        for (offset, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
            inner.transactions.insert(*tx_id, tx.clone());
            inner.tx_locations.insert(*tx_id, (height, offset as u32));

            // Only index checksums for notarization transactions (defense-in-depth)
            if noble_core::tx_types::handler_for(tx.tx_type).map_or(false, |h| h.needs_notarization_indexing()) {
                let entry = inner.checksum_index.entry(tx.checksum).or_default();
                if entry.len() >= MAX_CHECKSUM_REGISTRATIONS {
                    return Err(StorageError::ChecksumIndexFull {
                        checksum: tx.checksum.to_string(),
                        count: entry.len(),
                        max: MAX_CHECKSUM_REGISTRATIONS,
                    });
                }
                entry.push(*tx_id);
            }
        }

        // --- Version chain indexing + publisher index ---
        for (tx, tx_id) in block.transactions.iter().zip(tx_ids.iter()) {
            if noble_core::tx_types::handler_for(tx.tx_type).map_or(false, |h| h.needs_notarization_indexing()) {
                if let Some(prev_hex) = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_PREV_CHECKSUM)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                {
                    if let Ok(prev_hash) = Hash256::from_hex(prev_hex) {
                        inner
                            .version_chain
                            .entry(prev_hash)
                            .or_default()
                            .push(*tx_id);
                    }
                }

                // publisher_index: pubkey_wire → list of notarization tx_ids
                let publisher_wire = tx
                    .publisher_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?
                    .to_wire_bytes();
                let pub_entry = inner.publisher_index.entry(publisher_wire).or_default();
                if pub_entry.len() < MAX_CHECKSUM_REGISTRATIONS {
                    pub_entry.push(*tx_id);
                }
            }
        }

        // --- UTXO processing ---
        let mut spent_utxos: Vec<(OutPoint, UtxoEntry)> = Vec::new();
        let mut created_outputs: Vec<(OutPoint, NobleAddress)> = Vec::new();
        let mut total_fees: u64 = 0;

        for (offset, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
            let is_coinbase = tx.is_coinbase();

            // --- Process inputs (skip for coinbase) ---
            let mut input_sum: u64 = 0;
            if !is_coinbase {
                for txin in &tx.inputs {
                    let outpoint = &txin.prev_output;
                    let utxo = inner.utxo_set.get(outpoint).cloned().ok_or_else(|| {
                        StorageError::Database(format!(
                            "UTXO not found: {}:{} at height {}",
                            outpoint.txid, outpoint.vout, height
                        ))
                    })?;

                    // Check coinbase maturity using UtxoEntry::is_mature()
                    if utxo.is_coinbase && !utxo.is_mature(height) {
                        return Err(StorageError::Database(format!(
                            "coinbase UTXO not mature: created at {}, current {}, need {}",
                            utxo.height,
                            height,
                            utxo.height + COINBASE_MATURITY
                        )));
                    }

                    input_sum = input_sum.checked_add(utxo.value).ok_or_else(|| {
                        StorageError::Database("input sum overflow".into())
                    })?;

                    // Remove from utxo_set and address_utxos
                    inner.utxo_set.remove(outpoint);
                    if let Some(set) = inner.address_utxos.get_mut(&utxo.address) {
                        set.remove(outpoint);
                        if set.is_empty() {
                            inner.address_utxos.remove(&utxo.address);
                        }
                    }

                    spent_utxos.push((outpoint.clone(), utxo));
                }

                // Verify sum(inputs) >= sum(outputs)
                let output_sum: u64 = tx.outputs.iter().map(|o| o.value).sum();
                if input_sum < output_sum {
                    return Err(StorageError::InsufficientBalance {
                        available: input_sum,
                        needed: output_sum,
                    });
                }
                total_fees += input_sum - output_sum;
            }

            // --- Process outputs (for ALL txs including coinbase) ---
            for (vout, txout) in tx.outputs.iter().enumerate() {
                let outpoint = OutPoint {
                    txid: *tx_id,
                    vout: vout as u32,
                };
                let entry = UtxoEntry {
                    value: txout.value,
                    address: txout.address.clone(),
                    height,
                    is_coinbase,
                };
                inner.utxo_set.insert(outpoint.clone(), entry);
                inner
                    .address_utxos
                    .entry(txout.address.clone())
                    .or_default()
                    .insert(outpoint.clone());
                created_outputs.push((outpoint, txout.address.clone()));
            }

            // --- Address history ---
            // Record sender history (publisher of the tx)
            let sender_pk = tx
                .publisher_sig
                .to_noble_public_key()
                .map_err(|e| StorageError::Codec(e.to_string()))?;
            let sender_addr = NobleAddress::Noble(sender_pk);
            let sender_wire = sender_addr.to_wire_bytes();
            inner
                .address_history
                .insert((sender_wire, height, offset as u32), *tx_id);

            // Record history for output addresses
            for txout in &tx.outputs {
                if txout.address != sender_addr {
                    inner.address_history.insert(
                        (txout.address.to_wire_bytes(), height, offset as u32),
                        *tx_id,
                    );
                }
            }
        }

        // Store undo data for rollback
        if !spent_utxos.is_empty() {
            inner.undo_data.insert(height, spent_utxos);
        }
        if !created_outputs.is_empty() {
            inner.created_outputs.insert(height, created_outputs);
        }

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

        // --- MAX_SUPPLY cap enforcement (only subsidy increases supply) ---
        let block_subsidy = subsidy;
        if block_subsidy > 0 {
            // Total supply = sum of all UTXO values
            let cumulative: u64 = inner.utxo_set.values().map(|e| e.value).sum();
            if cumulative > MAX_SUPPLY {
                return Err(StorageError::SupplyOverflow {
                    cumulative,
                    max: MAX_SUPPLY,
                });
            }
        }

        // Update chain tip
        inner.chain_tip = Some(ChainTip {
            block_hash: *block_hash,
            height: block.header.height,
        });

        tracing::debug!("committed block at height {}", block.header.height);

        Ok(())
    }

    fn get_block(&self, block_hash: &Hash256) -> Result<Block, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .blocks
            .get(block_hash)
            .cloned()
            .ok_or_else(|| StorageError::BlockNotFound(block_hash.to_string()))
    }

    fn get_block_header(&self, block_hash: &Hash256) -> Result<BlockHeader, StorageError> {
        self.get_block(block_hash).map(|b| b.header)
    }

    fn get_block_hash_by_height(&self, height: u64) -> Result<Hash256, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .block_heights
            .get(&height)
            .copied()
            .ok_or_else(|| StorageError::BlockNotFound(format!("height {height}")))
    }

    fn get_transaction(&self, tx_id: &Hash256) -> Result<Transaction, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .transactions
            .get(tx_id)
            .cloned()
            .ok_or_else(|| StorageError::TransactionNotFound(tx_id.to_string()))
    }

    fn lookup_checksum(&self, checksum: &Hash256) -> Result<Vec<Hash256>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner
            .checksum_index
            .get(checksum)
            .cloned()
            .unwrap_or_default())
    }

    fn has_transaction(&self, tx_id: &Hash256) -> Result<bool, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.transactions.contains_key(tx_id))
    }

    fn get_transaction_location(&self, tx_id: &Hash256) -> Result<(u64, u32), StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .tx_locations
            .get(tx_id)
            .copied()
            .ok_or_else(|| StorageError::TransactionNotFound(tx_id.to_string()))
    }

    fn get_balance(&self, address: &NobleAddress) -> Result<u64, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        let balance = inner
            .address_utxos
            .get(address)
            .map(|outpoints| {
                outpoints
                    .iter()
                    .filter_map(|op| inner.utxo_set.get(op))
                    .map(|e| e.value)
                    .sum()
            })
            .unwrap_or(0);
        Ok(balance)
    }

    fn get_address_utxos(
        &self,
        address: &NobleAddress,
    ) -> Result<Vec<(noble_core::OutPoint, noble_core::UtxoEntry)>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        let mut result = Vec::new();
        if let Some(outpoints) = inner.address_utxos.get(address) {
            for op in outpoints {
                if let Some(entry) = inner.utxo_set.get(op) {
                    result.push((op.clone(), entry.clone()));
                }
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
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;

        let wire = address.to_wire_bytes();
        let skip = (page as usize) * (limit as usize);

        // Range scan: all entries whose first element matches wire bytes
        let start = (wire.clone(), 0u64, 0u32);
        let results: Vec<Hash256> = inner
            .address_history
            .range(start..)
            .take_while(|((w, _, _), _)| w == &wire)
            .skip(skip)
            .take(limit as usize)
            .map(|(_, tx_id)| *tx_id)
            .collect();

        Ok(results)
    }

    fn count_address_history(&self, address: &NobleAddress) -> Result<u64, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;

        let wire = address.to_wire_bytes();
        let start = (wire.clone(), 0u64, 0u32);
        let count = inner
            .address_history
            .range(start..)
            .take_while(|((w, _, _), _)| *w == wire)
            .count() as u64;
        Ok(count)
    }

    fn get_chain_tip(&self) -> Result<Option<ChainTip>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.chain_tip.clone())
    }

    #[tracing::instrument(
        skip(self),
        fields(task = "memory_storage_rollback", target_height, chain_id)
    )]
    fn rollback_to_height(
        &self,
        target_height: u64,
        chain_id: u32,
    ) -> Result<ChainTip, StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        tracing::debug!("rolling back to height {}", target_height);

        // Find tip
        let tip = inner
            .chain_tip
            .as_ref()
            .ok_or_else(|| StorageError::Database("no chain tip".into()))?;

        if target_height >= tip.height {
            return Ok(tip.clone()); // nothing to do
        }

        // Enforce MAX_REORG_DEPTH
        let depth = tip.height - target_height;
        if depth > MAX_REORG_DEPTH {
            return Err(StorageError::ReorgTooDeep {
                depth,
                max: MAX_REORG_DEPTH,
            });
        }

        // Reverse blocks from tip down to target_height+1
        let tip_h = tip.height;
        for h in (target_height + 1..=tip_h).rev() {
            // 1. Reverse created outputs: remove UTXOs created at this height
            if let Some(created) = inner.created_outputs.remove(&h) {
                for (outpoint, address) in &created {
                    inner.utxo_set.remove(outpoint);
                    if let Some(set) = inner.address_utxos.get_mut(address) {
                        set.remove(outpoint);
                        if set.is_empty() {
                            inner.address_utxos.remove(address);
                        }
                    }
                }
            }

            // 2. Restore spent UTXOs from undo data
            if let Some(spent) = inner.undo_data.remove(&h) {
                for (outpoint, entry) in spent {
                    inner
                        .address_utxos
                        .entry(entry.address.clone())
                        .or_default()
                        .insert(outpoint.clone());
                    inner.utxo_set.insert(outpoint, entry);
                }
            }

            // 3. Remove block data (transactions, checksum index, etc.)
            if let Some(hash) = inner.block_heights.remove(&h) {
                if let Some(block) = inner.blocks.remove(&hash) {
                    for tx in &block.transactions {
                        match tx.compute_tx_id(chain_id) {
                            Ok(tx_id) => {
                                inner.transactions.remove(&tx_id);
                                inner.tx_locations.remove(&tx_id);
                                if let Some(entries) = inner.checksum_index.get_mut(&tx.checksum) {
                                    entries.retain(|id| *id != tx_id);
                                    if entries.is_empty() {
                                        inner.checksum_index.remove(&tx.checksum);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("corrupt tx during rollback at height {h}: {e}");
                            }
                        }
                    }
                }
            }
        }

        // Clear and replay address_history, version_chain, publisher_index
        inner.address_history.clear();
        inner.version_chain.clear();
        inner.publisher_index.clear();

        // Replay address history + version chain + publisher index from 0..=target_height
        for h in 0..=target_height {
            let hash = *inner.block_heights.get(&h).ok_or_else(|| {
                StorageError::Database(format!("missing block at height {h} during replay"))
            })?;
            let block = inner
                .blocks
                .get(&hash)
                .ok_or_else(|| StorageError::Database(format!("missing block data at height {h}")))?
                .clone();

            for (offset, tx) in block.transactions.iter().enumerate() {
                let tx_id = tx
                    .compute_tx_id(chain_id)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;

                // Address history: sender
                let sender_pk = tx
                    .publisher_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                let sender_addr = NobleAddress::Noble(sender_pk);
                inner
                    .address_history
                    .insert((sender_addr.to_wire_bytes(), h, offset as u32), tx_id);

                // Address history: output addresses
                for txout in &tx.outputs {
                    if txout.address != sender_addr {
                        inner.address_history.insert(
                            (txout.address.to_wire_bytes(), h, offset as u32),
                            tx_id,
                        );
                    }
                }

                // Version chain + publisher index
                if noble_core::tx_types::handler_for(tx.tx_type).map_or(false, |h| h.needs_notarization_indexing()) {
                    if let Some(prev_hex) = tx
                        .metadata
                        .iter()
                        .find(|m| m.key == META_KEY_PREV_CHECKSUM)
                        .and_then(|m| std::str::from_utf8(&m.value).ok())
                    {
                        if let Ok(prev_hash) = Hash256::from_hex(prev_hex) {
                            inner
                                .version_chain
                                .entry(prev_hash)
                                .or_default()
                                .push(tx_id);
                        }
                    }

                    let publisher_wire = tx
                        .publisher_sig
                        .to_noble_public_key()
                        .map_err(|e| StorageError::Codec(e.to_string()))?
                        .to_wire_bytes();
                    inner
                        .publisher_index
                        .entry(publisher_wire)
                        .or_default()
                        .push(tx_id);
                }
            }
        }

        // Update chain tip
        let new_hash = *inner
            .block_heights
            .get(&target_height)
            .ok_or_else(|| StorageError::Database("missing target height after rollback".into()))?;
        let new_tip = ChainTip {
            block_hash: new_hash,
            height: target_height,
        };
        inner.chain_tip = Some(new_tip.clone());
        Ok(new_tip)
    }

    fn force_reset_to_genesis(&self, chain_id: u32) -> Result<ChainTip, StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;

        let tip = inner
            .chain_tip
            .as_ref()
            .ok_or_else(|| StorageError::Database("no chain tip".into()))?;

        if tip.height == 0 {
            return Ok(tip.clone());
        }

        tracing::warn!(
            "force_reset_to_genesis: wiping {} blocks (bypasses MAX_REORG_DEPTH)",
            tip.height
        );

        let tip_h = tip.height;
        for h in 1..=tip_h {
            if let Some(hash) = inner.block_heights.remove(&h) {
                if let Some(block) = inner.blocks.remove(&hash) {
                    for tx in &block.transactions {
                        match tx.compute_tx_id(chain_id) {
                            Ok(tx_id) => {
                                inner.transactions.remove(&tx_id);
                                inner.tx_locations.remove(&tx_id);
                                if let Some(entries) = inner.checksum_index.get_mut(&tx.checksum) {
                                    entries.retain(|id| *id != tx_id);
                                    if entries.is_empty() {
                                        inner.checksum_index.remove(&tx.checksum);
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("corrupt tx during force_reset at height {h}: {e}");
                            }
                        }
                    }
                }
            }
        }

        // Clear derived state
        inner.utxo_set.clear();
        inner.address_utxos.clear();
        inner.undo_data.clear();
        inner.created_outputs.clear();
        inner.address_history.clear();
        inner.version_chain.clear();
        inner.publisher_index.clear();

        // Replay genesis (height 0) UTXO set
        if let Some(&genesis_hash) = inner.block_heights.get(&0) {
            if let Some(block) = inner.blocks.get(&genesis_hash).cloned() {
                for tx in &block.transactions {
                    let tx_id = tx
                        .compute_tx_id(chain_id)
                        .map_err(|e| StorageError::Codec(e.to_string()))?;
                    let is_coinbase = tx.is_coinbase();
                    for (vout, txout) in tx.outputs.iter().enumerate() {
                        let outpoint = OutPoint {
                            txid: tx_id,
                            vout: vout as u32,
                        };
                        let entry = UtxoEntry {
                            value: txout.value,
                            address: txout.address.clone(),
                            height: 0,
                            is_coinbase,
                        };
                        inner.utxo_set.insert(outpoint.clone(), entry);
                        inner
                            .address_utxos
                            .entry(txout.address.clone())
                            .or_default()
                            .insert(outpoint);
                    }
                }
            }
            inner.chain_tip = Some(ChainTip {
                block_hash: genesis_hash,
                height: 0,
            });
            Ok(inner.chain_tip.clone().unwrap())
        } else {
            Err(StorageError::Database(
                "missing genesis block at height 0".into(),
            ))
        }
    }

    fn wipe_all_chain_data(&self) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;

        tracing::warn!("wipe_all_chain_data: clearing ALL in-memory storage (cross-chain adoption)");

        inner.blocks.clear();
        inner.block_heights.clear();
        inner.transactions.clear();
        inner.checksum_index.clear();
        inner.tx_locations.clear();
        inner.chain_tip = None;
        inner.utxo_set.clear();
        inner.address_utxos.clear();
        inner.undo_data.clear();
        inner.created_outputs.clear();
        inner.address_history.clear();
        inner.bans.clear();
        inner.key_rotations.clear();
        inner.peer_records.clear();
        inner.cycle_history.clear();
        inner.version_chain.clear();
        inner.publisher_index.clear();
        inner.badges.clear();
        inner.badge_proposals.clear();
        inner.block_votes.clear();
        inner.finality_state = None;
        inner.evidence.clear();
        inner.checkpoints.clear();

        Ok(())
    }

    fn get_recent_timestamps(&self, count: usize) -> Result<Vec<u64>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        let tip = match &inner.chain_tip {
            Some(t) => t.height,
            None => return Ok(vec![]),
        };
        let mut timestamps = Vec::with_capacity(count);
        let start = tip.saturating_sub(count.saturating_sub(1) as u64);
        for h in (start..=tip).rev() {
            if let Some(hash) = inner.block_heights.get(&h) {
                if let Some(block) = inner.blocks.get(hash) {
                    timestamps.push(block.header.timestamp);
                }
            }
            if timestamps.len() >= count {
                break;
            }
        }
        Ok(timestamps)
    }

    fn store_ban(&self, peer_id: &[u8], banned_until: u64, category_code: u8, evidence_hash: Option<&[u8; 32]>) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.bans.insert(peer_id.to_vec(), (banned_until, category_code, evidence_hash.copied()));
        Ok(())
    }

    fn remove_ban(&self, peer_id: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.bans.remove(peer_id);
        Ok(())
    }

    fn load_bans(&self) -> Result<Vec<(Vec<u8>, u64, u8, Option<[u8; 32]>)>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Only return non-expired bans
        Ok(inner
            .bans
            .iter()
            .filter(|(_, (until, _, _))| *until > now)
            .map(|(k, (until, cat, hash))| (k.clone(), *until, *cat, *hash))
            .collect())
    }

    fn store_key_rotation(
        &self,
        old_key: &NoblePublicKey,
        new_key: &NoblePublicKey,
        rotation_cycle: u64,
    ) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.key_rotations.insert(
            old_key.to_wire_bytes(),
            (new_key.to_wire_bytes(), rotation_cycle),
        );
        Ok(())
    }

    fn remove_key_rotation(&self, old_key: &NoblePublicKey) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.key_rotations.remove(&old_key.to_wire_bytes());
        Ok(())
    }

    fn load_key_rotations(&self) -> Result<Vec<KeyRotationRecord>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner
            .key_rotations
            .iter()
            .map(|(old_wire, (new_wire, cycle))| (old_wire.clone(), new_wire.clone(), *cycle))
            .collect())
    }

    fn store_peer_record(&self, record: &PeerRecord) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner
            .peer_records
            .insert(record.identity_key.clone(), record.clone());
        Ok(())
    }

    fn get_peer_record(&self, identity_key: &[u8]) -> Result<PeerRecord, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        inner
            .peer_records
            .get(identity_key)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    fn list_peer_records(&self) -> Result<Vec<PeerRecord>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.peer_records.values().cloned().collect())
    }

    fn remove_peer_record(&self, identity_key: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.peer_records.remove(identity_key);
        Ok(())
    }

    fn prune_peer_records(&self, now: u64, max_age_secs: u64) -> Result<u32, StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        let before = inner.peer_records.len();
        inner
            .peer_records
            .retain(|_, rec| !rec.is_stale(now, max_age_secs));
        Ok((before - inner.peer_records.len()) as u32)
    }

    // ── Version Chain ──

    fn lookup_version_successors(
        &self,
        prev_checksum: &Hash256,
    ) -> Result<Vec<Hash256>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner
            .version_chain
            .get(prev_checksum)
            .cloned()
            .unwrap_or_default())
    }

    // ── Publisher Index ──

    fn lookup_by_publisher(&self, pubkey_wire: &[u8]) -> Result<Vec<Hash256>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner
            .publisher_index
            .get(pubkey_wire)
            .cloned()
            .unwrap_or_default())
    }

    // ── Cycle History (H-002) ──

    fn store_cycle_history(&self, cycle: u64, data: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.cycle_history.insert(cycle, data.to_vec());
        Ok(())
    }

    fn get_recent_cycle_history(&self, count: usize) -> Result<Vec<Vec<u8>>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        // BTreeMap iterates in ascending order; we want newest-first.
        let entries: Vec<Vec<u8>> = inner
            .cycle_history
            .iter()
            .rev()
            .take(count)
            .map(|(_, v)| v.clone())
            .collect();
        Ok(entries)
    }

    fn clear_cycle_history(&self) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.cycle_history.clear();
        Ok(())
    }

    // ── Per-Block Vote Witness ──

    fn store_block_votes(&self, height: u64, data: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.block_votes.insert(height, data.to_vec());
        Ok(())
    }

    fn get_block_votes(&self, height: u64) -> Result<Option<Vec<u8>>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.block_votes.get(&height).cloned())
    }

    fn get_utxo(&self, outpoint: &noble_core::OutPoint) -> Result<Option<UtxoEntry>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.utxo_set.get(outpoint).cloned())
    }

    fn store_finality_state(&self, data: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.finality_state = Some(data.to_vec());
        Ok(())
    }

    fn load_finality_state(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.finality_state.clone())
    }

    // ── Badge State ──

    fn store_badge(&self, pubkey_wire: &[u8], badge_cbor: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.badges.insert(pubkey_wire.to_vec(), badge_cbor.to_vec());
        Ok(())
    }

    fn get_badge(&self, pubkey_wire: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.badges.get(pubkey_wire).cloned())
    }

    fn remove_badge(&self, pubkey_wire: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.badges.remove(pubkey_wire);
        Ok(())
    }

    fn list_badges(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.badges.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn store_badge_proposal(&self, proposal_hash: &[u8], proposal_cbor: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.badge_proposals.insert(proposal_hash.to_vec(), proposal_cbor.to_vec());
        Ok(())
    }

    fn get_badge_proposal(&self, proposal_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.badge_proposals.get(proposal_hash).cloned())
    }

    fn remove_badge_proposal(&self, proposal_hash: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.badge_proposals.remove(proposal_hash);
        Ok(())
    }

    fn list_badge_proposals(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.badge_proposals.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    // ── Checkpoint State ──

    fn store_checkpoint(&self, height: u64, data: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.checkpoints.insert(height, data.to_vec());
        Ok(())
    }

    fn load_checkpoints(&self) -> Result<Vec<(u64, Vec<u8>)>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(inner.checkpoints.iter().map(|(&h, v)| (h, v.clone())).collect())
    }

    fn store_evidence(&self, evidence_hash: &[u8], evidence_cbor: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        if inner.closed {
            return Err(StorageError::NotOpen);
        }
        inner.evidence.insert(evidence_hash.to_vec(), evidence_cbor.to_vec());
        Ok(())
    }

    fn get_evidence(&self, evidence_hash: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let inner = self.inner.read().unwrap();
        if inner.closed {
            return Err(StorageError::NotOpen);
        }
        Ok(inner.evidence.get(evidence_hash).cloned())
    }

    fn list_evidence(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, StorageError> {
        let inner = self.inner.read().unwrap();
        if inner.closed {
            return Err(StorageError::NotOpen);
        }
        Ok(inner.evidence.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
    }

    fn close(&mut self) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        inner.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::constants::{HALVING_INTERVAL, INITIAL_SUBSIDY, TX_TYPE_COINBASE, TX_TYPE_TRANSFER};
    use noble_core::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut, PROTOCOL_VERSION};
    use noble_test_utils::fixtures::test_chain_id;
    use noble_crypto::{
        ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };

    /// Convenience: wrap a NoblePublicKey into a NobleAddress for balance lookups.
    fn addr(pk: &NoblePublicKey) -> NobleAddress {
        NobleAddress::Noble(pk.clone())
    }

    /// Create a coinbase transaction that pays the subsidy to `validator_addr`.
    fn make_coinbase_tx(
        validator_addr: &NobleAddress,
        height: u64,
        chain_id: u32,
    ) -> (Transaction, Hash256) {
        make_coinbase_tx_with_fees(validator_addr, height, chain_id, 0)
    }

    fn make_coinbase_tx_with_fees(
        validator_addr: &NobleAddress,
        height: u64,
        chain_id: u32,
        extra_fees: u64,
    ) -> (Transaction, Hash256) {
        let subsidy = subsidy_at_height(height);
        let total = subsidy + extra_fees;
        // Coinbase uses a dummy signer (the validator's key isn't necessarily available,
        // but tests that need it pass sk/pk explicitly).
        let (sk, pk) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());

        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_COINBASE,
            inputs: vec![TxIn {
                prev_output: OutPoint::COINBASE_PREVOUT,
            }],
            outputs: if total > 0 {
                vec![TxOut {
                    value: total,
                    address: validator_addr.clone(),
                }]
            } else {
                vec![]
            },
            checksum: Hash256::ZERO,
            timestamp: 0,
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
        let msg = tx.compute_signing_message_for_chain(chain_id).unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(chain_id).unwrap();
        (tx, tx_id)
    }

    /// Create a notarization tx that has no inputs/outputs (fee=0 notarization for testing).
    fn make_signed_tx(sk: &[u8], pk: &[u8], doc: &[u8], timestamp: u64) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let checksum = sha256(doc);
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![],
            outputs: vec![],
            checksum,
            timestamp,
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
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    /// Create a transfer tx that spends specific UTXOs and creates outputs.
    fn make_transfer_tx(
        sk: &[u8],
        pk: &[u8],
        inputs: Vec<OutPoint>,
        outputs: Vec<TxOut>,
        timestamp: u64,
    ) -> (Transaction, Hash256) {
        let priv_key = NoblePrivateKey::Ed25519(sk.to_vec());
        let mut tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            inputs: inputs.into_iter().map(|op| TxIn { prev_output: op }).collect(),
            outputs,
            checksum: Hash256::ZERO,
            timestamp,
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
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
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

    /// Build a block with a specific validator keypair.
    /// Automatically prepends a coinbase transaction paying the subsidy to the validator.
    fn make_block_with_validator(
        txs: Vec<(Transaction, Hash256)>,
        height: u64,
        prev_hash: Hash256,
        timestamp: u64,
        val_sk: &[u8],
        val_pk: &[u8],
    ) -> (Block, Hash256, Vec<Hash256>) {
        make_block_with_validator_fees(txs, height, prev_hash, timestamp, val_sk, val_pk, 0)
    }

    fn make_block_with_validator_fees(
        txs: Vec<(Transaction, Hash256)>,
        height: u64,
        prev_hash: Hash256,
        timestamp: u64,
        val_sk: &[u8],
        val_pk: &[u8],
        fees: u64,
    ) -> (Block, Hash256, Vec<Hash256>) {
        let val_priv = NoblePrivateKey::Ed25519(val_sk.to_vec());
        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        let validator_addr = NobleAddress::Noble(val_pub.clone());

        // Build coinbase tx (subsidy + fees)
        let (coinbase_tx, coinbase_id) =
            make_coinbase_tx_with_fees(&validator_addr, height, test_chain_id(), fees);

        // Prepend coinbase
        let mut all_txs = vec![(coinbase_tx, coinbase_id)];
        all_txs.extend(txs);

        let transactions: Vec<Transaction> = all_txs.iter().map(|(tx, _)| tx.clone()).collect();
        let tx_ids: Vec<Hash256> = all_txs.iter().map(|(_, id)| *id).collect();
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

    #[test]
    fn empty_store_has_no_tip() {
        let store = MemoryStorage::new();
        assert!(store.get_chain_tip().unwrap().is_none());
    }

    #[test]
    fn commit_and_retrieve_block() {
        let store = MemoryStorage::new();
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

        store.commit_block(&block, &block_hash, &tx_ids).unwrap();

        // Retrieve block
        let got = store.get_block(&block_hash).unwrap();
        assert_eq!(got, block);

        // Retrieve header
        let header = store.get_block_header(&block_hash).unwrap();
        assert_eq!(header, block.header);

        // Retrieve by height
        let hash = store.get_block_hash_by_height(0).unwrap();
        assert_eq!(hash, block_hash);
    }

    #[test]
    fn commit_and_retrieve_transaction() {
        let store = MemoryStorage::new();
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

        store.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let got = store.get_transaction(&tx_id).unwrap();
        assert_eq!(got, tx);
        assert!(store.has_transaction(&tx_id).unwrap());
    }

    #[test]
    fn checksum_lookup() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Two different txs registering the same document (sender = validator, so funded)
        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_000);
        let (tx2, tx_id2) = make_signed_tx(&sk, &pk, b"same_doc", 1_700_000_001);

        let (block, block_hash, tx_ids) = make_block_with_validator(
            vec![(tx1.clone(), tx_id1), (tx2.clone(), tx_id2)],
            0,
            Hash256::ZERO,
            1_700_000_001,
            &sk,
            &pk,
        );

        store.commit_block(&block, &block_hash, &tx_ids).unwrap();

        let checksum = sha256(b"same_doc");
        let results = store.lookup_checksum(&checksum).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&tx_id1));
        assert!(results.contains(&tx_id2));
    }

    #[test]
    fn checksum_lookup_empty() {
        let store = MemoryStorage::new();
        let missing = Hash256::from_bytes([0xFF; 32]);
        let results = store.lookup_checksum(&missing).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn chain_tip_updates() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0 (sender = validator, so funded)
        let (tx0, tx_id0) = make_signed_tx(&sk, &pk, b"doc0", 1_700_000_000);
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![(tx0, tx_id0)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let tip = store.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash0);
        assert_eq!(tip.height, 0);

        // Block 1
        let (tx1, tx_id1) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![(tx1, tx_id1)], 1, hash0, 1_700_000_001, &sk, &pk);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let tip = store.get_chain_tip().unwrap().unwrap();
        assert_eq!(tip.block_hash, hash1);
        assert_eq!(tip.height, 1);
    }

    #[test]
    fn not_found_errors() {
        let store = MemoryStorage::new();
        let missing = Hash256::from_bytes([0xFF; 32]);

        assert!(matches!(
            store.get_block(&missing),
            Err(StorageError::BlockNotFound(_))
        ));
        assert!(matches!(
            store.get_transaction(&missing),
            Err(StorageError::TransactionNotFound(_))
        ));
        assert!(matches!(
            store.get_block_hash_by_height(999),
            Err(StorageError::BlockNotFound(_))
        ));
        assert!(!store.has_transaction(&missing).unwrap());
    }

    #[test]
    fn closed_store_rejects_operations() {
        let mut store = MemoryStorage::new();
        store.close().unwrap();

        let missing = Hash256::ZERO;
        assert!(matches!(
            store.get_block(&missing),
            Err(StorageError::NotOpen)
        ));
        assert!(matches!(store.get_chain_tip(), Err(StorageError::NotOpen)));
    }

    // --- UTXO balance tests ---

    #[test]
    fn balance_zero_for_unknown_address() {
        let store = MemoryStorage::new();
        let (_, pk) = ed25519::generate_keypair();
        let pubkey = NoblePublicKey::Ed25519(pk);
        assert_eq!(store.get_balance(&addr(&pubkey)).unwrap(), 0);
    }

    #[test]
    fn subsidy_credited_to_validator() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![], 1, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        let validator = block.header.validator_id.clone();
        store.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(store.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY);
    }

    #[test]
    fn subsidy_halves_at_halving_interval() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (block, block_hash, tx_ids) =
            make_block_with_validator(vec![], HALVING_INTERVAL, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        let validator = block.header.validator_id.clone();
        store.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(store.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn transfer_spends_utxo_and_creates_new() {
        let store = MemoryStorage::new();

        // Fund sender as validator of block 1 (gets subsidy via coinbase)
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let sender_addr = NobleAddress::Noble(sender_pub.clone());
        assert_eq!(store.get_balance(&sender_addr).unwrap(), INITIAL_SUBSIDY);

        // The coinbase tx_id is ids0[0] (first tx in block, which is the coinbase)
        let coinbase_outpoint = OutPoint {
            txid: ids0[0],
            vout: 0,
        };

        // Create transfer: spend coinbase UTXO (must wait for COINBASE_MATURITY)
        // So first commit enough blocks to reach maturity
        let mut prev_hash = hash0;
        for h in 2..=(1 + COINBASE_MATURITY) {
            let (b, bh, bids) = make_block_with_validator(
                vec![],
                h,
                prev_hash,
                1_700_000_000 + h,
                &sender_sk,
                &sender_pk,
            );
            store.commit_block(&b, &bh, &bids).unwrap();
            prev_hash = bh;
        }

        // Now create a transfer spending the original coinbase
        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(recip_pk));
        let amount = 100_000u64;
        let fee = 1_000u64;
        let change = INITIAL_SUBSIDY - amount - fee;

        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            vec![coinbase_outpoint],
            vec![
                TxOut {
                    value: amount,
                    address: recipient.clone(),
                },
                TxOut {
                    value: change,
                    address: sender_addr.clone(),
                },
            ],
            1_700_000_100,
        );
        let height = 1 + COINBASE_MATURITY + 1;
        let (block1, hash1, ids1) = make_block_with_validator_fees(
            vec![(tx, tx_id)],
            height,
            prev_hash,
            1_700_000_100,
            &sender_sk,
            &sender_pk,
            fee, // include tx fee in coinbase output
        );
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        // Recipient gets the amount
        assert_eq!(store.get_balance(&recipient).unwrap(), amount);

        // Sender has change + coinbase UTXOs from blocks 2..=height
        // Block 1 coinbase was spent by the transfer; blocks 2..=height coinbases remain
        // The block containing the transfer (at `height`) has coinbase = subsidy + fee
        let remaining_subsidies = (height - 1) * INITIAL_SUBSIDY + fee; // blocks 2..=height
        assert_eq!(
            store.get_balance(&sender_addr).unwrap(),
            change + remaining_subsidies
        );
    }

    #[test]
    fn transfer_insufficient_inputs_fails() {
        let store = MemoryStorage::new();

        // Sender has no UTXOs — try to spend a non-existent outpoint
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(recip_pk));
        let fake_outpoint = OutPoint {
            txid: Hash256::from_bytes([0xAA; 32]),
            vout: 0,
        };
        let (tx, tx_id) = make_transfer_tx(
            &sender_sk,
            &sender_pk,
            vec![fake_outpoint],
            vec![TxOut {
                value: 100_000,
                address: recipient,
            }],
            1_700_000_000,
        );
        let (block, block_hash, tx_ids) =
            make_block(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000);

        let result = store.commit_block(&block, &block_hash, &tx_ids);
        assert!(result.is_err(), "spending non-existent UTXO should fail");
    }

    #[test]
    fn history_records_notarization() {
        let store = MemoryStorage::new();

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
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) = make_block_with_validator(
            vec![(tx1, id1)],
            2,
            hash0,
            1_700_000_001,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let history = store.get_address_history(&addr(&sender_pub), 0, 100).unwrap();
        assert!(history.contains(&id1));
    }

    #[test]
    fn history_empty_for_unknown() {
        let store = MemoryStorage::new();
        let (_, pk) = ed25519::generate_keypair();
        let pubkey = NoblePublicKey::Ed25519(pk);
        let history = store.get_address_history(&addr(&pubkey), 0, 100).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn multi_block_balance_accumulation() {
        let store = MemoryStorage::new();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        let mut prev_hash = Hash256::ZERO;
        for h in 1..4 {
            let (block, hash, ids) = make_block_with_validator(
                vec![],
                h,
                prev_hash,
                1_700_000_000 + h,
                &val_sk,
                &val_pk,
            );
            store.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(store.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 3);
    }

    // --- Rollback tests ---

    #[test]
    fn rollback_removes_blocks() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        let mut prev = Hash256::ZERO;
        for h in 0..3u64 {
            let (b, hash, ids) =
                make_block_with_validator(vec![], h, prev, 1_700_000_000 + h, &sk, &pk);
            store.commit_block(&b, &hash, &ids).unwrap();
            prev = hash;
        }

        let tip = store.rollback_to_height(1, test_chain_id()).unwrap();
        assert_eq!(tip.height, 1);
        assert!(store.get_block_hash_by_height(2).is_err());
        let new_tip = store.get_chain_tip().unwrap().unwrap();
        assert_eq!(new_tip.height, 1);
    }

    #[test]
    fn rollback_restores_utxo_state() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let val_pub = NoblePublicKey::Ed25519(pk.to_vec());

        let mut prev = Hash256::ZERO;
        for h in 0..4u64 {
            let (b, hash, ids) =
                make_block_with_validator(vec![], h, prev, 1_700_000_000 + h, &sk, &pk);
            store.commit_block(&b, &hash, &ids).unwrap();
            prev = hash;
        }

        // Heights 0..=3: height 0 gives 0 subsidy, heights 1-3 give INITIAL_SUBSIDY each
        assert_eq!(store.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 3);
        store.rollback_to_height(2, test_chain_id()).unwrap();
        // After rollback to height 2: heights 0,1,2 remain; 0 gives 0, 1-2 give INITIAL_SUBSIDY each
        assert_eq!(store.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY * 2);
    }

    #[test]
    fn rollback_noop_at_tip() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (b, hash, ids) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b, &hash, &ids).unwrap();

        let tip = store.rollback_to_height(0, test_chain_id()).unwrap();
        assert_eq!(tip.height, 0);
    }

    #[test]
    fn rollback_clears_tx_index() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: empty (fund validator)
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: one tx
        let (tx1, id1) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_001);
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx1, id1)], 1, h0, 1_700_000_001, &sk, &pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        assert!(store.has_transaction(&id1).unwrap());
        store.rollback_to_height(0, test_chain_id()).unwrap();
        assert!(!store.has_transaction(&id1).unwrap());
    }

    #[test]
    fn get_transaction_location_found() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        let (tx1, id1) = make_signed_tx(&sk, &pk, b"doc1", 1_700_000_000);
        let (tx2, id2) = make_signed_tx(&sk, &pk, b"doc2", 1_700_000_000);
        let (block, hash, ids) = make_block_with_validator(
            vec![(tx1, id1), (tx2, id2)],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sk,
            &pk,
        );
        store.commit_block(&block, &hash, &ids).unwrap();

        // tx1 and tx2 are after coinbase (offset 0), so they are at offset 1 and 2
        let (h, off) = store.get_transaction_location(&id1).unwrap();
        assert_eq!(h, 0);
        assert_eq!(off, 1); // after coinbase

        let (h2, off2) = store.get_transaction_location(&id2).unwrap();
        assert_eq!(h2, 0);
        assert_eq!(off2, 2);

        // Unknown tx returns error
        let missing = Hash256::from_bytes([0xFF; 32]);
        assert!(store.get_transaction_location(&missing).is_err());
    }

    // --- Ban persistence tests ---

    #[test]
    fn store_and_load_ban() {
        let store = MemoryStorage::new();
        let peer_id = b"peer_12345678901234567890123456789012";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let banned_until = now + 86400;
        store.store_ban(peer_id, banned_until, 0x04, None).unwrap();

        let bans = store.load_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, peer_id.to_vec());
        assert_eq!(bans[0].1, banned_until);
        assert_eq!(bans[0].2, 0x04);
        assert_eq!(bans[0].3, None);
    }

    #[test]
    fn load_bans_filters_expired() {
        let store = MemoryStorage::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Expired ban
        store
            .store_ban(b"expired_peer", now.saturating_sub(100), 0x01, None)
            .unwrap();
        // Active ban
        store.store_ban(b"active_peer", now + 86400, 0x02, None).unwrap();

        let bans = store.load_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, b"active_peer".to_vec());
    }

    #[test]
    fn remove_ban() {
        let store = MemoryStorage::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.store_ban(b"peer1", now + 86400, 0x0C, None).unwrap();
        store.remove_ban(b"peer1").unwrap();

        let bans = store.load_bans().unwrap();
        assert!(bans.is_empty());
    }

    // --- Recent timestamps tests ---

    #[test]
    fn get_recent_timestamps_empty_chain() {
        let store = MemoryStorage::new();
        let ts = store.get_recent_timestamps(11).unwrap();
        assert!(ts.is_empty());
    }

    #[test]
    fn get_recent_timestamps_returns_newest_first() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Commit 3 blocks with distinct timestamps
        let mut prev_hash = Hash256::ZERO;
        for h in 0..3u64 {
            let timestamp = 1_700_000_000 + h * 100;
            let (tx, tx_id) = make_signed_tx(&sk, &pk, format!("doc{h}").as_bytes(), timestamp);
            let (block, hash, ids) =
                make_block_with_validator(vec![(tx, tx_id)], h, prev_hash, timestamp, &sk, &pk);
            store.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let ts = store.get_recent_timestamps(11).unwrap();
        assert_eq!(ts.len(), 3);
        // Newest first
        assert_eq!(ts[0], 1_700_000_200);
        assert_eq!(ts[1], 1_700_000_100);
        assert_eq!(ts[2], 1_700_000_000);
    }

    // --- Key rotation persistence tests ---

    #[test]
    fn store_and_load_key_rotation() {
        let store = MemoryStorage::new();
        let (_, old_pk) = ed25519::generate_keypair();
        let (_, new_pk) = ed25519::generate_keypair();
        let old_key = NoblePublicKey::Ed25519(old_pk.to_vec());
        let new_key = NoblePublicKey::Ed25519(new_pk.to_vec());

        store.store_key_rotation(&old_key, &new_key, 42).unwrap();

        let rotations = store.load_key_rotations().unwrap();
        assert_eq!(rotations.len(), 1);
        assert_eq!(rotations[0].0, old_key.to_wire_bytes());
        assert_eq!(rotations[0].1, new_key.to_wire_bytes());
        assert_eq!(rotations[0].2, 42);
    }

    #[test]
    fn remove_key_rotation() {
        let store = MemoryStorage::new();
        let (_, old_pk) = ed25519::generate_keypair();
        let (_, new_pk) = ed25519::generate_keypair();
        let old_key = NoblePublicKey::Ed25519(old_pk.to_vec());
        let new_key = NoblePublicKey::Ed25519(new_pk.to_vec());

        store.store_key_rotation(&old_key, &new_key, 42).unwrap();
        store.remove_key_rotation(&old_key).unwrap();

        let rotations = store.load_key_rotations().unwrap();
        assert!(rotations.is_empty());
    }

    // ── Peer Record Tests ──

    #[test]
    fn store_and_get_peer_record() {
        let store = MemoryStorage::new();
        let rec = PeerRecord::new(vec![0xAA; 32], vec![0xBB; 38], 1_700_000_000);
        store.store_peer_record(&rec).unwrap();

        let loaded = store.get_peer_record(&[0xAA; 32]).unwrap();
        assert_eq!(loaded, rec);
    }

    #[test]
    fn update_existing_peer_record() {
        let store = MemoryStorage::new();
        let mut rec = PeerRecord::new(vec![1, 2, 3], vec![4, 5, 6], 1000);
        store.store_peer_record(&rec).unwrap();

        rec.on_connected(2000);
        rec.last_addr = Some("/ip4/1.2.3.4/tcp/8780".into());
        store.store_peer_record(&rec).unwrap();

        let loaded = store.get_peer_record(&[1, 2, 3]).unwrap();
        assert_eq!(loaded.connection_count, 2);
        assert_eq!(loaded.last_seen, 2000);
        assert_eq!(loaded.last_addr.as_deref(), Some("/ip4/1.2.3.4/tcp/8780"));
    }

    #[test]
    fn list_peer_records() {
        let store = MemoryStorage::new();
        store
            .store_peer_record(&PeerRecord::new(vec![1], vec![10], 100))
            .unwrap();
        store
            .store_peer_record(&PeerRecord::new(vec![2], vec![20], 200))
            .unwrap();
        store
            .store_peer_record(&PeerRecord::new(vec![3], vec![30], 300))
            .unwrap();

        let records = store.list_peer_records().unwrap();
        assert_eq!(records.len(), 3);
    }

    #[test]
    fn remove_peer_record() {
        let store = MemoryStorage::new();
        store
            .store_peer_record(&PeerRecord::new(vec![1], vec![10], 100))
            .unwrap();
        store
            .store_peer_record(&PeerRecord::new(vec![2], vec![20], 200))
            .unwrap();

        store.remove_peer_record(&[1]).unwrap();
        assert!(store.get_peer_record(&[1]).is_err());
        assert!(store.get_peer_record(&[2]).is_ok());
    }

    #[test]
    fn prune_stale_peer_records() {
        let store = MemoryStorage::new();
        // Record at time 1000
        store
            .store_peer_record(&PeerRecord::new(vec![1], vec![10], 1000))
            .unwrap();
        // Record at time 5000
        store
            .store_peer_record(&PeerRecord::new(vec![2], vec![20], 5000))
            .unwrap();
        // Record at time 9000
        store
            .store_peer_record(&PeerRecord::new(vec![3], vec![30], 9000))
            .unwrap();

        // Prune at time 10000 with max_age 3000 — records older than 7000 are stale
        let pruned = store.prune_peer_records(10000, 3000).unwrap();
        assert_eq!(pruned, 2); // records 1 (age=9000) and 2 (age=5000) pruned
        let remaining = store.list_peer_records().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].identity_key, vec![3]);
    }

    #[test]
    fn get_nonexistent_peer_record_returns_error() {
        let store = MemoryStorage::new();
        assert!(matches!(
            store.get_peer_record(&[99]),
            Err(StorageError::NotFound)
        ));
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
            tx_type: TX_TYPE_NOTARIZATION,
            inputs: vec![],
            outputs: vec![],
            checksum,
            timestamp,
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
        let tx_id = tx.compute_tx_id(test_chain_id()).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn version_chain_indexed_on_commit() {
        let store = MemoryStorage::new();
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
        store.commit_block(&b0, &h0, &ids0).unwrap();

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
        store.commit_block(&b1, &h1, &ids1).unwrap();

        // v1_checksum should have tx_id2 as a successor
        let successors = store.lookup_version_successors(&v1_checksum).unwrap();
        assert_eq!(successors.len(), 1);
        assert_eq!(successors[0], tx_id2);
    }

    #[test]
    fn version_chain_empty_for_non_versioned() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Commit a normal notarization without version metadata
        let (tx, tx_id) = make_signed_tx(&sk, &pk, b"plain_doc", 1_700_000_000);
        let checksum = tx.checksum;
        let (b0, h0, ids0) =
            make_block_with_validator(vec![(tx, tx_id)], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // No successors for a plain document
        let successors = store.lookup_version_successors(&checksum).unwrap();
        assert!(successors.is_empty());
    }

    #[test]
    fn version_chain_multiple_successors() {
        let store = MemoryStorage::new();
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
        store.commit_block(&b0, &h0, &ids0).unwrap();

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
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let successors = store.lookup_version_successors(&v1_checksum).unwrap();
        assert_eq!(successors.len(), 2);
        assert!(successors.contains(&tx_id2a));
        assert!(successors.contains(&tx_id2b));
    }

    #[test]
    fn version_chain_rollback_cleans_index() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Block 0: empty genesis
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: v1 notarization
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_v1", None, Some(1), 1_700_000_001);
        let v1_checksum = tx1.checksum;
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx1, tx_id1)], 1, h0, 1_700_000_001, &sk, &pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

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
        store.commit_block(&b2, &h2, &ids2).unwrap();

        // Verify version chain exists
        assert_eq!(
            store.lookup_version_successors(&v1_checksum).unwrap().len(),
            1
        );

        // Rollback to height 1 (removes block 2 which has the v2)
        store.rollback_to_height(1, test_chain_id()).unwrap();

        // Version chain should be empty after rollback
        let successors = store.lookup_version_successors(&v1_checksum).unwrap();
        assert!(successors.is_empty());
    }

    // ── Publisher Index Tests ──

    #[test]
    fn publisher_index_populated_on_commit() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk.clone());
        let wire = pub_key.to_wire_bytes();

        // Block 0: empty genesis
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: two notarizations from same key
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_a", None, Some(1), 1_700_000_001);
        let (tx2, tx_id2) =
            make_versioned_notarization(&sk, &pk, b"doc_b", None, Some(1), 1_700_000_001);
        let (b1, h1, ids1) = make_block_with_validator(
            vec![(tx1, tx_id1), (tx2, tx_id2)],
            1,
            h0,
            1_700_000_001,
            &sk,
            &pk,
        );
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let results = store.lookup_by_publisher(&wire).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.contains(&tx_id1));
        assert!(results.contains(&tx_id2));
    }

    #[test]
    fn publisher_index_empty_for_unknown_key() {
        let store = MemoryStorage::new();
        let unknown_wire = vec![0x01; 33]; // fake Ed25519 wire key
        let results = store.lookup_by_publisher(&unknown_wire).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn publisher_index_multiple_publishers() {
        let store = MemoryStorage::new();

        let (sk_a, pk_a) = ed25519::generate_keypair();
        let pub_a = NoblePublicKey::Ed25519(pk_a.clone());
        let wire_a = pub_a.to_wire_bytes();

        let (sk_b, pk_b) = ed25519::generate_keypair();
        let pub_b = NoblePublicKey::Ed25519(pk_b.clone());
        let wire_b = pub_b.to_wire_bytes();

        // Block 0: empty genesis (subsidy(0)=0)
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk_a, &pk_a);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: empty — A gets subsidy(1) as validator
        let (b1, h1, ids1) = make_block_with_validator(vec![], 1, h0, 1_700_000_001, &sk_a, &pk_a);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        // Block 2: empty — B gets subsidy(2) as validator
        let (b2, h2, ids2) = make_block_with_validator(vec![], 2, h1, 1_700_000_002, &sk_b, &pk_b);
        store.commit_block(&b2, &h2, &ids2).unwrap();

        // Block 3: notarization from A
        let (tx_a, tx_id_a) =
            make_versioned_notarization(&sk_a, &pk_a, b"doc_by_a", None, Some(1), 1_700_000_003);
        let (b3, h3, ids3) =
            make_block_with_validator(vec![(tx_a, tx_id_a)], 3, h2, 1_700_000_003, &sk_b, &pk_b);
        store.commit_block(&b3, &h3, &ids3).unwrap();

        // Block 4: notarization from B
        let (tx_b, tx_id_b) =
            make_versioned_notarization(&sk_b, &pk_b, b"doc_by_b", None, Some(1), 1_700_000_004);
        let (b4, _h4, ids4) =
            make_block_with_validator(vec![(tx_b, tx_id_b)], 4, h3, 1_700_000_004, &sk_a, &pk_a);
        store.commit_block(&b4, &_h4, &ids4).unwrap();

        // Each publisher should only see their own tx_id
        let results_a = store.lookup_by_publisher(&wire_a).unwrap();
        assert_eq!(results_a.len(), 1);
        assert_eq!(results_a[0], tx_id_a);

        let results_b = store.lookup_by_publisher(&wire_b).unwrap();
        assert_eq!(results_b.len(), 1);
        assert_eq!(results_b[0], tx_id_b);
    }

    #[test]
    fn publisher_index_rollback_clears_and_replays() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk.clone());
        let wire = pub_key.to_wire_bytes();

        // Block 0: empty genesis
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: notarization A
        let (tx1, tx_id1) =
            make_versioned_notarization(&sk, &pk, b"doc_1", None, Some(1), 1_700_000_001);
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx1, tx_id1)], 1, h0, 1_700_000_001, &sk, &pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        // Block 2: notarization B
        let (tx2, tx_id2) =
            make_versioned_notarization(&sk, &pk, b"doc_2", None, Some(1), 1_700_000_002);
        let (b2, h2, ids2) =
            make_block_with_validator(vec![(tx2, tx_id2)], 2, h1, 1_700_000_002, &sk, &pk);
        store.commit_block(&b2, &h2, &ids2).unwrap();

        // Block 3: notarization C
        let (tx3, tx_id3) =
            make_versioned_notarization(&sk, &pk, b"doc_3", None, Some(1), 1_700_000_003);
        let (b3, _h3, ids3) =
            make_block_with_validator(vec![(tx3, tx_id3)], 3, h2, 1_700_000_003, &sk, &pk);
        store.commit_block(&b3, &_h3, &ids3).unwrap();

        // Before rollback: 3 tx_ids
        assert_eq!(store.lookup_by_publisher(&wire).unwrap().len(), 3);

        // Rollback to height 1 (removes blocks 2 and 3)
        store.rollback_to_height(1, test_chain_id()).unwrap();

        // After rollback: only tx_id1 from block 1
        let results = store.lookup_by_publisher(&wire).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tx_id1);
    }

    // --- count_address_history tests ---

    #[test]
    fn count_address_history_empty() {
        let store = MemoryStorage::new();
        let (_, pk) = ed25519::generate_keypair();
        let address = NobleAddress::Noble(NoblePublicKey::Ed25519(pk));
        let count = store.count_address_history(&address).unwrap();
        assert_eq!(count, 0, "empty store should have 0 history entries");
    }

    #[test]
    fn count_address_history_after_block() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();

        // Genesis block
        let genesis = make_block_with_validator(vec![], 0, Hash256::ZERO, 1_000_000, &sk, &pk);
        store
            .commit_block(&genesis.0, &genesis.1, &genesis.2)
            .unwrap();

        // Block 1: empty block with sender as validator (gives them subsidy)
        let block1 = make_block_with_validator(vec![], 1, genesis.1, 1_000_010, &sk, &pk);
        store
            .commit_block(&block1.0, &block1.1, &block1.2)
            .unwrap();

        // Block 2: tx from this sender (notarizations, no UTXO movement)
        let (tx1, tx1_id) = make_signed_tx(&sk, &pk, b"doc1", 1_000_020);
        let (tx2, tx2_id) = make_signed_tx(&sk, &pk, b"doc2", 1_000_021);
        let block2 = make_block_with_validator(
            vec![(tx1, tx1_id), (tx2, tx2_id)],
            2,
            block1.1,
            1_000_030,
            &sk,
            &pk,
        );
        store
            .commit_block(&block2.0, &block2.1, &block2.2)
            .unwrap();

        let sender_addr = NobleAddress::Noble(NoblePublicKey::Ed25519(pk));
        let count = store.count_address_history(&sender_addr).unwrap();
        // coinbase txs at heights 0,1,2 (3 entries) + 2 notarization txs = 5
        // But only notarizations use the sender_addr (coinbase publisher is a random key)
        // Actually, the coinbase publisher IS the sender (since make_coinbase_tx generates its own key).
        // The notarization publisher IS the sender.
        // So sender_addr only appears for the 2 notarization txs.
        assert!(count >= 2, "sender should have at least 2 history entries");
    }

    // --- UTXO-specific tests ---

    #[test]
    fn coinbase_maturity_enforced() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let _val_addr = NobleAddress::Noble(NoblePublicKey::Ed25519(pk.to_vec()));

        // Block 0: coinbase gives subsidy to validator
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 1, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Try to spend the coinbase immediately (height 2, needs height 1+6=7)
        let coinbase_outpoint = OutPoint {
            txid: ids0[0],
            vout: 0,
        };
        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(recip_pk));

        let (tx, tx_id) = make_transfer_tx(
            &sk,
            &pk,
            vec![coinbase_outpoint],
            vec![TxOut {
                value: INITIAL_SUBSIDY,
                address: recipient,
            }],
            1_700_000_001,
        );
        let (block, bhash, bids) =
            make_block_with_validator(vec![(tx, tx_id)], 2, h0, 1_700_000_001, &sk, &pk);
        let result = store.commit_block(&block, &bhash, &bids);
        assert!(result.is_err(), "spending immature coinbase should fail");
    }
}
