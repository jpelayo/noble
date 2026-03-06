// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory storage backend for testing.
//!
//! Implements `StorageEngine` with `HashMap`-based storage. Not suitable for
//! production use — data is lost when the process exits.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use noble_core::constants::{
    subsidy_at_height, MAX_REORG_DEPTH, MAX_SUPPLY, META_KEY_PREV_CHECKSUM, TX_TYPE_NOTARIZATION,
    TX_TYPE_TRANSFER,
};
use noble_core::{Block, BlockHeader, NobleAddress, PeerRecord, Transaction};
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
    /// Address balances in atomic units (GAP-H19).
    /// Supports both native NOBLE keys and Bitcoin-format addresses (dual-address system).
    balances: HashMap<NobleAddress, u64>,
    /// Address history: (wire_bytes, height, offset) → tx_id (GAP-H19).
    address_history: BTreeMap<(Vec<u8>, u64, u32), Hash256>,
    /// Persisted peer bans: peer_id_bytes → banned_until_unix.
    bans: HashMap<Vec<u8>, u64>,
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
            if tx.tx_type == noble_core::TX_TYPE_NOTARIZATION {
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
            if tx.tx_type == TX_TYPE_NOTARIZATION {
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

        // --- Balance accumulator (GAP-H19) ---
        // Phase 1: accumulate deltas as i128 to detect overflows later
        let mut deltas: HashMap<NobleAddress, i128> = HashMap::new();

        // Validator gets subsidy + fee share (gateway gets 50% of fee when present)
        let validator = &block.header.validator_id;
        let validator_addr = NobleAddress::Noble(validator.clone());
        let subsidy = subsidy_at_height(height) as i128;
        let mut validator_fee_total: i128 = 0;
        for tx in &block.transactions {
            let fee = tx.fee as i128;
            if let Some(ref gw) = tx.gateway_address {
                let gw_addr = NobleAddress::from_wire_bytes(gw)
                    .map_err(|e| StorageError::Codec(format!("bad gateway_address: {e}")))?;
                let gw_share = fee / 2;
                let val_share = fee - gw_share; // validator gets rounding
                *deltas.entry(gw_addr).or_default() += gw_share;
                validator_fee_total += val_share;
            } else {
                validator_fee_total += fee;
            }
        }
        *deltas.entry(validator_addr).or_default() += subsidy + validator_fee_total;

        for (offset, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
            let sender_pk = tx
                .publisher_sig
                .to_noble_public_key()
                .map_err(|e| StorageError::Codec(e.to_string()))?;
            // S34: Canonical debit address resolution
            // S35 F1: delta-aware balance closure — each tx sees effective balances
            // including earlier in-block changes (credits and debits)
            let need = (tx.amount.unwrap_or(0) + tx.fee) as u64;
            let sender_addr = noble_core::resolve_debit_address(
                &tx.source_address,
                &sender_pk,
                need,
                |a| {
                    let base = *inner.balances.get(a).unwrap_or(&0) as i128;
                    let delta = deltas.get(a).copied().unwrap_or(0);
                    let effective = base + delta;
                    if effective > 0 { effective as u64 } else { 0 }
                },
            )
            .map_err(|e| StorageError::Codec(e.to_string()))?;

            if tx.tx_type == TX_TYPE_TRANSFER {
                let amount = tx.amount.unwrap_or(0) as i128;
                let fee = tx.fee as i128;
                *deltas.entry(sender_addr.clone()).or_default() -= amount + fee;
                if let Some(ref recipient) = tx.recipient {
                    *deltas.entry(recipient.clone()).or_default() += amount;
                }
            } else {
                // Notarization: sender pays fee only
                let fee = tx.fee as i128;
                *deltas.entry(sender_addr.clone()).or_default() -= fee;
            }

            // Record history for sender
            let sender_wire = sender_addr.to_wire_bytes();
            inner
                .address_history
                .insert((sender_wire, height, offset as u32), *tx_id);

            // Record history for recipient (if transfer)
            if tx.tx_type == TX_TYPE_TRANSFER {
                if let Some(ref recipient) = tx.recipient {
                    inner
                        .address_history
                        .insert((recipient.to_wire_bytes(), height, offset as u32), *tx_id);
                }
            }
        }

        // Phase 2: apply deltas to current balances
        for (pubkey, delta) in &deltas {
            let current = *inner.balances.get(pubkey).unwrap_or(&0);
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
            inner.balances.insert(pubkey.clone(), new_balance as u64);
        }

        // Phase 3: MAX_SUPPLY cap enforcement
        let block_subsidy = subsidy_at_height(height);
        if block_subsidy > 0 {
            let cumulative: u64 = inner.balances.values().sum();
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
        Ok(*inner.balances.get(address).unwrap_or(&0))
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

        // Collect blocks to remove (target_height+1..=tip)
        let tip_h = tip.height;
        for h in (target_height + 1)..=tip_h {
            if let Some(hash) = inner.block_heights.remove(&h) {
                if let Some(block) = inner.blocks.remove(&hash) {
                    // Remove transactions and checksum entries
                    for tx in &block.transactions {
                        if let Ok(tx_id) = tx.compute_tx_id(chain_id) {
                            inner.transactions.remove(&tx_id);
                            inner.tx_locations.remove(&tx_id);
                            // Remove from checksum index
                            if let Some(entries) = inner.checksum_index.get_mut(&tx.checksum) {
                                entries.retain(|id| *id != tx_id);
                                if entries.is_empty() {
                                    inner.checksum_index.remove(&tx.checksum);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clear balances, history, version chain, and publisher index — replay from genesis
        inner.balances.clear();
        inner.address_history.clear();
        inner.version_chain.clear();
        inner.publisher_index.clear();

        // Replay balances from 0..=target_height
        for h in 0..=target_height {
            let hash = *inner.block_heights.get(&h).ok_or_else(|| {
                StorageError::Database(format!("missing block at height {h} during replay"))
            })?;
            let block = inner
                .blocks
                .get(&hash)
                .ok_or_else(|| StorageError::Database(format!("missing block data at height {h}")))?
                .clone();

            // Replay balance logic (same as commit_block)
            let mut deltas: std::collections::HashMap<NobleAddress, i128> =
                std::collections::HashMap::new();
            let validator = &block.header.validator_id;
            let validator_addr = NobleAddress::Noble(validator.clone());
            let subsidy = subsidy_at_height(h) as i128;
            let mut validator_fee_total: i128 = 0;
            for tx in &block.transactions {
                let fee = tx.fee as i128;
                if let Some(ref gw) = tx.gateway_address {
                    let gw_addr = NobleAddress::from_wire_bytes(gw)
                        .map_err(|e| StorageError::Codec(format!("bad gateway_address: {e}")))?;
                    let gw_share = fee / 2;
                    let val_share = fee - gw_share;
                    *deltas.entry(gw_addr).or_default() += gw_share;
                    validator_fee_total += val_share;
                } else {
                    validator_fee_total += fee;
                }
            }
            *deltas.entry(validator_addr).or_default() += subsidy + validator_fee_total;

            for (offset, tx) in block.transactions.iter().enumerate() {
                let sender_pk = tx
                    .publisher_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                // S34: Use canonical debit resolution (fixes P0 replay divergence)
                // S35 F1: delta-aware balance closure for replay path too
                let need = (tx.amount.unwrap_or(0) + tx.fee) as u64;
                let sender_addr = noble_core::resolve_debit_address(
                    &tx.source_address,
                    &sender_pk,
                    need,
                    |a| {
                        let base = *inner.balances.get(a).unwrap_or(&0) as i128;
                        let delta = deltas.get(a).copied().unwrap_or(0);
                        let effective = base + delta;
                        if effective > 0 { effective as u64 } else { 0 }
                    },
                )
                .map_err(|e| StorageError::Codec(e.to_string()))?;
                let tx_id = tx
                    .compute_tx_id(chain_id)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;

                if tx.tx_type == TX_TYPE_TRANSFER {
                    let amount = tx.amount.unwrap_or(0) as i128;
                    let fee = tx.fee as i128;
                    *deltas.entry(sender_addr.clone()).or_default() -= amount + fee;
                    if let Some(ref recipient) = tx.recipient {
                        *deltas.entry(recipient.clone()).or_default() += amount;
                        // History for recipient
                        inner
                            .address_history
                            .insert((recipient.to_wire_bytes(), h, offset as u32), tx_id);
                    }
                } else {
                    let fee = tx.fee as i128;
                    *deltas.entry(sender_addr.clone()).or_default() -= fee;
                }
                // History for sender
                let sender_wire = sender_addr.to_wire_bytes();
                inner
                    .address_history
                    .insert((sender_wire, h, offset as u32), tx_id);
            }

            // Replay version chain and publisher index
            for tx in &block.transactions {
                if tx.tx_type == TX_TYPE_NOTARIZATION {
                    let tx_id = tx
                        .compute_tx_id(chain_id)
                        .map_err(|e| StorageError::Codec(e.to_string()))?;

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

                    // Rebuild publisher_index
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

            for (pubkey, delta) in &deltas {
                let current = *inner.balances.get(pubkey).unwrap_or(&0);
                let new_balance = current as i128 + delta;
                if new_balance >= 0 {
                    inner.balances.insert(pubkey.clone(), new_balance as u64);
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
                        if let Ok(tx_id) = tx.compute_tx_id(chain_id) {
                            inner.transactions.remove(&tx_id);
                            inner.tx_locations.remove(&tx_id);
                            if let Some(entries) = inner.checksum_index.get_mut(&tx.checksum) {
                                entries.retain(|id| *id != tx_id);
                                if entries.is_empty() {
                                    inner.checksum_index.remove(&tx.checksum);
                                }
                            }
                        }
                    }
                }
            }
        }

        // Clear derived state
        inner.balances.clear();
        inner.address_history.clear();
        inner.version_chain.clear();
        inner.publisher_index.clear();

        // Replay genesis (height 0) for balances
        if let Some(&genesis_hash) = inner.block_heights.get(&0) {
            if let Some(block) = inner.blocks.get(&genesis_hash) {
                let validator_addr = NobleAddress::Noble(block.header.validator_id.clone());
                let subsidy = subsidy_at_height(0);
                if subsidy > 0 {
                    inner.balances.insert(validator_addr, subsidy);
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

    fn store_ban(&self, peer_id: &[u8], banned_until: u64) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.bans.insert(peer_id.to_vec(), banned_until);
        Ok(())
    }

    fn remove_ban(&self, peer_id: &[u8]) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        Self::check_open(&inner)?;
        inner.bans.remove(peer_id);
        Ok(())
    }

    fn load_bans(&self) -> Result<Vec<(Vec<u8>, u64)>, StorageError> {
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
            .filter(|(_, &until)| until > now)
            .map(|(k, v)| (k.clone(), *v))
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

    fn close(&mut self) -> Result<(), StorageError> {
        let mut inner = self.inner.write().unwrap();
        inner.closed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::constants::{HALVING_INTERVAL, INITIAL_SUBSIDY};
    use noble_core::{Block, BlockHeader, Transaction, mainnet_chain_id, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };

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
        let tx_id = tx.compute_tx_id(mainnet_chain_id()).unwrap();
        (tx, tx_id)
    }

    fn make_transfer_tx(
        sk: &[u8],
        pk: &[u8],
        recipient: &NoblePublicKey,  // wrapped into NobleAddress::Noble internally
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
        let tx_id = tx.compute_tx_id(mainnet_chain_id()).unwrap();
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

    // --- Balance storage tests (GAP-H19) ---

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
        let (block, block_hash, tx_ids) = make_block(vec![], 1, Hash256::ZERO, 1_700_000_000);
        let validator = block.header.validator_id.clone();
        store.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(store.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY);
    }

    #[test]
    fn subsidy_halves_at_halving_interval() {
        let store = MemoryStorage::new();
        let (block, block_hash, tx_ids) =
            make_block(vec![], HALVING_INTERVAL, Hash256::ZERO, 1_700_000_000);
        let validator = block.header.validator_id.clone();
        store.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(store.get_balance(&addr(&validator)).unwrap(), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn fees_credited_to_validator() {
        let store = MemoryStorage::new();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        // Create a funded sender first (via block 1 subsidy as validator)
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

        // Block 1: 2 notarization txs from funded sender, validated by val
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
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        // Validator gets subsidy + 2 * 1000 fee
        assert_eq!(
            store.get_balance(&addr(&validator)).unwrap(),
            INITIAL_SUBSIDY + 2_000
        );
    }

    #[test]
    fn notarization_debits_sender_fee() {
        let store = MemoryStorage::new();

        // Fund sender as validator of block 1 (gets subsidy)
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
        assert_eq!(store.get_balance(&addr(&sender_pub)).unwrap(), INITIAL_SUBSIDY);

        // Block 1: sender submits a notarization (different validator)
        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let fee = tx1.fee;
        let (block1, hash1, ids1) = make_block(vec![(tx1, id1)], 2, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        assert_eq!(
            store.get_balance(&addr(&sender_pub)).unwrap(),
            INITIAL_SUBSIDY - fee
        );
    }

    #[test]
    fn transfer_debits_sender_credits_recipient() {
        let store = MemoryStorage::new();

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
        store.commit_block(&block0, &hash0, &ids0).unwrap();

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
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert_eq!(
            store.get_balance(&addr(&sender_pub)).unwrap(),
            INITIAL_SUBSIDY - amount - fee
        );
        assert_eq!(store.get_balance(&addr(&recipient)).unwrap(), amount);
    }

    #[test]
    fn transfer_insufficient_balance_fails() {
        let store = MemoryStorage::new();

        // Sender has no funds (not a validator)
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

        let result = store.commit_block(&block, &block_hash, &tx_ids);
        assert!(matches!(
            result,
            Err(StorageError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn balance_overflow_fails() {
        let store = MemoryStorage::new();

        // Block 1: empty block so validator gets subsidy
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) =
            make_block_with_validator(vec![], 1, Hash256::ZERO, 1_700_000_000, &val_sk, &val_pk);
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        // Manually set balance to near u64::MAX
        {
            let mut inner = store.inner.write().unwrap();
            let val_pub = NobleAddress::Noble(NoblePublicKey::Ed25519(val_pk.to_vec()));
            inner.balances.insert(val_pub, u64::MAX - 10);
        }

        // Block 2: validator gets another subsidy → overflow
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![], 2, hash0, 1_700_000_001, &val_sk, &val_pk);
        let result = store.commit_block(&block1, &hash1, &ids1);
        assert!(matches!(result, Err(StorageError::BalanceOverflow { .. })));
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
        let (block1, hash1, ids1) = make_block(vec![(tx1, id1)], 2, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let history = store.get_address_history(&addr(&sender_pub), 0, 100).unwrap();
        assert!(history.contains(&id1));
    }

    #[test]
    fn history_records_transfer_both_parties() {
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
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert!(store
            .get_address_history(&addr(&sender_pub), 0, 100)
            .unwrap()
            .contains(&tx_id));
        assert!(store
            .get_address_history(&addr(&recipient), 0, 100)
            .unwrap()
            .contains(&tx_id));
    }

    #[test]
    fn history_pagination() {
        let store = MemoryStorage::new();

        // Fund sender as validator
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

        // 3 blocks with 1 notarization each
        let mut prev_hash = hash0;
        let mut all_ids = vec![];
        for i in 2..=4 {
            let (tx, id) = make_signed_tx(
                &sender_sk,
                &sender_pk,
                format!("doc{i}").as_bytes(),
                1_700_000_000 + i,
            );
            all_ids.push(id);
            let (block, hash, ids) = make_block_with_validator(
                vec![(tx, id)],
                i,
                prev_hash,
                1_700_000_000 + i,
                &sender_sk,
                &sender_pk,
            );
            store.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let page0 = store.get_address_history(&addr(&sender_pub), 0, 2).unwrap();
        assert_eq!(page0.len(), 2);
        let page1 = store.get_address_history(&addr(&sender_pub), 1, 2).unwrap();
        assert_eq!(page1.len(), 1);
        // No overlap
        assert!(!page0.contains(&page1[0]));
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
    fn history_chronological_order() {
        let store = MemoryStorage::new();

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

        let mut prev_hash = hash0;
        let mut expected_order = vec![];
        for i in 2..=4 {
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
            store.commit_block(&block, &hash, &ids).unwrap();
            prev_hash = hash;
        }

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let history = store.get_address_history(&addr(&sender_pub), 0, 100).unwrap();
        assert_eq!(history, expected_order);
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

    #[test]
    fn validator_gets_transfer_fees() {
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

        // Transfer tx validated by a different validator
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
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(store.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + fee);
    }

    #[test]
    fn self_transfer_balance_correct() {
        let store = MemoryStorage::new();

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
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        // Self-transfer (sender == recipient)
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
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        // Self-transfer: net effect is -fee only (amount cancels out)
        assert_eq!(
            store.get_balance(&addr(&sender_pub)).unwrap(),
            INITIAL_SUBSIDY - fee
        );
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

        let tip = store.rollback_to_height(1, mainnet_chain_id()).unwrap();
        assert_eq!(tip.height, 1);
        assert!(store.get_block_hash_by_height(2).is_err());
        let new_tip = store.get_chain_tip().unwrap().unwrap();
        assert_eq!(new_tip.height, 1);
    }

    #[test]
    fn rollback_recalculates_balances() {
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
        store.rollback_to_height(2, mainnet_chain_id()).unwrap();
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

        let tip = store.rollback_to_height(0, mainnet_chain_id()).unwrap();
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
        store.rollback_to_height(0, mainnet_chain_id()).unwrap();
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

        let (h, off) = store.get_transaction_location(&id1).unwrap();
        assert_eq!(h, 0);
        assert_eq!(off, 0);

        let (h2, off2) = store.get_transaction_location(&id2).unwrap();
        assert_eq!(h2, 0);
        assert_eq!(off2, 1);

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
        store.store_ban(peer_id, banned_until).unwrap();

        let bans = store.load_bans().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].0, peer_id.to_vec());
        assert_eq!(bans[0].1, banned_until);
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
            .store_ban(b"expired_peer", now.saturating_sub(100))
            .unwrap();
        // Active ban
        store.store_ban(b"active_peer", now + 86400).unwrap();

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
        store.store_ban(b"peer1", now + 86400).unwrap();
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

    // --- Gateway fee split tests ---

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
        let tx_id = tx.compute_tx_id(mainnet_chain_id()).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn mem_gateway_fee_split_50_50() {
        let store = MemoryStorage::new();
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, gw_pk) = ed25519::generate_keypair();
        let gw_key = NoblePublicKey::Ed25519(gw_pk.clone());
        let gw_wire = gw_key.to_wire_bytes();

        // Block 1: fund sender
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: tx with gateway, fee=2000
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
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(
            store.get_balance(&addr(&val_pub)).unwrap(),
            INITIAL_SUBSIDY + 1_000
        );
        assert_eq!(store.get_balance(&addr(&gw_key)).unwrap(), 1_000);
    }

    #[test]
    fn mem_gateway_fee_split_odd_rounds_to_validator() {
        let store = MemoryStorage::new();
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, gw_pk) = ed25519::generate_keypair();
        let gw_key = NoblePublicKey::Ed25519(gw_pk.clone());
        let gw_wire = gw_key.to_wire_bytes();

        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&b0, &h0, &ids0).unwrap();

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
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(store.get_balance(&addr(&val_pub)).unwrap(), INITIAL_SUBSIDY + 501);
        assert_eq!(store.get_balance(&addr(&gw_key)).unwrap(), 500);
    }

    #[test]
    fn mem_no_gateway_100_percent_to_validator() {
        let store = MemoryStorage::new();
        let (sender_sk, sender_pk) = ed25519::generate_keypair();

        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&b0, &h0, &ids0).unwrap();

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
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(
            store.get_balance(&addr(&val_pub)).unwrap(),
            INITIAL_SUBSIDY + 2_000
        );
    }

    #[test]
    fn mem_gateway_equals_validator() {
        let store = MemoryStorage::new();
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        let val_wire = val_pub.to_wire_bytes();

        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            1,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&b0, &h0, &ids0).unwrap();

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
        store.commit_block(&b1, &h1, &ids1).unwrap();

        // validator gets subsidy + val_share(1000) + gw_share(1000) = subsidy + 2000
        assert_eq!(
            store.get_balance(&addr(&val_pub)).unwrap(),
            INITIAL_SUBSIDY + 2_000
        );
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
        let tx_id = tx.compute_tx_id(mainnet_chain_id()).unwrap();
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
        store.rollback_to_height(1, mainnet_chain_id()).unwrap();

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
    fn publisher_index_ignores_transfers() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let pub_key = NoblePublicKey::Ed25519(pk.clone());
        let wire = pub_key.to_wire_bytes();

        let (_sk2, pk2) = ed25519::generate_keypair();
        let recipient = NoblePublicKey::Ed25519(pk2.clone());

        // Block 0: genesis with subsidy
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Block 1: transfer only (no notarization)
        let (tx_t, tx_id_t) = make_transfer_tx(&sk, &pk, &recipient, 100, 1_000, 1_700_000_001);
        let (b1, h1, ids1) =
            make_block_with_validator(vec![(tx_t, tx_id_t)], 1, h0, 1_700_000_001, &sk, &pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        // Publisher index should be empty — transfers are not indexed
        let results = store.lookup_by_publisher(&wire).unwrap();
        assert!(results.is_empty());

        // Also check recipient
        let wire2 = recipient.to_wire_bytes();
        let results2 = store.lookup_by_publisher(&wire2).unwrap();
        assert!(results2.is_empty());
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

        // Block 3: notarization from A (A has subsidy from block 1)
        let (tx_a, tx_id_a) =
            make_versioned_notarization(&sk_a, &pk_a, b"doc_by_a", None, Some(1), 1_700_000_003);
        let (b3, h3, ids3) =
            make_block_with_validator(vec![(tx_a, tx_id_a)], 3, h2, 1_700_000_003, &sk_b, &pk_b);
        store.commit_block(&b3, &h3, &ids3).unwrap();

        // Block 4: notarization from B (B has subsidy from blocks 2+3)
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
        store.rollback_to_height(1, mainnet_chain_id()).unwrap();

        // After rollback: only tx_id1 from block 1
        let results = store.lookup_by_publisher(&wire).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], tx_id1);
    }

    // --- Finding 3: count_address_history tests ---

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
        let genesis = make_block(vec![], 0, Hash256::ZERO, 1_000_000);
        store
            .commit_block(&genesis.0, &genesis.1, &genesis.2)
            .unwrap();

        // Block 1: empty block with sender as validator (gives them subsidy)
        let block1 = make_block_with_validator(vec![], 1, genesis.1, 1_000_010, &sk, &pk);
        store
            .commit_block(&block1.0, &block1.1, &block1.2)
            .unwrap();

        // Block 2: tx from this sender (they now have balance from subsidy)
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
        assert_eq!(count, 2, "sender should have 2 history entries");
    }

    // --- S35 F1: Forward execution delta-aware debit resolution ---

    #[test]
    fn commit_block_delta_aware_bucket_switch() {
        // Two transfers from same secp256k1 sender in one block:
        // tx1 debits Noble balance, tx2 debits Hash160 bucket.
        // Without delta-aware closure, the legacy fallback would see stale pre-block balances.
        let store = MemoryStorage::new();

        // Setup: generate secp256k1 sender keypair
        let (secp_sk, secp_pk_raw) = noble_crypto::secp256k1::generate_keypair();
        let sender_pk = NoblePublicKey::Secp256k1(secp_pk_raw.clone());

        let (_, recip_pk) = ed25519::generate_keypair();
        let recipient = NobleAddress::Noble(NoblePublicKey::Ed25519(recip_pk.to_vec()));

        let noble_addr = NobleAddress::Noble(sender_pk.clone());
        let h160_addr = NobleAddress::bitcoin_hash160_for_pubkey(&sender_pk).unwrap();

        // Block 0: empty genesis with a validator
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (b0, h0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &val_sk, &val_pk);
        store.commit_block(&b0, &h0, &ids0).unwrap();

        // Seed sender balances directly for test
        {
            let mut inner = store.inner.write().unwrap();
            inner.balances.insert(noble_addr.clone(), 10_000);
            inner.balances.insert(h160_addr.clone(), 10_000);
        }

        // Create tx1: drain Noble bucket (amount=8000, fee=1000 = 9000 from Noble)
        let mut tx1 = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"delta_tx1"),
            timestamp: 1_700_000_000,
            fee: 1_000,
            recipient: Some(recipient.clone()),
            amount: Some(8_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: noble_crypto::SCHEME_SECP256K1,
                public_key: secp_pk_raw.clone(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(noble_addr.to_wire_bytes()), // explicit Noble
        };
        let msg1 = tx1.compute_signing_message().unwrap();
        let sig1 = noble_crypto::secp256k1::sign(&secp_sk, &msg1).unwrap();
        tx1.publisher_sig.signature = sig1;
        let tx1_id = tx1.compute_tx_id(mainnet_chain_id()).unwrap();

        // Create tx2: debit Hash160 bucket (amount=5000, fee=1000)
        let mut tx2 = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_TRANSFER,
            checksum: sha256(b"delta_tx2"),
            timestamp: 1_700_000_001,
            fee: 1_000,
            recipient: Some(recipient.clone()),
            amount: Some(5_000),
            publisher_sig: SignatureEnvelope {
                scheme_id: noble_crypto::SCHEME_SECP256K1,
                public_key: secp_pk_raw.clone(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            source_address: Some(h160_addr.to_wire_bytes()), // explicit Hash160
        };
        let msg2 = tx2.compute_signing_message().unwrap();
        let sig2 = noble_crypto::secp256k1::sign(&secp_sk, &msg2).unwrap();
        tx2.publisher_sig.signature = sig2;
        let tx2_id = tx2.compute_tx_id(mainnet_chain_id()).unwrap();

        // Build block with both txs
        let block = make_block_with_validator(
            vec![(tx1, tx1_id), (tx2, tx2_id)],
            1,
            h0,
            1_700_000_010,
            &val_sk,
            &val_pk,
        );
        let result = store.commit_block(&block.0, &block.1, &block.2);
        assert!(result.is_ok(), "two-tx block with bucket switch should commit: {result:?}");

        // Verify final balances
        let noble_bal = store.get_balance(&noble_addr).unwrap();
        let h160_bal = store.get_balance(&h160_addr).unwrap();
        // Noble: 10000 - 9000 = 1000 (subsidy goes to validator, not sender)
        assert_eq!(noble_bal, 1_000, "Noble should be 10000 - 9000 = 1000");
        // Hash160: 10000 - 6000 = 4000
        assert_eq!(h160_bal, 4_000, "Hash160 should be 10000 - 6000 = 4000");
    }
}
