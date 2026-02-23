// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory storage backend for testing.
//!
//! Implements `StorageEngine` with `HashMap`-based storage. Not suitable for
//! production use — data is lost when the process exits.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use noble_core::constants::{subsidy_at_height, MAX_REORG_DEPTH, MAX_SUPPLY, TX_TYPE_TRANSFER};
use noble_core::{Block, BlockHeader, PeerRecord, Transaction};
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
    balances: HashMap<NoblePublicKey, u64>,
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

        // --- Balance accumulator (GAP-H19) ---
        // Phase 1: accumulate deltas as i128 to detect overflows later
        let mut deltas: HashMap<NoblePublicKey, i128> = HashMap::new();

        // Validator gets subsidy + fee share (gateway gets 50% of fee when present)
        let validator = &block.header.validator_id;
        let subsidy = subsidy_at_height(height) as i128;
        let mut validator_fee_total: i128 = 0;
        for tx in &block.transactions {
            let fee = tx.fee as i128;
            if let Some(ref gw) = tx.gateway_address {
                let gw_key = NoblePublicKey::from_wire_bytes(gw)
                    .map_err(|e| StorageError::Codec(format!("bad gateway_address: {e}")))?;
                let gw_share = fee / 2;
                let val_share = fee - gw_share; // validator gets rounding
                *deltas.entry(gw_key).or_default() += gw_share;
                validator_fee_total += val_share;
            } else {
                validator_fee_total += fee;
            }
        }
        *deltas.entry(validator.clone()).or_default() += subsidy + validator_fee_total;

        for (offset, (tx, tx_id)) in block.transactions.iter().zip(tx_ids.iter()).enumerate() {
            let sender = tx
                .publisher_sig
                .to_noble_public_key()
                .map_err(|e| StorageError::Codec(e.to_string()))?;

            if tx.tx_type == TX_TYPE_TRANSFER {
                let amount = tx.amount.unwrap_or(0) as i128;
                let fee = tx.fee as i128;
                *deltas.entry(sender.clone()).or_default() -= amount + fee;
                if let Some(ref recipient) = tx.recipient {
                    *deltas.entry(recipient.clone()).or_default() += amount;
                }
            } else {
                // Notarization: sender pays fee only
                let fee = tx.fee as i128;
                *deltas.entry(sender.clone()).or_default() -= fee;
            }

            // Record history for sender
            let sender_wire = tx
                .publisher_sig
                .to_noble_public_key()
                .map_err(|e| StorageError::Codec(e.to_string()))?
                .to_wire_bytes();
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

    fn get_balance(&self, pubkey: &NoblePublicKey) -> Result<u64, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;
        Ok(*inner.balances.get(pubkey).unwrap_or(&0))
    }

    fn get_address_history(
        &self,
        pubkey: &NoblePublicKey,
        page: u32,
        limit: u32,
    ) -> Result<Vec<Hash256>, StorageError> {
        let inner = self.inner.read().unwrap();
        Self::check_open(&inner)?;

        let wire = pubkey.to_wire_bytes();
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

        // Clear balances and history — replay from genesis
        inner.balances.clear();
        inner.address_history.clear();

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
            let mut deltas: std::collections::HashMap<NoblePublicKey, i128> =
                std::collections::HashMap::new();
            let validator = &block.header.validator_id;
            let subsidy = subsidy_at_height(h) as i128;
            let mut validator_fee_total: i128 = 0;
            for tx in &block.transactions {
                let fee = tx.fee as i128;
                if let Some(ref gw) = tx.gateway_address {
                    let gw_key = NoblePublicKey::from_wire_bytes(gw)
                        .map_err(|e| StorageError::Codec(format!("bad gateway_address: {e}")))?;
                    let gw_share = fee / 2;
                    let val_share = fee - gw_share;
                    *deltas.entry(gw_key).or_default() += gw_share;
                    validator_fee_total += val_share;
                } else {
                    validator_fee_total += fee;
                }
            }
            *deltas.entry(validator.clone()).or_default() += subsidy + validator_fee_total;

            for (offset, tx) in block.transactions.iter().enumerate() {
                let sender = tx
                    .publisher_sig
                    .to_noble_public_key()
                    .map_err(|e| StorageError::Codec(e.to_string()))?;
                let tx_id = tx
                    .compute_tx_id(chain_id)
                    .map_err(|e| StorageError::Codec(e.to_string()))?;

                if tx.tx_type == TX_TYPE_TRANSFER {
                    let amount = tx.amount.unwrap_or(0) as i128;
                    let fee = tx.fee as i128;
                    *deltas.entry(sender.clone()).or_default() -= amount + fee;
                    if let Some(ref recipient) = tx.recipient {
                        *deltas.entry(recipient.clone()).or_default() += amount;
                        // History for recipient
                        inner
                            .address_history
                            .insert((recipient.to_wire_bytes(), h, offset as u32), tx_id);
                    }
                } else {
                    let fee = tx.fee as i128;
                    *deltas.entry(sender.clone()).or_default() -= fee;
                }
                // History for sender
                let sender_wire = sender.to_wire_bytes();
                inner
                    .address_history
                    .insert((sender_wire, h, offset as u32), tx_id);
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
    use noble_core::{Block, BlockHeader, Transaction, MAINNET_CHAIN_ID, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
        SCHEME_ED25519,
    };

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
            recipient: Some(recipient.clone()),
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
        assert_eq!(store.get_balance(&pubkey).unwrap(), 0);
    }

    #[test]
    fn subsidy_credited_to_validator() {
        let store = MemoryStorage::new();
        let (block, block_hash, tx_ids) = make_block(vec![], 0, Hash256::ZERO, 1_700_000_000);
        let validator = block.header.validator_id.clone();
        store.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(store.get_balance(&validator).unwrap(), INITIAL_SUBSIDY);
    }

    #[test]
    fn subsidy_halves_at_halving_interval() {
        let store = MemoryStorage::new();
        let (block, block_hash, tx_ids) =
            make_block(vec![], HALVING_INTERVAL, Hash256::ZERO, 1_700_000_000);
        let validator = block.header.validator_id.clone();
        store.commit_block(&block, &block_hash, &tx_ids).unwrap();
        assert_eq!(store.get_balance(&validator).unwrap(), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn fees_credited_to_validator() {
        let store = MemoryStorage::new();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        // Create a funded sender first (via block 0 subsidy as validator)
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
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
            1,
            hash0,
            1_700_000_001,
            &val_sk,
            &val_pk,
        );
        let validator = block1.header.validator_id.clone();
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        // Validator gets subsidy + 2 * 1000 fee
        assert_eq!(
            store.get_balance(&validator).unwrap(),
            INITIAL_SUBSIDY + 2_000
        );
    }

    #[test]
    fn notarization_debits_sender_fee() {
        let store = MemoryStorage::new();

        // Fund sender as validator of block 0 (gets subsidy)
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert_eq!(store.get_balance(&sender_pub).unwrap(), INITIAL_SUBSIDY);

        // Block 1: sender submits a notarization (different validator)
        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let fee = tx1.fee;
        let (block1, hash1, ids1) = make_block(vec![(tx1, id1)], 1, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        assert_eq!(
            store.get_balance(&sender_pub).unwrap(),
            INITIAL_SUBSIDY - fee
        );
    }

    #[test]
    fn transfer_debits_sender_credits_recipient() {
        let store = MemoryStorage::new();

        // Fund sender as validator of block 0
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
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
        let (block1, hash1, ids1) = make_block(vec![(tx, tx_id)], 1, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert_eq!(
            store.get_balance(&sender_pub).unwrap(),
            INITIAL_SUBSIDY - amount - fee
        );
        assert_eq!(store.get_balance(&recipient).unwrap(), amount);
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

        // Block 0: empty block so validator gets subsidy
        let (val_sk, val_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &val_sk, &val_pk);
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        // Manually set balance to near u64::MAX
        {
            let mut inner = store.inner.write().unwrap();
            let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
            inner.balances.insert(val_pub, u64::MAX - 10);
        }

        // Block 1: validator gets another subsidy → overflow
        let (block1, hash1, ids1) =
            make_block_with_validator(vec![], 1, hash0, 1_700_000_001, &val_sk, &val_pk);
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
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let (tx1, id1) = make_signed_tx(&sender_sk, &sender_pk, b"doc1", 1_700_000_001);
        let (block1, hash1, ids1) = make_block(vec![(tx1, id1)], 1, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        let history = store.get_address_history(&sender_pub, 0, 100).unwrap();
        assert!(history.contains(&id1));
    }

    #[test]
    fn history_records_transfer_both_parties() {
        let store = MemoryStorage::new();

        // Fund sender
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
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
        let (block1, hash1, ids1) = make_block(vec![(tx, tx_id)], 1, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let sender_pub = NoblePublicKey::Ed25519(sender_pk.to_vec());
        assert!(store
            .get_address_history(&sender_pub, 0, 100)
            .unwrap()
            .contains(&tx_id));
        assert!(store
            .get_address_history(&recipient, 0, 100)
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
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        // 3 blocks with 1 notarization each
        let mut prev_hash = hash0;
        let mut all_ids = vec![];
        for i in 1..=3 {
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
        let page0 = store.get_address_history(&sender_pub, 0, 2).unwrap();
        assert_eq!(page0.len(), 2);
        let page1 = store.get_address_history(&sender_pub, 1, 2).unwrap();
        assert_eq!(page1.len(), 1);
        // No overlap
        assert!(!page0.contains(&page1[0]));
    }

    #[test]
    fn history_empty_for_unknown() {
        let store = MemoryStorage::new();
        let (_, pk) = ed25519::generate_keypair();
        let pubkey = NoblePublicKey::Ed25519(pk);
        let history = store.get_address_history(&pubkey, 0, 100).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn history_chronological_order() {
        let store = MemoryStorage::new();

        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
            Hash256::ZERO,
            1_700_000_000,
            &sender_sk,
            &sender_pk,
        );
        store.commit_block(&block0, &hash0, &ids0).unwrap();

        let mut prev_hash = hash0;
        let mut expected_order = vec![];
        for i in 1..=3 {
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
        let history = store.get_address_history(&sender_pub, 0, 100).unwrap();
        assert_eq!(history, expected_order);
    }

    #[test]
    fn multi_block_balance_accumulation() {
        let store = MemoryStorage::new();
        let (val_sk, val_pk) = ed25519::generate_keypair();

        let mut prev_hash = Hash256::ZERO;
        for h in 0..3 {
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
        assert_eq!(store.get_balance(&val_pub).unwrap(), INITIAL_SUBSIDY * 3);
    }

    #[test]
    fn validator_gets_transfer_fees() {
        let store = MemoryStorage::new();

        // Fund sender
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
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
            make_block_with_validator(vec![(tx, tx_id)], 1, hash0, 1_700_000_001, &val_sk, &val_pk);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(store.get_balance(&val_pub).unwrap(), INITIAL_SUBSIDY + fee);
    }

    #[test]
    fn self_transfer_balance_correct() {
        let store = MemoryStorage::new();

        // Fund sender as validator of block 0
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (block0, hash0, ids0) = make_block_with_validator(
            vec![],
            0,
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
        let (block1, hash1, ids1) = make_block(vec![(tx, tx_id)], 1, hash0, 1_700_000_001);
        store.commit_block(&block1, &hash1, &ids1).unwrap();

        // Self-transfer: net effect is -fee only (amount cancels out)
        assert_eq!(
            store.get_balance(&sender_pub).unwrap(),
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

        let tip = store.rollback_to_height(1, MAINNET_CHAIN_ID).unwrap();
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
        for h in 0..3u64 {
            let (b, hash, ids) =
                make_block_with_validator(vec![], h, prev, 1_700_000_000 + h, &sk, &pk);
            store.commit_block(&b, &hash, &ids).unwrap();
            prev = hash;
        }

        assert_eq!(store.get_balance(&val_pub).unwrap(), INITIAL_SUBSIDY * 3);
        store.rollback_to_height(1, MAINNET_CHAIN_ID).unwrap();
        assert_eq!(store.get_balance(&val_pub).unwrap(), INITIAL_SUBSIDY * 2);
    }

    #[test]
    fn rollback_noop_at_tip() {
        let store = MemoryStorage::new();
        let (sk, pk) = ed25519::generate_keypair();
        let (b, hash, ids) =
            make_block_with_validator(vec![], 0, Hash256::ZERO, 1_700_000_000, &sk, &pk);
        store.commit_block(&b, &hash, &ids).unwrap();

        let tip = store.rollback_to_height(0, MAINNET_CHAIN_ID).unwrap();
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
        store.rollback_to_height(0, MAINNET_CHAIN_ID).unwrap();
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
        };
        let msg = tx.compute_signing_message().unwrap();
        tx.publisher_sig = priv_key.sign(&msg).unwrap();
        let tx_id = tx.compute_tx_id(MAINNET_CHAIN_ID).unwrap();
        (tx, tx_id)
    }

    #[test]
    fn mem_gateway_fee_split_50_50() {
        let store = MemoryStorage::new();
        let (sender_sk, sender_pk) = ed25519::generate_keypair();
        let (_, gw_pk) = ed25519::generate_keypair();
        let gw_key = NoblePublicKey::Ed25519(gw_pk.clone());
        let gw_wire = gw_key.to_wire_bytes();

        // Block 0: fund sender
        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            0,
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
            make_block_with_validator(vec![(tx, tx_id)], 1, h0, 1_700_000_001, &val_sk, &val_pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(
            store.get_balance(&val_pub).unwrap(),
            INITIAL_SUBSIDY + 1_000
        );
        assert_eq!(store.get_balance(&gw_key).unwrap(), 1_000);
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
            0,
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
            make_block_with_validator(vec![(tx, tx_id)], 1, h0, 1_700_000_001, &val_sk, &val_pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(store.get_balance(&val_pub).unwrap(), INITIAL_SUBSIDY + 501);
        assert_eq!(store.get_balance(&gw_key).unwrap(), 500);
    }

    #[test]
    fn mem_no_gateway_100_percent_to_validator() {
        let store = MemoryStorage::new();
        let (sender_sk, sender_pk) = ed25519::generate_keypair();

        let (b0, h0, ids0) = make_block_with_validator(
            vec![],
            0,
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
            make_block_with_validator(vec![(tx, tx_id)], 1, h0, 1_700_000_001, &val_sk, &val_pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        let val_pub = NoblePublicKey::Ed25519(val_pk.to_vec());
        assert_eq!(
            store.get_balance(&val_pub).unwrap(),
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
            0,
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
            make_block_with_validator(vec![(tx, tx_id)], 1, h0, 1_700_000_001, &val_sk, &val_pk);
        store.commit_block(&b1, &h1, &ids1).unwrap();

        // validator gets subsidy + val_share(1000) + gw_share(1000) = subsidy + 2000
        assert_eq!(
            store.get_balance(&val_pub).unwrap(),
            INITIAL_SUBSIDY + 2_000
        );
    }
}
