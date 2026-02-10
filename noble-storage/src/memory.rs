// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! In-memory storage backend for testing.
//!
//! Implements `StorageEngine` with `HashMap`-based storage. Not suitable for
//! production use — data is lost when the process exits.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use noble_core::constants::{subsidy_at_height, TX_TYPE_TRANSFER};
use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::{Hash256, NoblePublicKey};

use crate::error::StorageError;
use crate::traits::{ChainTip, StorageEngine};
use crate::MAX_CHECKSUM_REGISTRATIONS;

/// Shared inner state behind a RwLock for thread-safe testing.
#[derive(Default)]
struct Inner {
    blocks: HashMap<Hash256, Block>,
    block_heights: HashMap<u64, Hash256>,
    transactions: HashMap<Hash256, Transaction>,
    checksum_index: HashMap<Hash256, Vec<Hash256>>,
    chain_tip: Option<ChainTip>,
    /// Address balances in atomic units (GAP-H19).
    balances: HashMap<NoblePublicKey, u64>,
    /// Address history: (wire_bytes, height, offset) → tx_id (GAP-H19).
    address_history: BTreeMap<(Vec<u8>, u64, u32), Hash256>,
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

        // Store transactions and checksum index
        for (tx, tx_id) in block.transactions.iter().zip(tx_ids.iter()) {
            inner.transactions.insert(*tx_id, tx.clone());

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

        // --- Balance accumulator (GAP-H19) ---
        let height = block.header.height;

        // Phase 1: accumulate deltas as i128 to detect overflows later
        let mut deltas: HashMap<NoblePublicKey, i128> = HashMap::new();

        // Validator gets subsidy + all fees
        let validator = &block.header.validator_id;
        let subsidy = subsidy_at_height(height) as i128;
        let total_fees: i128 = block.transactions.iter().map(|tx| tx.fee as i128).sum();
        *deltas.entry(validator.clone()).or_default() += subsidy + total_fees;

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

        // Update chain tip
        inner.chain_tip = Some(ChainTip {
            block_hash: *block_hash,
            height: block.header.height,
        });

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
}
