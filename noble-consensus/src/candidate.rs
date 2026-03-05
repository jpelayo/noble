// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Candidate block tracking within a consensus cycle.
//!
//! Enforces one-block-per-validator, tracks first-seen order for
//! tiebreaking, and collects orphaned transactions from losing candidates.

use std::collections::{HashMap, HashSet};

use noble_core::{Block, Transaction};
use noble_crypto::Hash256;
use tracing::{debug, trace};

/// A candidate block proposed during this cycle.
#[derive(Debug, Clone)]
pub struct CandidateEntry {
    /// The proposed block.
    pub block: Box<Block>,
    /// Hash of the proposed block.
    pub block_hash: Hash256,
    /// Unix timestamp when the candidate was received.
    pub received_at: u64,
    /// Insertion order for first-seen tiebreaking.
    order: usize,
}

/// Tracks proposed blocks within a single consensus cycle.
#[derive(Default)]
pub struct CandidateTracker {
    /// block_hash → candidate entry.
    candidates: HashMap<Hash256, CandidateEntry>,
    /// validator wire bytes → block_hash (enforces one-block-per-validator).
    by_validator: HashMap<Vec<u8>, Hash256>,
    /// Monotonic counter for insertion order.
    next_order: usize,
}

impl CandidateTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
            by_validator: HashMap::new(),
            next_order: 0,
        }
    }

    /// Add a candidate block.
    ///
    /// Returns `Err` with the validator's existing block hash if the validator
    /// already proposed a block this cycle (double-proposal).
    pub fn add_candidate(
        &mut self,
        block: Box<Block>,
        block_hash: Hash256,
        received_at: u64,
    ) -> Result<(), Hash256> {
        let validator_wire = block.header.validator_id.to_wire_bytes();

        // Enforce one block per validator per cycle
        if let Some(existing) = self.by_validator.get(&validator_wire) {
            return Err(*existing);
        }

        let order = self.next_order;
        self.next_order += 1;

        debug!(
            "new candidate block proposed at height {}",
            block.header.height
        );

        self.by_validator.insert(validator_wire, block_hash);
        self.candidates.insert(
            block_hash,
            CandidateEntry {
                block,
                block_hash,
                received_at,
                order,
            },
        );
        trace!(
            "candidate tracker: {} candidates for cycle",
            self.candidates.len()
        );
        Ok(())
    }

    /// Get a candidate by its block hash.
    pub fn get(&self, block_hash: &Hash256) -> Option<&CandidateEntry> {
        self.candidates.get(block_hash)
    }

    /// Return the preferred candidate (first-seen tiebreaker).
    pub fn preferred_candidate(&self) -> Option<&CandidateEntry> {
        self.candidates.values().min_by_key(|c| c.order)
    }

    /// Collect transactions from losing candidates that are NOT in the winning block.
    ///
    /// These transactions should be re-admitted to the mempool.
    /// Uses tx_id for dedup — two different transactions can share a checksum
    /// (same document, different publishers), so checksum is not sufficient.
    pub fn collect_orphaned_txs(&self, winner_hash: &Hash256, chain_id: u32) -> Vec<Transaction> {
        // Collect tx_ids from winner block as a dedup set
        let winner_tx_ids: HashSet<[u8; 32]> = self
            .candidates
            .get(winner_hash)
            .map(|entry| {
                entry
                    .block
                    .transactions
                    .iter()
                    .filter_map(|tx| tx.compute_tx_id(chain_id).ok().map(|h| h.0))
                    .collect()
            })
            .unwrap_or_default();

        self.candidates
            .iter()
            .filter(|(h, _)| *h != winner_hash)
            .flat_map(|(_, entry)| {
                entry
                    .block
                    .transactions
                    .iter()
                    .filter(|tx| {
                        tx.compute_tx_id(chain_id)
                            .map(|id| !winner_tx_ids.contains(&id.0))
                            .unwrap_or(true) // keep tx if id computation fails
                    })
                    .cloned()
            })
            .collect()
    }

    /// Return all candidates for the current cycle, ordered by received_at.
    pub fn all_candidates(&self) -> Vec<&CandidateEntry> {
        let mut entries: Vec<&CandidateEntry> = self.candidates.values().collect();
        entries.sort_by_key(|c| c.order);
        entries
    }

    /// Return the validator wire bytes for a candidate block hash.
    pub fn validator_of(&self, block_hash: &Hash256) -> Option<Vec<u8>> {
        self.candidates
            .get(block_hash)
            .map(|e| e.block.header.validator_id.to_wire_bytes())
    }

    /// Check if a validator (by wire bytes) has proposed this cycle.
    pub fn has_proposed(&self, validator_wire: &[u8]) -> bool {
        self.by_validator.contains_key(validator_wire)
    }

    /// Number of candidates currently tracked.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Whether there are no candidates.
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Clear all state for a new cycle.
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.by_validator.clear();
        self.next_order = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{BlockHeader, PROTOCOL_VERSION};
    use noble_crypto::{
        ed25519, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_ED25519,
    };

    fn make_candidate_block(
        val_pub: &NoblePublicKey,
        val_priv: &NoblePrivateKey,
        txs: Vec<Transaction>,
    ) -> (Box<Block>, Hash256) {
        let merkle_root = noble_core::compute_merkle_root(&[]);
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp: 1_700_000_000,
            height: 1,
            tx_count: txs.len() as u32,
            validator_id: val_pub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: val_pub.key_bytes().to_vec(),
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();
        let block_hash = header.compute_block_hash().unwrap();
        (
            Box::new(Block {
                header,
                transactions: txs,
            }),
            block_hash,
        )
    }

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    #[test]
    fn add_and_retrieve_candidate() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block, hash) = make_candidate_block(&pub_key, &priv_key, vec![]);

        tracker.add_candidate(block, hash, 1000).unwrap();
        assert_eq!(tracker.len(), 1);
        assert!(tracker.get(&hash).is_some());
    }

    #[test]
    fn double_proposal_rejected() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block1, hash1) = make_candidate_block(&pub_key, &priv_key, vec![]);
        let (block2, hash2) = make_candidate_block(&pub_key, &priv_key, vec![]);

        tracker.add_candidate(block1, hash1, 1000).unwrap();
        let err = tracker.add_candidate(block2, hash2, 1001).unwrap_err();
        assert_eq!(err, hash1, "should return the existing block hash");
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn preferred_candidate_is_first_seen() {
        let mut tracker = CandidateTracker::new();
        let (pk1, pub1) = make_validator();
        let (pk2, pub2) = make_validator();

        let (block1, hash1) = make_candidate_block(&pub1, &pk1, vec![]);
        let (block2, hash2) = make_candidate_block(&pub2, &pk2, vec![]);

        tracker.add_candidate(block1, hash1, 1000).unwrap();
        tracker.add_candidate(block2, hash2, 999).unwrap(); // earlier time but later insertion

        let preferred = tracker.preferred_candidate().unwrap();
        assert_eq!(
            preferred.block_hash, hash1,
            "first inserted should be preferred"
        );
    }

    #[test]
    fn orphan_recovery() {
        let mut tracker = CandidateTracker::new();
        let (pk1, pub1) = make_validator();
        let (pk2, pub2) = make_validator();

        // Block 1: empty
        let (block1, hash1) = make_candidate_block(&pub1, &pk1, vec![]);
        // Block 2: also empty (orphan recovery with empty blocks returns nothing)
        let (block2, hash2) = make_candidate_block(&pub2, &pk2, vec![]);

        tracker.add_candidate(block1, hash1, 1000).unwrap();
        tracker.add_candidate(block2, hash2, 1001).unwrap();

        // Winner is block1 → orphans from block2
        let orphans = tracker.collect_orphaned_txs(&hash1, 1);
        assert!(orphans.is_empty(), "empty blocks have no orphan txs");
    }

    #[test]
    fn clear_resets_state() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block, hash) = make_candidate_block(&pub_key, &priv_key, vec![]);

        tracker.add_candidate(block, hash, 1000).unwrap();
        assert_eq!(tracker.len(), 1);

        tracker.clear();
        assert!(tracker.is_empty());
        assert!(tracker.preferred_candidate().is_none());
    }

    #[test]
    fn different_validators_can_propose() {
        let mut tracker = CandidateTracker::new();
        let (pk1, pub1) = make_validator();
        let (pk2, pub2) = make_validator();
        let (pk3, pub3) = make_validator();

        let (b1, h1) = make_candidate_block(&pub1, &pk1, vec![]);
        let (b2, h2) = make_candidate_block(&pub2, &pk2, vec![]);
        let (b3, h3) = make_candidate_block(&pub3, &pk3, vec![]);

        tracker.add_candidate(b1, h1, 1000).unwrap();
        tracker.add_candidate(b2, h2, 1001).unwrap();
        tracker.add_candidate(b3, h3, 1002).unwrap();
        assert_eq!(tracker.len(), 3);
    }
}
