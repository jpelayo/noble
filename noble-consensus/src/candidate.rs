// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Candidate block tracking within a consensus cycle.
//!
//! Enforces one-block-per-validator, tracks first-seen order for
//! tiebreaking, and collects orphaned transactions from losing candidates.

use std::collections::{HashMap, HashSet, VecDeque};

use noble_core::{Block, BlockHeader, Transaction};
use noble_crypto::Hash256;
use tracing::{debug, trace};

/// Result of adding a candidate to the tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddCandidateResult {
    /// First proposal from this validator — accepted.
    Accepted,
    /// Second proposal — replaced the previous one. Contains old hash.
    Replaced(Hash256),
}

/// Long-lived FIFO-bounded block hash memory.
///
/// Remembers every block hash ever processed by `handle_block_proposed`.
/// Checked BEFORE `add_candidate()` so that any block from any prior cycle
/// is immediately recognized as a duplicate delivery — eliminating false
/// `DuplicateProposal (0x04)` bans that occur when stale blocks bypass the
/// `CandidateTracker.previous_hashes` one-cycle window.
pub struct DeliveredBlockLog {
    hashes: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl DeliveredBlockLog {
    /// Create a new log with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            hashes: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Insert a block hash.  Returns `true` if it was new, `false` if already seen.
    pub fn insert(&mut self, hash: [u8; 32]) -> bool {
        if self.hashes.contains(&hash) {
            return false;
        }
        // FIFO eviction when at capacity.
        if self.hashes.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.hashes.remove(&oldest);
            }
        }
        self.hashes.insert(hash);
        self.order.push_back(hash);
        true
    }

    /// Check if a block hash has been seen.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.hashes.contains(hash)
    }

    /// Clear all state (used for blockchain hop / hard reset).
    pub fn clear(&mut self) {
        self.hashes.clear();
        self.order.clear();
    }

    /// Number of entries currently stored.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

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
///
/// Allows one free replacement per validator per cycle ("one-hiccup tolerance"):
/// - 1st proposal: accepted
/// - 2nd proposal: replaces the 1st (take youngest), no ban
/// - 3rd proposal: rejected, evidence published, penalty scored
#[derive(Default)]
pub struct CandidateTracker {
    /// block_hash → candidate entry.
    candidates: HashMap<Hash256, CandidateEntry>,
    /// validator wire bytes → (block_hash, proposal_count).
    by_validator: HashMap<Vec<u8>, (Hash256, u8)>,
    /// Monotonic counter for insertion order.
    next_order: usize,
    /// Block hashes from the previous cycle.  Used to detect stale
    /// re-deliveries that arrive after the tracker was cleared at a cycle
    /// boundary.  Without this, a delayed block from cycle N arriving in
    /// cycle N+1 (at the same height after an empty cycle) would collide
    /// with the validator's new proposal and trigger a false 0x04
    /// DuplicateProposal ban.
    previous_hashes: HashSet<Hash256>,
    /// First block header per validator — retained for evidence construction
    /// if a 3rd proposal arrives (uses 1st + 3rd headers for evidence).
    first_blocks: HashMap<Vec<u8>, BlockHeader>,
}

impl CandidateTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
            by_validator: HashMap::new(),
            next_order: 0,
            previous_hashes: HashSet::new(),
            first_blocks: HashMap::new(),
        }
    }

    /// Add a candidate block.
    ///
    /// One-hiccup tolerance: allows one free replacement per validator per cycle.
    /// - 1st proposal → `Ok(Accepted)`
    /// - 2nd proposal → `Ok(Replaced(old_hash))` — old candidate removed, new inserted
    /// - 3rd proposal → `Err(existing_hash)` — caller creates evidence and scores penalty
    ///
    /// Stale re-deliveries (blocks from a previous cycle arriving after the
    /// tracker was cleared) are detected via `previous_hashes` and returned as
    /// `Err(block_hash)` — the caller's duplicate-delivery guard handles them
    /// without banning.
    pub fn add_candidate(
        &mut self,
        block: Box<Block>,
        block_hash: Hash256,
        received_at: u64,
    ) -> Result<AddCandidateResult, Hash256> {
        // Stale re-delivery: this block was tracked in the previous cycle.
        // Return Err(block_hash) so the caller treats it as a duplicate
        // delivery (same hash) rather than a double proposal.
        if self.previous_hashes.contains(&block_hash) {
            debug!(
                "stale block {} from previous cycle — treating as duplicate",
                block_hash
            );
            return Err(block_hash);
        }

        let validator_wire = block.header.validator_id.to_wire_bytes();

        if let Some(&(existing_hash, count)) = self.by_validator.get(&validator_wire) {
            if count >= 2 {
                // 3rd+ proposal — reject for evidence + penalty scoring
                return Err(existing_hash);
            }
            // 2nd proposal — replacement (take youngest)
            let old_hash = existing_hash;
            // Retain 1st block header for evidence if a 3rd arrives
            if let Some(old_entry) = self.candidates.remove(&old_hash) {
                self.first_blocks
                    .entry(validator_wire.clone())
                    .or_insert_with(|| old_entry.block.header.clone());
            }
            // Add old hash to previous_hashes for stale re-delivery guard
            self.previous_hashes.insert(old_hash);

            let order = self.next_order;
            self.next_order += 1;

            debug!(
                "replacement proposal at height {} (old: {})",
                block.header.height, old_hash
            );

            self.by_validator.insert(validator_wire, (block_hash, 2));
            self.candidates.insert(
                block_hash,
                CandidateEntry {
                    block,
                    block_hash,
                    received_at,
                    order,
                },
            );
            return Ok(AddCandidateResult::Replaced(old_hash));
        }

        // 1st proposal — accepted
        let order = self.next_order;
        self.next_order += 1;

        debug!(
            "new candidate block proposed at height {}",
            block.header.height
        );

        self.by_validator.insert(validator_wire, (block_hash, 1));
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
        Ok(AddCandidateResult::Accepted)
    }

    /// Return the retained first block header for a validator (for triple-proposal evidence).
    pub fn first_block_header(&self, validator_wire: &[u8]) -> Option<&BlockHeader> {
        self.first_blocks.get(validator_wire)
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
    /// (same document, different issuers), so checksum is not sufficient.
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
    ///
    /// **Accumulates** current candidate hashes into `previous_hashes` so that
    /// stale re-deliveries arriving after the clear can be detected and ignored
    /// (instead of triggering false double-proposal bans).  Hashes accumulate
    /// across cycles (extending detection from 1 cycle to ~25 cycles / ~8 hours).
    /// Capped at 256 entries — on overflow, resets to current candidates only.
    pub fn clear(&mut self) {
        // Only accumulate when there are actual candidates.
        // Both `handle_cycle_boundary` and `handle_phase_transition(Proposal)`
        // call clear() in sequence — the second call would see an empty
        // candidates map and must not wipe the hashes saved by the first call.
        if !self.candidates.is_empty() {
            for hash in self.candidates.keys() {
                self.previous_hashes.insert(*hash);
            }
            // Cap at 256 entries.  On overflow, replace with current only.
            if self.previous_hashes.len() > 256 {
                self.previous_hashes = self.candidates.keys().cloned().collect();
            }
        }
        self.candidates.clear();
        self.by_validator.clear();
        self.first_blocks.clear();
        self.next_order = 0;
    }

    /// Clear all state including stale hash memory.
    ///
    /// Used for hard resets (e.g., blockchain hop) where previous-cycle
    /// context is no longer valid.
    pub fn clear_all(&mut self) {
        self.candidates.clear();
        self.by_validator.clear();
        self.previous_hashes.clear();
        self.first_blocks.clear();
        self.next_order = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_core::{BlockHeader, PROTOCOL_VERSION};
    use noble_crypto::{
        secp256k1, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope, SCHEME_SECP256K1,
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
                scheme_id: SCHEME_SECP256K1,
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
        let (sk, _) = secp256k1::generate_keypair();
        let priv_key = NoblePrivateKey::Secp256k1(sk);
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
    fn double_proposal_replaces() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block1, hash1) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let (block2, hash2) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_001);
        assert_ne!(hash1, hash2);

        tracker.add_candidate(block1, hash1, 1000).unwrap();
        let result = tracker.add_candidate(block2, hash2, 1001).unwrap();
        assert_eq!(result, AddCandidateResult::Replaced(hash1));
        assert_eq!(tracker.len(), 1);
        assert!(tracker.get(&hash1).is_none(), "old candidate should be removed");
        assert!(tracker.get(&hash2).is_some(), "new candidate should be present");
        assert!(tracker.has_proposed(&pub_key.to_wire_bytes()));
    }

    #[test]
    fn triple_proposal_rejected() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block1, hash1) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let (block2, hash2) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_001);
        let (block3, hash3) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_002);

        tracker.add_candidate(block1, hash1, 1000).unwrap();
        tracker.add_candidate(block2, hash2, 1001).unwrap();
        let err = tracker.add_candidate(block3, hash3, 1002).unwrap_err();
        assert_eq!(err, hash2, "should return the current (2nd) block hash");
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn replacement_preserves_first_block_header() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block1, hash1) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let (block2, hash2) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_001);
        let wire = pub_key.to_wire_bytes();

        let _ = tracker.add_candidate(block1, hash1, 1000);
        let _ = tracker.add_candidate(block2, hash2, 1001);
        assert!(tracker.first_block_header(&wire).is_some(), "should retain 1st header for evidence");
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

    /// Helper: create a block with a specific timestamp (produces a different hash).
    fn make_candidate_block_at(
        val_pub: &NoblePublicKey,
        val_priv: &NoblePrivateKey,
        timestamp: u64,
    ) -> (Box<Block>, Hash256) {
        let merkle_root = noble_core::compute_merkle_root(&[]);
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: Hash256::ZERO,
            merkle_root,
            timestamp,
            height: 1,
            tx_count: 0,
            validator_id: val_pub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_SECP256K1,
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
                transactions: vec![],
            }),
            block_hash,
        )
    }

    #[test]
    fn stale_block_detected_after_clear() {
        // Simulate: cycle N has a proposal, cycle boundary clears tracker,
        // then the same block re-arrives in cycle N+1.
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block1, hash1) = make_candidate_block(&pub_key, &priv_key, vec![]);

        // Cycle N: add block
        tracker.add_candidate(block1, hash1, 1000).unwrap();
        assert_eq!(tracker.len(), 1);

        // Cycle boundary: clear
        tracker.clear();
        assert!(tracker.is_empty());

        // Cycle N+1: same block re-arrives (stale delivery)
        let (block1_copy, _) = make_candidate_block(&pub_key, &priv_key, vec![]);
        let err = tracker.add_candidate(block1_copy, hash1, 2000).unwrap_err();
        // Returns same hash → caller treats as duplicate delivery, no ban
        assert_eq!(err, hash1);
        assert!(tracker.is_empty(), "stale block should not be added");
    }

    #[test]
    fn stale_then_new_proposal_accepted() {
        // Stale block arrives first, then the validator's new proposal.
        // The new proposal should be accepted without triggering double-proposal.
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();

        // Cycle N: propose at timestamp T1
        let (block_old, hash_old) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        tracker.add_candidate(block_old, hash_old, 1000).unwrap();

        // Cycle boundary
        tracker.clear();

        // Cycle N+1: stale block arrives first
        let (block_old_copy, _) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let err = tracker
            .add_candidate(block_old_copy, hash_old, 2000)
            .unwrap_err();
        assert_eq!(err, hash_old, "stale delivery returns same hash");

        // New proposal from same validator (different timestamp → different hash)
        let (block_new, hash_new) = make_candidate_block_at(&pub_key, &priv_key, 1_700_001_200);
        assert_ne!(hash_old, hash_new);
        tracker
            .add_candidate(block_new, hash_new, 2001)
            .unwrap();
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn new_then_stale_no_ban() {
        // New proposal arrives first, then stale block from previous cycle.
        // The stale block should be detected and ignored.
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();

        // Cycle N: propose at timestamp T1
        let (block_old, hash_old) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        tracker.add_candidate(block_old, hash_old, 1000).unwrap();

        // Cycle boundary
        tracker.clear();

        // Cycle N+1: new proposal arrives first
        let (block_new, hash_new) = make_candidate_block_at(&pub_key, &priv_key, 1_700_001_200);
        tracker.add_candidate(block_new, hash_new, 2000).unwrap();
        assert_eq!(tracker.len(), 1);

        // Stale block from cycle N arrives late
        let (block_old_copy, _) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let err = tracker
            .add_candidate(block_old_copy, hash_old, 2001)
            .unwrap_err();
        // Returns hash_old (same hash) → duplicate delivery, NOT double proposal
        assert_eq!(err, hash_old, "stale delivery returns its own hash");
        assert_eq!(tracker.len(), 1, "tracker unchanged");
    }

    #[test]
    fn true_triple_proposal_detected() {
        // Same cycle, same validator, three different blocks → triple proposal → reject 3rd.
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();

        let (block1, hash1) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let (block2, hash2) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_001);
        let (block3, hash3) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_002);
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);

        tracker.add_candidate(block1, hash1, 1000).unwrap();
        // 2nd: replacement
        let result = tracker.add_candidate(block2, hash2, 1001).unwrap();
        assert_eq!(result, AddCandidateResult::Replaced(hash1));
        assert_eq!(tracker.len(), 1);
        // 3rd: rejected
        let err = tracker.add_candidate(block3, hash3, 1002).unwrap_err();
        assert_eq!(err, hash2, "should return current (2nd) hash");
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn clear_all_wipes_stale_hashes() {
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();
        let (block, hash) = make_candidate_block(&pub_key, &priv_key, vec![]);

        tracker.add_candidate(block, hash, 1000).unwrap();
        tracker.clear();
        assert!(tracker.previous_hashes.contains(&hash));

        tracker.clear_all();
        assert!(tracker.previous_hashes.is_empty());
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

    // --- DeliveredBlockLog tests ---

    #[test]
    fn delivered_log_insert_returns_true_for_new() {
        let mut log = DeliveredBlockLog::new(16);
        assert!(log.insert([0xAA; 32]));
    }

    #[test]
    fn delivered_log_insert_returns_false_for_duplicate() {
        let mut log = DeliveredBlockLog::new(16);
        assert!(log.insert([0xAA; 32]));
        assert!(!log.insert([0xAA; 32]));
    }

    #[test]
    fn delivered_log_contains_after_insert() {
        let mut log = DeliveredBlockLog::new(16);
        assert!(!log.contains(&[0xBB; 32]));
        log.insert([0xBB; 32]);
        assert!(log.contains(&[0xBB; 32]));
    }

    #[test]
    fn delivered_log_fifo_eviction_at_capacity() {
        let mut log = DeliveredBlockLog::new(3);
        let h1 = [0x01; 32];
        let h2 = [0x02; 32];
        let h3 = [0x03; 32];
        let h4 = [0x04; 32];

        log.insert(h1);
        log.insert(h2);
        log.insert(h3);
        assert_eq!(log.len(), 3);

        // Inserting h4 should evict h1 (oldest).
        log.insert(h4);
        assert_eq!(log.len(), 3);
        assert!(!log.contains(&h1), "oldest entry should be evicted");
        assert!(log.contains(&h2));
        assert!(log.contains(&h3));
        assert!(log.contains(&h4));
    }

    #[test]
    fn delivered_log_clear_wipes_all() {
        let mut log = DeliveredBlockLog::new(16);
        log.insert([0x01; 32]);
        log.insert([0x02; 32]);
        assert_eq!(log.len(), 2);

        log.clear();
        assert!(log.is_empty());
        assert!(!log.contains(&[0x01; 32]));
    }

    // --- CandidateTracker accumulation tests ---

    #[test]
    fn stale_block_detected_two_cycles_later() {
        // Block from cycle N should be detected in cycle N+2.
        let mut tracker = CandidateTracker::new();
        let (priv_key, pub_key) = make_validator();

        // Cycle N: propose
        let (block_n, hash_n) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        tracker.add_candidate(block_n, hash_n, 1000).unwrap();
        tracker.clear(); // Cycle N → N+1

        // Cycle N+1: empty cycle (no proposals)
        tracker.clear(); // Cycle N+1 → N+2

        // Cycle N+2: stale block from cycle N re-arrives
        let (block_n_copy, _) = make_candidate_block_at(&pub_key, &priv_key, 1_700_000_000);
        let err = tracker.add_candidate(block_n_copy, hash_n, 3000).unwrap_err();
        assert_eq!(err, hash_n, "stale block from cycle N detected in cycle N+2");
    }

    #[test]
    fn previous_hashes_cap_enforced() {
        let mut tracker = CandidateTracker::new();

        // Fill previous_hashes with many entries across many cycles.
        for cycle in 0..260 {
            let (pk, pub_k) = make_validator();
            let (block, hash) = make_candidate_block_at(&pub_k, &pk, 1_700_000_000 + cycle);
            tracker.add_candidate(block, hash, cycle).unwrap();
            tracker.clear();
        }

        // After 260 cycles with 1 unique proposal each, previous_hashes
        // should have been capped and reset on overflow.
        assert!(
            tracker.previous_hashes.len() <= 256,
            "previous_hashes should be capped at 256, got {}",
            tracker.previous_hashes.len()
        );
    }
}
