// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! PoR vote management — security-critical module resolving GAP-C6, GAP-C7, GAP-C8.
//!
//! - **GAP-C6**: `compute_majority()` requires `total_peers >= min_peers_for_consensus`.
//! - **GAP-C7**: `record_vote()` verifies vote signature before recording.
//! - **GAP-C8**: Vote counting uses `peer_id` (transport-layer identity), not pubkey.

use std::collections::{HashMap, HashSet};
use std::fmt;

use noble_crypto::{
    sha256, Hash256, NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::config::ConsensusConfig;

/// Error type for vote recording operations (AUD2-M4).
#[derive(Debug)]
pub enum VoteError {
    /// The vote's cycle number doesn't match the manager's current cycle.
    WrongCycle { expected: u64, got: u64 },
    /// The vote signature failed verification.
    Crypto(noble_crypto::CryptoError),
}

impl fmt::Display for VoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VoteError::WrongCycle { expected, got } => {
                write!(f, "wrong cycle: expected {expected}, got {got}")
            }
            VoteError::Crypto(e) => write!(f, "crypto: {e}"),
        }
    }
}

impl std::error::Error for VoteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VoteError::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<noble_crypto::CryptoError> for VoteError {
    fn from(e: noble_crypto::CryptoError) -> Self {
        VoteError::Crypto(e)
    }
}

/// A Proof of Reputation vote cast by a validator for a candidate block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PorVote {
    /// The cycle number this vote applies to.
    pub cycle: u64,
    /// Hash of the candidate block being voted for.
    pub candidate_hash: Hash256,
    /// The voter's public key.
    pub voter_pubkey: NoblePublicKey,
    /// Signature over `sha256(cbor(cycle, candidate_hash))`.
    pub signature: SignatureEnvelope,
}

/// Internal payload for vote signing.
#[derive(Serialize)]
struct VoteSigningPayload {
    cycle: u64,
    candidate_hash: Hash256,
}

impl PorVote {
    /// Compute the 32-byte signing payload: `sha256(canonical_cbor(cycle, candidate_hash))`.
    pub fn signing_payload(cycle: u64, candidate_hash: Hash256) -> [u8; 32] {
        let payload = VoteSigningPayload {
            cycle,
            candidate_hash,
        };
        let canonical = noble_codec::to_canonical_cbor(&payload)
            .expect("vote signing payload serialization should never fail");
        sha256(&canonical).0
    }

    /// Create a signed vote.
    pub fn sign(
        cycle: u64,
        candidate_hash: Hash256,
        private_key: &NoblePrivateKey,
        public_key: NoblePublicKey,
    ) -> Result<Self, noble_crypto::CryptoError> {
        let msg = Self::signing_payload(cycle, candidate_hash);
        let signature = private_key.sign(&msg)?;
        Ok(Self {
            cycle,
            candidate_hash,
            voter_pubkey: public_key,
            signature,
        })
    }

    /// Verify the vote signature against the embedded public key (GAP-C7).
    pub fn verify(&self) -> Result<(), noble_crypto::CryptoError> {
        let msg = Self::signing_payload(self.cycle, self.candidate_hash);
        self.voter_pubkey.verify(&msg, &self.signature)
    }
}

/// Strength of consensus when a candidate wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusStrength {
    /// Candidate received > 50% of votes.
    Strong,
    /// Candidate received ≥ plurality floor but ≤ 50%.
    Plurality,
}

/// Result of majority computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationResult {
    /// A candidate was selected.
    Adopt {
        candidate_hash: Hash256,
        strength: ConsensusStrength,
    },
    /// No candidate achieved sufficient support.
    Indeterminate,
}

/// Tracks votes per cycle and computes consensus outcomes.
///
/// Votes are indexed by peer_id (transport identity, GAP-C8),
/// not by voter public key (which could be spoofed via Sybil).
#[derive(Default)]
pub struct VoteManager {
    /// candidate_hash → set of peer_ids that voted for it.
    votes: HashMap<Hash256, HashSet<Vec<u8>>>,
    /// Set of peer_ids that have already voted (one vote per peer per cycle).
    voted_peers: HashSet<Vec<u8>>,
    /// Current cycle number for vote validation (AUD2-M4).
    current_cycle: u64,
}

impl VoteManager {
    /// Create a new empty vote manager.
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            voted_peers: HashSet::new(),
            current_cycle: 0,
        }
    }

    /// Set the current cycle number (AUD2-M4).
    pub fn set_current_cycle(&mut self, cycle: u64) {
        self.current_cycle = cycle;
    }

    /// Record a vote from a peer.
    ///
    /// - Validates the vote cycle matches `current_cycle` (AUD2-M4).
    /// - Verifies the vote signature (GAP-C7).
    /// - Rejects duplicate votes from the same peer_id (GAP-C8).
    /// - Returns `true` if the vote was accepted, `false` if duplicate.
    #[tracing::instrument(skip(self, vote), fields(task = "consensus_vote"))]
    pub fn record_vote(&mut self, peer_id: &[u8], vote: &PorVote) -> Result<bool, VoteError> {
        // AUD2-M4: Validate vote cycle matches current cycle
        if vote.cycle != self.current_cycle {
            return Err(VoteError::WrongCycle {
                expected: self.current_cycle,
                got: vote.cycle,
            });
        }

        // GAP-C7: Verify signature before recording
        vote.verify()?;

        // GAP-C8: One vote per peer_id
        if self.voted_peers.contains(peer_id) {
            debug!("duplicate vote from peer (ignored)");
            return Ok(false);
        }

        self.voted_peers.insert(peer_id.to_vec());
        self.votes
            .entry(vote.candidate_hash)
            .or_default()
            .insert(peer_id.to_vec());

        let count = self.voted_peers.len();
        debug!(
            "vote received from validator, tally: {} total recorded",
            count
        );
        Ok(true)
    }

    /// Return current vote counts per candidate hash.
    ///
    /// Used by voting strategies (e.g. FollowMajority) to observe the
    /// emerging consensus before casting their own vote.
    pub fn current_tallies(&self) -> HashMap<Hash256, usize> {
        self.votes
            .iter()
            .map(|(hash, peers)| (*hash, peers.len()))
            .collect()
    }

    /// Compute the majority outcome.
    ///
    /// - GAP-C6: If `total_peers < config.min_peers_for_consensus` → Indeterminate.
    /// - Tier 1: leader > 50% → Adopt(Strong).
    /// - Tier 2: leader ≥ total_peers / plurality_floor_divisor → Adopt(Plurality).
    /// - Tiebreaker: lower candidate_hash wins (lexicographic).
    /// - Otherwise → Indeterminate.
    pub fn compute_majority(
        &self,
        total_peers: usize,
        config: &ConsensusConfig,
    ) -> MigrationResult {
        // GAP-C6: Minimum peer check
        if total_peers < config.min_peers_for_consensus {
            return MigrationResult::Indeterminate;
        }

        if self.votes.is_empty() {
            return MigrationResult::Indeterminate;
        }

        // Find the leader (most votes). Tiebreaker: lower candidate_hash.
        let mut candidates: Vec<(Hash256, usize)> = self
            .votes
            .iter()
            .map(|(hash, peers)| (*hash, peers.len()))
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let (leader_hash, leader_count) = candidates[0];

        // Handle ties: if multiple candidates have the same top count,
        // pick the one with the lexicographically lower hash.
        let tied: Vec<_> = candidates
            .iter()
            .filter(|(_, count)| *count == leader_count)
            .collect();
        let winner_hash = if tied.len() > 1 {
            tied.iter().map(|(h, _)| *h).min().unwrap()
        } else {
            leader_hash
        };

        // Tier 1: Strong majority (> 50%)
        if leader_count * 2 > total_peers {
            info!(
                "vote tally complete: winner = {}, strength = Strong, votes = {}/{}",
                winner_hash, leader_count, total_peers
            );
            return MigrationResult::Adopt {
                candidate_hash: winner_hash,
                strength: ConsensusStrength::Strong,
            };
        }

        // Tier 2: Plurality floor (≥ total / divisor)
        let floor = total_peers / config.plurality_floor_divisor as usize;
        if leader_count >= floor.max(1) {
            info!(
                "vote tally complete: winner = {}, strength = Plurality, votes = {}/{}",
                winner_hash, leader_count, total_peers
            );
            return MigrationResult::Adopt {
                candidate_hash: winner_hash,
                strength: ConsensusStrength::Plurality,
            };
        }

        debug!(
            "vote tally indeterminate: leader has {}/{} votes, floor = {}",
            leader_count, total_peers, floor
        );
        MigrationResult::Indeterminate
    }

    /// Total number of unique peers that voted.
    pub fn total_votes(&self) -> usize {
        self.voted_peers.len()
    }

    /// Clear all votes for a new cycle.
    ///
    /// Optionally set the new cycle number via `set_current_cycle()` after clearing.
    pub fn clear(&mut self) {
        self.votes.clear();
        self.voted_peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::ed25519;

    fn make_vote(cycle: u64, candidate: Hash256) -> (PorVote, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let vote = PorVote::sign(cycle, candidate, &priv_key, pub_key.clone()).unwrap();
        (vote, pub_key)
    }

    fn hash_n(n: u8) -> Hash256 {
        Hash256::from_bytes([n; 32])
    }

    fn default_config() -> ConsensusConfig {
        ConsensusConfig::default()
    }

    #[test]
    fn vote_sign_verify() {
        let candidate = hash_n(1);
        let (vote, _) = make_vote(0, candidate);
        assert!(vote.verify().is_ok());
    }

    #[test]
    fn vote_tampered_signature_rejected() {
        let candidate = hash_n(1);
        let (mut vote, _) = make_vote(0, candidate);
        vote.signature.signature = vec![0u8; 64];
        assert!(vote.verify().is_err());
    }

    #[test]
    fn gap_c7_signature_verified_before_recording() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (mut vote, _) = make_vote(0, candidate);
        vote.signature.signature = vec![0u8; 64]; // corrupt
        let result = mgr.record_vote(b"peer1", &vote);
        assert!(result.is_err(), "invalid sig must be rejected");
        assert_eq!(mgr.total_votes(), 0);
    }

    #[test]
    fn gap_c8_duplicate_peer_rejected() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (vote, _) = make_vote(0, candidate);
        assert!(mgr.record_vote(b"peer1", &vote).unwrap());
        // Same peer_id, different vote object → rejected
        let (vote2, _) = make_vote(0, candidate);
        assert!(!mgr.record_vote(b"peer1", &vote2).unwrap());
        assert_eq!(mgr.total_votes(), 1);
    }

    #[test]
    fn gap_c6_insufficient_peers_indeterminate() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (vote, _) = make_vote(0, candidate);
        mgr.record_vote(b"peer1", &vote).unwrap();
        // total_peers=2 < min_peers=3 → Indeterminate
        assert_eq!(
            mgr.compute_majority(2, &default_config()),
            MigrationResult::Indeterminate
        );
    }

    #[test]
    fn strong_majority_over_50_percent() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        for i in 0..3u8 {
            let (vote, _) = make_vote(0, candidate);
            mgr.record_vote(&[i], &vote).unwrap();
        }
        // 3/5 = 60% > 50% → Strong
        let result = mgr.compute_majority(5, &default_config());
        assert_eq!(
            result,
            MigrationResult::Adopt {
                candidate_hash: candidate,
                strength: ConsensusStrength::Strong,
            }
        );
    }

    #[test]
    fn plurality_at_floor() {
        let mut mgr = VoteManager::new();
        let a = hash_n(1);
        let b = hash_n(2);
        // 2 votes for A, 1 for B → total_peers=6
        // 2/6 = 33% = floor(6/3)=2 → Plurality
        let (v1, _) = make_vote(0, a);
        let (v2, _) = make_vote(0, a);
        let (v3, _) = make_vote(0, b);
        mgr.record_vote(b"p1", &v1).unwrap();
        mgr.record_vote(b"p2", &v2).unwrap();
        mgr.record_vote(b"p3", &v3).unwrap();

        let result = mgr.compute_majority(6, &default_config());
        assert_eq!(
            result,
            MigrationResult::Adopt {
                candidate_hash: a,
                strength: ConsensusStrength::Plurality,
            }
        );
    }

    #[test]
    fn indeterminate_below_plurality_floor() {
        let mut mgr = VoteManager::new();
        let a = hash_n(1);
        let b = hash_n(2);
        let c = hash_n(3);
        // 1 vote each for A, B, C → total_peers=10
        // max_count=1, floor(10/3)=3 → 1 < 3 → Indeterminate
        let (v1, _) = make_vote(0, a);
        let (v2, _) = make_vote(0, b);
        let (v3, _) = make_vote(0, c);
        mgr.record_vote(b"p1", &v1).unwrap();
        mgr.record_vote(b"p2", &v2).unwrap();
        mgr.record_vote(b"p3", &v3).unwrap();

        let result = mgr.compute_majority(10, &default_config());
        assert_eq!(result, MigrationResult::Indeterminate);
    }

    #[test]
    fn tiebreaker_lower_hash_wins() {
        let mut mgr = VoteManager::new();
        let low = Hash256::from_bytes([0x01; 32]);
        let high = Hash256::from_bytes([0xFF; 32]);
        // 2 votes for high, 2 for low → tie → lower hash wins
        let (v1, _) = make_vote(0, high);
        let (v2, _) = make_vote(0, high);
        let (v3, _) = make_vote(0, low);
        let (v4, _) = make_vote(0, low);
        mgr.record_vote(b"p1", &v1).unwrap();
        mgr.record_vote(b"p2", &v2).unwrap();
        mgr.record_vote(b"p3", &v3).unwrap();
        mgr.record_vote(b"p4", &v4).unwrap();

        let result = mgr.compute_majority(5, &default_config());
        match result {
            MigrationResult::Adopt { candidate_hash, .. } => {
                assert_eq!(candidate_hash, low, "lower hash should win tiebreaker")
            }
            other => panic!("expected Adopt, got {:?}", other),
        }
    }

    #[test]
    fn empty_votes_indeterminate() {
        let mgr = VoteManager::new();
        assert_eq!(
            mgr.compute_majority(5, &default_config()),
            MigrationResult::Indeterminate
        );
    }

    #[test]
    fn clear_resets_state() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (vote, _) = make_vote(0, candidate);
        mgr.record_vote(b"peer1", &vote).unwrap();
        assert_eq!(mgr.total_votes(), 1);

        mgr.clear();
        mgr.set_current_cycle(1);
        assert_eq!(mgr.total_votes(), 0);
        // Can vote again after clear
        let (vote2, _) = make_vote(1, candidate);
        assert!(mgr.record_vote(b"peer1", &vote2).unwrap());
    }

    #[test]
    fn signing_payload_deterministic() {
        let candidate = hash_n(42);
        let msg1 = PorVote::signing_payload(5, candidate);
        let msg2 = PorVote::signing_payload(5, candidate);
        assert_eq!(msg1, msg2);
    }

    #[test]
    fn aud2_m4_vote_with_wrong_cycle_rejected() {
        let mut mgr = VoteManager::new();
        mgr.set_current_cycle(5);
        let candidate = hash_n(1);
        // Create a vote for cycle 3 (stale), but manager expects cycle 5
        let (vote, _) = make_vote(3, candidate);
        let result = mgr.record_vote(b"peer1", &vote);
        match result {
            Err(VoteError::WrongCycle { expected, got }) => {
                assert_eq!(expected, 5);
                assert_eq!(got, 3);
            }
            other => panic!("expected WrongCycle error, got {:?}", other),
        }
        assert_eq!(mgr.total_votes(), 0, "stale vote should not be counted");
    }
}
