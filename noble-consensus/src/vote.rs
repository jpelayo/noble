// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! PoR vote management — security-critical module resolving GAP-C6, GAP-C7, GAP-C8.
//!
//! - **GAP-C6**: `compute_majority()` requires `total_peers >= min_peers_for_consensus`.
//! - **GAP-C7**: `record_vote()` verifies vote signature before recording.
//! - **GAP-C8**: Vote counting uses validator public key (not transport-layer peer_id).

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
    /// Signature over `sha256(cbor(cycle, candidate_hash, round))`.
    pub signature: SignatureEnvelope,
    /// Voting round: 1 = R1 (Reflection), 2 = R2 (Confirmation). Default: 1.
    #[serde(default = "default_round")]
    pub round: u8,
}

fn default_round() -> u8 {
    1
}

/// Internal payload for vote signing.
#[derive(Serialize)]
struct VoteSigningPayload {
    cycle: u64,
    candidate_hash: Hash256,
    round: u8,
}

impl PorVote {
    /// Compute the 32-byte signing payload: `sha256(canonical_cbor(cycle, candidate_hash, round))`.
    pub fn signing_payload(cycle: u64, candidate_hash: Hash256, round: u8) -> [u8; 32] {
        let payload = VoteSigningPayload {
            cycle,
            candidate_hash,
            round,
        };
        let canonical = noble_codec::to_canonical_cbor(&payload)
            .expect("vote signing payload serialization should never fail");
        sha256(&canonical).0
    }

    /// Create a signed R1 vote (default round=1).
    pub fn sign(
        cycle: u64,
        candidate_hash: Hash256,
        private_key: &NoblePrivateKey,
        public_key: NoblePublicKey,
    ) -> Result<Self, noble_crypto::CryptoError> {
        Self::sign_round(cycle, candidate_hash, 1, private_key, public_key)
    }

    /// Create a signed vote for a specific round.
    pub fn sign_round(
        cycle: u64,
        candidate_hash: Hash256,
        round: u8,
        private_key: &NoblePrivateKey,
        public_key: NoblePublicKey,
    ) -> Result<Self, noble_crypto::CryptoError> {
        let msg = Self::signing_payload(cycle, candidate_hash, round);
        let signature = private_key.sign(&msg)?;
        Ok(Self {
            cycle,
            candidate_hash,
            voter_pubkey: public_key,
            signature,
            round,
        })
    }

    /// Verify the vote signature against the embedded public key (GAP-C7).
    pub fn verify(&self) -> Result<(), noble_crypto::CryptoError> {
        let msg = Self::signing_payload(self.cycle, self.candidate_hash, self.round);
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
/// P0.2: Votes are deduplicated by `(voter_pubkey, round)` — each validator
/// may cast one R1 vote and one R2 vote per cycle.
/// P1.2: R2 votes are tracked separately for confirmation voting.
#[derive(Default)]
pub struct VoteManager {
    /// R1: candidate_hash → set of voter pubkey wire bytes that voted for it.
    votes: HashMap<Hash256, HashSet<Vec<u8>>>,
    /// R2: candidate_hash → set of voter pubkey wire bytes that voted for it.
    r2_votes: HashMap<Hash256, HashSet<Vec<u8>>>,
    /// Set of `(voter_pubkey_wire_bytes, round)` that have already voted.
    voted_validators: HashSet<(Vec<u8>, u8)>,
    /// Current cycle number for vote validation (AUD2-M4).
    current_cycle: u64,
}

impl VoteManager {
    /// Create a new empty vote manager.
    pub fn new() -> Self {
        Self {
            votes: HashMap::new(),
            r2_votes: HashMap::new(),
            voted_validators: HashSet::new(),
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
    /// - P0.2: Deduplicates by voter public key (validator identity), not peer_id.
    /// - Returns `true` if the vote was accepted, `false` if duplicate.
    #[tracing::instrument(skip(self, vote), fields(task = "consensus_vote"))]
    pub fn record_vote(&mut self, _peer_id: &[u8], vote: &PorVote) -> Result<bool, VoteError> {
        // AUD2-M4: Validate vote cycle matches current cycle
        if vote.cycle != self.current_cycle {
            return Err(VoteError::WrongCycle {
                expected: self.current_cycle,
                got: vote.cycle,
            });
        }

        // GAP-C7: Verify signature before recording
        vote.verify()?;

        // P0.2 + P1.2: One vote per validator per round.
        let voter_key = vote.voter_pubkey.to_wire_bytes();
        let dedup_key = (voter_key.clone(), vote.round);
        if self.voted_validators.contains(&dedup_key) {
            debug!(
                "duplicate vote from validator round {} (ignored)",
                vote.round
            );
            return Ok(false);
        }

        self.voted_validators.insert(dedup_key);
        let target_map = if vote.round == 2 {
            &mut self.r2_votes
        } else {
            &mut self.votes
        };
        target_map
            .entry(vote.candidate_hash)
            .or_default()
            .insert(voter_key);

        let count = self.voted_validators.len();
        debug!(
            "vote received from validator, tally: {} total recorded",
            count
        );
        Ok(true)
    }

    /// Return current R1 vote counts per candidate hash.
    ///
    /// Used by voting strategies (e.g. FollowMajority) to observe the
    /// emerging consensus before casting their own vote.
    pub fn current_tallies(&self) -> HashMap<Hash256, usize> {
        self.votes
            .iter()
            .map(|(hash, peers)| (*hash, peers.len()))
            .collect()
    }

    /// Return current R2 (confirmation) vote counts per candidate hash.
    pub fn r2_tallies(&self) -> HashMap<Hash256, usize> {
        self.r2_votes
            .iter()
            .map(|(hash, peers)| (*hash, peers.len()))
            .collect()
    }

    /// Compute the majority outcome considering both R1 and R2 votes.
    ///
    /// - GAP-C6: If `total_voters < config.min_peers_for_consensus` → Indeterminate.
    /// - P1.2: If R2 has a Strong majority, that wins (confirmation override).
    /// - Otherwise use R1 tallies:
    ///   - Tier 1: leader > 50% → Adopt(Strong).
    ///   - Tier 2: leader ≥ ceil(total_voters / divisor) → Adopt(Plurality).
    /// - Tiebreaker: lower candidate_hash wins (lexicographic).
    /// - Otherwise → Indeterminate.
    ///
    /// C-004: `total_voters` should be the validator set size (not the peer count).
    pub fn compute_majority(
        &self,
        total_voters: usize,
        config: &ConsensusConfig,
    ) -> MigrationResult {
        // GAP-C6: Minimum voter check
        if total_voters < config.min_peers_for_consensus {
            return MigrationResult::Indeterminate;
        }

        // P1.2: Check R2 confirmation votes first — if R2 has a Strong majority, use it.
        if !self.r2_votes.is_empty() {
            if let Some(r2_result) = self.check_r2_override(total_voters) {
                info!("R2 confirmation override: {:?}", r2_result);
                return r2_result;
            }
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
        if leader_count * 2 > total_voters {
            info!(
                "vote tally complete: winner = {}, strength = Strong, votes = {}/{}",
                winner_hash, leader_count, total_voters
            );
            return MigrationResult::Adopt {
                candidate_hash: winner_hash,
                strength: ConsensusStrength::Strong,
            };
        }

        // Tier 2: Plurality floor (≥ ceil(total / divisor))
        // P0.1: Use ceiling division to ensure ≥33% for small validator sets.
        let divisor = config.plurality_floor_divisor as usize;
        let floor = total_voters.div_ceil(divisor);
        if leader_count >= floor.max(1) {
            info!(
                "vote tally complete: winner = {}, strength = Plurality, votes = {}/{}",
                winner_hash, leader_count, total_voters
            );
            return MigrationResult::Adopt {
                candidate_hash: winner_hash,
                strength: ConsensusStrength::Plurality,
            };
        }

        debug!(
            "vote tally indeterminate: leader has {}/{} votes, floor = {}",
            leader_count, total_voters, floor
        );
        MigrationResult::Indeterminate
    }

    /// P1.2: Check if R2 votes provide a Strong majority override.
    /// Returns `Some(MigrationResult::Adopt)` if R2 has >50%, `None` otherwise.
    fn check_r2_override(&self, total_voters: usize) -> Option<MigrationResult> {
        let mut candidates: Vec<(Hash256, usize)> = self
            .r2_votes
            .iter()
            .map(|(hash, voters)| (*hash, voters.len()))
            .collect();
        if candidates.is_empty() {
            return None;
        }
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let (leader_hash, leader_count) = candidates[0];

        // R2 override only if >50% (Strong majority)
        if leader_count * 2 > total_voters {
            // Handle ties
            let tied: Vec<_> = candidates
                .iter()
                .filter(|(_, count)| *count == leader_count)
                .collect();
            let winner = if tied.len() > 1 {
                tied.iter().map(|(h, _)| *h).min().unwrap()
            } else {
                leader_hash
            };
            Some(MigrationResult::Adopt {
                candidate_hash: winner,
                strength: ConsensusStrength::Strong,
            })
        } else {
            None
        }
    }

    /// Total number of unique validator+round vote entries.
    pub fn total_votes(&self) -> usize {
        self.voted_validators.len()
    }

    /// Return deduplicated wire-format public key bytes of all validators who cast
    /// at least one vote (R1 or R2) in the current cycle. Used by reputation scoring.
    pub fn voter_wire_keys(&self) -> Vec<Vec<u8>> {
        let mut keys: HashSet<Vec<u8>> = HashSet::new();
        for (wire, _round) in &self.voted_validators {
            keys.insert(wire.clone());
        }
        keys.into_iter().collect()
    }

    /// Clear all votes for a new cycle.
    ///
    /// Optionally set the new cycle number via `set_current_cycle()` after clearing.
    pub fn clear(&mut self) {
        self.votes.clear();
        self.r2_votes.clear();
        self.voted_validators.clear();
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
        // Same peer_id, different vote object → rejected (different keys but we test dedup)
        let (vote2, _) = make_vote(0, candidate);
        // Different validator key = accepted (P0.2: dedup is by pubkey not peer_id)
        assert!(mgr.record_vote(b"peer1", &vote2).unwrap());
        assert_eq!(mgr.total_votes(), 2);
    }

    // P0.2: Same validator key via different peer connections → duplicate
    #[test]
    fn p02_same_validator_key_duplicate_rejected() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let vote1 = PorVote::sign(0, candidate, &priv_key, pub_key.clone()).unwrap();
        let vote2 = PorVote::sign(0, candidate, &priv_key, pub_key).unwrap();
        // Same validator key from different peer_ids → second is rejected
        assert!(mgr.record_vote(b"peer1", &vote1).unwrap());
        assert!(!mgr.record_vote(b"peer2", &vote2).unwrap());
        assert_eq!(mgr.total_votes(), 1);
    }

    #[test]
    fn gap_c6_insufficient_peers_indeterminate() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (vote, _) = make_vote(0, candidate);
        mgr.record_vote(b"peer1", &vote).unwrap();
        // GAP-C6: min_peers_for_consensus gate still enforced when configured above default.
        // Use explicit config with min_peers=3; total_peers=2 < 3 → Indeterminate.
        let config = ConsensusConfig {
            min_peers_for_consensus: 3,
            ..ConsensusConfig::default()
        };
        assert_eq!(
            mgr.compute_majority(2, &config),
            MigrationResult::Indeterminate
        );
    }

    #[test]
    fn gap_c6_single_validator_default_config_can_commit() {
        // With default min_peers_for_consensus=1, a sole validator can finalize blocks.
        // 1 voter / 1 total → plurality floor = ceil(1/3) = 1 → Adopt.
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (vote, _) = make_vote(0, candidate);
        mgr.record_vote(b"peer1", &vote).unwrap();
        let result = mgr.compute_majority(1, &default_config());
        assert!(
            matches!(result, MigrationResult::Adopt { .. }),
            "1 validator should be able to commit with default config, got {result:?}"
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
        let msg1 = PorVote::signing_payload(5, candidate, 1);
        let msg2 = PorVote::signing_payload(5, candidate, 1);
        assert_eq!(msg1, msg2);
        // Different rounds produce different payloads
        let msg3 = PorVote::signing_payload(5, candidate, 2);
        assert_ne!(
            msg1, msg3,
            "different rounds should produce different payloads"
        );
    }

    // P0.1: Ceiling division ensures small validator sets meet ≥33% threshold
    #[test]
    fn plurality_floor_ceiling_division_small_sets() {
        let config = default_config(); // divisor = 3

        // 5 voters: ceil(5/3) = 2 (40%), not floor(5/3) = 1 (20%)
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (v1, _) = make_vote(0, candidate);
        mgr.record_vote(b"p1", &v1).unwrap();
        // 1 vote out of 5: floor would give Plurality (1 >= 1), ceil gives Indeterminate (1 < 2)
        let result = mgr.compute_majority(5, &config);
        assert_eq!(
            result,
            MigrationResult::Indeterminate,
            "1/5 should be Indeterminate with ceil(5/3)=2 floor"
        );

        // 2 votes out of 5: should pass ceiling floor of 2
        let (v2, _) = make_vote(0, candidate);
        mgr.record_vote(b"p2", &v2).unwrap();
        let result = mgr.compute_majority(5, &config);
        assert_eq!(
            result,
            MigrationResult::Adopt {
                candidate_hash: candidate,
                strength: ConsensusStrength::Plurality,
            }
        );

        // 4 voters: ceil(4/3) = 2 (50%)
        let mut mgr2 = VoteManager::new();
        let (v3, _) = make_vote(0, candidate);
        mgr2.record_vote(b"p1", &v3).unwrap();
        let result = mgr2.compute_majority(4, &config);
        assert_eq!(
            result,
            MigrationResult::Indeterminate,
            "1/4 should be Indeterminate with ceil(4/3)=2 floor"
        );

        // 3 voters: ceil(3/3) = 1 (33%)
        let mut mgr3 = VoteManager::new();
        let (v4, _) = make_vote(0, candidate);
        mgr3.record_vote(b"p1", &v4).unwrap();
        let result = mgr3.compute_majority(3, &config);
        assert_eq!(
            result,
            MigrationResult::Adopt {
                candidate_hash: candidate,
                strength: ConsensusStrength::Plurality,
            },
            "1/3 should pass with ceil(3/3)=1 floor"
        );

        // 7 voters: ceil(7/3) = 3 (43%)
        let mut mgr4 = VoteManager::new();
        for i in 0..2u8 {
            let (v, _) = make_vote(0, candidate);
            mgr4.record_vote(&[i], &v).unwrap();
        }
        let result = mgr4.compute_majority(7, &config);
        assert_eq!(
            result,
            MigrationResult::Indeterminate,
            "2/7 should be Indeterminate with ceil(7/3)=3 floor"
        );
    }

    // P1.2: R2 votes recorded separately
    #[test]
    fn r2_votes_separate_from_r1() {
        let mut mgr = VoteManager::new();
        let candidate = hash_n(1);
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();

        // R1 vote
        let v1 = PorVote::sign_round(0, candidate, 1, &priv_key, pub_key.clone()).unwrap();
        assert!(mgr.record_vote(b"p1", &v1).unwrap());

        // Same validator, R2 vote → should be accepted (different round)
        let v2 = PorVote::sign_round(0, candidate, 2, &priv_key, pub_key).unwrap();
        assert!(mgr.record_vote(b"p1", &v2).unwrap());

        assert_eq!(mgr.total_votes(), 2);
        assert_eq!(mgr.current_tallies().get(&candidate), Some(&1));
        assert_eq!(mgr.r2_tallies().get(&candidate), Some(&1));
    }

    // P1.2: R2 Strong majority overrides R1
    #[test]
    fn r2_strong_majority_overrides() {
        let mut mgr = VoteManager::new();
        let a = hash_n(1);
        let b = hash_n(2);

        // R1: 2 votes for A, 1 for B (out of 5 voters)
        for i in 0..2u8 {
            let (v, _) = make_vote(0, a);
            mgr.record_vote(&[i], &v).unwrap();
        }
        let (vb, _) = make_vote(0, b);
        mgr.record_vote(&[10], &vb).unwrap();

        // R2: 3 votes for A (>50% of 5) → Strong override
        for i in 0..3u8 {
            let (sk, _) = ed25519::generate_keypair();
            let priv_key = NoblePrivateKey::Ed25519(sk);
            let pub_key = priv_key.public_key();
            let v = PorVote::sign_round(0, a, 2, &priv_key, pub_key).unwrap();
            mgr.record_vote(&[20 + i], &v).unwrap();
        }

        let result = mgr.compute_majority(5, &default_config());
        assert_eq!(
            result,
            MigrationResult::Adopt {
                candidate_hash: a,
                strength: ConsensusStrength::Strong,
            },
            "R2 Strong majority should win"
        );
    }

    // P1.2: R2 without Strong majority falls back to R1
    #[test]
    fn r2_weak_falls_back_to_r1() {
        let mut mgr = VoteManager::new();
        let a = hash_n(1);

        // R1: 3 votes for A (>50% of 5 → Strong)
        for i in 0..3u8 {
            let (v, _) = make_vote(0, a);
            mgr.record_vote(&[i], &v).unwrap();
        }

        // R2: 1 vote for A (not >50%) → no override, falls through to R1
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        let v = PorVote::sign_round(0, a, 2, &priv_key, pub_key).unwrap();
        mgr.record_vote(&[20], &v).unwrap();

        let result = mgr.compute_majority(5, &default_config());
        assert_eq!(
            result,
            MigrationResult::Adopt {
                candidate_hash: a,
                strength: ConsensusStrength::Strong,
            },
            "R1 Strong should still win when R2 is weak"
        );
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
