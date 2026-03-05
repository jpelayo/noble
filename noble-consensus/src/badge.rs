// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Presence Badge system — binary vote eligibility earned by sustained network presence.
//!
//! Badges are granted/revoked by on-chain consensus votes (TX_TYPE 0x03/0x04/0x05).
//! Local suspension is a temporary protective measure broadcast via GossipSub.

use serde::{Deserialize, Serialize};

/// Status of a vote badge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BadgeStatus {
    /// Badge holder is active and eligible to vote.
    Active,
    /// Badge temporarily suspended (local decision, not on-chain).
    Suspended,
    /// Badge permanently revoked by on-chain vote.
    Revoked,
}

/// A vote badge record stored in the `vote_badges` column family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteBadge {
    /// Current status of the badge.
    pub status: BadgeStatus,
    /// Block height when the badge was granted.
    pub granted_at_height: u64,
    /// Cycle number when the badge was granted.
    pub granted_at_cycle: u64,
    /// Wire bytes of the proposer who nominated this badge-holder.
    pub proposed_by: Vec<u8>,
    /// Last time this peer was seen active (unix timestamp).
    pub last_seen: u64,
    /// Unix timestamp when locally suspended (None = not suspended).
    pub suspended_at: Option<u64>,
    /// Number of peers that reported suspension of this badge-holder.
    pub suspension_reports: u32,
}

impl VoteBadge {
    /// Create a new active badge.
    pub fn new(height: u64, cycle: u64, proposed_by: Vec<u8>, now: u64) -> Self {
        Self {
            status: BadgeStatus::Active,
            granted_at_height: height,
            granted_at_cycle: cycle,
            proposed_by,
            last_seen: now,
            suspended_at: None,
            suspension_reports: 0,
        }
    }

    /// Check if the badge is currently eligible for voting.
    pub fn is_eligible(&self) -> bool {
        self.status == BadgeStatus::Active
    }

    /// Locally suspend this badge.
    pub fn suspend(&mut self, now: u64) {
        if self.status == BadgeStatus::Active {
            self.status = BadgeStatus::Suspended;
            self.suspended_at = Some(now);
        }
    }

    /// Recover from suspension (peer came back online).
    pub fn recover(&mut self) {
        if self.status == BadgeStatus::Suspended {
            self.status = BadgeStatus::Active;
            self.suspended_at = None;
            self.suspension_reports = 0;
        }
    }

    /// Permanently revoke (on-chain decision).
    pub fn revoke(&mut self) {
        self.status = BadgeStatus::Revoked;
    }

    /// Update last-seen timestamp.
    pub fn touch(&mut self, now: u64) {
        self.last_seen = now;
    }
}

/// Reason for a badge revocation proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Submitted duplicate block proposals in the same cycle.
    DuplicateProposal,
    /// Violated protocol rules (e.g., invalid messages).
    ProtocolAbuse,
    /// Extended absence beyond suspension threshold.
    ExtendedAbsence,
    /// Node identity misrepresentation (false name, false org_type, impersonation).
    Misrepresentation,
    /// Other reason (free-text).
    Other,
}

/// Reason for a local suspension notice broadcast.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuspensionReason {
    /// Submitted conflicting block proposals.
    DuplicateProposal,
    /// Violated protocol rules.
    ProtocolViolation,
    /// Flooded the network with transactions.
    TxFlood,
    /// Extended absence from the network.
    Absence {
        /// Unix timestamp when last activity was observed.
        last_seen: u64,
    },
}

/// A suspension notice broadcast via GossipSub.
///
/// Local suspension is temporary and off-chain, but communicated to the network
/// so other nodes can independently verify and also stop counting the suspect's votes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspensionNotice {
    /// Wire bytes of the target being suspended.
    pub target_pubkey: Vec<u8>,
    /// Wire bytes of the reporter (must hold an active badge).
    pub reporter_pubkey: Vec<u8>,
    /// Reason for suspension.
    pub reason: SuspensionReason,
    /// Optional serialized proof (e.g., two conflicting block headers).
    pub evidence: Option<Vec<u8>>,
    /// Unix timestamp of the report.
    pub timestamp: u64,
    /// Signature by the reporter's identity key.
    pub reporter_signature: Vec<u8>,
}

/// Type of badge proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BadgeProposalType {
    /// Grant a badge to a new validator.
    Grant,
    /// Revoke an existing badge.
    Revoke,
}

/// Number of cycles a proposal stays open for voting.
pub const BADGE_VOTE_WINDOW_CYCLES: u64 = 10;

/// A badge proposal (grant or revoke) tracked through its lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeProposal {
    /// Whether this is a grant or revoke proposal.
    pub proposal_type: BadgeProposalType,
    /// Wire bytes of the target pubkey.
    pub target_pubkey: Vec<u8>,
    /// Wire bytes of the proposer.
    pub proposer_pubkey: Vec<u8>,
    /// Reason for revocation (only for Revoke proposals).
    pub reason: Option<RevocationReason>,
    /// Cycle when the proposal was created.
    pub created_at_cycle: u64,
    /// Cycle when voting closes.
    pub expires_at_cycle: u64,
    /// Pubkeys (wire bytes) that voted yes.
    pub votes_for: Vec<Vec<u8>>,
    /// Pubkeys (wire bytes) that voted no.
    pub votes_against: Vec<Vec<u8>>,
    /// Status: "active", "passed", "rejected", "expired".
    pub status: String,
}

impl BadgeProposal {
    /// Create a new active proposal.
    pub fn new(
        proposal_type: BadgeProposalType,
        target_pubkey: Vec<u8>,
        proposer_pubkey: Vec<u8>,
        reason: Option<RevocationReason>,
        current_cycle: u64,
    ) -> Self {
        Self {
            proposal_type,
            target_pubkey,
            proposer_pubkey,
            reason,
            created_at_cycle: current_cycle,
            expires_at_cycle: current_cycle + BADGE_VOTE_WINDOW_CYCLES,
            votes_for: Vec::new(),
            votes_against: Vec::new(),
            status: "active".to_string(),
        }
    }

    /// Record a vote. Returns false if voter already voted.
    pub fn record_vote(&mut self, voter_pubkey: Vec<u8>, approve: bool) -> bool {
        if self.votes_for.contains(&voter_pubkey) || self.votes_against.contains(&voter_pubkey) {
            return false;
        }
        if approve {
            self.votes_for.push(voter_pubkey);
        } else {
            self.votes_against.push(voter_pubkey);
        }
        true
    }

    /// Check if a voter has already voted.
    pub fn has_voted(&self, voter_pubkey: &[u8]) -> bool {
        self.votes_for.iter().any(|v| v == voter_pubkey)
            || self.votes_against.iter().any(|v| v == voter_pubkey)
    }

    /// Tally votes and determine outcome.
    /// Returns true if the proposal passes (simple majority of `total_eligible`).
    pub fn passes(&self, total_eligible: usize) -> bool {
        if total_eligible == 0 {
            return false;
        }
        self.votes_for.len() > total_eligible / 2
    }
}

/// Metadata for a badge proposal transaction (TX_TYPE 0x03).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeProposalMeta {
    /// 33-byte wire pubkey of the target.
    pub target_pubkey: Vec<u8>,
    /// 0x01 = grant, 0x02 = revoke.
    pub proposal_type: u8,
    /// RevocationReason discriminant (revoke only).
    pub reason: Option<u8>,
}

/// Metadata for a badge vote transaction (TX_TYPE 0x04).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeVoteMeta {
    /// Hash of the proposal transaction.
    pub proposal_hash: Vec<u8>,
    /// True = approve, false = reject.
    pub vote: bool,
}

/// Proposal type byte constants.
pub const PROPOSAL_TYPE_GRANT: u8 = 0x01;
pub const PROPOSAL_TYPE_REVOKE: u8 = 0x02;

/// In-memory badge store for the consensus engine.
///
/// Wraps a `HashMap` of pubkey wire bytes → VoteBadge.
/// In production, this is backed by the `vote_badges` CF in RocksDB.
#[derive(Default)]
pub struct BadgeStore {
    badges: std::collections::HashMap<Vec<u8>, VoteBadge>,
}

impl BadgeStore {
    /// Create an empty badge store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a badge by pubkey wire bytes.
    pub fn get_badge(&self, pubkey_wire: &[u8]) -> Option<&VoteBadge> {
        self.badges.get(pubkey_wire)
    }

    /// Get a mutable badge reference.
    pub fn get_badge_mut(&mut self, pubkey_wire: &[u8]) -> Option<&mut VoteBadge> {
        self.badges.get_mut(pubkey_wire)
    }

    /// Set (insert or update) a badge.
    pub fn set_badge(&mut self, pubkey_wire: Vec<u8>, badge: VoteBadge) {
        self.badges.insert(pubkey_wire, badge);
    }

    /// List all active badges.
    pub fn list_active_badges(&self) -> Vec<(&Vec<u8>, &VoteBadge)> {
        self.badges
            .iter()
            .filter(|(_, b)| b.status == BadgeStatus::Active)
            .collect()
    }

    /// Count active badges.
    pub fn count_active(&self) -> usize {
        self.badges
            .values()
            .filter(|b| b.status == BadgeStatus::Active)
            .count()
    }

    /// Check if a pubkey holds an active badge.
    pub fn is_active(&self, pubkey_wire: &[u8]) -> bool {
        self.badges
            .get(pubkey_wire)
            .is_some_and(|b| b.status == BadgeStatus::Active)
    }

    /// Check if a pubkey holds any badge (active, suspended, or revoked).
    pub fn has_badge(&self, pubkey_wire: &[u8]) -> bool {
        self.badges.contains_key(pubkey_wire)
    }

    /// Total badges (all statuses).
    pub fn len(&self) -> usize {
        self.badges.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.badges.is_empty()
    }

    /// Remove a badge by pubkey wire bytes.
    pub fn remove_badge(&mut self, pubkey_wire: &[u8]) {
        self.badges.remove(pubkey_wire);
    }

    /// List all badges (all statuses).
    pub fn list_all(&self) -> Vec<(&Vec<u8>, &VoteBadge)> {
        self.badges.iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_codec::NobleCbor;

    fn make_badge(now: u64) -> VoteBadge {
        VoteBadge::new(1, 0, vec![0xAA; 32], now)
    }

    #[test]
    fn new_badge_is_active() {
        let badge = make_badge(1_700_000_000);
        assert_eq!(badge.status, BadgeStatus::Active);
        assert!(badge.is_eligible());
    }

    #[test]
    fn suspend_and_recover() {
        let mut badge = make_badge(1_700_000_000);
        badge.suspend(1_700_100_000);
        assert_eq!(badge.status, BadgeStatus::Suspended);
        assert!(!badge.is_eligible());
        assert!(badge.suspended_at.is_some());

        badge.recover();
        assert_eq!(badge.status, BadgeStatus::Active);
        assert!(badge.is_eligible());
        assert!(badge.suspended_at.is_none());
    }

    #[test]
    fn revoked_badge_not_eligible() {
        let mut badge = make_badge(1_700_000_000);
        badge.revoke();
        assert_eq!(badge.status, BadgeStatus::Revoked);
        assert!(!badge.is_eligible());
    }

    #[test]
    fn revoked_badge_cannot_recover() {
        let mut badge = make_badge(1_700_000_000);
        badge.revoke();
        badge.recover(); // should be a no-op since only Suspended can recover
        assert_eq!(badge.status, BadgeStatus::Revoked);
    }

    #[test]
    fn badge_store_operations() {
        let mut store = BadgeStore::new();
        let key = vec![0x01; 32];
        let badge = make_badge(1_700_000_000);

        store.set_badge(key.clone(), badge);
        assert_eq!(store.len(), 1);
        assert!(store.is_active(&key));
        assert_eq!(store.count_active(), 1);

        // Suspend
        store.get_badge_mut(&key).unwrap().suspend(1_700_100_000);
        assert!(!store.is_active(&key));
        assert_eq!(store.count_active(), 0);
        assert!(store.has_badge(&key));
    }

    #[test]
    fn badge_store_list_active() {
        let mut store = BadgeStore::new();
        let k1 = vec![0x01; 32];
        let k2 = vec![0x02; 32];
        let k3 = vec![0x03; 32];

        store.set_badge(k1.clone(), make_badge(100));
        store.set_badge(k2.clone(), make_badge(100));
        store.set_badge(k3.clone(), make_badge(100));

        store.get_badge_mut(&k2).unwrap().suspend(200);
        store.get_badge_mut(&k3).unwrap().revoke();

        let active = store.list_active_badges();
        assert_eq!(active.len(), 1);
        assert_eq!(*active[0].0, k1);
    }

    #[test]
    fn bootstrap_mode_allows_presence_only() {
        // During bootstrap (first 60 days), peers with minimum presence can vote
        // without a formal badge. This is checked in the engine, not here,
        // but we verify the constants exist.
        assert!(noble_core::BOOTSTRAP_MODE_CYCLES > 0);
        assert!(noble_core::BADGE_MIN_PRESENCE_SECS > 0);
    }

    #[test]
    fn suspension_notice_serialization() {
        let notice = SuspensionNotice {
            target_pubkey: vec![0x01; 32],
            reporter_pubkey: vec![0x02; 32],
            reason: SuspensionReason::DuplicateProposal,
            evidence: Some(vec![0xFF; 64]),
            timestamp: 1_700_000_000,
            reporter_signature: vec![0xAA; 64],
        };
        let bytes = noble_codec::to_canonical_cbor(&notice).unwrap();
        let decoded = SuspensionNotice::from_cbor(&bytes).unwrap();
        assert_eq!(decoded.target_pubkey, notice.target_pubkey);
        assert_eq!(decoded.reporter_pubkey, notice.reporter_pubkey);
        assert_eq!(decoded.reason, SuspensionReason::DuplicateProposal);
    }
}
