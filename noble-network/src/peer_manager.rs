// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Peer reputation management, ban scoring, and connection limits.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use noble_core::NodeAnnounce;

use crate::config::NetworkConfig;

/// Direction of a peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Categories of misbehavior and their associated ban score penalties.
///
/// Ban scoring table (from architecture-design.md):
/// - InvalidBlock: 50
/// - InvalidTransaction: 20
/// - ProtocolViolation: 30
/// - DuplicateProposal: 100 (instant ban)
/// - ExcessiveConnections: 25
/// - Unresponsive: 10
/// - InvalidVote: 20 (GAP-M6: standardized to 20)
/// - InvalidAnnounce: 15 (low — metadata is self-declared)
/// - TxFlood: 25 (sustained tx relay rate limit violation)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehavior {
    InvalidBlock,
    InvalidTransaction,
    ProtocolViolation,
    DuplicateProposal,
    ExcessiveConnections,
    Unresponsive,
    InvalidVote,
    InvalidAnnounce,
    TxFlood,
}

impl Misbehavior {
    /// Returns the ban score penalty for this misbehavior.
    pub fn penalty(self) -> u32 {
        match self {
            Self::InvalidBlock => 50,
            Self::InvalidTransaction => 20,
            Self::ProtocolViolation => 30,
            Self::DuplicateProposal => 100,
            Self::ExcessiveConnections => 25,
            Self::Unresponsive => 10,
            Self::InvalidVote => 20,
            Self::InvalidAnnounce => 15,
            Self::TxFlood => 25,
        }
    }
}

/// State tracked for each connected peer.
#[derive(Debug, Clone)]
pub struct PeerState {
    pub direction: Direction,
    pub ban_score: u32,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub chain_tip: Option<(u64, [u8; 32])>,
    pub latency: Option<Duration>,
    pub announce: Option<Box<NodeAnnounce>>,
    /// Remote multiaddr string (set on connect or identify).
    pub addr: Option<String>,
}

/// Manages connected peers, enforces connection limits, and tracks ban scores.
pub struct PeerManager {
    peers: HashMap<PeerId, PeerState>,
    banned: HashMap<PeerId, Instant>,
    max_outbound: usize,
    max_inbound: usize,
    ban_threshold: u32,
    ban_duration: Duration,
}

impl PeerManager {
    /// Create a new `PeerManager` from the given configuration.
    pub fn new(config: &NetworkConfig) -> Self {
        Self {
            peers: HashMap::new(),
            banned: HashMap::new(),
            max_outbound: config.max_outbound,
            max_inbound: config.max_inbound,
            ban_threshold: config.ban_threshold,
            ban_duration: Duration::from_secs(config.ban_duration_secs),
        }
    }

    /// Handle a new peer connection. Returns `true` if accepted, `false` if rejected
    /// (due to connection limits or ban).
    pub fn on_connected(&mut self, peer_id: PeerId, direction: Direction) -> bool {
        if self.is_banned(&peer_id) {
            return false;
        }

        let (current, max) = match direction {
            Direction::Inbound => (self.inbound_count(), self.max_inbound),
            Direction::Outbound => (self.outbound_count(), self.max_outbound),
        };

        if current >= max {
            return false;
        }

        let now = Instant::now();
        self.peers.insert(
            peer_id,
            PeerState {
                direction,
                ban_score: 0,
                connected_at: now,
                last_seen: now,
                chain_tip: None,
                latency: None,
                announce: None,
                addr: None,
            },
        );
        true
    }

    /// Handle a peer disconnection.
    pub fn on_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Record a misbehavior for a peer. Returns `true` if the peer's cumulative
    /// score has reached the ban threshold and the peer should be disconnected.
    pub fn record_misbehavior(&mut self, peer_id: &PeerId, misbehavior: Misbehavior) -> bool {
        let penalty = misbehavior.penalty();

        if let Some(state) = self.peers.get_mut(peer_id) {
            state.ban_score = state.ban_score.saturating_add(penalty);
            if state.ban_score >= self.ban_threshold {
                self.banned.insert(*peer_id, Instant::now());
                self.peers.remove(peer_id);
                return true;
            }
        }
        false
    }

    /// Update a peer's reported chain tip.
    pub fn update_chain_tip(&mut self, peer_id: &PeerId, height: u64, hash: [u8; 32]) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.chain_tip = Some((height, hash));
            state.last_seen = Instant::now();
        }
    }

    /// Update a peer's measured latency.
    pub fn update_latency(&mut self, peer_id: &PeerId, latency: Duration) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.latency = Some(latency);
        }
    }

    /// Store a node identity announcement for a peer.
    pub fn update_announce(&mut self, peer_id: &PeerId, announce: NodeAnnounce) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.announce = Some(Box::new(announce));
        }
    }

    /// Retrieve the cached node announce for a peer.
    pub fn get_announce(&self, peer_id: &PeerId) -> Option<&NodeAnnounce> {
        self.peers.get(peer_id)?.announce.as_deref()
    }

    /// Update a peer's remote address.
    pub fn update_addr(&mut self, peer_id: &PeerId, addr: String) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.addr = Some(addr);
        }
    }

    /// Return the addresses of all connected peers that have a known address.
    pub fn connected_addrs(&self) -> Vec<String> {
        self.peers.values().filter_map(|s| s.addr.clone()).collect()
    }

    /// Return outbound peer addresses.
    pub fn outbound_addrs(&self) -> Vec<String> {
        self.peers
            .values()
            .filter(|s| s.direction == Direction::Outbound)
            .filter_map(|s| s.addr.clone())
            .collect()
    }

    /// Returns peers that are ahead of `our_height`, sorted by height (descending).
    pub fn best_peers(&self, our_height: u64) -> Vec<(PeerId, u64)> {
        let mut ahead: Vec<(PeerId, u64)> = self
            .peers
            .iter()
            .filter_map(|(id, state)| {
                state
                    .chain_tip
                    .filter(|(h, _)| *h > our_height)
                    .map(|(h, _)| (*id, h))
            })
            .collect();
        ahead.sort_by(|a, b| b.1.cmp(&a.1));
        ahead
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(banned_at) = self.banned.get(peer_id) {
            banned_at.elapsed() < self.ban_duration
        } else {
            false
        }
    }

    /// Returns `(inbound_count, outbound_count)`.
    pub fn peer_count(&self) -> (usize, usize) {
        (self.inbound_count(), self.outbound_count())
    }

    /// Total number of connected peers.
    pub fn total_peers(&self) -> usize {
        self.peers.len()
    }

    /// Whether we need more outbound connections.
    pub fn needs_outbound(&self) -> bool {
        self.outbound_count() < self.max_outbound
    }

    /// Get the state of a specific peer (if connected).
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerState> {
        self.peers.get(peer_id)
    }

    /// Remove expired bans. Should be called periodically.
    pub fn cleanup_expired_bans(&mut self) -> usize {
        let before = self.banned.len();
        self.banned
            .retain(|_, banned_at| banned_at.elapsed() < self.ban_duration);
        before - self.banned.len()
    }

    fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|s| s.direction == Direction::Inbound)
            .count()
    }

    fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|s| s.direction == Direction::Outbound)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> NetworkConfig {
        NetworkConfig {
            max_outbound: 2,
            max_inbound: 3,
            ban_threshold: 100,
            ban_duration_secs: 86_400,
            ..NetworkConfig::testnet()
        }
    }

    fn random_peer() -> PeerId {
        PeerId::random()
    }

    #[test]
    fn accept_peer_within_limits() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        assert!(pm.on_connected(p, Direction::Outbound));
        assert_eq!(pm.total_peers(), 1);
    }

    #[test]
    fn reject_peer_over_outbound_limit() {
        let mut pm = PeerManager::new(&test_config());
        assert!(pm.on_connected(random_peer(), Direction::Outbound));
        assert!(pm.on_connected(random_peer(), Direction::Outbound));
        // Third outbound should be rejected (max=2).
        assert!(!pm.on_connected(random_peer(), Direction::Outbound));
    }

    #[test]
    fn reject_peer_over_inbound_limit() {
        let mut pm = PeerManager::new(&test_config());
        assert!(pm.on_connected(random_peer(), Direction::Inbound));
        assert!(pm.on_connected(random_peer(), Direction::Inbound));
        assert!(pm.on_connected(random_peer(), Direction::Inbound));
        // Fourth inbound should be rejected (max=3).
        assert!(!pm.on_connected(random_peer(), Direction::Inbound));
    }

    #[test]
    fn disconnect_removes_peer() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);
        assert_eq!(pm.total_peers(), 1);
        pm.on_disconnected(&p);
        assert_eq!(pm.total_peers(), 0);
    }

    #[test]
    fn misbehavior_accumulates_score() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // InvalidTransaction = 20, twice = 40, under threshold.
        assert!(!pm.record_misbehavior(&p, Misbehavior::InvalidTransaction));
        assert!(!pm.record_misbehavior(&p, Misbehavior::InvalidTransaction));
        assert_eq!(pm.get_peer(&p).unwrap().ban_score, 40);
    }

    #[test]
    fn misbehavior_triggers_ban_at_threshold() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // InvalidBlock(50) + InvalidBlock(50) = 100 = threshold.
        assert!(!pm.record_misbehavior(&p, Misbehavior::InvalidBlock));
        assert!(pm.record_misbehavior(&p, Misbehavior::InvalidBlock));

        assert!(pm.is_banned(&p));
        assert_eq!(pm.total_peers(), 0);
    }

    #[test]
    fn duplicate_proposal_instant_ban() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // DuplicateProposal = 100 = instant ban.
        assert!(pm.record_misbehavior(&p, Misbehavior::DuplicateProposal));
        assert!(pm.is_banned(&p));
    }

    #[test]
    fn banned_peer_rejected_on_connect() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);
        pm.record_misbehavior(&p, Misbehavior::DuplicateProposal);

        // Try to reconnect — should be rejected.
        assert!(!pm.on_connected(p, Direction::Inbound));
    }

    #[test]
    fn best_peers_returns_sorted() {
        let mut pm = PeerManager::new(&test_config());
        let p1 = random_peer();
        let p2 = random_peer();
        pm.on_connected(p1, Direction::Outbound);
        pm.on_connected(p2, Direction::Inbound);
        pm.update_chain_tip(&p1, 100, [1; 32]);
        pm.update_chain_tip(&p2, 200, [2; 32]);

        let best = pm.best_peers(50);
        assert_eq!(best.len(), 2);
        assert_eq!(best[0].1, 200); // p2 first (higher)
        assert_eq!(best[1].1, 100); // p1 second
    }

    #[test]
    fn best_peers_excludes_behind() {
        let mut pm = PeerManager::new(&test_config());
        let p1 = random_peer();
        pm.on_connected(p1, Direction::Outbound);
        pm.update_chain_tip(&p1, 50, [1; 32]);

        let best = pm.best_peers(100);
        assert!(best.is_empty());
    }

    #[test]
    fn needs_outbound() {
        let mut pm = PeerManager::new(&test_config());
        assert!(pm.needs_outbound());
        pm.on_connected(random_peer(), Direction::Outbound);
        assert!(pm.needs_outbound()); // 1 < 2
        pm.on_connected(random_peer(), Direction::Outbound);
        assert!(!pm.needs_outbound()); // 2 == 2
    }

    #[test]
    fn peer_count_by_direction() {
        let mut pm = PeerManager::new(&test_config());
        pm.on_connected(random_peer(), Direction::Inbound);
        pm.on_connected(random_peer(), Direction::Outbound);
        pm.on_connected(random_peer(), Direction::Inbound);
        let (inb, outb) = pm.peer_count();
        assert_eq!(inb, 2);
        assert_eq!(outb, 1);
    }

    #[test]
    fn misbehavior_penalties() {
        assert_eq!(Misbehavior::InvalidBlock.penalty(), 50);
        assert_eq!(Misbehavior::InvalidTransaction.penalty(), 20);
        assert_eq!(Misbehavior::ProtocolViolation.penalty(), 30);
        assert_eq!(Misbehavior::DuplicateProposal.penalty(), 100);
        assert_eq!(Misbehavior::ExcessiveConnections.penalty(), 25);
        assert_eq!(Misbehavior::Unresponsive.penalty(), 10);
        assert_eq!(Misbehavior::InvalidVote.penalty(), 20);
        assert_eq!(Misbehavior::InvalidAnnounce.penalty(), 15);
        assert_eq!(Misbehavior::TxFlood.penalty(), 25);
    }

    #[test]
    fn addr_tracking() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);
        assert!(pm.get_peer(&p).unwrap().addr.is_none());

        pm.update_addr(&p, "/ip4/1.2.3.4/tcp/9333".to_string());
        assert_eq!(
            pm.get_peer(&p).unwrap().addr.as_deref(),
            Some("/ip4/1.2.3.4/tcp/9333")
        );
    }

    #[test]
    fn connected_addrs_returns_known() {
        let mut pm = PeerManager::new(&test_config());
        let p1 = random_peer();
        let p2 = random_peer();
        pm.on_connected(p1, Direction::Outbound);
        pm.on_connected(p2, Direction::Inbound);
        pm.update_addr(&p1, "/ip4/1.2.3.4/tcp/9333".to_string());
        // p2 has no addr — should not appear.
        let addrs = pm.connected_addrs();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].contains("1.2.3.4"));
    }

    #[test]
    fn peer_state_stores_announce() {
        use noble_core::{NodeRole, OrgType};
        use noble_crypto::NoblePrivateKey;

        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // Initially no announce
        assert!(pm.get_announce(&p).is_none());

        // Create a signed announce
        let sk = NoblePrivateKey::Ed25519(vec![42u8; 32]);
        let pk = sk.public_key();
        let announce = NodeAnnounce::sign(
            pk,
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            1_700_000_000,
            &sk,
        )
        .unwrap();

        pm.update_announce(&p, announce.clone());
        let stored = pm.get_announce(&p).unwrap();
        assert_eq!(stored.node_name, "test");
    }
}
