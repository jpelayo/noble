// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Peer reputation management, ban scoring, and connection limits.

use std::collections::{HashMap, VecDeque};
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

/// Fixed categories for peer misbehavior (wire-stable IDs).
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
/// - EvidenceReceived: 100 (instant ban — network evidence of double proposal)
/// - Misrepresentation: 50 (false identity claims)
/// - ManualBan: 100 (operator-initiated via RPC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BanCategory {
    /// Invalid block proposal (failed validation rules B1-B12).
    InvalidBlock = 0x01,
    /// Invalid transaction relay (failed T1-T26).
    InvalidTransaction = 0x02,
    /// Protocol-level violation (chain_id mismatch, version mismatch, malformed wire message).
    ProtocolViolation = 0x03,
    /// Double block proposal in the same cycle (instant ban, slashable).
    DuplicateProposal = 0x04,
    /// Excessive connection attempts from the same subnet.
    ExcessiveConnections = 0x05,
    /// Peer failed to respond within timeout.
    Unresponsive = 0x06,
    /// Invalid consensus vote (wrong cycle, bad signature, non-validator).
    InvalidVote = 0x07,
    /// Invalid NodeAnnounce (bad signature, malformed identity fields).
    InvalidAnnounce = 0x08,
    /// Transaction relay rate limit exceeded.
    TxFlood = 0x09,
    /// Double-proposal evidence received and verified from the network.
    EvidenceReceived = 0x0A,
    /// Node identity misrepresentation (wrong name, false org_type claim, impersonation).
    Misrepresentation = 0x0B,
    /// Manual ban issued by the operator via RPC.
    ManualBan = 0x0C,
}

impl BanCategory {
    /// Returns the ban score penalty for this category.
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
            Self::EvidenceReceived => 100,
            Self::Misrepresentation => 50,
            Self::ManualBan => 100,
        }
    }

    /// Human-readable name for display in RPC/GUI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBlock => "invalid_block",
            Self::InvalidTransaction => "invalid_transaction",
            Self::ProtocolViolation => "protocol_violation",
            Self::DuplicateProposal => "duplicate_proposal",
            Self::ExcessiveConnections => "excessive_connections",
            Self::Unresponsive => "unresponsive",
            Self::InvalidVote => "invalid_vote",
            Self::InvalidAnnounce => "invalid_announce",
            Self::TxFlood => "tx_flood",
            Self::EvidenceReceived => "evidence_received",
            Self::Misrepresentation => "misrepresentation",
            Self::ManualBan => "manual_ban",
        }
    }
}

/// A ban reason combining a fixed category with a human-readable subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanReason {
    pub category: BanCategory,
    /// Free-text clarification (e.g. "block hash 0xab12… failed B3: merkle root mismatch").
    /// Capped at 256 chars. Empty string is valid.
    pub subject: String,
}

impl BanReason {
    /// Create a new ban reason, truncating subject to 256 chars.
    pub fn new(category: BanCategory, subject: impl Into<String>) -> Self {
        let mut subject = subject.into();
        subject.truncate(256);
        Self { category, subject }
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
    /// AUD-H2: Recent misbehavior events within the rate-limiting window.
    /// Each entry is (timestamp, penalty_points).
    pub misbehavior_window: VecDeque<(Instant, u32)>,
    /// AUD2-H5: Timestamp of the last misbehavior event (for ban score decay).
    pub last_misbehavior: Option<Instant>,
    /// Last ban reason (set when ban threshold reached, surfaced via RPC/GUI).
    pub last_ban_reason: Option<BanReason>,
    /// Clock offset in milliseconds (positive = peer ahead of us). `None` if not yet sampled.
    pub clock_offset_ms: Option<i64>,
}

/// Maximum length of a software version string in a NodeAnnounce.
const MAX_SOFTWARE_VERSION_LEN: usize = 32;

/// Parse a semver-style "major.minor.patch" string into a tuple.
/// Returns `None` if the format is invalid.
fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    Some((
        parts[0].parse().ok()?,
        parts[1].parse().ok()?,
        parts[2].parse().ok()?,
    ))
}

/// Compare two semver strings. Returns `true` if `a` is strictly greater than `b`.
/// Falls back to lexicographic comparison if either string is not valid semver.
fn is_semver_greater(a: &str, b: &str) -> bool {
    match (parse_semver(a), parse_semver(b)) {
        (Some(av), Some(bv)) => av > bv,
        _ => a > b,
    }
}

/// Validate a software version string: max 32 chars, only `[a-zA-Z0-9.\-]`.
pub fn validate_software_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_SOFTWARE_VERSION_LEN
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Maximum penalty points allowed within the rate-limit window (60 seconds).
const RATE_LIMIT_WINDOW_SECS: u64 = 60;
/// Maximum penalty points within the window before further accumulation is suppressed.
const RATE_LIMIT_WINDOW_MAX: u32 = 50;
/// Duration of mass-ban cooldown in seconds (5 minutes).
const MASS_BAN_COOLDOWN_SECS: u64 = 300;

/// Manages connected peers, enforces connection limits, and tracks ban scores.
pub struct PeerManager {
    peers: HashMap<PeerId, PeerState>,
    banned: HashMap<PeerId, Instant>,
    max_outbound: usize,
    max_inbound: usize,
    ban_threshold: u32,
    ban_duration: Duration,
    /// Highest software version seen across all peer announcements.
    max_software_version: String,
    /// AUD-L2: Total unique peers ever seen (connected at least once).
    total_ever_seen: usize,
    /// AUD-L2: Number of peers currently banned.
    banned_count: usize,
    /// AUD-L2: If mass-ban detected, cooldown pauses new bans until this instant.
    ban_cooldown: Option<Instant>,
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
            max_software_version: noble_core::SOFTWARE_VERSION.to_string(),
            total_ever_seen: 0,
            banned_count: 0,
            ban_cooldown: None,
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
        self.total_ever_seen += 1;
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
                misbehavior_window: VecDeque::new(),
                last_misbehavior: None,
                last_ban_reason: None,
                clock_offset_ms: None,
            },
        );
        tracing::info!(task = "peer_connect", peer_id = %peer_id, "peer connected");
        true
    }

    /// Handle a peer disconnection.
    pub fn on_disconnected(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
        tracing::info!(task = "peer_disconnect", peer_id = %peer_id, "peer disconnected");
    }

    /// Record a misbehavior for a peer. Returns `true` if the peer's cumulative
    /// score has reached the ban threshold and should be banned.
    ///
    /// Includes three hardening mechanisms:
    /// - **AUD-H2**: Rate-limits penalty accumulation to max 50 points per 60-second window.
    /// - **AUD2-H5**: Decays existing ban_score by 1 point per minute since last misbehavior.
    /// - **AUD-L2**: Detects mass-ban conditions and pauses banning during cooldown.
    pub fn record_misbehavior(&mut self, peer_id: &PeerId, reason: BanReason) -> bool {
        let penalty = reason.category.penalty();
        let now = Instant::now();

        if let Some(state) = self.peers.get_mut(peer_id) {
            // AUD2-H5: Decay existing ban_score by 1 point per minute since last misbehavior.
            if let Some(last) = state.last_misbehavior {
                let elapsed_minutes = last.elapsed().as_secs() / 60;
                state.ban_score = state.ban_score.saturating_sub(elapsed_minutes as u32);
            }

            // AUD-H2: Rate-limit window — drain old entries and check window total.
            let window_cutoff = now - Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
            state
                .misbehavior_window
                .retain(|(ts, _)| *ts > window_cutoff);
            let window_total: u32 = state.misbehavior_window.iter().map(|(_, p)| *p).sum();

            // Push the new event into the window regardless (for tracking).
            state.misbehavior_window.push_back((now, penalty));

            if window_total > RATE_LIMIT_WINDOW_MAX {
                tracing::warn!(
                    task = "peer_ban",
                    %peer_id,
                    window_total,
                    "rate-limit: penalty suppressed (>{}/{}s window)",
                    RATE_LIMIT_WINDOW_MAX,
                    RATE_LIMIT_WINDOW_SECS,
                );
                // Update last_misbehavior timestamp even if suppressed.
                state.last_misbehavior = Some(now);
                return false;
            }

            // Accumulate penalty to ban_score.
            state.ban_score = state.ban_score.saturating_add(penalty);
            state.last_misbehavior = Some(now);
            state.last_ban_reason = Some(reason);

            tracing::debug!(
                task = "peer_ban",
                "ban score updated for peer: +{} (total: {})",
                penalty,
                state.ban_score,
            );

            if state.ban_score >= self.ban_threshold {
                // AUD-L2: Check for mass-ban cooldown before banning.
                if let Some(cooldown_until) = self.ban_cooldown {
                    if now < cooldown_until {
                        tracing::warn!(
                            task = "peer_ban",
                            %peer_id,
                            "mass-ban cooldown active — ban suppressed",
                        );
                        return false;
                    }
                    // Cooldown expired — clear it.
                    self.ban_cooldown = None;
                }

                self.banned.insert(*peer_id, now);
                self.peers.remove(peer_id);
                self.banned_count += 1;

                // AUD-L2: Check mass-ban condition after banning.
                if self.check_mass_ban() {
                    self.ban_cooldown = Some(now + Duration::from_secs(MASS_BAN_COOLDOWN_SECS));
                }
                return true;
            }
        }
        false
    }

    /// AUD-L2: Check whether we've banned more than half of all peers ever seen.
    /// Returns `true` if a mass-ban condition is detected.
    pub fn check_mass_ban(&self) -> bool {
        if self.total_ever_seen == 0 {
            return false;
        }
        if self.banned_count > self.total_ever_seen / 2 {
            tracing::error!(
                task = "mass_ban",
                banned = self.banned_count,
                total_ever_seen = self.total_ever_seen,
                "MASS-BAN DETECTED: >50% of peers banned — activating cooldown",
            );
            return true;
        }
        false
    }

    /// Get the Unix timestamp at which a peer's ban expires (if banned).
    pub fn get_ban_expiry(&self, peer_id: &PeerId) -> Option<u64> {
        self.banned.get(peer_id).map(|banned_at| {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let elapsed = banned_at.elapsed().as_secs();
            now_unix + self.ban_duration.as_secs().saturating_sub(elapsed)
        })
    }

    /// Load persisted bans from storage at startup.
    ///
    /// `bans` is a list of (peer_id_bytes, banned_until_unix) from storage.
    /// Only non-expired bans are imported.
    pub fn load_persisted_bans(&mut self, bans: Vec<(Vec<u8>, u64)>) {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for (peer_bytes, banned_until) in bans {
            if banned_until > now_unix {
                if let Ok(peer_id) = PeerId::from_bytes(&peer_bytes) {
                    // Compute the Instant when this ban was placed.
                    let remaining_secs = banned_until - now_unix;
                    let ban_duration_secs = self.ban_duration.as_secs();
                    let elapsed_secs = ban_duration_secs.saturating_sub(remaining_secs);
                    let banned_at = Instant::now() - Duration::from_secs(elapsed_secs);
                    self.banned.insert(peer_id, banned_at);
                }
            }
        }
    }

    /// Get a peer's last known chain tip (height, hash), if any.
    pub fn get_chain_tip(&self, peer_id: &PeerId) -> Option<(u64, [u8; 32])> {
        self.peers.get(peer_id).and_then(|s| s.chain_tip)
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

    /// Update a peer's clock offset (milliseconds, positive = peer ahead).
    pub fn update_clock_offset(&mut self, peer_id: &PeerId, offset_ms: i64) {
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.clock_offset_ms = Some(offset_ms);
        }
    }

    /// Compute the median clock offset across all peers that have data.
    /// Returns `None` if fewer than 2 peers have clock offset samples.
    pub fn median_clock_offset_ms(&self) -> Option<i64> {
        let mut offsets: Vec<i64> = self
            .peers
            .values()
            .filter_map(|s| s.clock_offset_ms)
            .collect();
        if offsets.len() < 2 {
            return None;
        }
        offsets.sort_unstable();
        let mid = offsets.len() / 2;
        if offsets.len() % 2 == 0 {
            Some((offsets[mid - 1] + offsets[mid]) / 2)
        } else {
            Some(offsets[mid])
        }
    }

    /// Store a node identity announcement for a peer.
    /// Also updates the max software version seen across all peers.
    pub fn update_announce(&mut self, peer_id: &PeerId, announce: NodeAnnounce) {
        if is_semver_greater(&announce.software_version, &self.max_software_version) {
            self.max_software_version = announce.software_version.clone();
        }
        if let Some(state) = self.peers.get_mut(peer_id) {
            state.announce = Some(Box::new(announce));
        }
    }

    /// Returns the highest software version seen across all peer announcements.
    pub fn max_software_version_seen(&self) -> &str {
        &self.max_software_version
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

    /// Return inbound peer addresses.
    pub fn inbound_addrs(&self) -> Vec<String> {
        self.peers
            .values()
            .filter(|s| s.direction == Direction::Inbound)
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

    /// Unban a peer (operator RPC). Removes from both in-memory ban map and connected peer state.
    pub fn unban(&mut self, peer_id: &PeerId) {
        self.banned.remove(peer_id);
    }

    /// List all currently banned peers with metadata for the RPC response.
    pub fn list_banned_entries(&self) -> Vec<crate::messages::BannedPeerEntry> {
        let mut entries = Vec::new();
        for (pid, banned_at) in &self.banned {
            if banned_at.elapsed() >= self.ban_duration {
                continue; // expired
            }
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let remaining = self.ban_duration.as_secs().saturating_sub(banned_at.elapsed().as_secs());
            let banned_until = now_unix + remaining;

            // Try to get last ban reason from peer state (may be disconnected already)
            let (category, subject, score) = self.peers.get(pid).and_then(|s| {
                s.last_ban_reason.as_ref().map(|r| (r.category.as_str().to_string(), r.subject.clone(), s.ban_score))
            }).unwrap_or_else(|| ("manual_ban".to_string(), String::new(), 100));

            entries.push(crate::messages::BannedPeerEntry {
                peer_id_bytes: pid.to_bytes(),
                ban_score: score,
                banned_until,
                reason_category: category,
                reason_subject: subject,
            });
        }
        entries
    }

    /// Remove expired bans. Should be called periodically.
    pub fn cleanup_expired_bans(&mut self) -> usize {
        let before = self.banned.len();
        self.banned
            .retain(|_, banned_at| banned_at.elapsed() < self.ban_duration);
        let removed = before - self.banned.len();
        self.banned_count = self.banned_count.saturating_sub(removed);
        removed
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
        assert!(!pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidTransaction, "test")));
        assert!(!pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidTransaction, "test")));
        assert_eq!(pm.get_peer(&p).unwrap().ban_score, 40);
    }

    #[test]
    fn misbehavior_triggers_ban_at_threshold() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // InvalidBlock(50) + InvalidBlock(50) = 100 = threshold.
        assert!(!pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidBlock, "test")));
        assert!(pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidBlock, "test")));

        assert!(pm.is_banned(&p));
        assert_eq!(pm.total_peers(), 0);
    }

    #[test]
    fn duplicate_proposal_instant_ban() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // DuplicateProposal = 100 = instant ban.
        assert!(pm.record_misbehavior(&p, BanReason::new(BanCategory::DuplicateProposal, "test")));
        assert!(pm.is_banned(&p));
    }

    #[test]
    fn banned_peer_rejected_on_connect() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);
        pm.record_misbehavior(&p, BanReason::new(BanCategory::DuplicateProposal, "test"));

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
    fn ban_category_penalties() {
        assert_eq!(BanCategory::InvalidBlock.penalty(), 50);
        assert_eq!(BanCategory::InvalidTransaction.penalty(), 20);
        assert_eq!(BanCategory::ProtocolViolation.penalty(), 30);
        assert_eq!(BanCategory::DuplicateProposal.penalty(), 100);
        assert_eq!(BanCategory::ExcessiveConnections.penalty(), 25);
        assert_eq!(BanCategory::Unresponsive.penalty(), 10);
        assert_eq!(BanCategory::InvalidVote.penalty(), 20);
        assert_eq!(BanCategory::InvalidAnnounce.penalty(), 15);
        assert_eq!(BanCategory::TxFlood.penalty(), 25);
        assert_eq!(BanCategory::EvidenceReceived.penalty(), 100);
        assert_eq!(BanCategory::Misrepresentation.penalty(), 50);
        assert_eq!(BanCategory::ManualBan.penalty(), 100);
    }

    #[test]
    fn addr_tracking() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);
        assert!(pm.get_peer(&p).unwrap().addr.is_none());

        pm.update_addr(&p, "/ip4/1.2.3.4/tcp/8780".to_string());
        assert_eq!(
            pm.get_peer(&p).unwrap().addr.as_deref(),
            Some("/ip4/1.2.3.4/tcp/8780")
        );
    }

    #[test]
    fn connected_addrs_returns_known() {
        let mut pm = PeerManager::new(&test_config());
        let p1 = random_peer();
        let p2 = random_peer();
        pm.on_connected(p1, Direction::Outbound);
        pm.on_connected(p2, Direction::Inbound);
        pm.update_addr(&p1, "/ip4/1.2.3.4/tcp/8780".to_string());
        // p2 has no addr — should not appear.
        let addrs = pm.connected_addrs();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].contains("1.2.3.4"));
    }

    #[test]
    fn get_ban_expiry_returns_future_timestamp() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);
        pm.record_misbehavior(&p, BanReason::new(BanCategory::DuplicateProposal, "test"));

        let expiry = pm.get_ban_expiry(&p);
        assert!(expiry.is_some());
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Expiry should be roughly ban_duration_secs (~86400) in the future.
        assert!(expiry.unwrap() > now_unix);
    }

    #[test]
    fn load_persisted_bans_restores_bans() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        let peer_bytes = p.to_bytes().to_vec();

        // Future ban
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let banned_until = now_unix + 3600; // 1 hour from now

        pm.load_persisted_bans(vec![(peer_bytes, banned_until)]);
        assert!(pm.is_banned(&p));
    }

    #[test]
    fn load_persisted_bans_ignores_expired() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        let peer_bytes = p.to_bytes().to_vec();

        // Expired ban
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let banned_until = now_unix.saturating_sub(100); // 100s ago

        pm.load_persisted_bans(vec![(peer_bytes, banned_until)]);
        assert!(!pm.is_banned(&p));
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
            None,
            false,
            false,
            0,
            String::new(),
            1_700_000_000,
            &sk,
        )
        .unwrap();

        pm.update_announce(&p, announce.clone());
        let stored = pm.get_announce(&p).unwrap();
        assert_eq!(stored.node_name, "test");
    }

    #[test]
    fn max_software_version_starts_at_own() {
        let pm = PeerManager::new(&test_config());
        assert_eq!(pm.max_software_version_seen(), noble_core::SOFTWARE_VERSION);
    }

    #[test]
    fn max_software_version_updates_on_newer() {
        use noble_core::{NodeRole, OrgType};
        use noble_crypto::NoblePrivateKey;

        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        let sk = NoblePrivateKey::Ed25519(vec![42u8; 32]);
        let pk = sk.public_key();
        let mut announce = NodeAnnounce::sign(
            pk,
            "test".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            0,
            String::new(),
            1_700_000_000,
            &sk,
        )
        .unwrap();

        // Use a version that is always higher than SOFTWARE_VERSION.
        announce.software_version = "99.0.0".to_string();
        pm.update_announce(&p, announce);
        assert_eq!(pm.max_software_version_seen(), "99.0.0");
    }

    #[test]
    fn max_software_version_ignores_older() {
        use noble_core::{NodeRole, OrgType};
        use noble_crypto::NoblePrivateKey;

        let mut pm = PeerManager::new(&test_config());
        let p1 = random_peer();
        let p2 = random_peer();
        pm.on_connected(p1, Direction::Outbound);
        pm.on_connected(p2, Direction::Inbound);

        let sk = NoblePrivateKey::Ed25519(vec![42u8; 32]);
        let pk = sk.public_key();

        // First announce with a version always higher than SOFTWARE_VERSION.
        let mut a1 = NodeAnnounce::sign(
            pk.clone(),
            "n1".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            0,
            String::new(),
            1_700_000_000,
            &sk,
        )
        .unwrap();
        a1.software_version = "99.0.0".to_string();
        pm.update_announce(&p1, a1);

        // Second announce with an older version — should not downgrade the max.
        let mut a2 = NodeAnnounce::sign(
            pk,
            "n2".to_string(),
            OrgType::Individual,
            None,
            NodeRole::FullNode,
            None,
            None,
            None,
            None,
            false,
            false,
            0,
            String::new(),
            1_700_000_000,
            &sk,
        )
        .unwrap();
        a2.software_version = noble_core::SOFTWARE_VERSION.to_string();
        pm.update_announce(&p2, a2);

        assert_eq!(pm.max_software_version_seen(), "99.0.0");
    }

    #[test]
    fn semver_comparison_correct() {
        // Basic ordering
        assert!(is_semver_greater("0.2.0", "0.1.0"));
        assert!(is_semver_greater("1.0.0", "0.99.99"));
        assert!(is_semver_greater("0.10.0", "0.2.0")); // This would fail with lexicographic
        assert!(!is_semver_greater("0.1.0", "0.2.0"));
        assert!(!is_semver_greater("0.1.0", "0.1.0")); // Equal

        // Invalid semver falls back to string comparison
        assert!(is_semver_greater("b", "a"));
    }

    #[test]
    fn parse_semver_valid() {
        assert_eq!(parse_semver("0.1.0"), Some((0, 1, 0)));
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_semver("10.20.30"), Some((10, 20, 30)));
    }

    #[test]
    fn parse_semver_invalid() {
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("1.2"), None);
        assert_eq!(parse_semver("1.2.3.4"), None);
        assert_eq!(parse_semver("a.b.c"), None);
    }

    #[test]
    fn validate_software_version_rules() {
        assert!(validate_software_version("0.1.0"));
        assert!(validate_software_version("1.0.0-beta"));
        assert!(validate_software_version("noble-v2.3.4"));

        // Empty
        assert!(!validate_software_version(""));
        // Too long
        assert!(!validate_software_version(&"x".repeat(33)));
        // Invalid chars
        assert!(!validate_software_version("v1.0 beta"));
        assert!(!validate_software_version("v1.0@rc1"));
    }

    // ---- AUD-H2: Ban score rate limiting tests ----

    #[test]
    fn rate_limit_rapid_flood_capped() {
        // Rapid flood of penalties within the same 60-second window should be capped
        // at 50 points. After 50 points in the window, further penalties are suppressed.
        let mut pm = PeerManager::new(&test_config()); // ban_threshold = 100
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // Send 3 x InvalidTransaction(20) = 60 points attempted.
        // First two: window total 0 then 20, both <= 50, so accumulated (total = 40).
        // Third: window total = 40 <= 50, so accumulated (total = 60).
        pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidTransaction, "test"));
        pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidTransaction, "test"));
        pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidTransaction, "test"));
        // Window total before 4th call = 60 > 50, so 4th is suppressed.
        pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidTransaction, "test"));

        // ban_score should be 60 (3 x 20), not 80 (4th was suppressed).
        let state = pm.get_peer(&p).unwrap();
        assert_eq!(state.ban_score, 60);
        assert!(!pm.is_banned(&p)); // Still under threshold 100.
    }

    #[test]
    fn rate_limit_slow_accumulation_still_works() {
        // With no time pressure (each penalty within the window budget),
        // penalties accumulate normally and can reach the ban threshold.
        let cfg = NetworkConfig {
            max_outbound: 8,
            max_inbound: 8,
            ban_threshold: 100,
            ban_duration_secs: 86_400,
            ..NetworkConfig::testnet()
        };
        let mut pm = PeerManager::new(&cfg);
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // Unresponsive(10) x 2 = 20. Window total stays under 50.
        assert!(!pm.record_misbehavior(&p, BanReason::new(BanCategory::Unresponsive, "test")));
        assert!(!pm.record_misbehavior(&p, BanReason::new(BanCategory::Unresponsive, "test")));
        assert_eq!(pm.get_peer(&p).unwrap().ban_score, 20);

        // Then InvalidBlock(50) = window total would be 30 (20+10=30 before this call).
        // Wait — window has 10, 10 = 20, plus 50 = 70 after. But check is *before* adding,
        // so window_total = 20 <= 50, so it accumulates.
        assert!(!pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidBlock, "test")));
        assert_eq!(pm.get_peer(&p).unwrap().ban_score, 70);
    }

    #[test]
    fn rate_limit_window_drains_correctly() {
        // Manually verify the window tracking by checking the window length.
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        pm.record_misbehavior(&p, BanReason::new(BanCategory::Unresponsive, "test"));
        pm.record_misbehavior(&p, BanReason::new(BanCategory::Unresponsive, "test"));

        let state = pm.get_peer(&p).unwrap();
        // Two events should be in the window.
        assert_eq!(state.misbehavior_window.len(), 2);
        // Both are recent so the sum = 20.
        let sum: u32 = state.misbehavior_window.iter().map(|(_, p)| *p).sum();
        assert_eq!(sum, 20);
    }

    // ---- AUD-L2: Mass-ban detection tests ----

    #[test]
    fn mass_ban_triggers_at_over_50_percent() {
        let cfg = NetworkConfig {
            max_outbound: 10,
            max_inbound: 10,
            ban_threshold: 100,
            ban_duration_secs: 86_400,
            ..NetworkConfig::testnet()
        };
        let mut pm = PeerManager::new(&cfg);

        // Connect 4 peers (total_ever_seen = 4)
        let peers: Vec<PeerId> = (0..4).map(|_| random_peer()).collect();
        for &p in &peers {
            pm.on_connected(p, Direction::Outbound);
        }

        // Ban 3 of 4 (>50%): each with DuplicateProposal(100) = instant ban.
        pm.record_misbehavior(
            &peers[0],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );
        pm.record_misbehavior(
            &peers[1],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );
        pm.record_misbehavior(
            &peers[2],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );
        // After 3 bans: banned_count=3, total_ever_seen=4, 3 > 4/2=2 → mass-ban detected.
        assert!(pm.check_mass_ban());
        // Cooldown should be active.
        assert!(pm.ban_cooldown.is_some());
    }

    #[test]
    fn mass_ban_cooldown_prevents_further_bans() {
        let cfg = NetworkConfig {
            max_outbound: 10,
            max_inbound: 10,
            ban_threshold: 100,
            ban_duration_secs: 86_400,
            ..NetworkConfig::testnet()
        };
        let mut pm = PeerManager::new(&cfg);

        // Connect 4 peers
        let peers: Vec<PeerId> = (0..4).map(|_| random_peer()).collect();
        for &p in &peers {
            pm.on_connected(p, Direction::Outbound);
        }

        // Ban 3 to trigger mass-ban
        pm.record_misbehavior(
            &peers[0],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );
        pm.record_misbehavior(
            &peers[1],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );
        pm.record_misbehavior(
            &peers[2],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );

        // 4th peer: DuplicateProposal should be suppressed by cooldown
        let banned = pm.record_misbehavior(
            &peers[3],
            BanReason::new(BanCategory::DuplicateProposal, "test"),
        );
        assert!(!banned, "ban should be suppressed during mass-ban cooldown");
        // Peer should still be connected (not banned)
        assert!(!pm.is_banned(&peers[3]));
    }

    // ---- AUD2-H5: Ban score decay tests ----

    #[test]
    fn ban_score_decays_over_time() {
        let mut pm = PeerManager::new(&test_config());
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // Record initial misbehavior.
        pm.record_misbehavior(&p, BanReason::new(BanCategory::InvalidBlock, "test")); // +50

        // Simulate time passing by directly setting last_misbehavior in the past.
        if let Some(state) = pm.peers.get_mut(&p) {
            // Set last_misbehavior to 10 minutes ago.
            state.last_misbehavior = Some(Instant::now() - Duration::from_secs(600));
        }

        // Record another misbehavior. Decay should subtract 10 points (10 minutes).
        // Score before decay: 50, after decay: 50 - 10 = 40, then +10 = 50.
        pm.record_misbehavior(&p, BanReason::new(BanCategory::Unresponsive, "test")); // +10
        let state = pm.get_peer(&p).unwrap();
        assert_eq!(state.ban_score, 50); // 50 - 10 (decay) + 10 (new penalty) = 50
    }

    #[test]
    fn rapid_offenses_still_accumulate_to_ban() {
        // Rapid offenses (no time for decay) should still accumulate normally.
        let mut pm = PeerManager::new(&test_config()); // threshold = 100
        let p = random_peer();
        pm.on_connected(p, Direction::Outbound);

        // DuplicateProposal = 100 = instant ban. No time for decay.
        let banned =
            pm.record_misbehavior(&p, BanReason::new(BanCategory::DuplicateProposal, "test"));
        assert!(banned, "instant ban should still work with decay enabled");
        assert!(pm.is_banned(&p));
    }
}
