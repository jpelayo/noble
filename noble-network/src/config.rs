// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network configuration.

use noble_core::constants::PROTOCOL_VERSION;

/// Primary P2P listen port.
pub const P2P_PORT_PRIMARY: u16 = 8780;

/// First alternate P2P port (auto-bind fallback).
pub const P2P_PORT_ALT1: u16 = 8781;

/// Second alternate P2P port (auto-bind fallback).
pub const P2P_PORT_ALT2: u16 = 8782;

/// All P2P ports tried during auto-bind (primary → alt1 → alt2).
pub const P2P_PORTS: [u16; 3] = [P2P_PORT_PRIMARY, P2P_PORT_ALT1, P2P_PORT_ALT2];

/// JSON-RPC HTTP server port.
pub const RPC_HTTP_PORT: u16 = 8783;

/// WebSocket-only server port.
pub const WS_PORT: u16 = 8784;

/// Prometheus metrics HTTP server port (disabled by default).
pub const METRICS_PORT: u16 = 8787;

/// Dashboard GUI HTTP server port.
pub const GUI_PORT: u16 = 8785;

/// Faucet HTTP server port (token onboarding).
pub const FAUCET_PORT: u16 = 8786;

/// Default genesis seed node hostname.
pub const DEFAULT_GENESIS_NODE: &str = "node.infinitecontext.com";

/// Default genesis seed node as a multiaddr string.
pub const DEFAULT_GENESIS_SEED: &str = "/dns4/node.infinitecontext.com/tcp/8780";

/// Legacy alias kept for backward compatibility within the crate.
pub const DEFAULT_LISTEN_PORT: u16 = P2P_PORT_PRIMARY;

/// Default maximum outbound peer connections.
pub const DEFAULT_MAX_OUTBOUND: usize = 8;

/// Default maximum inbound peer connections.
pub const DEFAULT_MAX_INBOUND: usize = 32;

/// Default ban score threshold before a peer is banned.
pub const DEFAULT_BAN_THRESHOLD: u32 = 100;

/// Default ban duration in seconds (24 hours).
pub const DEFAULT_BAN_DURATION_SECS: u64 = 86_400;

/// Chain height below which a node is considered "early-chain" and tolerates
/// chain_id mismatches from peers.  Independently-bootstrapped nodes with
/// short chains must stay connected so fork resolution can trigger adoption.
pub const EARLY_CHAIN_HEIGHT_LIMIT: u64 = 5;

/// Configuration for the NOBLE P2P network layer.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Multiaddr string to listen on (e.g. "/ip4/0.0.0.0/tcp/8780").
    pub listen_addr: String,

    /// Data directory for persisting the P2P identity keypair (`p2p_identity.key`).
    /// `None` means ephemeral keypair (new PeerId on every restart — for tests).
    pub data_dir: Option<std::path::PathBuf>,

    /// Bootstrap peer multiaddr strings to connect on startup.
    pub bootstrap_peers: Vec<String>,

    /// Maximum number of outbound connections.
    pub max_outbound: usize,

    /// Maximum number of inbound connections.
    pub max_inbound: usize,

    /// Cumulative misbehavior score before banning a peer.
    pub ban_threshold: u32,

    /// How long a banned peer stays banned, in seconds.
    pub ban_duration_secs: u64,

    /// Network chain identifier (genesis-derived, set by the node at runtime).
    pub chain_id: u32,

    /// Protocol version for compatibility checks.
    pub protocol_version: u16,

    /// Whether to enable mDNS local peer discovery (useful for development).
    pub enable_mdns: bool,

    /// Whether to enable Kademlia DHT for peer discovery.
    pub enable_kademlia: bool,

    /// Interval in seconds between Kademlia random walks for peer discovery.
    pub kad_walk_interval_secs: u64,

    /// Maximum transaction relay rate per peer per second (token bucket).
    pub tx_relay_rate_per_sec: u32,

    /// Burst capacity for the per-peer transaction relay token bucket.
    pub tx_relay_burst: u32,

    /// Interval in seconds between peer address exchanges via gossip.
    pub peer_exchange_interval_secs: u64,

    /// Maximum number of addresses to include in a single peer exchange message.
    pub max_addrs_per_exchange: usize,

    /// Maximum outbound connections allowed to the same /16 subnet.
    pub max_outbound_per_subnet: usize,

    /// Interval in seconds between peer quality rotation checks.
    pub peer_rotation_interval_secs: u64,

    /// Per-installation entropy for at-rest encryption of `p2p_identity.key`.
    /// `None` means no encryption (for tests). Set by the node from `.chain_meta`.
    pub chain_meta: Option<[u8; 32]>,

    /// Pre-loaded P2P identity keypair bytes (protobuf-encoded) from the unified keystore.
    /// When `Some`, the service uses these bytes directly instead of reading `p2p_identity.key`.
    pub pre_loaded_p2p_key: Option<Vec<u8>>,

    /// Gossipsub heartbeat interval in seconds (default: 10).
    /// Lower values speed up mesh formation in tests.
    pub gossipsub_heartbeat_interval_secs: u64,

    /// Local chain tip height.  Updated by the node on each committed block.
    /// Used by the chain_id mismatch check: nodes with very short chains
    /// (≤ `EARLY_CHAIN_HEIGHT_LIMIT`) tolerate chain_id mismatches so that
    /// independently bootstrapped nodes can reconnect and adopt the longer chain.
    pub tip_height: u64,

    /// External IP address (auto-detected by the node).
    /// When set, advertised to peers via the Identify protocol so they know
    /// our reachable address (handles 0.0.0.0 bind, NAT, VPN, Docker).
    pub external_ip: Option<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("/ip4/0.0.0.0/tcp/{DEFAULT_LISTEN_PORT}"),
            data_dir: None,
            bootstrap_peers: Vec::new(),
            max_outbound: DEFAULT_MAX_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            ban_duration_secs: DEFAULT_BAN_DURATION_SECS,
            chain_id: 0,
            protocol_version: PROTOCOL_VERSION,
            enable_mdns: true,
            enable_kademlia: true,
            kad_walk_interval_secs: 300,
            tx_relay_rate_per_sec: 100,
            tx_relay_burst: 100,
            peer_exchange_interval_secs: 960,
            max_addrs_per_exchange: 1000,
            max_outbound_per_subnet: 2,
            peer_rotation_interval_secs: 600,
            chain_meta: None,
            pre_loaded_p2p_key: None,
            gossipsub_heartbeat_interval_secs: 1,
            tip_height: 0,
            external_ip: None,
        }
    }
}

impl NetworkConfig {
    /// Create a local test configuration with mDNS enabled and a random port.
    pub fn local_test() -> Self {
        Self {
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            ..Self::default()
        }
    }

    /// Total maximum peers (inbound + outbound).
    pub fn max_peers(&self) -> usize {
        self.max_inbound + self.max_outbound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.max_outbound, 8);
        assert_eq!(cfg.max_inbound, 32);
        assert_eq!(cfg.ban_threshold, 100);
        assert_eq!(cfg.ban_duration_secs, 86_400);
        assert_eq!(cfg.chain_id, 0);
        assert_eq!(cfg.protocol_version, PROTOCOL_VERSION);
        assert!(cfg.enable_mdns);
        assert!(cfg.listen_addr.contains("8780"));
        assert!(cfg.enable_kademlia);
        assert_eq!(cfg.kad_walk_interval_secs, 300);
        assert_eq!(cfg.tx_relay_rate_per_sec, 100);
        assert_eq!(cfg.tx_relay_burst, 100);
        assert_eq!(cfg.peer_exchange_interval_secs, 960);
        assert_eq!(cfg.max_addrs_per_exchange, 1000);
        assert_eq!(cfg.max_outbound_per_subnet, 2);
        assert_eq!(cfg.peer_rotation_interval_secs, 600);
    }

    #[test]
    fn p2p_ports_constant() {
        assert_eq!(P2P_PORTS, [8780, 8781, 8782]);
    }

    #[test]
    fn default_config_uses_primary_port() {
        let cfg = NetworkConfig::default();
        assert!(cfg.listen_addr.contains(&P2P_PORT_PRIMARY.to_string()));
    }

    #[test]
    fn local_test_config() {
        let cfg = NetworkConfig::local_test();
        assert_eq!(cfg.chain_id, 0);
        assert!(cfg.listen_addr.contains("127.0.0.1"));
        assert!(cfg.listen_addr.contains("/tcp/0"));
    }

    #[test]
    fn max_peers() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.max_peers(), 40);
    }
}
