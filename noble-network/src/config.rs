// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network configuration.

use noble_core::constants::{MAINNET_CHAIN_ID, PROTOCOL_VERSION};

/// Default listen port for NOBLE P2P.
pub const DEFAULT_LISTEN_PORT: u16 = 9333;

/// Default maximum outbound peer connections.
pub const DEFAULT_MAX_OUTBOUND: usize = 8;

/// Default maximum inbound peer connections.
pub const DEFAULT_MAX_INBOUND: usize = 32;

/// Default ban score threshold before a peer is banned.
pub const DEFAULT_BAN_THRESHOLD: u32 = 100;

/// Default ban duration in seconds (24 hours).
pub const DEFAULT_BAN_DURATION_SECS: u64 = 86_400;

/// Configuration for the NOBLE P2P network layer.
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Multiaddr string to listen on (e.g. "/ip4/0.0.0.0/tcp/9333").
    pub listen_addr: String,

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

    /// Network chain identifier (e.g. `MAINNET_CHAIN_ID`).
    pub chain_id: u32,

    /// Protocol version for compatibility checks.
    pub protocol_version: u16,

    /// Whether to enable mDNS local peer discovery (useful for development).
    pub enable_mdns: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: format!("/ip4/0.0.0.0/tcp/{DEFAULT_LISTEN_PORT}"),
            bootstrap_peers: Vec::new(),
            max_outbound: DEFAULT_MAX_OUTBOUND,
            max_inbound: DEFAULT_MAX_INBOUND,
            ban_threshold: DEFAULT_BAN_THRESHOLD,
            ban_duration_secs: DEFAULT_BAN_DURATION_SECS,
            chain_id: MAINNET_CHAIN_ID,
            protocol_version: PROTOCOL_VERSION,
            enable_mdns: true,
        }
    }
}

impl NetworkConfig {
    /// Create a testnet configuration with mDNS enabled and a random port.
    pub fn testnet() -> Self {
        Self {
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            chain_id: noble_core::constants::TESTNET_CHAIN_ID,
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
        assert_eq!(cfg.chain_id, MAINNET_CHAIN_ID);
        assert_eq!(cfg.protocol_version, PROTOCOL_VERSION);
        assert!(cfg.enable_mdns);
        assert!(cfg.listen_addr.contains("9333"));
    }

    #[test]
    fn testnet_config() {
        let cfg = NetworkConfig::testnet();
        assert_eq!(cfg.chain_id, noble_core::constants::TESTNET_CHAIN_ID);
        assert!(cfg.listen_addr.contains("127.0.0.1"));
        assert!(cfg.listen_addr.contains("/tcp/0"));
    }

    #[test]
    fn max_peers() {
        let cfg = NetworkConfig::default();
        assert_eq!(cfg.max_peers(), 40);
    }
}
