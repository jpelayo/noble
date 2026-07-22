// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! libp2p transport, peer management and chain sync for the NOBLE protocol.
//!
//! # Architecture
//!
//! `noble-network` is decoupled from storage and mempool via trait abstractions
//! ([`BlockProvider`], [`TxProvider`]). The node binary wires these together.
//! Communication between the node and the network layer uses channel-based
//! [`NetworkCommand`] / [`NetworkEvent`] messages.
//!
//! # Modules
//!
//! - [`config`] — Network configuration (listen address, peer limits, ban thresholds).
//! - [`messages`] — Wire message types for sync, transaction, and gossip protocols.
//! - [`codec`] — CBOR encoding/decoding for GossipSub payloads.
//! - [`peer_manager`] — Peer reputation, ban scoring, and connection limits.
//! - [`sync_manager`] — Headers-first chain synchronization state machine.
//! - [`behaviour`] — Composite libp2p `NetworkBehaviour`.
//! - [`transport`] — Swarm construction (TCP + Noise + Yamux).
//! - [`service`] — Main event loop and [`NetworkHandle`].

pub mod ancestor;
pub mod behaviour;
pub mod codec;
pub mod config;
pub mod diversity;
pub mod error;
pub mod gossip_outcome;
pub mod messages;
pub mod peer_manager;
pub mod rate_limiter;
pub mod seen_cache;
pub mod service;
pub mod sync_manager;
pub mod topics;
pub mod traits;
pub mod transport;

// Re-export primary public API types.
pub use config::NetworkConfig;
pub use config::{
    FAUCET_PORT, GUI_PORT, METRICS_PORT, P2P_PORTS, P2P_PORT_ALT1, P2P_PORT_ALT2,
    P2P_PORT_PRIMARY, RPC_HTTP_PORT, WS_PORT,
};
pub use error::NetworkError;
pub use messages::{BannedPeerEntry, NetworkCommand, NetworkEvent, ReqProtocol};
pub use peer_manager::{BanCategory, BanEntry, BanReason, Direction, MisbehaviorOutcome, PeerManager};
pub use service::{start_network, NetworkHandle};
pub use sync_manager::{SyncAction, SyncManager, SyncState};
pub use traits::{BlockProvider, TxProvider};

// Re-export libp2p Multiaddr so dependents don't need a direct libp2p dependency.
pub use libp2p::Multiaddr;

/// Rebuild a multiaddr string replacing ONLY its `/tcp/<port>` component
/// (K3-10). Typed component walk — safe for `/ip6/…`, `/dns4/…`, and any
/// trailing protocol suffixes, unlike string surgery. Errors if the input is
/// not a valid multiaddr.
pub fn multiaddr_with_tcp_port(addr: &str, port: u16) -> Result<String, String> {
    let parsed: Multiaddr = addr
        .parse()
        .map_err(|e| format!("invalid multiaddr {addr:?}: {e}"))?;
    // libp2p parses "" as a valid EMPTY multiaddr; require a Tcp component so
    // a portless (useless-as-listener) address is rejected, not passed through.
    let mut found_tcp = false;
    let rebuilt: Multiaddr = parsed
        .iter()
        .map(|p| match p {
            libp2p::multiaddr::Protocol::Tcp(_) => {
                found_tcp = true;
                libp2p::multiaddr::Protocol::Tcp(port)
            }
            other => other,
        })
        .collect();
    if !found_tcp {
        return Err(format!("multiaddr {addr:?} has no /tcp component"));
    }
    Ok(rebuilt.to_string())
}

#[cfg(test)]
mod multiaddr_port_tests {
    use super::multiaddr_with_tcp_port;

    #[test]
    fn swaps_only_the_tcp_port() {
        assert_eq!(
            multiaddr_with_tcp_port("/ip4/0.0.0.0/tcp/8780", 9000).unwrap(),
            "/ip4/0.0.0.0/tcp/9000"
        );
        assert_eq!(
            multiaddr_with_tcp_port("/ip4/192.168.1.7/tcp/8780", 9000).unwrap(),
            "/ip4/192.168.1.7/tcp/9000"
        );
        // IPv6 host survives intact (the string-surgery approach broke this).
        assert_eq!(
            multiaddr_with_tcp_port("/ip6/::1/tcp/8780", 9000).unwrap(),
            "/ip6/::1/tcp/9000"
        );
        // DNS + trailing p2p suffix survive.
        assert_eq!(
            multiaddr_with_tcp_port("/dns4/node.example.com/tcp/8780", 9000).unwrap(),
            "/dns4/node.example.com/tcp/9000"
        );
    }

    #[test]
    fn invalid_multiaddr_is_an_error() {
        assert!(multiaddr_with_tcp_port("0.0.0.0:8780", 9000).is_err());
        assert!(multiaddr_with_tcp_port("", 9000).is_err());
    }
}
