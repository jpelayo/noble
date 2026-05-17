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
pub use messages::{BannedPeerEntry, NetworkCommand, NetworkEvent};
pub use peer_manager::{BanCategory, BanEntry, BanReason, Direction, MisbehaviorOutcome, PeerManager};
pub use service::{start_network, NetworkHandle};
pub use sync_manager::{SyncAction, SyncManager, SyncState};
pub use traits::{BlockProvider, TxProvider};

// Re-export libp2p Multiaddr so dependents don't need a direct libp2p dependency.
pub use libp2p::Multiaddr;
