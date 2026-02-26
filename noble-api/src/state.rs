// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared API state available to all RPC method handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use tokio::sync::{broadcast, mpsc};

use noble_consensus::CycleEngine;
use noble_mempool::Mempool;
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;
use noble_wallet::{KeyStore, WalletState};

/// Node identity — persisted to `data_dir/identity.json`, mutable via RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentityData {
    pub node_name: String,
    pub org_type: String,
    #[serde(default)]
    pub org_name: String,
    pub node_role: String,
    #[serde(default)]
    pub contact_email: String,
    #[serde(default)]
    pub website: String,
    #[serde(default)]
    pub host_address: String,
    #[serde(default)]
    pub wants_to_validate: bool,
    #[serde(default)]
    pub wants_to_vote: bool,
    /// Preferred P2P port (8780, 8781, or 8782). Applied on node restart.
    #[serde(default = "default_p2p_port")]
    pub p2p_port: u16,
}

fn default_p2p_port() -> u16 {
    8780
}

/// Network statistics maintained by the node event loop.
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Total number of connected peers.
    pub peer_count: usize,
    /// Number of inbound connections.
    pub inbound_count: usize,
    /// Number of outbound connections.
    pub outbound_count: usize,
}

/// Metadata about a connected peer, maintained by the node event loop.
#[derive(Debug, Clone)]
pub struct PeerInfoEntry {
    /// Hex-encoded peer ID.
    pub peer_id: String,
    /// Connection direction: "inbound" or "outbound".
    pub direction: String,
    /// Multiaddr of the peer.
    pub addr: String,
    /// Unix timestamp when the peer connected.
    pub connected_at: u64,
    /// Accumulated ban score.
    pub ban_score: u32,
}

/// Shared state available to all RPC method handlers.
///
/// Generic over `S: StorageEngine` because the storage trait has
/// `close(&mut self)`, which prevents `Arc<dyn StorageEngine>`.
/// Instead we wrap in `Arc<RwLock<S>>` so the node can call `close`
/// on shutdown with a write lock.
///
/// # Lock ordering
///
/// All locks follow the hierarchy defined in `noble-node::lock_order::LockOrder`:
///
/// `WalletKeystore(0) < WalletState(1) < Storage(2) < Consensus(3) < Mempool(4) < NetworkStats(5) < PeerInfo(6) < TotpValidator(7)`
///
/// When acquiring multiple locks, always acquire lower-ordered locks first.
pub struct ApiState<S: StorageEngine + Send + Sync + 'static> {
    /// Block/transaction persistence. **Lock order: 2 (Storage).**
    pub storage: Arc<RwLock<S>>,
    /// Transaction mempool. **Lock order: 4 (Mempool).**
    pub mempool: Arc<Mutex<Mempool>>,
    /// Consensus engine (cycle management, validator list). **Lock order: 3 (Consensus).**
    pub consensus: Arc<RwLock<CycleEngine>>,
    /// Channel to send commands to the network service.
    pub network_cmd: mpsc::Sender<NetworkCommand>,
    /// Encrypted keystore for signing. **Lock order: 0 (WalletKeystore).**
    pub wallet_keystore: Arc<Mutex<KeyStore>>,
    /// Wallet lock/unlock state with auto-expire. **Lock order: 1 (WalletState).**
    pub wallet_state: Arc<Mutex<WalletState>>,
    /// Network statistics (updated by the node event loop). **Lock order: 5 (NetworkStats).**
    pub network_stats: Arc<RwLock<NetworkStats>>,
    /// Chain ID for tx_id computation and validation.
    pub chain_id: u32,
    /// Server start time (for uptime reporting).
    pub start_time: Instant,
    /// Highest software version observed across all peer NodeAnnounce messages. **Lock order: 8 (MaxNetworkVersion).**
    pub max_network_version: Arc<RwLock<String>>,
    /// RPC rate limiter (per-IP token bucket). None = disabled.
    pub rate_limiter: Option<Arc<crate::rate_limit::RpcRateLimiter>>,
    /// TOTP validator for API authentication. None = auth disabled. **Lock order: 7 (TotpValidator).**
    pub totp_validator: Option<Arc<RwLock<crate::auth::TotpValidator>>>,
    /// TOTP enforcement scope (All, WriteOnly, None).
    pub totp_scope: crate::middleware::TotpScope,
    /// Path to the TOTP secret file (for rotation persistence). None = not configured.
    pub totp_secret_path: Option<std::path::PathBuf>,
    /// Configured RPC port (for getNodeInfo response).
    pub rpc_port: u16,
    /// Configured WebSocket port (for getNodeInfo response).
    pub ws_port: u16,
    /// Configured P2P port (for getNodeInfo response).
    pub p2p_port: u16,

    // --- Broadcast channels for WebSocket subscriptions ---
    /// New block notifications.
    pub new_block_tx: broadcast::Sender<serde_json::Value>,
    /// New transaction notifications.
    pub new_tx_tx: broadcast::Sender<serde_json::Value>,
    /// Cycle phase change notifications.
    pub cycle_phase_tx: broadcast::Sender<serde_json::Value>,
    /// Peer connect/disconnect notifications.
    pub peer_update_tx: broadcast::Sender<serde_json::Value>,

    /// Runtime trace handle for the trace RPC methods. None = tracing not initialized.
    pub trace_handle: Option<Arc<crate::trace_types::TraceHandle>>,

    /// Gateway identity key (wire bytes). When set, wallet-built transactions
    /// get this as `gateway_address` so the node earns 50% of the fee.
    /// Wrapped in RwLock to support runtime key rotation.
    pub gateway_key: RwLock<Option<Vec<u8>>>,

    /// IP access control filter. None = middleware not installed (localhost-only).
    pub ip_filter: Option<crate::ip_filter::IpFilter>,

    /// Path to the gateway key file for persistence on rotation. None = auto-derived (no persistence).
    pub gateway_key_path: Option<std::path::PathBuf>,

    /// Path to the validator list persistence file (CBOR). None = no persistence.
    pub validator_list_path: Option<std::path::PathBuf>,

    /// Live connected peer info, keyed by hex peer_id. Updated by the node event loop. **Lock order: 6 (PeerInfo).**
    pub peer_info: Arc<RwLock<HashMap<String, PeerInfoEntry>>>,

    /// Mutable node identity. Loaded from identity.json (or noble.toml fallback).
    pub node_identity: Arc<RwLock<NodeIdentityData>>,
    /// Path to identity.json for persistence. None = no persistence.
    pub identity_path: Option<std::path::PathBuf>,
}
