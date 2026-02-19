// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared API state available to all RPC method handlers.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use tokio::sync::{broadcast, mpsc};

use noble_consensus::CycleEngine;
use noble_mempool::Mempool;
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;
use noble_wallet::{KeyStore, WalletState};

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

/// Shared state available to all RPC method handlers.
///
/// Generic over `S: StorageEngine` because the storage trait has
/// `close(&mut self)`, which prevents `Arc<dyn StorageEngine>`.
/// Instead we wrap in `Arc<RwLock<S>>` so the node can call `close`
/// on shutdown with a write lock.
pub struct ApiState<S: StorageEngine + Send + Sync + 'static> {
    /// Block/transaction persistence.
    pub storage: Arc<RwLock<S>>,
    /// Transaction mempool.
    pub mempool: Arc<Mutex<Mempool>>,
    /// Consensus engine (cycle management, validator list).
    pub consensus: Arc<RwLock<CycleEngine>>,
    /// Channel to send commands to the network service.
    pub network_cmd: mpsc::Sender<NetworkCommand>,
    /// Encrypted keystore for signing.
    pub wallet_keystore: Arc<Mutex<KeyStore>>,
    /// Wallet lock/unlock state with auto-expire.
    pub wallet_state: Arc<Mutex<WalletState>>,
    /// Network statistics (updated by the node event loop).
    pub network_stats: Arc<RwLock<NetworkStats>>,
    /// Chain ID for tx_id computation and validation.
    pub chain_id: u32,
    /// Server start time (for uptime reporting).
    pub start_time: Instant,
    /// Highest software version observed across all peer NodeAnnounce messages.
    pub max_network_version: Arc<RwLock<String>>,
    /// RPC rate limiter (per-IP token bucket). None = disabled.
    pub rate_limiter: Option<Arc<crate::rate_limit::RpcRateLimiter>>,
    /// TOTP validator for API authentication. None = auth disabled.
    pub totp_validator: Option<Arc<RwLock<crate::auth::TotpValidator>>>,
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
    pub gateway_key: Option<Vec<u8>>,

    /// IP access control filter. None = middleware not installed (localhost-only).
    pub ip_filter: Option<crate::ip_filter::IpFilter>,
}
