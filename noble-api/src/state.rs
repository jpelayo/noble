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

    // --- Broadcast channels for WebSocket subscriptions ---
    /// New block notifications.
    pub new_block_tx: broadcast::Sender<serde_json::Value>,
    /// New transaction notifications.
    pub new_tx_tx: broadcast::Sender<serde_json::Value>,
    /// Cycle phase change notifications.
    pub cycle_phase_tx: broadcast::Sender<serde_json::Value>,
    /// Peer connect/disconnect notifications.
    pub peer_update_tx: broadcast::Sender<serde_json::Value>,
}
