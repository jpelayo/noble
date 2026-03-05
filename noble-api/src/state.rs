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
    /// ISO 3166-1 alpha-3 country code (e.g. "USA", "ESP").
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub wants_to_validate: bool,
    #[serde(default)]
    pub wants_to_vote: bool,
    /// Preferred P2P port (8780, 8781, or 8782). Applied on node restart.
    #[serde(default = "default_p2p_port")]
    pub p2p_port: u16,
    /// Explicit completion marker. Only `true` after the full setup wizard
    /// (CLI or GUI) has finished. Presence of `identity.json` or a non-empty
    /// `node_name` alone does NOT constitute completion.
    #[serde(default)]
    pub setup_complete: bool,
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
    /// Median clock offset across peers (ms, positive = peers ahead). `None` if < 2 peers sampled.
    pub median_clock_offset_ms: Option<i64>,
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
    /// Peer's chain tip height (from last status exchange). `None` if unknown.
    pub chain_tip_height: Option<u64>,
    /// Peer's chain tip hash (from last status exchange). `None` if unknown.
    pub chain_tip_hash: Option<String>,
    /// Peer's active proposal height (from gossip NodeAnnounce). `None` if not proposing.
    pub proposed_height: Option<u64>,
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
/// `WalletKeystore(0) < WalletState(1) < Storage(2) < Consensus(3) < Mempool(4) < NetworkStats(5) < PeerInfo(6) < TotpValidator(7) < MaxNetworkVersion(8) < TlsCertInfo(9)`
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

    /// SHA-256 fingerprint of the active TLS certificate (hex). None when TLS is disabled.
    /// Wrapped in RwLock so `regenerateTlsCert` / `uploadTlsCert` can update it at runtime.
    /// **Lock order: 9 (TlsCertInfo).**
    pub tls_fingerprint: RwLock<Option<String>>,

    /// ISO 8601 `not_after` of the active TLS certificate. None when TLS is disabled.
    /// **Lock order: 9 (TlsCertInfo).**
    pub tls_expires_at: RwLock<Option<String>>,

    /// Unix timestamp (seconds) of `not_after` for `days_remaining` computation.
    /// **Lock order: 9 (TlsCertInfo).**
    pub tls_expiry_secs: RwLock<Option<i64>>,

    /// Subject Alternative Names of the active TLS certificate.
    /// **Lock order: 9 (TlsCertInfo).**
    pub tls_sans: RwLock<Vec<String>>,

    /// Callback to regenerate the self-signed TLS certificate.
    /// Captures `data_dir` and the node's extra SANs list at startup.
    /// Parameters: `extra_sans: Vec<String>` — SANs for the new cert.
    /// Returns: `Ok((fingerprint, expires_at_iso, expiry_unix_secs, sans))` or `Err(message)`.
    /// `None` when TLS is disabled or in tests that don't wire up TLS.
    pub tls_regenerate: Option<Arc<dyn Fn(Vec<String>) -> Result<(String, String, i64, Vec<String>), String> + Send + Sync>>,

    /// Callback to validate and write an external (CA-signed) TLS certificate.
    /// Parameters: `(cert_pem, key_pem, chain_pem: Option<String>)`.
    /// Returns: `Ok((fingerprint, expires_at_iso, expiry_unix_secs, sans))` or `Err(message)`.
    /// `None` when TLS is disabled or in tests that don't wire up TLS.
    pub tls_upload: Option<Arc<dyn Fn(String, String, Option<String>) -> Result<(String, String, i64, Vec<String>), String> + Send + Sync>>,

    /// True when the node has not completed the setup wizard (`setup_complete` is false
    /// in `identity.json`). Affects CORS policy and GUI navigation guard.
    pub setup_mode: bool,

    /// Allowed CORS origins for the RPC server (e.g. "https://127.0.0.1:8785").
    /// Built at startup from localhost defaults plus any LAN IPs in TLS SANs or allowed_ips.
    /// Wrapped in Arc<RwLock> so `setAllowedIps` can update origins at runtime.
    pub allowed_cors_origins: std::sync::Arc<parking_lot::RwLock<Vec<String>>>,

    /// Allowed RPC origins for the GUI server CSP connect-src directive.
    /// Wrapped in Arc<RwLock> so `setAllowedIps` can update origins at runtime.
    pub rpc_origins: std::sync::Arc<parking_lot::RwLock<Vec<String>>>,

    /// HTTP/HTTPS scheme string ("http" or "https") used for CORS origin rebuilding.
    pub cors_scheme: String,

    /// Dashboard GUI port (for rebuilding CORS/CSP origins in `setAllowedIps`).
    pub gui_port: u16,

    /// True when TLS was requested but cert failed and tls_allow_plaintext_fallback=true.
    /// Exposed so the GUI can show a plaintext-mode warning banner.
    pub tls_plaintext_mode: bool,

    /// Base58btc-encoded libp2p PeerId of this node (from the persistent P2P keypair).
    pub peer_id: String,

    /// Hex-encoded wire pubkey of the validator key (if the node is in validator mode).
    pub validator_pubkey: Option<String>,

    /// Signature scheme of the validator key: `"ed25519"` or `"secp256k1"` (if enabled).
    pub validator_scheme: Option<String>,

    /// File path used to load the validator key (if enabled).
    pub validator_key_path: Option<String>,

    /// Path to the data directory (for storage_bytes calculation).
    pub data_dir: Option<std::path::PathBuf>,

    /// Pruning mode string: "archive", "moderate", "aggressive".
    pub pruning_mode: String,

    /// Number of blocks to keep when pruning. 0 = archive (keep all).
    pub keep_blocks: u64,

    /// Configured reward address string (as entered by the operator).
    /// Can be a Bitcoin address (bc1q..., 1..., bc1p...) or hex NOBLE pubkey.
    pub reward_address: RwLock<Option<String>>,

    /// Callback to enable TOTP authentication.
    /// Returns `Ok((secret_base32, otpauth_uri))`.
    /// `None` when TOTP is already enabled.
    pub enable_totp: Option<Arc<dyn Fn() -> Result<(String, String), String> + Send + Sync>>,

    /// Callback to update a config value in noble.toml.
    /// Parameters: `(section, key, value)`.
    /// Returns `Ok(restart_required)` or `Err(message)`.
    pub set_config_value: Option<Arc<dyn Fn(&str, &str, &str) -> Result<bool, String> + Send + Sync>>,

    /// Path to noble.toml for config updates.
    pub config_path: Option<std::path::PathBuf>,

    /// Per-installation entropy for at-rest file encryption (`.chain_meta`).
    pub chain_meta: [u8; 32],

    /// Live seed node list. Initialized from `[network] seeds` in noble.toml.
    pub seeds: RwLock<Vec<String>>,

    /// Trigger channel to re-publish NodeAnnounce (e.g. after identity update).
    pub announce_trigger: mpsc::Sender<()>,

    /// RocksDB block cache size in megabytes (from `[storage] cache_size_mb`).
    pub cache_size_mb: u32,

    /// Whether Zstd compression is enabled on the blocks CF (from `[storage] compression`).
    pub compression_enabled: bool,

    /// Maximum database size in GB (from `[storage] max_db_size_gb`). 0 = unlimited.
    pub max_db_size_gb: u64,

    /// Network name: "mainnet", "testnet", or "regtest".
    pub network_name: String,

    /// Hex-encoded genesis block hash for chain identity.
    pub genesis_hash: String,
}
