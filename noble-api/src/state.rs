// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared API state available to all RPC method handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::lock_order::{TrackedMutex, TrackedRwLock};

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
    /// Misbehavior category codes accumulated by this peer.
    pub misbehavior_categories: Vec<u8>,
    /// Peer's chain tip height (from last status exchange). `None` if unknown.
    pub chain_tip_height: Option<u64>,
    /// Peer's chain tip hash (from last status exchange). `None` if unknown.
    pub chain_tip_hash: Option<String>,
    /// Peer's active proposal height (from gossip NodeAnnounce). `None` if not proposing.
    pub proposed_height: Option<u64>,
    /// Noble identity key wire bytes (from NodeAnnounce). Links PeerId to validator key.
    pub identity_key: Option<Vec<u8>>,
    /// Node name from the most recent NodeAnnounce.
    pub node_name: Option<String>,
    /// Round-trip latency in milliseconds (from libp2p ping). `None` if not yet measured.
    pub latency_ms: Option<u64>,
    /// Last ban reason category + subject (from most recent misbehavior).
    pub last_ban_reason: Option<(String, String)>,
    /// Peer's chain ID (from NodeAnnounce). `None` if not yet announced.
    pub chain_id: Option<u32>,
    /// Peer's minimum fee rate preference (groats/byte, from NodeAnnounce).
    pub min_fee_rate: Option<u64>,
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
/// `WalletKeystore(0) < WalletState(1) < Storage(2) < ValidatorRegistry(3) < Consensus(4) < Mempool(5) < NetworkStats(6) < PeerInfo(7) < TotpValidator(8) < MaxNetworkVersion(9) < TlsCertInfo(10)`
///
/// When acquiring multiple locks, always acquire lower-ordered locks first.
///
/// A live, swappable handle to the TOTP validator, shared between `ApiState` and
/// the decoupled GUI server. The inner `Option` lets `enableTotp` install a
/// validator at runtime (the legacy `totp_validator` field stays `None` until
/// restart), so the GUI admin lock can validate codes against the current secret
/// without a restart. Both layers hold a clone of the SAME outer `Arc`.
pub type SharedTotpSlot =
    Arc<RwLock<Option<Arc<RwLock<crate::auth::TotpValidator>>>>>;

pub struct ApiState<S: StorageEngine + Send + Sync + 'static> {
    /// Block/transaction persistence. **Lock order: 2 (Storage).**
    pub storage: Arc<TrackedRwLock<S>>,
    /// Transaction mempool. **Lock order: 5 (Mempool).**
    pub mempool: Arc<TrackedMutex<Mempool>>,
    /// Validator/participant registry. **Lock order: 3 (ValidatorRegistry).**
    pub validator_registry: Arc<TrackedRwLock<noble_consensus::ValidatorRegistry>>,
    /// Consensus engine (cycle management, validator list). **Lock order: 4 (Consensus).**
    pub consensus: Arc<TrackedRwLock<CycleEngine>>,
    /// Channel to send commands to the network service.
    pub network_cmd: mpsc::Sender<NetworkCommand>,
    /// Encrypted keystore for signing. **Lock order: 0 (WalletKeystore).**
    pub wallet_keystore: Arc<Mutex<KeyStore>>,
    /// Wallet lock/unlock state with auto-expire. **Lock order: 1 (WalletState).**
    pub wallet_state: Arc<Mutex<WalletState>>,
    /// Network statistics (updated by the node event loop). **Lock order: 6 (NetworkStats).**
    pub network_stats: Arc<TrackedRwLock<NetworkStats>>,
    /// Chain ID for tx_id computation and validation. Shared with Node so updates propagate.
    pub chain_id: Arc<AtomicU32>,
    /// Server start time (for uptime reporting).
    pub start_time: Instant,
    /// Highest software version observed across all peer NodeAnnounce messages. **Lock order: 9 (MaxNetworkVersion).**
    pub max_network_version: Arc<RwLock<String>>,
    /// RPC rate limiter (per-IP token bucket). None = disabled.
    pub rate_limiter: Option<Arc<crate::rate_limit::RpcRateLimiter>>,
    /// TOTP validator for API authentication. None = auth disabled. **Lock order: 8 (TotpValidator).**
    pub totp_validator: Option<Arc<RwLock<crate::auth::TotpValidator>>>,
    /// TOTP enforcement scope (All, WriteOnly, None).
    pub totp_scope: crate::middleware::TotpScope,
    /// Path to the TOTP secret file (for rotation persistence). None = not configured.
    pub totp_secret_path: Option<std::path::PathBuf>,
    /// Live, swappable TOTP validator handle shared with the GUI server so the
    /// GUI admin lock validates against the current secret across runtime
    /// enable/rotate. **Lock order: 8 (TotpValidator).**
    pub totp_slot: SharedTotpSlot,
    /// Whether the GUI admin lock (session login wall on the dashboard) is
    /// enabled. Hot-reloadable via `setConfigValue`; the same `Arc` is shared
    /// into the GUI server so toggling takes effect without a restart.
    pub gui_lock_enabled: Arc<std::sync::atomic::AtomicBool>,
    /// Per-boot GUI admin-lock proxy-trust secret (see
    /// `crate::middleware::GUI_PROXY_AUTH_HEADER`). Shared with the GUI server,
    /// which attaches it to proxied requests it has already session-authenticated
    /// so the loopback RPC accepts them under any `totp_scope`.
    pub gui_proxy_secret: Arc<String>,
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

    /// Live connected peer info, keyed by hex peer_id. Updated by the node event loop. **Lock order: 7 (PeerInfo).**
    pub peer_info: Arc<TrackedRwLock<HashMap<String, PeerInfoEntry>>>,

    /// Mutable node identity. Loaded from identity.json (or noble.toml fallback). **Lock order: 11 (NodeIdentity).**
    pub node_identity: Arc<TrackedRwLock<NodeIdentityData>>,
    /// Path to identity.json for persistence. None = no persistence.
    pub identity_path: Option<std::path::PathBuf>,

    /// SHA-256 fingerprint of the active TLS certificate (hex). None when TLS is disabled.
    /// Wrapped in RwLock so `regenerateTlsCert` / `uploadTlsCert` can update it at runtime.
    /// **Lock order: 10 (TlsCertInfo).**
    pub tls_fingerprint: RwLock<Option<String>>,

    /// ISO 8601 `not_after` of the active TLS certificate. None when TLS is disabled.
    /// **Lock order: 10 (TlsCertInfo).**
    pub tls_expires_at: RwLock<Option<String>>,

    /// Unix timestamp (seconds) of `not_after` for `days_remaining` computation.
    /// **Lock order: 10 (TlsCertInfo).**
    pub tls_expiry_secs: RwLock<Option<i64>>,

    /// Subject Alternative Names of the active TLS certificate.
    /// **Lock order: 10 (TlsCertInfo).**
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

    /// Configured maximum connected peers. Updated at runtime by `setConfigValue`.
    pub max_peers: std::sync::atomic::AtomicU32,

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
    /// Wrapped in RwLock so `setNodeIdentity` can hot-reload after setup.
    /// **Lock order: 12 (ValidatorPubkey).**
    pub validator_pubkey: TrackedRwLock<Option<String>>,

    /// Signature scheme of the validator key: `"secp256k1"`.
    pub validator_scheme: parking_lot::RwLock<Option<String>>,

    /// File path used to load the validator key (if enabled).
    pub validator_key_path: parking_lot::RwLock<Option<String>>,

    /// Path to the data directory (for storage_bytes calculation).
    pub data_dir: Option<std::path::PathBuf>,

    /// Snapshot of the multi-path sharding tiers passed to RocksDB at
    /// boot (`[storage] extra_data_dirs` resolved to `(path, target_bytes)`).
    /// Drives `noble_getStoragePaths`, `noble_discoverShards`,
    /// `noble_reconcileStorage`. Empty in legacy single-volume mode.
    pub extra_data_dirs: Vec<(std::path::PathBuf, u64)>,

    /// Reconciliation mode the node booted with. Echoed back through
    /// `noble_getStoragePaths.reconcile_mode`. String form to avoid
    /// importing the `ReconcileMode` enum into `noble-api`.
    pub reconcile_mode: String,

    /// Pruning mode string: "archive", "moderate", "aggressive".
    pub pruning_mode: String,

    /// Number of blocks to keep when pruning. 0 = archive (keep all).
    pub keep_blocks: u64,

    /// Configured reward address string (as entered by the operator).
    /// Can be a Bitcoin address (bc1q..., 1..., bc1p...) or hex NOBLE pubkey.
    pub reward_address: RwLock<Option<String>>,

    /// Shared parsed reward address — written by RPC, read by CycleEngine during
    /// block proposals. Hot-reload: writing here takes effect on the next proposal.
    pub engine_reward_address: Arc<parking_lot::RwLock<Option<noble_core::NobleAddress>>>,

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
    /// Operator's DB size target in GB (from `[storage] max_db_size_gb`;
    /// 0 = unlimited; advisory — nothing enforces it yet).
    pub max_db_size_gb: u32,

    /// Whether Zstd compression is enabled on the blocks CF (from `[storage] compression`).
    pub compression_enabled: bool,

    /// Chain label (hex chain ID or empty for pre-genesis).
    pub network_name: String,

    /// Hex-encoded genesis block hash for chain identity.
    pub genesis_hash: String,

    /// Blockchains discovered via NodeAnnounce from peers on different chains.
    /// Shared with the Node event loop which writes; API reads.
    pub discovered_blockchains: Arc<Mutex<HashMap<u32, crate::types::DiscoveredBlockchainInfo>>>,

    /// Fork resolver shared with HealingManager for RPC reads.
    pub fork_resolver: Arc<parking_lot::Mutex<noble_consensus::ForkResolver>>,

    /// True when the node is catching up blocks from an ahead peer (shared with Node event loop).
    pub sync_behind: Arc<std::sync::atomic::AtomicBool>,

    /// Target height the node is syncing towards (0 = not syncing, shared with Node event loop).
    pub sync_target_height: Arc<std::sync::atomic::AtomicU64>,

    /// Current sync progress height (shared with HealingManager for real-time reads).
    pub sync_progress_current: Arc<std::sync::atomic::AtomicU64>,

    /// Overall sync target height (shared with HealingManager for real-time reads).
    pub sync_progress_total: Arc<std::sync::atomic::AtomicU64>,

    /// Centralized alignment state. Written by HealingManager per tick, read by RPC.
    pub alignment: Arc<parking_lot::RwLock<noble_consensus::AlignmentSnapshot>>,

    /// Cached faucet discovery results. Updated by the node on cycle boundaries.
    pub faucet_cache: crate::types::FaucetCache,

    /// Faucet wallet address (bech32m). Read from config, updated by storeFaucetSecret.
    pub faucet_address: parking_lot::RwLock<String>,

    /// Faucet listen address (e.g. "0.0.0.0:8786"). Set from config.
    pub faucet_listen: parking_lot::RwLock<String>,

    /// Whether the faucet server is enabled. Shared (Arc) with the node's
    /// faucet supervisor: setConfigValue flips it, the supervisor applies it
    /// live (spawn/kill the child, no restart required).
    pub faucet_enabled: Arc<std::sync::atomic::AtomicBool>,

    /// Whether the faucet child is ACTUALLY listening — verified by the
    /// node's faucet supervisor probing the real HTTP endpoint. The GUI badge
    /// derives Running/Not-running from this, never from config or on-chain
    /// balance (which survive a dead daemon).
    pub faucet_listening: Arc<std::sync::atomic::AtomicBool>,

    /// Validator's personal minimum fee rate (groats/byte) for block proposal.
    /// Hot-reloadable via setConfigValue("consensus", "min_fee_rate", "N").
    /// Shared with Node for block proposal filtering.
    pub min_fee_rate: Arc<std::sync::atomic::AtomicU64>,
}

/// Canonical node name resolution from validator wire bytes.
///
/// Checks four sources in priority order:
/// 1. **Validator snapshot** — operator-set friendly name.
/// 2. **Peer records** — `node_name` from the most recent `NodeAnnounce`.
/// 3. **Self identity** — this node's own `node_name` (when `wire` is our key).
/// 4. **Display key** — `nbl1…` bech32 address, or hex wire bytes.
///
/// Returns `(friendly_name, is_resolved)` where `is_resolved` is `true` when
/// sources 1–3 provided a non-empty name (not the raw key fallback).
///
/// This is the **single canonical** name resolver. Every UI surface (RPC
/// responses, WebSocket events, CLI output) MUST use this function.
pub fn resolve_node_name<S: StorageEngine>(
    wire: &[u8],
    validator_registry: &noble_consensus::ValidatorRegistry,
    storage: &S,
    self_validator_pubkey_hex: Option<&str>,
    self_node_name: &str,
) -> (String, bool) {
    // 1. Validator registry (operator-set friendly name).
    if let Some(entry) = validator_registry.find_by_wire(wire) {
        let n = entry.name();
        if !n.is_empty() {
            return (n, true);
        }
    }

    // 2. Peer records (NodeAnnounce history).
    if let Ok(records) = storage.list_peer_records() {
        for rec in &records {
            if rec.identity_key == wire {
                if let Some(ref ann) = rec.last_announce {
                    if !ann.node_name.is_empty() {
                        return (ann.node_name.clone(), true);
                    }
                }
                break;
            }
        }
    }

    // 3. Self identity.
    if let Some(pk_hex) = self_validator_pubkey_hex {
        let wire_hex = hex::encode(wire);
        if pk_hex == wire_hex && !self_node_name.is_empty() {
            return (self_node_name.to_string(), true);
        }
    }

    // 4. Display key fallback (bech32 or hex).
    let display = noble_crypto::noble_addr::encode_wire_bytes(wire)
        .unwrap_or_else(|| hex::encode(wire));
    (display, false)
}

impl<S: StorageEngine + Send + Sync + 'static> ApiState<S> {
    /// Resolve a node name from wire bytes using all available sources.
    /// Convenience method that delegates to the free function [`resolve_node_name`].
    ///
    /// # Lock contract — DO NOT CALL WHILE HOLDING ANY OF THESE LOCKS
    /// This acquires `storage`(2), `validator_registry`(3), `node_identity`,
    /// and `validator_pubkey` internally. A caller that already holds
    /// `validator_registry` (any mode) re-locks it recursively → deadlock; a
    /// caller holding `peer_info`(7) inverts the hierarchy. Snapshot the wires
    /// you need into owned data, drop your guards, THEN call this in a second
    /// loop. See `get_badge_holders` for the correct pattern.
    pub fn resolve_name(&self, wire: &[u8]) -> String {
        let storage = self.storage.read();         // Lock order: 2
        let registry = self.validator_registry.read(); // Lock order: 3
        let self_name = self.node_identity.read().node_name.clone();
        resolve_node_name(
            wire,
            &registry,
            &*storage,
            self.validator_pubkey.read().as_deref(),
            &self_name,
        ).0
    }

    /// Resolve a node name, returning `None` if only the raw key fallback was available.
    ///
    /// # Lock contract — DO NOT CALL WHILE HOLDING ANY OF THESE LOCKS
    /// Same as [`Self::resolve_name`]: acquires `storage`(2),
    /// `validator_registry`(3), `node_identity`, `validator_pubkey`. Never call
    /// it while holding `validator_registry` or `peer_info` — snapshot first,
    /// drop, then resolve.
    pub fn resolve_friendly_name(&self, wire: &[u8]) -> Option<String> {
        let storage = self.storage.read();         // Lock order: 2
        let registry = self.validator_registry.read(); // Lock order: 3
        let self_name = self.node_identity.read().node_name.clone();
        let (name, resolved) = resolve_node_name(
            wire,
            &registry,
            &*storage,
            self.validator_pubkey.read().as_deref(),
            &self_name,
        );
        if resolved { Some(name) } else { None }
    }
}
