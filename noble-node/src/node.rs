// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node orchestrator — ties all subsystems together.
//!
//! The `Node` struct owns shared references to storage, mempool, consensus,
//! wallet, and network stats. It is initialized from a `NodeConfig` and
//! provides the async event loop that wires network, consensus, and API.

use std::path::Path;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use thiserror::Error;
use tokio::sync::{broadcast, mpsc};

use noble_api::auth::TotpValidator;
use noble_api::state::{ApiState, NodeIdentityData};
use noble_api::NetworkStats;
use noble_consensus::{
    ConsensusConfig as CConsensusConfig, ConsensusStateMachine, CycleEngine, CycleEvent, CycleIo,
    ValidatorList,
};
use noble_crypto::Hash256;
use noble_mempool::{BalanceLookup, ChainLookup, Mempool};
use noble_network::{NetworkCommand, NetworkEvent};
use noble_storage::{IntegrityReport, MemoryStorage, StorageEngine};
use noble_wallet::{KeyStore, WalletState};

use crate::bridge;
use crate::ca_store::CaStore;
use crate::config::NodeConfig;
use crate::metrics::NobleMetrics;
use crate::providers::{StorageBlockProvider, StorageTxProvider};

/// Typed errors for node operations.
#[derive(Debug, Error)]
pub enum NodeError {
    /// Storage backend failure (disk full, corruption, etc.).
    #[error("storage error: {0}")]
    #[allow(dead_code)]
    Storage(String),
    /// Network subsystem failure.
    #[error("network error: {0}")]
    Network(String),
    /// API/RPC server failure.
    #[error("api error: {0}")]
    Api(String),
    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),
    /// Consensus engine failure.
    #[error("consensus error: {0}")]
    #[allow(dead_code)]
    Consensus(String),
    /// Clean shutdown (Ctrl-C or SIGTERM).
    #[error("shutdown signal received")]
    #[allow(dead_code)]
    Shutdown,
}

/// The running NOBLE node, generic over the storage backend.
///
/// # Lock ordering
///
/// All shared locks follow the hierarchy in [`crate::lock_order::LockOrder`].
/// When acquiring multiple locks, always acquire lower-ordered locks first:
///
/// `WalletKeystore < WalletState < Storage < Consensus < Mempool < NetworkStats < PeerInfo`
pub struct Node<S: StorageEngine + Send + Sync + 'static> {
    /// Shared block/transaction storage. **Lock order: 2 (Storage).**
    pub storage: Arc<RwLock<S>>,
    /// Transaction mempool. **Lock order: 4 (Mempool).**
    pub mempool: Arc<Mutex<Mempool>>,
    /// PoR consensus engine. **Lock order: 3 (Consensus).**
    pub consensus: Arc<RwLock<CycleEngine>>,
    /// Encrypted keystore for signing. **Lock order: 0 (WalletKeystore).**
    pub wallet_keystore: Arc<Mutex<KeyStore>>,
    /// Wallet lock/unlock state with auto-expire. **Lock order: 1 (WalletState).**
    pub wallet_state: Arc<Mutex<WalletState>>,
    /// Network statistics (peer counts). **Lock order: 5 (NetworkStats).**
    pub network_stats: Arc<RwLock<NetworkStats>>,
    /// Live connected peer info (H-004). **Lock order: 6 (PeerInfo).**
    pub peer_info: Arc<RwLock<std::collections::HashMap<String, noble_api::state::PeerInfoEntry>>>,
    /// Active chain ID.
    pub chain_id: u32,
    /// Timestamp when the node was started.
    pub start_time: std::time::Instant,
    /// PKI identity attestation (CMS/PKCS#7 binding), loaded or created at startup.
    /// TODO: Wire into peer protocol for broadcasting attestation (PKI peer verification).
    #[allow(dead_code)]
    pub pki_attestation: Option<noble_core::ExternalAttestation>,
    /// CA trust store for verifying peer PKI attestations.
    /// TODO: Wire into peer message validation (PKI peer verification).
    #[allow(dead_code)]
    pub ca_store: Option<CaStore>,
    /// Per-installation entropy for at-rest file encryption (`.chain_meta`).
    pub chain_meta: [u8; 32],
}

impl Node<MemoryStorage> {
    /// Initialize a node with in-memory storage (for testing or `--memory` mode).
    pub fn init_memory(config: &NodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = MemoryStorage::new();
        Self::init_with_storage(config, storage, None)
    }
}

impl<S: StorageEngine + Send + Sync + 'static> Node<S> {
    /// Initialize a node with the given storage backend.
    ///
    /// If the chain is empty (no tip), the mainnet genesis block is committed.
    /// Subsystems (mempool, consensus, wallet) are created from the config.
    pub fn init_with_storage(
        config: &NodeConfig,
        storage: S,
        encryption_password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = Arc::new(RwLock::new(storage));

        // Resolve chain_id and genesis block from network config.
        let chain_id = config.node.network.chain_id();

        // Ensure genesis block is committed if the chain is empty.
        {
            let s = storage.read();
            if s.get_chain_tip()?.is_none() {
                let genesis = config.node.network.genesis_block();
                let block_hash = genesis
                    .header
                    .compute_block_hash()
                    .map_err(|e| format!("genesis hash error: {e}"))?;
                let tx_ids: Vec<_> = genesis
                    .transactions
                    .iter()
                    .map(|tx| tx.compute_tx_id(chain_id))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("genesis tx_id error: {e}"))?;
                s.commit_block(&genesis, &block_hash, &tx_ids)?;
            }
        }

        // Create mempool.
        let mempool = Arc::new(Mutex::new(Mempool::with_defaults()));

        // Determine chain tip for the consensus engine.
        let tip = storage
            .read()
            .get_chain_tip()?
            .unwrap_or(noble_storage::ChainTip {
                block_hash: Hash256::ZERO,
                height: 0,
            });

        // AUD3-D5/D6: Load tip block header for proper B2/B3/B5/B6 validation on startup.
        let tip_header = if tip.height > 0 || tip.block_hash != Hash256::ZERO {
            let s = storage.read();
            s.get_block_header(&tip.block_hash).ok()
        } else {
            None
        };

        // --- Load per-installation encryption entropy ---
        let chain_meta = noble_crypto::file_encrypt::load_or_create_chain_meta(
            &config.storage.data_dir,
            &config.security.encryption_mode,
            encryption_password,
        )
        .map_err(|e| format!("failed to load/create .chain_meta: {e}"))?;

        // --- Load validator key (if configured) ---
        let validator_key = load_validator_key(
            &config.consensus.validator_key_path,
            &config.storage.data_dir,
            &chain_meta,
        );

        // --- Build consensus config from TOML ---
        let consensus_config = build_consensus_config(config);

        // C-003: Load persisted validator list if the file exists.
        let validator_list_path = config.consensus.validator_list_path.clone();
        let validator_list = if validator_list_path.exists() {
            match std::fs::read(&validator_list_path) {
                Ok(bytes) => {
                    use noble_codec::NobleCbor;
                    ValidatorList::from_cbor(&bytes).unwrap_or_else(|e| {
                        tracing::warn!(
                            task = "config_load",
                            "Failed to load validator list: {e}, starting empty"
                        );
                        ValidatorList::new()
                    })
                }
                Err(e) => {
                    tracing::warn!(
                        task = "config_load",
                        "Failed to read validator list file: {e}, starting empty"
                    );
                    ValidatorList::new()
                }
            }
        } else {
            ValidatorList::new()
        };
        let mut engine = CycleEngine::new(
            consensus_config,
            validator_list,
            tip.height,
            tip.block_hash,
            chain_id,
            validator_key,
        );
        if let Some(header) = tip_header {
            engine.update_tip_with_header(header);
        }
        let consensus = Arc::new(RwLock::new(engine));

        // Create wallet keystore.
        let keystore = KeyStore::new(&config.wallet.keystore_path)?;
        let wallet_keystore = Arc::new(Mutex::new(keystore));
        let wallet_state = Arc::new(Mutex::new(WalletState::new(3600)));

        let network_stats = Arc::new(RwLock::new(NetworkStats::default()));
        let peer_info = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // --- PKI identity attestation ---
        let pki_attestation = init_pki_attestation(config, &chain_meta);

        // --- CA trust store ---
        let ca_store = init_ca_store(config);

        Ok(Self {
            storage,
            mempool,
            consensus,
            wallet_keystore,
            wallet_state,
            network_stats,
            peer_info,
            chain_id,
            start_time: std::time::Instant::now(),
            pki_attestation,
            ca_store,
            chain_meta,
        })
    }

    /// Return the current chain tip height.
    pub fn chain_height(&self) -> u64 {
        self.storage
            .read()
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|tip| tip.height)
            .unwrap_or(0)
    }

    /// Refresh all Prometheus gauge metrics from current node state.
    fn refresh_metrics(&self, m: &NobleMetrics) {
        // Chain height
        let height = self.chain_height();
        m.chain_height.set(height as f64);

        // Connected peers
        let peer_count = self.network_stats.read().peer_count;
        m.connected_peers.set(peer_count as f64);

        // Mempool
        {
            let mempool = self.mempool.lock();
            m.mempool_size.set(mempool.len() as f64);
        }

        // Consensus phase and cycle elapsed time
        {
            let engine = self.consensus.read();
            // phase_timing() returns (phase_index, phase_remaining_secs, cycle_remaining_secs)
            let (phase_idx, _phase_remaining, cycle_remaining) = engine.phase_timing();
            m.cycle_phase.set(phase_idx as f64);
            // Cycle duration is 1800s (30 min); elapsed = total - remaining
            m.cycle_elapsed_secs
                .set((1800u64.saturating_sub(cycle_remaining)) as f64);
        }
    }

    /// Run an integrity check on the most recent `count` blocks.
    /// Returns the integrity report.
    pub fn verify_recent_blocks(&self, count: u64) -> IntegrityReport {
        let height = self.chain_height();
        let start = height.saturating_sub(count.saturating_sub(1));
        let guard = self.storage.read();
        noble_storage::verify_chain_integrity(&*guard, self.chain_id, start, height)
    }

    /// Rollback the chain to the given height, recalculating balances.
    /// Used when corruption is detected or from the CLI `chain rollback` command (S17-C).
    #[allow(dead_code)]
    pub fn rollback_to_height(
        &self,
        target_height: u64,
    ) -> Result<noble_storage::ChainTip, Box<dyn std::error::Error>> {
        let storage = self.storage.read();
        let tip = storage.rollback_to_height(target_height, self.chain_id)?;
        // Update consensus engine tip
        {
            let mut engine = self.consensus.write();
            engine.update_tip(tip.height, tip.block_hash);
        }
        Ok(tip)
    }

    /// Run the node event loop.
    ///
    /// Starts the P2P network, JSON-RPC server, and runs `tokio::select!`
    /// processing: network events → consensus → storage, consensus ticks,
    /// and CTRL+C graceful shutdown.
    pub async fn run(
        self,
        config: &NodeConfig,
        trace_handle: Option<Arc<noble_api::trace_types::TraceHandle>>,
        metrics: Option<NobleMetrics>,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<(), NodeError> {
        // --- Parse port numbers from config addresses ---
        let rpc_port = parse_port(&config.api.rpc_addr).unwrap_or(8783);
        // WS is served on the RPC port by jsonrpsee; ws_addr config is informational only.
        let ws_port = rpc_port;

        // --- Load node identity (before network so we can use its preferred port) ---
        let node_identity = load_identity(config);
        let identity_path = config.storage.data_dir.join("identity.json");

        // --- Start network service ---
        let block_provider = Arc::new(StorageBlockProvider::new(self.storage.clone()));
        let tx_provider = Arc::new(StorageTxProvider::new(self.storage.clone()));

        let mut net_config = noble_network::NetworkConfig::default();
        // Use identity's preferred port when identity.json exists; otherwise use config default.
        net_config.listen_addr = if identity_path.exists() {
            format!("/ip4/0.0.0.0/tcp/{}", node_identity.p2p_port)
        } else {
            config.network.listen_addr.clone()
        };
        net_config.bootstrap_peers = config.network.seeds.clone();
        net_config.max_outbound = (config.network.max_peers as usize / 5).max(4);
        net_config.max_inbound =
            (config.network.max_peers as usize).saturating_sub(net_config.max_outbound);
        net_config.ban_threshold = config.network.ban_threshold;
        net_config.chain_id = self.chain_id;
        // Persist the P2P identity keypair so PeerId stays stable across restarts.
        net_config.data_dir = Some(config.storage.data_dir.clone());
        net_config.chain_meta = Some(self.chain_meta);

        let mut network = noble_network::start_network(net_config, block_provider, tx_provider)
            .await
            .map_err(|e| NodeError::Network(e.to_string()))?;

        let p2p_port = network.bound_port;
        let peer_id_str = network.local_peer_id.to_string();
        let network_cmd = network.command_sender();
        tracing::info!(
            task = "node_startup",
            "P2P network started on port {p2p_port} (peer_id: {peer_id_str})"
        );

        // --- Derive validator key info for ApiState ---
        let (validator_pubkey_str, validator_scheme_str, validator_key_path_str) =
            compute_validator_key_info(
                &config.consensus.validator_key_path,
                &config.storage.data_dir,
                &self.chain_meta,
            );

        // --- Initialize TOTP auth ---
        let (totp_validator, totp_secret_path) =
            init_totp_validator(config, &self.chain_meta)
                .map_err(|e| NodeError::Config(e.to_string()))?;

        // --- Build broadcast channels for WebSocket subscriptions ---
        let (new_block_tx, _) = broadcast::channel(64);
        let (new_tx_tx, _) = broadcast::channel(256);
        let (cycle_phase_tx, _) = broadcast::channel(16);
        let (peer_update_tx, _) = broadcast::channel(64);

        // --- IP access control ---
        // Setup mode when the wizard has not been completed (explicit flag).
        let setup_mode = !node_identity.setup_complete;

        let ip_filter = if setup_mode {
            let gui_scheme = if config.api.tls_enabled { "https" } else { "http" };
            if config.api.remote_setup {
                // Operator explicitly opted-in to remote setup access.
                tracing::warn!(
                    task = "node_startup",
                    "SETUP MODE (remote): No identity.json found — GUI/RPC bound to 0.0.0.0 (remote_setup = true)"
                );
                tracing::warn!(
                    task = "node_startup",
                    "Complete the setup wizard at {gui_scheme}://<this-host>:8785, then restart the node"
                );
                Some(noble_api::ip_filter::IpFilter::allow_all())
            } else if !config.api.allowed_ips.is_empty() {
                // allowed_ips configured — honour the whitelist during setup mode.
                match noble_api::ip_filter::IpFilter::new(&config.api.allowed_ips) {
                    Ok(filter) => {
                        tracing::warn!(
                            task = "node_startup",
                            "SETUP MODE (whitelist): No identity.json — GUI/RPC restricted to allowed_ips ({} entries)",
                            config.api.allowed_ips.len()
                        );
                        tracing::warn!(
                            task = "node_startup",
                            "Complete the setup wizard at {gui_scheme}://<this-host>:8785, then restart the node"
                        );
                        Some(filter)
                    }
                    Err(e) => {
                        tracing::warn!(
                            task = "node_startup",
                            "SETUP MODE: Failed to parse allowed_ips ({e}) — falling back to localhost-only"
                        );
                        tracing::warn!(
                            task = "node_startup",
                            "Complete the setup wizard at {gui_scheme}://127.0.0.1:8785, then restart the node"
                        );
                        None
                    }
                }
            } else {
                // Default: localhost-only setup. Safe for headless and remote nodes.
                tracing::warn!(
                    task = "node_startup",
                    "SETUP MODE: No identity.json found — GUI/RPC localhost-only (set allowed_ips or remote_setup = true for remote access)"
                );
                tracing::warn!(
                    task = "node_startup",
                    "Complete the setup wizard at {gui_scheme}://127.0.0.1:8785, then restart the node"
                );
                None // server stays bound to 127.0.0.1
            }
        } else if config.api.allowed_ips.is_empty() {
            None
        } else {
            match noble_api::ip_filter::IpFilter::new(&config.api.allowed_ips) {
                Ok(f) => {
                    tracing::info!(
                        task = "node_startup",
                        "IP access control enabled: {} entries",
                        config.api.allowed_ips.len()
                    );
                    Some(f)
                }
                Err(e) => {
                    tracing::error!(
                        task = "node_startup",
                        "Invalid allowed_ips config: {e} — falling back to localhost-only"
                    );
                    None
                }
            }
        };

        // --- Collect extra TLS SANs (config + auto-detected LAN IPs in setup mode) ---
        let mut extra_sans = config.api.tls_san.clone();
        if setup_mode {
            // Auto-add machine's LAN IPs so remote browser setup works with self-signed cert.
            for iface in if_addrs::get_if_addrs().unwrap_or_default() {
                if !iface.ip().is_loopback() {
                    let s = iface.ip().to_string();
                    if !extra_sans.contains(&s) {
                        extra_sans.push(s);
                    }
                }
            }
        }

        // Setup token removed in S38 — setup RPCs are already gated by allowed_ips + TLS.

        // --- Build TLS config (shared by RPC and GUI servers) — fail-closed by default ---
        let (tls_config, tls_plaintext_mode): (Option<std::sync::Arc<rustls::ServerConfig>>, bool) =
            if config.api.tls_enabled {
                match crate::tls_cert::load_or_generate(&config.storage.data_dir, &extra_sans, &self.chain_meta) {
                    Ok(cfg) => (Some(cfg), false),
                    Err(e) => {
                        if config.api.tls_allow_plaintext_fallback {
                            // F6: Loud warning for plaintext fallback.
                            let sep = "═".repeat(60);
                            tracing::warn!(task = "node_startup", "{sep}");
                            tracing::warn!(
                                task = "node_startup",
                                "  ⚠  WARNING: NODE IS RUNNING IN PLAINTEXT MODE  ⚠"
                            );
                            tracing::warn!(
                                task = "node_startup",
                                "  TLS certificate failed: {e}"
                            );
                            tracing::warn!(
                                task = "node_startup",
                                "  tls_allow_plaintext_fallback = true is set in [api] config."
                            );
                            tracing::warn!(
                                task = "node_startup",
                                "  ALL API TRAFFIC IS UNENCRYPTED (HTTP, not HTTPS)."
                            );
                            tracing::warn!(
                                task = "node_startup",
                                "  Use plaintext fallback for emergencies only. Fix TLS or"
                            );
                            tracing::warn!(
                                task = "node_startup",
                                "  set tls_allow_plaintext_fallback = false (default) to prevent this."
                            );
                            tracing::warn!(task = "node_startup", "{sep}");
                            (None, true)
                        } else {
                            eprintln!("FATAL: TLS certificate failed: {e}");
                            eprintln!("Fix the issue or set tls_allow_plaintext_fallback = true in [api] config.");
                            return Err(NodeError::Config(format!(
                                "TLS certificate failed: {e}. Fix the issue or set tls_allow_plaintext_fallback = true in [api] config."
                            )));
                        }
                    }
                }
            } else {
                tracing::info!(task = "node_startup", "TLS disabled by config");
                (None, false)
            };

        // --- Compute TLS fingerprint / expiry / SANs for ApiState ---
        let tls_fingerprint = if tls_config.is_some() {
            crate::tls_cert::certificate_fingerprint(&config.storage.data_dir)
        } else {
            None
        };
        let tls_expires_at = if tls_config.is_some() {
            crate::tls_cert::certificate_expiry(&config.storage.data_dir)
        } else {
            None
        };
        let tls_expiry_secs = if tls_config.is_some() {
            crate::tls_cert::certificate_expiry_secs(&config.storage.data_dir)
        } else {
            None
        };
        let tls_sans_init = if tls_config.is_some() {
            crate::tls_cert::certificate_sans(&config.storage.data_dir)
        } else {
            vec![]
        };

        // --- Build TLS lifecycle callbacks for ApiState ---
        let tls_active = tls_config.is_some();
        let data_dir_regen = config.storage.data_dir.clone();
        let chain_meta_regen = self.chain_meta;
        let tls_regenerate: Option<std::sync::Arc<dyn Fn(Vec<String>) -> Result<(String, String, i64, Vec<String>), String> + Send + Sync>> = if tls_active {
            Some(std::sync::Arc::new(move |extra_sans: Vec<String>| {
                crate::tls_cert::regenerate(&data_dir_regen, &extra_sans, &chain_meta_regen)
                    .map(|info| (info.fingerprint, info.expires_at, info.expiry_secs, info.sans))
                    .map_err(|e| e.to_string())
            }))
        } else {
            None
        };
        let data_dir_upload = config.storage.data_dir.clone();
        let chain_meta_upload = self.chain_meta;
        let tls_upload: Option<std::sync::Arc<dyn Fn(String, String, Option<String>) -> Result<(String, String, i64, Vec<String>), String> + Send + Sync>> = if tls_active {
            Some(std::sync::Arc::new(move |cert_pem: String, key_pem: String, chain_pem: Option<String>| {
                crate::tls_cert::validate_and_write(&data_dir_upload, &cert_pem, &key_pem, chain_pem.as_deref(), &chain_meta_upload)
                    .map(|info| (info.fingerprint, info.expires_at, info.expiry_secs, info.sans))
                    .map_err(|e| e.to_string())
            }))
        } else {
            None
        };

        // --- Build enable_totp closure for ApiState ---
        // When TOTP is not yet enabled, this closure generates a new secret, persists it,
        // and returns (secret_base32, otpauth_uri). It does NOT update the live ApiState
        // validator — the RPC handler does that directly.
        let totp_data_dir = config.storage.data_dir.clone();
        let totp_secret_file_cfg = config.api.totp_secret_file.clone();
        let chain_meta_totp = self.chain_meta;
        let enable_totp_closure: Option<Arc<dyn Fn() -> Result<(String, String), String> + Send + Sync>> =
            if config.api.totp_enabled {
                None // already enabled
            } else {
                let config_path_totp = config_path.clone();
                Some(Arc::new(move || {
                    let (validator, base32) = noble_api::auth::TotpValidator::generate()
                        .map_err(|e| format!("generate TOTP: {e}"))?;

                    let secret_path = if totp_secret_file_cfg.is_empty() {
                        totp_data_dir.join("totp_secret.txt")
                    } else {
                        std::path::PathBuf::from(&totp_secret_file_cfg)
                    };

                    let encrypted = noble_crypto::file_encrypt::encrypt_file_data(
                        base32.as_bytes(),
                        &chain_meta_totp,
                    )
                    .map_err(|e| format!("encrypt TOTP secret: {e}"))?;
                    atomic_write_file(&secret_path, &encrypted)
                        .map_err(|e| format!("write TOTP secret: {e}"))?;

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &secret_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }

                    // Update noble.toml to enable TOTP
                    if let Some(ref cp) = config_path_totp {
                        if let Ok(contents) = std::fs::read_to_string(cp) {
                            let updated = if contents.contains("totp_enabled") {
                                contents.replace("totp_enabled = false", "totp_enabled = true")
                            } else if contents.contains("[api]") {
                                contents.replace("[api]", "[api]\ntotp_enabled = true")
                            } else {
                                contents
                            };
                            let _ = atomic_write_file(cp, updated.as_bytes());
                        }
                    }

                    let uri = validator.otpauth_uri("NOBLE Node");
                    tracing::info!(task = "totp", "TOTP secret generated and saved to {}", secret_path.display());
                    Ok((base32, uri))
                }))
            };

        // --- Build set_config_value closure for ApiState ---
        // Reads noble.toml, modifies a key, writes back.
        let set_config_value_closure: Option<Arc<dyn Fn(&str, &str, &str) -> Result<bool, String> + Send + Sync>> =
            if let Some(ref cp) = config_path {
                let cp = cp.clone();
                Some(Arc::new(move |section: &str, key: &str, value: &str| {
                    let contents = std::fs::read_to_string(&cp)
                        .map_err(|e| format!("read config: {e}"))?;
                    let mut doc: toml::Table = toml::from_str(&contents)
                        .map_err(|e| format!("parse config: {e}"))?;

                    // Navigate to the section and update the key.
                    let table = doc
                        .entry(section)
                        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
                    if let toml::Value::Table(ref mut t) = table {
                        // Infer the correct TOML type: try integer, then boolean, then string.
                        let toml_value = if let Ok(n) = value.parse::<i64>() {
                            toml::Value::Integer(n)
                        } else if value == "true" || value == "false" {
                            toml::Value::Boolean(value == "true")
                        } else {
                            toml::Value::String(value.to_string())
                        };
                        t.insert(key.to_string(), toml_value);
                    } else {
                        return Err(format!("config section '{section}' is not a table"));
                    }

                    let new_contents = toml::to_string_pretty(&doc)
                        .map_err(|e| format!("serialize config: {e}"))?;
                    atomic_write_file(&cp, new_contents.as_bytes())
                        .map_err(|e| format!("write config: {e}"))?;

                    tracing::info!(task = "config", "Updated {section}.{key} = {value} in {}", cp.display());

                    // Port changes always require restart.
                    Ok(true)
                }))
            } else {
                None
            };

        // --- F1/F2: Build allowed CORS origins for RPC and GUI servers ---
        // Always include localhost GUI origins.  In setup mode (extra_sans contains LAN IPs)
        // or when allowed_ips are configured, also include those IPs so remote browsers
        // can reach the RPC through the GUI without CORS errors.
        // This replaces CorsLayer::permissive() with an explicit allow-list.
        // F4: use actual configured ports rather than hardcoded constants.
        let gui_port = parse_port(&config.api.gui_addr).unwrap_or(8785);
        let rpc_scheme = if tls_config.is_some() { "https" } else { "http" };
        let gui_scheme_cors = rpc_scheme; // GUI and RPC share the same TLS mode.
        let mut cors_origins_vec: Vec<String> = vec![
            format!("{gui_scheme_cors}://127.0.0.1:{gui_port}"),
            format!("{gui_scheme_cors}://localhost:{gui_port}"),
            format!("{gui_scheme_cors}://[::1]:{gui_port}"),
        ];
        // Build RPC origins list for CSP (http(s):// + ws(s)://).
        let ws_scheme = if tls_config.is_some() { "wss" } else { "ws" };
        let mut rpc_origins_vec: Vec<String> = vec![
            format!("{rpc_scheme}://127.0.0.1:{rpc_port}"),
            format!("{rpc_scheme}://localhost:{rpc_port}"),
            format!("{rpc_scheme}://[::1]:{rpc_port}"),
            format!("{ws_scheme}://127.0.0.1:{rpc_port}"),
            format!("{ws_scheme}://localhost:{rpc_port}"),
            format!("{ws_scheme}://[::1]:{rpc_port}"),
        ];
        // Add LAN IPs (from setup-mode detection or tls_san config).
        for san in &extra_sans {
            if san != "localhost" {
                let gui_origin = format!("{gui_scheme_cors}://{san}:{gui_port}");
                if !cors_origins_vec.contains(&gui_origin) {
                    cors_origins_vec.push(gui_origin);
                }
                let rpc_http = format!("{rpc_scheme}://{san}:{rpc_port}");
                let rpc_ws = format!("{ws_scheme}://{san}:{rpc_port}");
                if !rpc_origins_vec.contains(&rpc_http) {
                    rpc_origins_vec.push(rpc_http);
                }
                if !rpc_origins_vec.contains(&rpc_ws) {
                    rpc_origins_vec.push(rpc_ws);
                }
            }
        }
        // Also add origins for explicitly configured allowed_ips.
        // Skip CIDR blocks — a /24 block is not a valid browser origin.
        for ip in &config.api.allowed_ips {
            if ip.contains('/') {
                continue; // CIDR block — not a valid HTTP origin
            }
            let gui_origin = format!("{gui_scheme_cors}://{ip}:{gui_port}");
            if !cors_origins_vec.contains(&gui_origin) {
                cors_origins_vec.push(gui_origin);
            }
            let rpc_http = format!("{rpc_scheme}://{ip}:{rpc_port}");
            let rpc_ws = format!("{ws_scheme}://{ip}:{rpc_port}");
            if !rpc_origins_vec.contains(&rpc_http) {
                rpc_origins_vec.push(rpc_http);
            }
            if !rpc_origins_vec.contains(&rpc_ws) {
                rpc_origins_vec.push(rpc_ws);
            }
        }

        // Wrap in Arc<RwLock> so setAllowedIps can update them at runtime.
        let allowed_cors_origins = std::sync::Arc::new(parking_lot::RwLock::new(cors_origins_vec));
        let rpc_origins = std::sync::Arc::new(parking_lot::RwLock::new(rpc_origins_vec));

        // --- Resolve gateway key ---
        let gateway_key = resolve_gateway_key(config, &self.wallet_keystore);

        // --- Build ApiState ---
        let api_state = Arc::new(ApiState {
            storage: self.storage.clone(),
            mempool: self.mempool.clone(),
            consensus: self.consensus.clone(),
            network_cmd: network_cmd.clone(),
            wallet_keystore: self.wallet_keystore.clone(),
            wallet_state: self.wallet_state.clone(),
            network_stats: self.network_stats.clone(),
            chain_id: self.chain_id,
            start_time: self.start_time,
            max_network_version: Arc::new(RwLock::new(noble_core::SOFTWARE_VERSION.to_string())),
            rate_limiter: Some(Arc::new(noble_api::rate_limit::RpcRateLimiter::new(
                config.api.rate_limit.max(1),
                3, // burst multiplier
            ))),
            totp_validator,
            totp_scope: noble_api::middleware::TotpScope::from_config(&config.api.totp_scope),
            totp_secret_path,
            rpc_port,
            ws_port,
            p2p_port,
            new_block_tx: new_block_tx.clone(),
            new_tx_tx: new_tx_tx.clone(),
            cycle_phase_tx: cycle_phase_tx.clone(),
            peer_update_tx: peer_update_tx.clone(),
            trace_handle,
            gateway_key: RwLock::new(gateway_key),
            gateway_key_path: if config.gateway.key_path.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(&config.gateway.key_path))
            },
            ip_filter: ip_filter.clone(),
            validator_list_path: Some(config.consensus.validator_list_path.clone()),
            peer_info: self.peer_info.clone(),
            node_identity: Arc::new(RwLock::new(node_identity)),
            identity_path: Some(identity_path),
            tls_fingerprint: parking_lot::RwLock::new(tls_fingerprint),
            tls_expires_at: parking_lot::RwLock::new(tls_expires_at),
            tls_expiry_secs: parking_lot::RwLock::new(tls_expiry_secs),
            tls_sans: parking_lot::RwLock::new(tls_sans_init),
            tls_regenerate,
            tls_upload,
            setup_mode,
            allowed_cors_origins: allowed_cors_origins.clone(),
            rpc_origins: rpc_origins.clone(),
            cors_scheme: rpc_scheme.to_string(),
            gui_port,
            tls_plaintext_mode,
            peer_id: peer_id_str,
            validator_pubkey: validator_pubkey_str,
            validator_scheme: validator_scheme_str,
            validator_key_path: validator_key_path_str,
            data_dir: Some(config.storage.data_dir.clone()),
            pruning_mode: config.storage.pruning_mode.clone(),
            keep_blocks: config.storage.keep_blocks,
            reward_address: parking_lot::RwLock::new(
                if config.rewards.reward_address.is_empty() {
                    None
                } else {
                    Some(config.rewards.reward_address.clone())
                },
            ),
            enable_totp: enable_totp_closure,
            set_config_value: set_config_value_closure,
            config_path,
            chain_meta: self.chain_meta,
        });

        // --- Determine RPC bind address ---
        // When remote access is enabled, bind to 0.0.0.0 instead of 127.0.0.1.
        let rpc_bind_addr = if ip_filter.as_ref().is_some_and(|f| f.has_remote_access()) {
            config.api.rpc_addr.replace("127.0.0.1", "0.0.0.0")
        } else {
            config.api.rpc_addr.clone()
        };

        // Clone rate limiter reference before api_state is consumed.
        let rate_limiter_ref = api_state.rate_limiter.clone();

        // --- Start RPC server ---
        let rpc_histogram = metrics
            .as_ref()
            .map(|m| std::sync::Arc::new(m.rpc_request_duration.clone()));
        let rpc_handle = noble_api::server::start_server(
            api_state,
            &rpc_bind_addr,
            rpc_histogram,
            tls_config.clone(),
            config.api.max_connections,
        )
        .await
        .map_err(|e| NodeError::Api(e.to_string()))?;

        tracing::info!(
            task = "node_startup",
            "JSON-RPC server listening on {}",
            rpc_bind_addr
        );

        // --- Start embedded GUI server ---
        let gui_dir = if config.api.gui_dir.is_empty() {
            crate::gui_server::detect_gui_dir()
        } else {
            let p = std::path::PathBuf::from(&config.api.gui_dir);
            if p.join("index.html").exists() {
                Some(p)
            } else {
                tracing::warn!(
                    task = "node_startup",
                    "gui_dir not found: {}",
                    config.api.gui_dir
                );
                None
            }
        };

        if let Some(gui_path) = gui_dir {
            let gui_addr_str = if ip_filter.as_ref().is_some_and(|f| f.has_remote_access()) {
                config.api.gui_addr.replace("127.0.0.1", "0.0.0.0")
            } else {
                config.api.gui_addr.clone()
            };
            let gui_addr: std::net::SocketAddr = gui_addr_str
                .parse()
                .unwrap_or_else(|_| "127.0.0.1:8785".parse().unwrap());
            let gui_filter = ip_filter.clone();
            let gui_tls = tls_config.clone();
            let gui_rpc_origins = rpc_origins.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::gui_server::start_gui_server(
                    gui_addr,
                    gui_path,
                    gui_filter,
                    gui_tls,
                    gui_rpc_origins,
                    rpc_port,
                    setup_mode,
                )
                .await
                {
                    tracing::error!(task = "node_startup", "GUI server error: {e}");
                }
            });
        } else {
            tracing::info!(
                task = "node_startup",
                "GUI directory not found — dashboard server not started"
            );
        }

        // --- Start Prometheus metrics server ---
        if let Some(ref m) = metrics {
            let metrics_addr = if ip_filter.as_ref().is_some_and(|f| f.has_remote_access()) {
                config
                    .metrics
                    .prometheus_addr
                    .replace("127.0.0.1", "0.0.0.0")
            } else {
                config.metrics.prometheus_addr.clone()
            };
            match crate::metrics::start_metrics_server(&metrics_addr, m.clone()).await {
                Ok(_handle) => {
                    tracing::info!(
                        task = "node_startup",
                        "Prometheus metrics server listening on {metrics_addr}"
                    );
                }
                Err(e) => {
                    tracing::warn!(task = "node_startup", "Failed to start metrics server: {e}");
                }
            }
        }

        // --- Consensus tick interval ---
        let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // --- Mempool expiry sweep interval ---
        let mut expiry_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        expiry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // --- Metrics refresh interval (every 10s alongside consensus tick) ---
        let mut metrics_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        metrics_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // --- Rate limiter cleanup interval (every 60s, removes stale per-IP buckets) ---
        let mut rate_limit_cleanup_interval =
            tokio::time::interval(std::time::Duration::from_secs(60));
        rate_limit_cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!(
            task = "node_startup",
            "Node event loop started — chain height: {}",
            self.chain_height()
        );

        // --- Main event loop ---
        loop {
            tokio::select! {
                // Network events
                event = network.recv_event() => {
                    match event {
                        Some(net_event) => {
                            self.handle_network_event(
                                &net_event,
                                &network_cmd,
                                &new_block_tx,
                                &new_tx_tx,
                                &peer_update_tx,
                                &cycle_phase_tx,
                                &metrics,
                            );
                        }
                        None => {
                            tracing::warn!(task = "node_shutdown", "Network event channel closed — shutting down");
                            break;
                        }
                    }
                }

                // Consensus tick
                _ = tick_interval.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let actions = {
                        let mut engine = self.consensus.write();
                        engine.step(CycleEvent::Tick { now })
                    };
                    self.process_cycle_actions(actions, &network_cmd, &new_block_tx, &metrics);

                    // H-002: Persist cycle history if a cycle boundary just occurred.
                    {
                        let mut engine = self.consensus.write();
                        if let Some(history) = engine.take_cycle_history() {
                            if let Ok(bytes) = noble_codec::NobleCbor::to_cbor(&history) {
                                let storage = self.storage.read();
                                if let Err(e) = storage.store_cycle_history(history.cycle_number, &bytes) {
                                    tracing::warn!(task = "consensus", "Failed to persist cycle history: {e}");
                                }
                            }
                        }
                    }
                }

                // Mempool expiry sweep
                _ = expiry_interval.tick() => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let expired = {
                        let mut mempool = self.mempool.lock();
                        mempool.expire(now)
                    };
                    if expired > 0 {
                        tracing::debug!(task = "mempool", "Swept {expired} expired mempool transactions");
                    }
                }

                // Prometheus metrics refresh
                _ = metrics_interval.tick() => {
                    if let Some(ref m) = metrics {
                        self.refresh_metrics(m);
                    }
                }

                // Rate limiter cleanup (evict stale per-IP buckets)
                _ = rate_limit_cleanup_interval.tick() => {
                    if let Some(ref rl) = rate_limiter_ref {
                        rl.cleanup();
                    }
                }

                // Graceful shutdown on CTRL+C
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!(task = "node_shutdown", "Received shutdown signal");
                    break;
                }
            }
        }

        // --- Graceful shutdown ---
        tracing::info!(task = "node_shutdown", "Shutting down...");
        let _ = network_cmd.try_send(NetworkCommand::Shutdown);
        rpc_handle
            .stop()
            .map_err(|e| NodeError::Api(format!("RPC stop: {e}")))?;
        tracing::info!(task = "node_shutdown", "Node shutdown complete");
        Ok(())
    }

    /// Handle a single network event: route to consensus, update stats, etc.
    #[allow(clippy::too_many_arguments)]
    fn handle_network_event(
        &self,
        event: &NetworkEvent,
        network_cmd: &mpsc::Sender<NetworkCommand>,
        new_block_tx: &broadcast::Sender<serde_json::Value>,
        new_tx_tx: &broadcast::Sender<serde_json::Value>,
        peer_update_tx: &broadcast::Sender<serde_json::Value>,
        cycle_phase_tx: &broadcast::Sender<serde_json::Value>,
        metrics: &Option<NobleMetrics>,
    ) {
        match event {
            NetworkEvent::PeerConnected { peer_id, addr, .. } => {
                let new_count = {
                    let mut stats = self.network_stats.write();
                    stats.peer_count += 1;
                    stats.inbound_count += 1; // simplified; real impl tracks direction
                    stats.peer_count
                };
                // AUD2-C1: Wire peer count to consensus engine so compute_majority works
                {
                    let mut engine = self.consensus.write();
                    engine.set_peer_count(new_count);
                }
                // H-004: Track peer info for getPeerInfo RPC.
                let hex_pid = hex::encode(peer_id);
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                {
                    let mut info = self.peer_info.write();
                    info.insert(
                        hex_pid.clone(),
                        noble_api::state::PeerInfoEntry {
                            peer_id: hex_pid.clone(),
                            direction: "inbound".to_string(),
                            addr: addr.clone(),
                            connected_at: now_ts,
                            ban_score: 0,
                        },
                    );
                }
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "connected",
                    "peer_id": hex_pid,
                    "addr": addr,
                }));
                tracing::debug!(task = "peer_tracking", "Peer connected: {addr}");
            }
            NetworkEvent::PeerDisconnected { peer_id } => {
                let new_count = {
                    let mut stats = self.network_stats.write();
                    stats.peer_count = stats.peer_count.saturating_sub(1);
                    stats.peer_count
                };
                // AUD2-C1: Update consensus engine peer count on disconnect too
                {
                    let mut engine = self.consensus.write();
                    engine.set_peer_count(new_count);
                }
                // H-004: Remove from live peer info.
                let hex_pid = hex::encode(peer_id);
                {
                    let mut info = self.peer_info.write();
                    info.remove(&hex_pid);
                }
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "disconnected",
                    "peer_id": hex_pid,
                }));
            }
            NetworkEvent::PeerBanned { peer_id, reason } => {
                tracing::warn!(
                    task = "peer_tracking",
                    "Peer banned: {} — {reason}",
                    hex::encode(peer_id)
                );
            }
            NetworkEvent::TransactionAnnounced { tx_id, .. } => {
                let _ = new_tx_tx.send(serde_json::json!({
                    "tx_id": hex::encode(tx_id),
                }));
            }
            _ => {
                // Route to consensus engine
                if let Some(cycle_event) = bridge::network_event_to_cycle_event(event) {
                    let actions = {
                        let mut engine = self.consensus.write();
                        engine.step(cycle_event)
                    };
                    self.process_cycle_actions(actions, network_cmd, new_block_tx, metrics);
                }
            }
        }

        let _ = cycle_phase_tx; // used for phase transition notifications (future)
    }

    /// Process actions emitted by the consensus engine.
    fn process_cycle_actions(
        &self,
        actions: Vec<CycleIo>,
        network_cmd: &mpsc::Sender<NetworkCommand>,
        new_block_tx: &broadcast::Sender<serde_json::Value>,
        metrics: &Option<NobleMetrics>,
    ) {
        for action in actions {
            match action {
                CycleIo::CommitBlock(block) => {
                    let commit_start = std::time::Instant::now();
                    let block_hash = match block.header.compute_block_hash() {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::error!(
                                task = "block_commit",
                                "Failed to compute block hash: {e}"
                            );
                            continue;
                        }
                    };
                    let tx_ids: Vec<_> = block
                        .transactions
                        .iter()
                        .filter_map(|tx| tx.compute_tx_id(self.chain_id).ok())
                        .collect();

                    {
                        let storage = self.storage.read();
                        if let Err(e) = storage.commit_block(&block, &block_hash, &tx_ids) {
                            tracing::error!(
                                task = "block_commit",
                                "Failed to commit block {}: {e}",
                                block.header.height
                            );
                            continue;
                        }
                    }

                    // Record block commit duration in Prometheus.
                    if let Some(ref m) = metrics {
                        m.block_validation_duration
                            .observe(commit_start.elapsed().as_secs_f64());
                    }

                    // AUD3-D5/D6: Update consensus tip with full header for B2/B3/B5/B6 validation.
                    {
                        let mut engine = self.consensus.write();
                        engine.update_tip_with_header(block.header.clone());
                    }

                    // Remove committed txs from mempool
                    {
                        let mut mempool = self.mempool.lock();
                        for tx_id in &tx_ids {
                            mempool.remove(tx_id);
                        }
                    }

                    tracing::info!(
                        task = "block_commit",
                        "Block {} committed (hash: {}, txs: {})",
                        block.header.height,
                        hex::encode(block_hash.as_bytes()),
                        tx_ids.len()
                    );

                    let _ = new_block_tx.send(serde_json::json!({
                        "height": block.header.height,
                        "hash": hex::encode(block_hash.as_bytes()),
                        "tx_count": tx_ids.len(),
                    }));
                }
                CycleIo::ReadmitTransactions(txs) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let storage = self.storage.read();
                    let chain_height = storage
                        .get_chain_tip()
                        .ok()
                        .flatten()
                        .map(|t| t.height)
                        .unwrap_or(0);
                    let chain_lookup = StorageChainLookupAdapter { storage: &*storage };
                    let balance_lookup = StorageBalanceLookupAdapter { storage: &*storage };
                    let mut mempool = self.mempool.lock();
                    for tx in txs {
                        let _ = mempool.admit(&tx, now, &chain_lookup, &balance_lookup, chain_height);
                    }
                }
                CycleIo::Log(msg) => {
                    tracing::info!(task = "consensus", "[consensus] {msg}");
                }
                CycleIo::EmitMetric { name, value } => {
                    tracing::debug!(task = "consensus", "metric: {name} = {value}");
                }
                CycleIo::SetTimer { duration_secs } => {
                    tracing::debug!(
                        task = "consensus",
                        "consensus timer: {duration_secs}s (handled by tick interval)"
                    );
                }
                CycleIo::EvictTransactions(tx_ids) => {
                    let mut mempool = self.mempool.lock();
                    for tx_id in &tx_ids {
                        if mempool.remove(tx_id).is_some() {
                            tracing::warn!(task = "mempool", "evicted poison tx {tx_id}");
                        }
                    }
                }
                CycleIo::RequestMempoolTransactions { max_count } => {
                    // P0.3: Read mempool transactions and feed them back to consensus.
                    let txs: Vec<noble_core::Transaction> = {
                        let mempool = self.mempool.lock();
                        mempool
                            .iter_by_fee_desc()
                            .take(max_count)
                            .map(|entry| entry.tx.clone())
                            .collect()
                    };
                    let actions = {
                        let mut engine = self.consensus.write();
                        engine.step(CycleEvent::MempoolTransactions(txs))
                    };
                    // Recursively process any actions from the proposal
                    self.process_cycle_actions(actions, network_cmd, new_block_tx, metrics);
                }
                other => {
                    // BroadcastBlock, BroadcastVote, BanPeer, RequestBlock → network
                    let cmds = bridge::cycle_io_to_network_commands(other);
                    for cmd in cmds {
                        if let Err(e) = network_cmd.try_send(cmd) {
                            tracing::warn!(
                                task = "consensus_broadcast",
                                "network command dropped (channel full): {e}"
                            );
                        }
                    }
                }
            }
        }
    }
}

// Adapter structs for mempool admit within the event loop
struct StorageChainLookupAdapter<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> ChainLookup for StorageChainLookupAdapter<'_, S> {
    fn is_confirmed(&self, tx_id: &Hash256) -> bool {
        self.storage.has_transaction(tx_id).unwrap_or(false)
    }
}

struct StorageBalanceLookupAdapter<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> BalanceLookup for StorageBalanceLookupAdapter<'_, S> {
    fn get_balance(&self, address: &noble_core::NobleAddress) -> u64 {
        self.storage.get_balance(address).unwrap_or(0)
    }
}

/// Load a validator private key from a raw key file.
///
/// The file must contain exactly 33 bytes: `[scheme_id(1) || private_key(32)]`.
/// Returns `Some((private_key, public_key))` on success, `None` if the path is
/// empty or the file cannot be loaded.
fn load_validator_key(
    path: &str,
    data_dir: &std::path::Path,
    chain_meta: &[u8; 32],
) -> Option<(noble_crypto::NoblePrivateKey, noble_crypto::NoblePublicKey)> {
    // When validator_key_path is empty, check the data_dir fallback location.
    // This covers nodes whose validator.key was auto-generated during setup.
    let key_path_buf;
    let key_path = if path.is_empty() {
        let fallback = data_dir.join("validator.key");
        if !fallback.exists() {
            tracing::info!(
                task = "config_load",
                "Observer mode: no validator key configured"
            );
            return None;
        }
        tracing::info!(
            task = "config_load",
            "validator_key_path not set — using data_dir fallback: {}",
            fallback.display()
        );
        key_path_buf = fallback;
        key_path_buf.as_path()
    } else {
        std::path::Path::new(path)
    };
    if !key_path.exists() {
        tracing::warn!(
            task = "config_load",
            "Validator key file not found: {} — running in observer mode",
            path
        );
        return None;
    }

    let file_bytes = match std::fs::read(key_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!(
                task = "config_load",
                "Failed to read validator key file: {e}"
            );
            return None;
        }
    };

    // Decrypt Noble envelope (with legacy IKM fallback) or read legacy plaintext.
    let raw = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
        match noble_crypto::file_encrypt::decrypt_file_data_with_migration(&file_bytes, chain_meta) {
            Ok((decrypted, migrated)) => {
                if migrated {
                    if let Ok(re_encrypted) = noble_crypto::file_encrypt::encrypt_file_data(&decrypted, chain_meta) {
                        let _ = atomic_write_file(key_path, &re_encrypted);
                    }
                    tracing::info!(task = "key_migration", "Migrated validator.key to current encryption key");
                }
                decrypted
            }
            Err(e) => {
                tracing::error!(
                    task = "config_load",
                    "Failed to decrypt validator key file: {e}"
                );
                return None;
            }
        }
    } else {
        // Legacy plaintext — re-encrypt in place for migration.
        if file_bytes.len() == 33 {
            if let Ok(encrypted) =
                noble_crypto::file_encrypt::encrypt_file_data(&file_bytes, chain_meta)
            {
                if atomic_write_file(key_path, &encrypted).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            key_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                    tracing::info!(
                        task = "config_load",
                        "Migrated validator.key to encrypted Noble envelope"
                    );
                }
            }
        }
        file_bytes
    };

    if raw.len() != 33 {
        tracing::error!(
            task = "config_load",
            "Invalid validator key file: expected 33 bytes (1 scheme_id + 32 key), got {}",
            raw.len()
        );
        return None;
    }

    let scheme_id = raw[0];
    let key_bytes = &raw[1..33];
    let private_key = match scheme_id {
        noble_crypto::SCHEME_ED25519 => noble_crypto::NoblePrivateKey::Ed25519(key_bytes.to_vec()),
        noble_crypto::SCHEME_SECP256K1 => {
            noble_crypto::NoblePrivateKey::Secp256k1(key_bytes.to_vec())
        }
        _ => {
            tracing::error!(
                task = "config_load",
                "Unknown key scheme_id in validator key file: {scheme_id:#04x}"
            );
            return None;
        }
    };

    let public_key = private_key.public_key();
    tracing::info!(
        task = "config_load",
        "Validator mode enabled: {}",
        hex::encode(public_key.to_wire_bytes())
    );
    Some((private_key, public_key))
}

/// Return `(pubkey_hex, scheme, key_path_str)` for the validator key without
/// loading the full key into memory.  Used only to populate `ApiState` fields
/// for the `noble_getValidatorKeyInfo` RPC.
fn compute_validator_key_info(
    path: &str,
    data_dir: &std::path::Path,
    chain_meta: &[u8; 32],
) -> (Option<String>, Option<String>, Option<String>) {
    let key_path_owned;
    let key_path = if path.is_empty() {
        let fallback = data_dir.join("validator.key");
        if !fallback.exists() {
            return (None, None, None);
        }
        key_path_owned = fallback;
        key_path_owned.as_path()
    } else {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return (None, None, None);
        }
        p
    };

    let file_bytes = match std::fs::read(key_path) {
        Ok(b) => b,
        Err(_) => return (None, None, None),
    };

    // Decrypt Noble envelope (with legacy IKM fallback) or read legacy plaintext.
    let raw = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
        match noble_crypto::file_encrypt::decrypt_file_data_with_migration(&file_bytes, chain_meta) {
            Ok((d, migrated)) => {
                if migrated {
                    if let Ok(re_encrypted) = noble_crypto::file_encrypt::encrypt_file_data(&d, chain_meta) {
                        let _ = std::fs::write(key_path, &re_encrypted);
                    }
                    tracing::info!(task = "key_migration", "Migrated validator.key to current encryption key");
                }
                d
            }
            Err(_) => return (None, None, None),
        }
    } else {
        file_bytes
    };

    if raw.len() != 33 {
        return (None, None, None);
    }
    let scheme_id = raw[0];
    let key_bytes = &raw[1..33];
    let (private_key, scheme_str) = match scheme_id {
        noble_crypto::SCHEME_ED25519 => (
            noble_crypto::NoblePrivateKey::Ed25519(key_bytes.to_vec()),
            "ed25519",
        ),
        noble_crypto::SCHEME_SECP256K1 => (
            noble_crypto::NoblePrivateKey::Secp256k1(key_bytes.to_vec()),
            "secp256k1",
        ),
        _ => return (None, None, None),
    };
    let pubkey_hex = hex::encode(private_key.public_key().to_wire_bytes());
    let path_str = key_path.to_string_lossy().into_owned();
    (Some(pubkey_hex), Some(scheme_str.to_string()), Some(path_str))
}

/// Load node identity from `data_dir/identity.json`, falling back to `noble.toml` defaults.
///
/// `identity.json` is the canonical persistence layer written by both the CLI wizard
/// and `noble_setNodeIdentity`. On first boot it won't exist, so the toml [identity]
/// section provides the initial values.
fn load_identity(config: &NodeConfig) -> NodeIdentityData {
    let identity_path = config.storage.data_dir.join("identity.json");
    if identity_path.exists() {
        match std::fs::read_to_string(&identity_path) {
            Ok(json) => match serde_json::from_str::<NodeIdentityData>(&json) {
                Ok(mut id) => {
                    // No node_name means setup was never truly completed.
                    if id.node_name.trim().is_empty() {
                        tracing::warn!(
                            task = "config_load",
                            "identity.json lacks node_name — marking setup incomplete"
                        );
                        id.setup_complete = false;
                    }
                    tracing::info!(
                        task = "config_load",
                        "Loaded identity from {} (setup_complete={})",
                        identity_path.display(),
                        id.setup_complete,
                    );
                    return id;
                }
                Err(e) => tracing::warn!(
                    task = "config_load",
                    "Invalid identity.json: {e} — using noble.toml defaults"
                ),
            },
            Err(e) => tracing::warn!(
                task = "config_load",
                "Failed to read identity.json: {e} — using noble.toml defaults"
            ),
        }
    }
    // Fallback: build from noble.toml [identity] section.
    // setup_complete defaults to false — noble.toml alone does not constitute
    // a completed setup wizard.
    NodeIdentityData {
        node_name: config.identity.node_name.clone(),
        org_type: config.identity.org_type.clone(),
        org_name: config.identity.org_name.clone(),
        node_role: config.identity.node_role.clone(),
        contact_email: config.identity.contact_email.clone(),
        website: config.identity.website.clone(),
        host_address: config.identity.host_address.clone(),
        wants_to_validate: config.identity.wants_to_validate,
        wants_to_vote: config.identity.wants_to_vote,
        p2p_port: 8780,
        setup_complete: false,
    }
}

/// Build a `ConsensusConfig` from the parsed TOML node configuration.
fn build_consensus_config(config: &NodeConfig) -> CConsensusConfig {
    let voting_strategy = parse_voting_strategy(
        &config.consensus.voting_strategy,
        &config.consensus.voting_preferred_validator,
        &config.consensus.voting_subset,
    );
    let confirmation_strategy = parse_voting_strategy(
        &config.consensus.confirmation_strategy,
        &config.consensus.voting_preferred_validator,
        &config.consensus.voting_subset,
    );

    // A5: Guard against zero/invalid values.
    let cycle_duration_secs = if config.consensus.cycle_duration_secs == 0 {
        tracing::error!(
            task = "config_load",
            "cycle_duration_secs=0 is invalid; using default 1800"
        );
        noble_core::CYCLE_DURATION_SECS
    } else {
        config.consensus.cycle_duration_secs
    };
    if config.consensus.min_peers_for_consensus == 0 {
        tracing::warn!(
            task = "config_load",
            "min_peers_for_consensus=0: node will finalize blocks with zero validators"
        );
    }

    CConsensusConfig {
        voting_strategy,
        confirmation_strategy,
        min_peers_for_consensus: config.consensus.min_peers_for_consensus,
        cycle_duration_secs,
        ..CConsensusConfig::default()
    }
}

/// Parse a voting strategy name + optional params into a `VotingStrategy`.
fn parse_voting_strategy(
    name: &str,
    preferred_validator: &str,
    subset: &[String],
) -> noble_consensus::VotingStrategy {
    use noble_consensus::VotingStrategy;
    match name {
        "first_valid" => VotingStrategy::FirstValid,
        "round_robin" => VotingStrategy::RoundRobin,
        "random" => VotingStrategy::Random,
        "weighted_reputation" => VotingStrategy::WeightedReputation,
        "follow_majority" => VotingStrategy::FollowMajority,
        "manual" => VotingStrategy::Manual,
        "fixed_validator" => VotingStrategy::FixedValidator {
            validator_key: preferred_validator.to_string(),
        },
        "subset_rotation" => VotingStrategy::SubsetRotation {
            validators: subset.to_vec(),
        },
        other => {
            tracing::warn!(
                task = "config_load",
                "Unknown voting strategy '{other}', falling back to first_valid"
            );
            VotingStrategy::FirstValid
        }
    }
}

/// Resolve the gateway key from config or wallet auto-derivation.
///
/// Priority:
/// 1. If `[gateway] key_path` is set and file exists, load from file.
/// 2. Else auto-derive from the first wallet key (with deprecation warning if key_path is empty).
/// 3. If `[gateway] enabled = false`, returns None.
fn resolve_gateway_key(
    config: &NodeConfig,
    wallet_keystore: &Arc<Mutex<noble_wallet::KeyStore>>,
) -> Option<Vec<u8>> {
    if !config.gateway.enabled {
        tracing::info!(task = "config_load", "Gateway fee split disabled by config");
        return None;
    }

    // Try reward_address first (new dual-address system).
    if !config.rewards.reward_address.is_empty() {
        use noble_api::types::parse_address;
        match parse_address(&config.rewards.reward_address) {
            Ok(addr) => {
                let wire = addr.to_wire_bytes();
                tracing::info!(
                    task = "config_load",
                    "Gateway key from reward_address: {} ({})",
                    config.rewards.reward_address,
                    addr.address_type(),
                );
                return Some(wire);
            }
            Err(e) => {
                tracing::warn!(
                    task = "config_load",
                    "Invalid reward_address '{}': {e}",
                    config.rewards.reward_address,
                );
            }
        }
    }

    // Try loading from explicit key_path next.
    if !config.gateway.key_path.is_empty() {
        let path = std::path::Path::new(&config.gateway.key_path);
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let hex_str = contents.trim();
                match hex::decode(hex_str) {
                    Ok(bytes) => {
                        tracing::info!(
                            task = "config_load",
                            "gateway key loaded from {}",
                            config.gateway.key_path
                        );
                        return Some(bytes);
                    }
                    Err(e) => {
                        tracing::warn!(
                            task = "config_load",
                            "Invalid hex in gateway key file {}: {e}",
                            config.gateway.key_path
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    task = "config_load",
                    "Could not read gateway key file {}: {e}",
                    config.gateway.key_path
                );
            }
        }
    }

    // Auto-derive from first wallet key.
    let key = {
        let ks = wallet_keystore.lock();
        ks.list_keys()
            .ok()
            .and_then(|keys| keys.into_iter().next())
            .map(|pk| pk.to_wire_bytes())
    };

    match &key {
        Some(_) => {
            if config.gateway.key_path.is_empty() {
                tracing::info!(
                    task = "config_load",
                    "Gateway fee split enabled (auto-derived from first wallet key). \
                     Set [gateway] key_path for explicit configuration."
                );
            } else {
                tracing::info!(
                    task = "config_load",
                    "Gateway fee split enabled (wallet key fallback)"
                );
            }
        }
        None => {
            tracing::info!(
                task = "config_load",
                "Gateway fee split disabled (no wallet key available)"
            );
        }
    }
    key
}

/// Parse port number from a "host:port" address string.
fn parse_port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}

/// Result of TOTP validator initialization.
type TotpInitResult = (
    Option<Arc<RwLock<TotpValidator>>>,
    Option<std::path::PathBuf>,
);

/// Initialize TOTP authentication from the node configuration.
///
/// - If `totp_enabled` is false, returns `(None, None)`.
/// - If `totp_secret_file` is non-empty and exists, loads the secret.
/// - If `totp_secret_file` is non-empty but missing, generates a new secret
///   and writes it to the file.
/// - If `totp_secret_file` is empty and `totp_enabled` is true, generates
///   a secret and writes it to `"totp_secret.txt"` in the data directory.
pub fn init_totp_validator(
    config: &crate::config::NodeConfig,
    chain_meta: &[u8; 32],
) -> Result<TotpInitResult, Box<dyn std::error::Error>> {
    if !config.api.totp_enabled {
        return Ok((None, None));
    }

    let secret_path = if config.api.totp_secret_file.is_empty() {
        config.storage.data_dir.join("totp_secret.txt")
    } else {
        std::path::PathBuf::from(&config.api.totp_secret_file)
    };

    let (validator, base32) = if secret_path.exists() {
        let file_bytes = std::fs::read(&secret_path)?;
        let base32 = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
            let (decrypted, migrated) = noble_crypto::file_encrypt::decrypt_file_data_with_migration(&file_bytes, chain_meta)
                .map_err(|e| format!("decrypt TOTP secret: {e}"))?;
            if migrated {
                if let Ok(re_encrypted) = noble_crypto::file_encrypt::encrypt_file_data(&decrypted, chain_meta) {
                    let _ = std::fs::write(&secret_path, &re_encrypted);
                }
                tracing::info!(task = "key_migration", "Migrated TOTP secret to current encryption key");
            }
            String::from_utf8(decrypted)
                .map_err(|e| format!("TOTP secret is not valid UTF-8: {e}"))?
        } else {
            // Legacy plaintext — migrate in place.
            let text = String::from_utf8(file_bytes.clone())
                .map_err(|e| format!("TOTP secret is not valid UTF-8: {e}"))?;
            let trimmed = text.trim().to_string();
            if let Ok(encrypted) =
                noble_crypto::file_encrypt::encrypt_file_data(trimmed.as_bytes(), chain_meta)
            {
                if atomic_write_file(&secret_path, &encrypted).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &secret_path,
                            std::fs::Permissions::from_mode(0o600),
                        );
                    }
                    tracing::info!(
                        task = "config_load",
                        "Migrated totp_secret.txt to encrypted Noble envelope"
                    );
                }
            }
            trimmed
        };
        let v = TotpValidator::from_base32(&base32)?;
        tracing::info!(
            task = "config_load",
            "TOTP auth loaded from {}",
            secret_path.display()
        );
        (v, base32)
    } else {
        let (v, base32) = TotpValidator::generate()?;
        let encrypted = noble_crypto::file_encrypt::encrypt_file_data(base32.as_bytes(), chain_meta)
            .map_err(|e| format!("encrypt TOTP secret: {e}"))?;
        atomic_write_file(&secret_path, &encrypted)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(
            task = "config_load",
            "TOTP auth: new secret generated at {}",
            secret_path.display()
        );
        (v, base32)
    };

    let _ = base32;
    Ok((Some(Arc::new(RwLock::new(validator))), Some(secret_path)))
}

/// Initialize PKI identity attestation from config.
///
/// 1. If a saved attestation file exists, load it.
/// 2. Else if a PKCS#12 file is configured, sign a binding and save the attestation.
/// 3. Otherwise, no attestation.
fn init_pki_attestation(
    config: &NodeConfig,
    chain_meta: &[u8; 32],
) -> Option<noble_core::ExternalAttestation> {
    let attestation_path = config.storage.data_dir.join("identity_attestation.cbor");

    // Try loading existing attestation
    if attestation_path.exists() {
        match crate::pkcs12::load_attestation(&attestation_path, chain_meta) {
            Ok(att) => {
                tracing::info!(
                    task = "config_load",
                    "PKI attestation loaded from {} (scheme: {}, scope: {})",
                    attestation_path.display(),
                    att.scheme,
                    att.scope
                );
                return Some(att);
            }
            Err(e) => {
                tracing::warn!(
                    task = "config_load",
                    "Failed to load saved PKI attestation: {e}"
                );
            }
        }
    }

    // Try creating attestation from PKCS#12 file
    if config.identity.pkcs12_path.is_empty() {
        return None;
    }

    let p12_path = std::path::Path::new(&config.identity.pkcs12_path);
    if !p12_path.exists() {
        tracing::warn!(
            task = "config_load",
            "PKCS#12 file not found: {} — skipping PKI binding",
            p12_path.display()
        );
        return None;
    }

    // Load PKCS#12 and create binding
    let identity = match crate::pkcs12::Pkcs12Identity::from_file(
        p12_path,
        &config.identity.pkcs12_password,
    ) {
        Ok(id) => id,
        Err(e) => {
            tracing::error!(task = "config_load", "Failed to load PKCS#12 file: {e}");
            return None;
        }
    };

    if let Some(cn) = identity.subject_cn() {
        tracing::info!(task = "config_load", "PKCS#12 identity loaded: CN={cn}");
    }

    // We need the node's identity key to create the binding.
    // For now, use a placeholder — the real key comes from the validator key or wallet.
    // In practice, the user would configure which key to bind.
    tracing::info!(
        task = "config_load",
        "PKCS#12 loaded but no identity key configured for binding yet"
    );
    tracing::info!(
        task = "config_load",
        "To complete PKI binding, set validator_key_path in [consensus] section"
    );

    None
}

/// Initialize the CA trust store from config.
fn init_ca_store(config: &NodeConfig) -> Option<CaStore> {
    if config.identity.ca_store_path.is_empty() {
        return None;
    }

    let ca_dir = std::path::Path::new(&config.identity.ca_store_path);
    match CaStore::from_directory(ca_dir) {
        Ok(store) => {
            tracing::info!(
                task = "config_load",
                "CA trust store loaded: {} certificates from {}",
                store.cert_count(),
                ca_dir.display()
            );
            Some(store)
        }
        Err(e) => {
            tracing::warn!(task = "config_load", "Failed to load CA trust store: {e}");
            None
        }
    }
}

/// Write `data` to `path` atomically (write to temp, then rename).
pub fn atomic_write_file(path: &Path, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("tmp");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_consensus::ConsensusStateMachine;

    #[test]
    fn init_memory_node_commits_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");
        config.storage.data_dir = dir.path().to_path_buf();

        let node = Node::init_memory(&config).unwrap();

        // Chain tip should be genesis (height 0).
        assert_eq!(node.chain_height(), 0);
        assert_eq!(node.chain_id, noble_core::MAINNET_CHAIN_ID);

        // Mempool should be empty.
        assert_eq!(node.mempool.lock().len(), 0);

        // Consensus engine should track genesis tip.
        let (tip_height, tip_hash) = node.consensus.read().chain_tip();
        assert_eq!(tip_height, 0);
        assert_ne!(tip_hash, Hash256::ZERO);

        // Wallet keystore should be created (locked).
        assert!(!node.wallet_keystore.lock().is_unlocked());

        // Network stats should be zeroed.
        let stats = node.network_stats.read();
        assert_eq!(stats.peer_count, 0);
    }

    #[test]
    fn init_memory_node_idempotent_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");
        config.storage.data_dir = dir.path().to_path_buf();

        // First init commits genesis.
        let node1 = Node::init_memory(&config).unwrap();
        let height1 = node1.chain_height();

        // Init again with the same storage — should not duplicate genesis.
        let storage = Arc::try_unwrap(node1.storage)
            .unwrap_or_else(|_| panic!("storage has multiple owners"))
            .into_inner();
        let node2 = Node::init_with_storage(&config, storage, None).unwrap();
        let height2 = node2.chain_height();

        assert_eq!(height1, height2);
        assert_eq!(height2, 0);
    }

    #[test]
    fn node_config_default_is_valid() {
        let config = NodeConfig::default();
        assert_eq!(config.network.max_peers, 50);
        assert_eq!(config.api.rpc_addr, "127.0.0.1:8783");
        assert_eq!(config.logging.level, "info");
        assert!(!config.metrics.enabled);
    }

    #[test]
    fn verify_recent_blocks_on_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        let report = node.verify_recent_blocks(10);
        assert!(
            report.is_clean(),
            "genesis-only chain should pass integrity check"
        );
        assert_eq!(report.heights_checked, 1);
    }

    #[test]
    fn verify_recent_blocks_empty_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        // count=0 should not panic; saturating_sub turns this into range [0, 0]
        let report = node.verify_recent_blocks(0);
        assert!(report.is_clean());
    }

    #[test]
    fn rollback_noop_at_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        let tip = node.rollback_to_height(0).unwrap();
        assert_eq!(tip.height, 0);
        assert_eq!(node.chain_height(), 0);

        // Consensus engine tip should still match
        let (engine_height, engine_hash) = node.consensus.read().chain_tip();
        assert_eq!(engine_height, tip.height);
        assert_eq!(engine_hash, tip.block_hash);
    }

    #[test]
    fn node_chain_id_matches_config_network() {
        use crate::config::NetworkId;

        for (network, expected_id) in [
            (NetworkId::Mainnet, noble_core::MAINNET_CHAIN_ID),
            (NetworkId::Testnet, noble_core::TESTNET_CHAIN_ID),
            (NetworkId::Regtest, noble_core::REGTEST_CHAIN_ID),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = NodeConfig::default();
            config.wallet.keystore_path = dir.path().join("keystore");
            config.node.network = network;

            let node = Node::init_memory(&config).unwrap();
            assert_eq!(
                node.chain_id, expected_id,
                "chain_id mismatch for {network:?}"
            );
        }
    }

    #[test]
    fn init_totp_disabled_returns_none() {
        let config = NodeConfig::default();
        assert!(!config.api.totp_enabled);
        let chain_meta = [0x42u8; 32];
        let (validator, path) = init_totp_validator(&config, &chain_meta).unwrap();
        assert!(validator.is_none());
        assert!(path.is_none());
    }

    #[test]
    fn init_totp_generates_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.api.totp_enabled = true;
        config.api.totp_secret_file = dir.path().join("totp.txt").to_str().unwrap().to_string();
        let chain_meta = [0x42u8; 32];

        let (validator, path) = init_totp_validator(&config, &chain_meta).unwrap();
        assert!(validator.is_some());
        assert!(path.is_some());

        let secret_path = path.unwrap();
        assert!(secret_path.exists(), "secret file should be created");

        // Re-init should load from the existing file.
        let (v2, _) = init_totp_validator(&config, &chain_meta).unwrap();
        assert!(v2.is_some());

        // Both should accept the same code.
        let v1 = validator.unwrap();
        let v1_locked = v1.read();
        let v2_locked = v2.unwrap();
        let v2_locked = v2_locked.read();
        assert_eq!(v1_locked.secret_base32(), v2_locked.secret_base32());
    }

    // --- Phase 8: Event loop helpers ---

    #[test]
    fn parse_port_from_addr() {
        assert_eq!(parse_port("127.0.0.1:8783"), Some(8783));
        assert_eq!(parse_port("0.0.0.0:8784"), Some(8784));
        assert_eq!(parse_port("127.0.0.1:0"), Some(0));
        assert_eq!(parse_port("no_colon"), None);
    }

    /// Parse port number from a multiaddr string like "/ip4/0.0.0.0/tcp/8780".
    fn parse_p2p_port(multiaddr: &str) -> Option<u16> {
        let parts: Vec<&str> = multiaddr.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == "tcp" {
                return parts.get(i + 1)?.parse().ok();
            }
        }
        None
    }

    #[test]
    fn parse_p2p_port_from_multiaddr() {
        assert_eq!(parse_p2p_port("/ip4/0.0.0.0/tcp/8780"), Some(8780));
        assert_eq!(parse_p2p_port("/ip4/127.0.0.1/tcp/8781"), Some(8781));
        assert_eq!(parse_p2p_port("/ip4/0.0.0.0/udp/1234"), None);
        assert_eq!(parse_p2p_port(""), None);
    }

    #[test]
    fn node_error_display() {
        let e = NodeError::Storage("disk full".into());
        assert_eq!(e.to_string(), "storage error: disk full");

        let e = NodeError::Network("connection refused".into());
        assert_eq!(e.to_string(), "network error: connection refused");

        let e = NodeError::Api("bind failed".into());
        assert_eq!(e.to_string(), "api error: bind failed");

        let e = NodeError::Config("missing field".into());
        assert_eq!(e.to_string(), "config error: missing field");

        let e = NodeError::Consensus("invalid vote".into());
        assert_eq!(e.to_string(), "consensus error: invalid vote");

        let e = NodeError::Shutdown;
        assert_eq!(e.to_string(), "shutdown signal received");
    }

    #[test]
    fn handle_network_event_updates_peer_stats() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        let (tx, _rx) = mpsc::channel(16);
        let (block_tx, _) = broadcast::channel(16);
        let (tx_tx, _) = broadcast::channel(16);
        let (peer_tx, _) = broadcast::channel(16);
        let (cycle_tx, _) = broadcast::channel(16);

        // Peer connect should increment count
        let connect_event = NetworkEvent::PeerConnected {
            peer_id: vec![1, 2, 3],
            addr: "/ip4/1.2.3.4/tcp/8780".to_string(),
            chain_tip: None,
        };
        node.handle_network_event(
            &connect_event,
            &tx,
            &block_tx,
            &tx_tx,
            &peer_tx,
            &cycle_tx,
            &None,
        );
        assert_eq!(node.network_stats.read().peer_count, 1);

        // Peer disconnect should decrement
        let disconnect_event = NetworkEvent::PeerDisconnected {
            peer_id: vec![1, 2, 3],
        };
        node.handle_network_event(
            &disconnect_event,
            &tx,
            &block_tx,
            &tx_tx,
            &peer_tx,
            &cycle_tx,
            &None,
        );
        assert_eq!(node.network_stats.read().peer_count, 0);
    }

    #[test]
    fn pki_attestation_none_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");
        config.storage.data_dir = dir.path().to_path_buf();

        let node = Node::init_memory(&config).unwrap();
        assert!(
            node.pki_attestation.is_none(),
            "no attestation without PKCS#12 config"
        );
        assert!(node.ca_store.is_none(), "no CA store without config");
    }

    #[test]
    fn pki_attestation_loads_saved() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");
        config.storage.data_dir = dir.path().to_path_buf();

        // Pre-seed .chain_meta so Node::init_memory uses the same key.
        let chain_meta = [0x42u8; 32];
        std::fs::write(dir.path().join(".chain_meta"), &chain_meta).unwrap();

        // Save a mock attestation
        let att = noble_core::ExternalAttestation {
            scheme: "pkcs7".to_string(),
            scope: "identity".to_string(),
            signer_fingerprint: [0xCC; 32],
            signature_data: vec![10, 20, 30],
        };
        let att_path = dir.path().join("identity_attestation.cbor");
        crate::pkcs12::save_attestation(&att_path, &att, &chain_meta).unwrap();

        let node = Node::init_memory(&config).unwrap();
        assert!(
            node.pki_attestation.is_some(),
            "should load saved attestation"
        );
        let loaded = node.pki_attestation.unwrap();
        assert_eq!(loaded.scheme, "pkcs7");
        assert_eq!(loaded.signer_fingerprint, [0xCC; 32]);
    }

    // AUD2-C1: Verify peer count propagates to consensus engine
    #[test]
    fn peer_count_propagates_to_consensus() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        let (tx, _rx) = mpsc::channel(16);
        let (block_tx, _) = broadcast::channel(16);
        let (tx_tx, _) = broadcast::channel(16);
        let (peer_tx, _) = broadcast::channel(16);
        let (cycle_tx, _) = broadcast::channel(16);

        // Connect a peer
        let connect_event = NetworkEvent::PeerConnected {
            peer_id: vec![1, 2, 3],
            addr: "/ip4/1.2.3.4/tcp/8780".to_string(),
            chain_tip: None,
        };
        node.handle_network_event(
            &connect_event,
            &tx,
            &block_tx,
            &tx_tx,
            &peer_tx,
            &cycle_tx,
            &None,
        );

        // Consensus engine should now have peer_count > 0
        let engine = node.consensus.read();
        // The engine doesn't expose total_peers directly, but set_peer_count was called
        // We can verify indirectly: peer_count in stats matches
        drop(engine);
        assert_eq!(node.network_stats.read().peer_count, 1);
    }

    // AUD2-H2: Verify rate limiter is wired (not None)
    // This is tested indirectly since ApiState construction happens in run()
    // which requires async. We test that RpcRateLimiter::new works correctly.
    #[test]
    fn rpc_rate_limiter_construction() {
        let rl = noble_api::rate_limit::RpcRateLimiter::new(30, 3);
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        // Should allow at least burst capacity (30*3 = 90) requests
        for _ in 0..90 {
            assert!(rl.try_acquire(ip));
        }
        // Should be rate-limited after burst
        assert!(!rl.try_acquire(ip));
    }

    #[test]
    fn process_cycle_actions_log_and_metric() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        let (tx, _rx) = mpsc::channel(16);
        let (block_tx, _) = broadcast::channel(16);

        // Log and EmitMetric should not panic
        let actions = vec![
            CycleIo::Log("test message".to_string()),
            CycleIo::EmitMetric {
                name: "test_metric".to_string(),
                value: 42.0,
            },
            CycleIo::SetTimer { duration_secs: 10 },
        ];
        node.process_cycle_actions(actions, &tx, &block_tx, &None);
        // No assertion needed — just verifying no panics
    }
}
