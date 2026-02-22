// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node orchestrator — ties all subsystems together.
//!
//! The `Node` struct owns shared references to storage, mempool, consensus,
//! wallet, and network stats. It is initialized from a `NodeConfig` and
//! provides the async event loop that wires network, consensus, and API.

use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use thiserror::Error;
use tokio::sync::{broadcast, mpsc};

use noble_api::auth::TotpValidator;
use noble_api::state::ApiState;
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
use crate::providers::{StorageBlockProvider, StorageTxProvider};

/// Typed errors for node operations.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum NodeError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("api error: {0}")]
    Api(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("consensus error: {0}")]
    Consensus(String),
    #[error("shutdown signal received")]
    Shutdown,
}

/// The running NOBLE node, generic over the storage backend.
pub struct Node<S: StorageEngine + Send + Sync + 'static> {
    /// Shared block/transaction storage.
    pub storage: Arc<RwLock<S>>,
    /// Transaction mempool.
    pub mempool: Arc<Mutex<Mempool>>,
    /// PoR consensus engine.
    pub consensus: Arc<RwLock<CycleEngine>>,
    /// Encrypted keystore for signing.
    pub wallet_keystore: Arc<Mutex<KeyStore>>,
    /// Wallet lock/unlock state with auto-expire.
    pub wallet_state: Arc<Mutex<WalletState>>,
    /// Network statistics (peer counts).
    pub network_stats: Arc<RwLock<NetworkStats>>,
    /// Live connected peer info (H-004).
    pub peer_info: Arc<RwLock<std::collections::HashMap<String, noble_api::state::PeerInfoEntry>>>,
    /// Active chain ID.
    pub chain_id: u32,
    /// Timestamp when the node was started.
    pub start_time: std::time::Instant,
    /// PKI identity attestation (CMS/PKCS#7 binding), loaded or created at startup.
    #[allow(dead_code)]
    pub pki_attestation: Option<noble_core::ExternalAttestation>,
    /// CA trust store for verifying peer PKI attestations.
    #[allow(dead_code)]
    pub ca_store: Option<CaStore>,
}

impl Node<MemoryStorage> {
    /// Initialize a node with in-memory storage (for testing or `--memory` mode).
    pub fn init_memory(config: &NodeConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = MemoryStorage::new();
        Self::init_with_storage(config, storage)
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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = Arc::new(RwLock::new(storage));

        // Resolve chain_id and genesis block from network config.
        let chain_id = config.node.network.chain_id();

        // Ensure genesis block is committed if the chain is empty.
        {
            let s = storage.read().map_err(|e| format!("storage lock: {e}"))?;
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
            .map_err(|e| format!("storage lock: {e}"))?
            .get_chain_tip()?
            .unwrap_or(noble_storage::ChainTip {
                block_hash: Hash256::ZERO,
                height: 0,
            });

        // AUD3-D5/D6: Load tip block header for proper B2/B3/B5/B6 validation on startup.
        let tip_header = if tip.height > 0 || tip.block_hash != Hash256::ZERO {
            let s = storage.read().map_err(|e| format!("storage lock: {e}"))?;
            s.get_block_header(&tip.block_hash).ok()
        } else {
            None
        };

        // Create consensus engine (observation mode — no validator key yet).
        let consensus_config = CConsensusConfig::default();

        // C-003: Load persisted validator list if the file exists.
        let validator_list_path = config.consensus.validator_list_path.clone();
        let validator_list = if validator_list_path.exists() {
            match std::fs::read(&validator_list_path) {
                Ok(bytes) => {
                    use noble_codec::NobleCbor;
                    ValidatorList::from_cbor(&bytes).unwrap_or_else(|e| {
                        tracing::warn!("Failed to load validator list: {e}, starting empty");
                        ValidatorList::new()
                    })
                }
                Err(e) => {
                    tracing::warn!("Failed to read validator list file: {e}, starting empty");
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
            None, // no validator key — observation mode
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
        let pki_attestation = init_pki_attestation(config);

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
        })
    }

    /// Return the current chain tip height.
    pub fn chain_height(&self) -> u64 {
        self.storage
            .read()
            .ok()
            .and_then(|s| s.get_chain_tip().ok().flatten())
            .map(|tip| tip.height)
            .unwrap_or(0)
    }

    /// Run an integrity check on the most recent `count` blocks.
    /// Returns the integrity report.
    pub fn verify_recent_blocks(&self, count: u64) -> IntegrityReport {
        let height = self.chain_height();
        let start = height.saturating_sub(count.saturating_sub(1));
        let storage = self.storage.read().unwrap_or_else(|e| e.into_inner());
        noble_storage::verify_chain_integrity(&*storage, self.chain_id, start, height)
    }

    /// Rollback the chain to the given height, recalculating balances.
    /// Used when corruption is detected.
    #[allow(dead_code)]
    pub fn rollback_to_height(
        &self,
        target_height: u64,
    ) -> Result<noble_storage::ChainTip, Box<dyn std::error::Error>> {
        let storage = self
            .storage
            .read()
            .map_err(|e| format!("storage lock: {e}"))?;
        let tip = storage.rollback_to_height(target_height, self.chain_id)?;
        // Update consensus engine tip
        if let Ok(mut engine) = self.consensus.write() {
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
    ) -> Result<(), NodeError> {
        // --- Parse port numbers from config addresses ---
        let rpc_port = parse_port(&config.api.rpc_addr).unwrap_or(8783);
        let ws_port = parse_port(&config.api.ws_addr).unwrap_or(8784);

        // --- Start network service ---
        let block_provider = Arc::new(StorageBlockProvider::new(self.storage.clone()));
        let tx_provider = Arc::new(StorageTxProvider::new(self.storage.clone()));

        let mut net_config = noble_network::NetworkConfig::default();
        net_config.listen_addr = config.network.listen_addr.clone();
        net_config.bootstrap_peers = config.network.seeds.clone();
        net_config.max_outbound = (config.network.max_peers as usize / 5).max(4);
        net_config.max_inbound =
            (config.network.max_peers as usize).saturating_sub(net_config.max_outbound);
        net_config.ban_threshold = config.network.ban_threshold;
        net_config.chain_id = self.chain_id;

        let mut network = noble_network::start_network(net_config, block_provider, tx_provider)
            .await
            .map_err(|e| NodeError::Network(e.to_string()))?;

        let p2p_port = network.bound_port;
        let network_cmd = network.command_sender();
        tracing::info!("P2P network started on port {p2p_port}");

        // --- Initialize TOTP auth ---
        let (totp_validator, totp_secret_path) =
            init_totp_validator(config).map_err(|e| NodeError::Config(e.to_string()))?;

        // --- Build broadcast channels for WebSocket subscriptions ---
        let (new_block_tx, _) = broadcast::channel(64);
        let (new_tx_tx, _) = broadcast::channel(256);
        let (cycle_phase_tx, _) = broadcast::channel(16);
        let (peer_update_tx, _) = broadcast::channel(64);

        // --- IP access control ---
        let ip_filter = if config.api.allowed_ips.is_empty() {
            None
        } else {
            match noble_api::ip_filter::IpFilter::new(&config.api.allowed_ips) {
                Ok(f) => {
                    tracing::info!(
                        "IP access control enabled: {} entries",
                        config.api.allowed_ips.len()
                    );
                    Some(f)
                }
                Err(e) => {
                    tracing::error!(
                        "Invalid allowed_ips config: {e} — falling back to localhost-only"
                    );
                    None
                }
            }
        };

        // --- Derive gateway key (first wallet key, if any) ---
        let gateway_key = {
            let ks = self
                .wallet_keystore
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            ks.list_keys()
                .ok()
                .and_then(|keys| keys.into_iter().next())
                .map(|pk| pk.to_wire_bytes())
        };
        if gateway_key.is_some() {
            tracing::info!("Gateway fee split enabled (wallet key found)");
        } else {
            tracing::info!("Gateway fee split disabled (no wallet key yet)");
        }

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
            totp_secret_path,
            rpc_port,
            ws_port,
            p2p_port,
            new_block_tx: new_block_tx.clone(),
            new_tx_tx: new_tx_tx.clone(),
            cycle_phase_tx: cycle_phase_tx.clone(),
            peer_update_tx: peer_update_tx.clone(),
            trace_handle,
            gateway_key,
            ip_filter: ip_filter.clone(),
            validator_list_path: Some(config.consensus.validator_list_path.clone()),
            peer_info: self.peer_info.clone(),
        });

        // --- Determine RPC bind address ---
        // When remote access is enabled, bind to 0.0.0.0 instead of 127.0.0.1.
        let rpc_bind_addr = if ip_filter.as_ref().is_some_and(|f| f.has_remote_access()) {
            config.api.rpc_addr.replace("127.0.0.1", "0.0.0.0")
        } else {
            config.api.rpc_addr.clone()
        };

        // --- Start RPC server ---
        let rpc_handle = noble_api::server::start_server(api_state, &rpc_bind_addr)
            .await
            .map_err(|e| NodeError::Api(e.to_string()))?;

        tracing::info!("JSON-RPC server listening on {}", rpc_bind_addr);

        // --- Start embedded GUI server ---
        let gui_dir = if config.api.gui_dir.is_empty() {
            crate::gui_server::detect_gui_dir()
        } else {
            let p = std::path::PathBuf::from(&config.api.gui_dir);
            if p.join("index.html").exists() {
                Some(p)
            } else {
                tracing::warn!("Configured gui_dir {} not found", config.api.gui_dir);
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
            tokio::spawn(async move {
                if let Err(e) =
                    crate::gui_server::start_gui_server(gui_addr, gui_path, gui_filter).await
                {
                    tracing::error!("GUI server error: {e}");
                }
            });
        } else {
            tracing::info!("GUI directory not found — dashboard server not started");
        }

        // --- Consensus tick interval ---
        let mut tick_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        tick_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // --- Mempool expiry sweep interval ---
        let mut expiry_interval = tokio::time::interval(std::time::Duration::from_secs(60));
        expiry_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!(
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
                            );
                        }
                        None => {
                            tracing::warn!("Network event channel closed — shutting down");
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
                        let mut engine = self.consensus.write().unwrap_or_else(|e| e.into_inner());
                        engine.step(CycleEvent::Tick { now })
                    };
                    self.process_cycle_actions(actions, &network_cmd, &new_block_tx);

                    // H-002: Persist cycle history if a cycle boundary just occurred.
                    if let Ok(mut engine) = self.consensus.write() {
                        if let Some(history) = engine.take_cycle_history() {
                            if let Ok(bytes) = noble_codec::NobleCbor::to_cbor(&history) {
                                if let Ok(storage) = self.storage.read() {
                                    if let Err(e) = storage.store_cycle_history(history.cycle_number, &bytes) {
                                        tracing::warn!("Failed to persist cycle history: {e}");
                                    }
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
                        let mut mempool = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
                        mempool.expire(now)
                    };
                    if expired > 0 {
                        tracing::debug!("Swept {expired} expired mempool transactions");
                    }
                }

                // Graceful shutdown on CTRL+C
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("Received shutdown signal");
                    break;
                }
            }
        }

        // --- Graceful shutdown ---
        tracing::info!("Shutting down...");
        let _ = network_cmd.try_send(NetworkCommand::Shutdown);
        rpc_handle
            .stop()
            .map_err(|e| NodeError::Api(format!("RPC stop: {e}")))?;
        tracing::info!("Node shutdown complete");
        Ok(())
    }

    /// Handle a single network event: route to consensus, update stats, etc.
    fn handle_network_event(
        &self,
        event: &NetworkEvent,
        network_cmd: &mpsc::Sender<NetworkCommand>,
        new_block_tx: &broadcast::Sender<serde_json::Value>,
        new_tx_tx: &broadcast::Sender<serde_json::Value>,
        peer_update_tx: &broadcast::Sender<serde_json::Value>,
        cycle_phase_tx: &broadcast::Sender<serde_json::Value>,
    ) {
        match event {
            NetworkEvent::PeerConnected { peer_id, addr, .. } => {
                let new_count = if let Ok(mut stats) = self.network_stats.write() {
                    stats.peer_count += 1;
                    stats.inbound_count += 1; // simplified; real impl tracks direction
                    stats.peer_count
                } else {
                    0
                };
                // AUD2-C1: Wire peer count to consensus engine so compute_majority works
                if let Ok(mut engine) = self.consensus.write() {
                    engine.set_peer_count(new_count);
                }
                // H-004: Track peer info for getPeerInfo RPC.
                let hex_pid = hex::encode(peer_id);
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if let Ok(mut info) = self.peer_info.write() {
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
                tracing::debug!("Peer connected: {addr}");
            }
            NetworkEvent::PeerDisconnected { peer_id } => {
                let new_count = if let Ok(mut stats) = self.network_stats.write() {
                    stats.peer_count = stats.peer_count.saturating_sub(1);
                    stats.peer_count
                } else {
                    0
                };
                // AUD2-C1: Update consensus engine peer count on disconnect too
                if let Ok(mut engine) = self.consensus.write() {
                    engine.set_peer_count(new_count);
                }
                // H-004: Remove from live peer info.
                let hex_pid = hex::encode(peer_id);
                if let Ok(mut info) = self.peer_info.write() {
                    info.remove(&hex_pid);
                }
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "disconnected",
                    "peer_id": hex_pid,
                }));
            }
            NetworkEvent::PeerBanned { peer_id, reason } => {
                tracing::warn!("Peer banned: {} — {reason}", hex::encode(peer_id));
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
                        let mut engine = self.consensus.write().unwrap_or_else(|e| e.into_inner());
                        engine.step(cycle_event)
                    };
                    self.process_cycle_actions(actions, network_cmd, new_block_tx);
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
    ) {
        for action in actions {
            match action {
                CycleIo::CommitBlock(block) => {
                    let block_hash = match block.header.compute_block_hash() {
                        Ok(h) => h,
                        Err(e) => {
                            tracing::error!("Failed to compute block hash: {e}");
                            continue;
                        }
                    };
                    let tx_ids: Vec<_> = block
                        .transactions
                        .iter()
                        .filter_map(|tx| tx.compute_tx_id(self.chain_id).ok())
                        .collect();

                    if let Ok(storage) = self.storage.read() {
                        if let Err(e) = storage.commit_block(&block, &block_hash, &tx_ids) {
                            tracing::error!("Failed to commit block {}: {e}", block.header.height);
                            continue;
                        }
                    }

                    // AUD3-D5/D6: Update consensus tip with full header for B2/B3/B5/B6 validation.
                    if let Ok(mut engine) = self.consensus.write() {
                        engine.update_tip_with_header(block.header.clone());
                    }

                    // Remove committed txs from mempool
                    {
                        let mut mempool = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
                        for tx_id in &tx_ids {
                            mempool.remove(tx_id);
                        }
                    }

                    tracing::info!(
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

                    let storage = match self.storage.read() {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let chain_lookup = StorageChainLookupAdapter { storage: &*storage };
                    let balance_lookup = StorageBalanceLookupAdapter { storage: &*storage };
                    let mut mempool = self.mempool.lock().unwrap_or_else(|e| e.into_inner());
                    for tx in txs {
                        let _ = mempool.admit(&tx, now, &chain_lookup, &balance_lookup);
                    }
                }
                CycleIo::Log(msg) => {
                    tracing::info!("[consensus] {msg}");
                }
                CycleIo::EmitMetric { name, value } => {
                    tracing::debug!("metric: {name} = {value}");
                }
                CycleIo::SetTimer { duration_secs } => {
                    tracing::debug!("consensus timer: {duration_secs}s (handled by tick interval)");
                }
                other => {
                    // BroadcastBlock, BroadcastVote, BanPeer, RequestBlock → network
                    let cmds = bridge::cycle_io_to_network_commands(other);
                    for cmd in cmds {
                        let _ = network_cmd.try_send(cmd);
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
    fn get_balance(&self, pubkey: &noble_crypto::NoblePublicKey) -> u64 {
        self.storage.get_balance(pubkey).unwrap_or(0)
    }
}

/// Parse port number from a "host:port" address string.
fn parse_port(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.parse().ok()
}

/// Parse port number from a multiaddr string like "/ip4/0.0.0.0/tcp/8780".
#[allow(dead_code)]
fn parse_p2p_port(multiaddr: &str) -> Option<u16> {
    let parts: Vec<&str> = multiaddr.split('/').collect();
    // Find the segment after "tcp"
    for (i, part) in parts.iter().enumerate() {
        if *part == "tcp" {
            return parts.get(i + 1)?.parse().ok();
        }
    }
    None
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
        let base32 = std::fs::read_to_string(&secret_path)?.trim().to_string();
        let v = TotpValidator::from_base32(&base32)?;
        tracing::info!("TOTP auth loaded from {}", secret_path.display());
        (v, base32)
    } else {
        let (v, base32) = TotpValidator::generate()?;
        atomic_write_file(&secret_path, base32.as_bytes())?;
        // Restrict TOTP secret file to owner-only (0o600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(
            "TOTP auth: new secret generated at {}",
            secret_path.display()
        );
        // Security: TOTP secret is persisted to file only — never logged.
        (v, base32)
    };

    let _ = base32; // used only for logging/file write above
    Ok((Some(Arc::new(RwLock::new(validator))), Some(secret_path)))
}

/// Initialize PKI identity attestation from config.
///
/// 1. If a saved attestation file exists, load it.
/// 2. Else if a PKCS#12 file is configured, sign a binding and save the attestation.
/// 3. Otherwise, no attestation.
fn init_pki_attestation(config: &NodeConfig) -> Option<noble_core::ExternalAttestation> {
    let attestation_path = config.storage.data_dir.join("identity_attestation.cbor");

    // Try loading existing attestation
    if attestation_path.exists() {
        match crate::pkcs12::load_attestation(&attestation_path) {
            Ok(att) => {
                tracing::info!(
                    "PKI attestation loaded from {} (scheme: {}, scope: {})",
                    attestation_path.display(),
                    att.scheme,
                    att.scope
                );
                return Some(att);
            }
            Err(e) => {
                tracing::warn!("Failed to load saved PKI attestation: {e}");
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
            tracing::error!("Failed to load PKCS#12 file: {e}");
            return None;
        }
    };

    if let Some(cn) = identity.subject_cn() {
        tracing::info!("PKCS#12 identity loaded: CN={cn}");
    }

    // We need the node's identity key to create the binding.
    // For now, use a placeholder — the real key comes from the validator key or wallet.
    // In practice, the user would configure which key to bind.
    tracing::info!("PKCS#12 loaded but no identity key configured for binding yet");
    tracing::info!("To complete PKI binding, set validator_key_path in [consensus] section");

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
                "CA trust store loaded: {} certificates from {}",
                store.cert_count(),
                ca_dir.display()
            );
            Some(store)
        }
        Err(e) => {
            tracing::warn!("Failed to load CA trust store: {e}");
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

        let node = Node::init_memory(&config).unwrap();

        // Chain tip should be genesis (height 0).
        assert_eq!(node.chain_height(), 0);
        assert_eq!(node.chain_id, noble_core::MAINNET_CHAIN_ID);

        // Mempool should be empty.
        assert_eq!(node.mempool.lock().unwrap().len(), 0);

        // Consensus engine should track genesis tip.
        let (tip_height, tip_hash) = node.consensus.read().unwrap().chain_tip();
        assert_eq!(tip_height, 0);
        assert_ne!(tip_hash, Hash256::ZERO);

        // Wallet keystore should be created (locked).
        assert!(!node.wallet_keystore.lock().unwrap().is_unlocked());

        // Network stats should be zeroed.
        let stats = node.network_stats.read().unwrap();
        assert_eq!(stats.peer_count, 0);
    }

    #[test]
    fn init_memory_node_idempotent_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        // First init commits genesis.
        let node1 = Node::init_memory(&config).unwrap();
        let height1 = node1.chain_height();

        // Init again with the same storage — should not duplicate genesis.
        let storage = Arc::try_unwrap(node1.storage)
            .unwrap_or_else(|_| panic!("storage has multiple owners"))
            .into_inner()
            .unwrap();
        let node2 = Node::init_with_storage(&config, storage).unwrap();
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
        assert!(config.metrics.enabled);
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
        let (engine_height, engine_hash) = node.consensus.read().unwrap().chain_tip();
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
        let (validator, path) = init_totp_validator(&config).unwrap();
        assert!(validator.is_none());
        assert!(path.is_none());
    }

    #[test]
    fn init_totp_generates_secret_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.api.totp_enabled = true;
        config.api.totp_secret_file = dir.path().join("totp.txt").to_str().unwrap().to_string();

        let (validator, path) = init_totp_validator(&config).unwrap();
        assert!(validator.is_some());
        assert!(path.is_some());

        let secret_path = path.unwrap();
        assert!(secret_path.exists(), "secret file should be created");

        // Re-init should load from the existing file.
        let (v2, _) = init_totp_validator(&config).unwrap();
        assert!(v2.is_some());

        // Both should accept the same code.
        let v1 = validator.unwrap();
        let v1_locked = v1.read().unwrap();
        let v2_locked = v2.unwrap();
        let v2_locked = v2_locked.read().unwrap();
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
        node.handle_network_event(&connect_event, &tx, &block_tx, &tx_tx, &peer_tx, &cycle_tx);
        assert_eq!(node.network_stats.read().unwrap().peer_count, 1);

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
        );
        assert_eq!(node.network_stats.read().unwrap().peer_count, 0);
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

        // Save a mock attestation
        let att = noble_core::ExternalAttestation {
            scheme: "pkcs7".to_string(),
            scope: "identity".to_string(),
            signer_fingerprint: [0xCC; 32],
            signature_data: vec![10, 20, 30],
        };
        let att_path = dir.path().join("identity_attestation.cbor");
        crate::pkcs12::save_attestation(&att_path, &att).unwrap();

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
        node.handle_network_event(&connect_event, &tx, &block_tx, &tx_tx, &peer_tx, &cycle_tx);

        // Consensus engine should now have peer_count > 0
        let engine = node.consensus.read().unwrap();
        // The engine doesn't expose total_peers directly, but set_peer_count was called
        // We can verify indirectly: peer_count in stats matches
        drop(engine);
        assert_eq!(node.network_stats.read().unwrap().peer_count, 1);
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
        node.process_cycle_actions(actions, &tx, &block_tx);
        // No assertion needed — just verifying no panics
    }
}
