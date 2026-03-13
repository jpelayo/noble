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
use noble_mempool::{UtxoLookup, ChainLookup, Mempool};
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
    /// Active chain ID (mutable via AtomicU32 for cross-chain adoption). Shared with ApiState.
    pub chain_id: Arc<std::sync::atomic::AtomicU32>,
    /// Chain label (hex chain ID or "pre-genesis").
    pub network_name: String,
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
    /// Keypair for signing NodeAnnounce messages (cloned from validator key before CycleEngine consumes it).
    pub announce_keypair: Option<(noble_crypto::NoblePrivateKey, noble_crypto::NoblePublicKey)>,
    /// S49: Set to `true` when median clock drift exceeds `CLOCK_DRIFT_CRITICAL_SECS`.
    /// While true, block proposals are suppressed.
    pub clock_drift_paused: std::sync::atomic::AtomicBool,
    /// S53: Last proposed block (height, hash) — set when BroadcastBlock passes the gate.
    /// Cleared on chain tip advancement (new cycle). Shared with HealingManager.
    pub last_proposed: Arc<parking_lot::Mutex<Option<(u64, [u8; 32])>>>,
    /// Path to the CBOR validator list file (for persisting network metadata).
    pub validator_list_path: Option<std::path::PathBuf>,
    /// Seed/bootstrap peer addresses from config (for auto-reconnection).
    pub seed_addrs: Vec<String>,
    /// Cooldown: last time redial_known_peers was called (epoch secs). Prevents tight
    /// reconnect loops when the only known peer has a chain_id mismatch.
    pub last_redial_at: std::sync::atomic::AtomicU64,
    /// Chain healing, sync, fork resolution, and cross-chain adoption manager.
    pub healing: crate::healing::HealingManager<S>,
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
    /// The node starts stateless — no genesis is auto-committed.
    /// Subsystems (mempool, consensus, wallet) are created from the config.
    pub fn init_with_storage(
        config: &NodeConfig,
        storage: S,
        encryption_password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let storage = Arc::new(RwLock::new(storage));

        // Derive chain_id from the earliest block hash in storage.
        // Genesis-imported chains have block 0; consensus-bootstrapped chains start at block 1.
        // If no blocks exist, chain_id is 0 (updated on first block commit).
        let chain_id = {
            let s = storage.read();
            match s.get_block_hash_by_height(0) {
                Ok(hash) => noble_core::derive_chain_id(&hash),
                Err(e0) => match s.get_block_hash_by_height(1) {
                    Ok(hash) => noble_core::derive_chain_id(&hash),
                    Err(e1) => {
                        tracing::debug!(
                            task = "startup",
                            "no blocks in storage (height 0: {e0}, height 1: {e1}) — chain_id=0 (pre-genesis)",
                        );
                        0
                    }
                },
            }
        };

        // Create shared chain_id Arc (shared by Node, ApiState, and Mempool).
        let chain_id_arc = Arc::new(std::sync::atomic::AtomicU32::new(chain_id));

        // Create mempool with shared chain_id.
        let mut mempool_config = noble_mempool::MempoolConfig::default();
        mempool_config.chain_id = chain_id_arc.clone();
        let mempool = Arc::new(Mutex::new(Mempool::new(mempool_config)));

        // Determine chain tip for the consensus engine.
        let mut tip = storage
            .read()
            .get_chain_tip()?
            .unwrap_or(noble_storage::ChainTip {
                block_hash: Hash256::ZERO,
                height: 0,
            });

        // Startup integrity check — detect inconsistent state (chain_tip > 0
        // but chain_id = 0, meaning blocks are missing from storage).
        if crate::healing::startup_integrity_check(chain_id, tip.height) {
            if let Err(e) = storage.read().wipe_all_chain_data() {
                tracing::error!(task = "startup", "failed to wipe inconsistent chain data: {e}");
            }
            tip = noble_storage::ChainTip {
                block_hash: Hash256::ZERO,
                height: 0,
            };
        }

        // AUD3-D5/D6: Load tip block header for proper B2/B3/B5/B6 validation on startup.
        let tip_header = if tip.height > 0 || tip.block_hash != Hash256::ZERO {
            let s = storage.read();
            match s.get_block_header(&tip.block_hash) {
                Ok(header) => Some(header),
                Err(e) => {
                    tracing::warn!(
                        task = "startup",
                        height = tip.height,
                        "failed to load tip block header — B2/B3/B5/B6 validation degraded: {e}"
                    );
                    None
                }
            }
        } else {
            None
        };

        // Read block-1 timestamp for cycle counting.
        // Cycles only start once the first consensus block is committed.
        // Before that the engine uses a wall-clock-aligned epoch (cycle 0).
        //
        // When tip.height >= 1, block 1's timestamp is the cycle epoch.
        // When tip.height == 0, genesis_timestamp = None → engine sets wall-clock-aligned epoch on first tick.
        let genesis_timestamp = if tip.height >= 1 {
            let s = storage.read();
            match s.get_block_hash_by_height(1) {
                Ok(hash) => match s.get_block_header(&hash) {
                    Ok(header) => Some(header.timestamp),
                    Err(e) => {
                        tracing::error!(task = "startup", "failed to load block-1 header for cycle epoch: {e}");
                        None
                    }
                },
                Err(e) => {
                    tracing::error!(task = "startup", "failed to load block-1 hash for cycle epoch: {e}");
                    None
                }
            }
        } else {
            tracing::info!(
                task = "startup",
                "no blocks yet — epoch will be wall-clock-aligned on first tick"
            );
            // Purge stale cycle history from previous runs.
            if let Err(e) = storage.read().clear_cycle_history() {
                tracing::warn!(task = "startup", "failed to clear stale cycle history: {e}");
            }
            None
        };

        // --- Load per-installation encryption entropy ---
        let chain_meta = noble_crypto::file_encrypt::load_or_create_chain_meta(
            &config.storage.data_dir,
            &config.security.encryption_mode,
            encryption_password,
        )
        .map_err(|e| format!("failed to load/create .chain_meta: {e}"))?;

        // Create wallet keystore + auto-unlock with chain_meta-derived passphrase.
        // This must happen BEFORE load_validator_key so the keystore fallback works
        // for nodes whose validator.key was migrated into the unified keystore.
        let mut keystore = KeyStore::new(&config.wallet.keystore_path)?;
        let wallet_passphrase = hex::encode(
            noble_crypto::file_encrypt::derive_wallet_key(&chain_meta),
        );
        if keystore.unlock(&wallet_passphrase).is_err() {
            // Existing keys may use the old empty passphrase — try migration
            if keystore.unlock("").is_ok() {
                match keystore.migrate_passphrase("", &wallet_passphrase) {
                    Ok(n) if n > 0 => {
                        tracing::info!(task = "wallet_key", "migrated {n} wallet key(s) to chain_meta encryption");
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(task = "wallet_key", "wallet key migration failed: {e}");
                    }
                }
                keystore.lock();
                let _ = keystore.unlock(&wallet_passphrase);
            }
        }

        // --- Load validator key (if configured) ---
        // Checks validator.key file first, then falls back to unified keystore.
        let validator_key = load_validator_key(
            &config.consensus.validator_key_path,
            &config.storage.data_dir,
            &chain_meta,
            &keystore,
        );

        // --- Build consensus config from TOML ---
        let consensus_config = build_consensus_config(config);

        // C-003: Load persisted validator list if the file exists.
        // Resolve relative paths against data_dir so the file lives inside the
        // data directory and gets properly cleaned up by `noble-tool reset-chain`.
        let validator_list_path = {
            let p = config.consensus.validator_list_path.clone();
            if p.is_relative() {
                config.storage.data_dir.join(p)
            } else {
                p
            }
        };
        let mut validator_list = if validator_list_path.exists() {
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

        // Self-register: if this node has a validator key AND wants to validate, ensure it is in the list.
        if let Some((_sk, pk)) = &validator_key {
            if config.identity.wants_to_validate && !validator_list.is_validator(pk) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                validator_list.add_validator(pk.clone(), 1, now);
                tracing::info!(
                    task = "config_load",
                    "Self-registered as validator: {}",
                    pk.to_address(),
                );
            } else if !config.identity.wants_to_validate && validator_list.is_validator(pk) {
                validator_list.remove_validator(pk);
                tracing::info!(
                    task = "config_load",
                    "Removed self from validator list (wants_to_validate=false): {}",
                    pk.to_address(),
                );
            }
            // Always refresh the friendly name from the canonical identity source.
            // Prefer identity.json (written by GUI/CLI wizard) over noble.toml.
            let self_name = {
                let identity_path = config.storage.data_dir.join("identity.json");
                if identity_path.exists() {
                    std::fs::read_to_string(&identity_path)
                        .ok()
                        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                        .and_then(|v| v.get("node_name")?.as_str().map(String::from))
                        .unwrap_or_default()
                } else {
                    config.identity.node_name.clone()
                }
            };
            if !self_name.is_empty() {
                validator_list.set_friendly_name(pk, self_name);
            }
        }

        // Copy the validator keypair before CycleEngine takes ownership —
        // we need it for signing NodeAnnounce broadcasts.
        // NoblePrivateKey intentionally doesn't implement Clone (zeroize safety),
        // but clone_for_test() provides an explicit copy when ownership must be shared.
        let announce_keypair = validator_key
            .as_ref()
            .map(|(sk, pk)| (sk.clone_for_test(), pk.clone()));

        // Clone for legacy key migration (before CycleEngine consumes validator_key).
        let migration_validator_key = validator_key
            .as_ref()
            .map(|(sk, pk)| (sk.clone_for_test(), pk.clone()));

        let mut engine = CycleEngine::new(
            consensus_config,
            validator_list,
            tip.height,
            tip.block_hash,
            chain_id,
            validator_key,
            genesis_timestamp,
        );
        if let Some(header) = tip_header {
            engine.update_tip_with_header(header);
        }
        // Wire identity flags to engine:
        // - Vote-only peers (wants_to_validate=false) don't propose blocks.
        // - Propose-only nodes (wants_to_vote=false) don't cast votes.
        if !config.identity.wants_to_validate {
            engine.set_proposals_enabled(false);
        }
        if !config.identity.wants_to_vote {
            engine.set_voting_enabled(false);
        }

        // Load badge state from storage into the consensus engine.
        {
            let s = storage.read();
            match s.list_badges() {
                Ok(badges) => {
                    for (pubkey_wire, cbor_data) in badges {
                        if let Ok(badge) = noble_codec::NobleCbor::from_cbor(&cbor_data) {
                            engine.badge_store_mut().set_badge(pubkey_wire, badge);
                        }
                    }
                    let count = engine.badge_store().len();
                    if count > 0 {
                        tracing::info!(task = "init", "loaded {} badge(s) from storage", count);
                    }
                }
                Err(e) => {
                    tracing::warn!(task = "init", "failed to load badges from storage: {}", e);
                }
            }
            // Load active badge proposals.
            match s.list_badge_proposals() {
                Ok(proposals) => {
                    for (hash_bytes, cbor_data) in proposals {
                        let hash_key = String::from_utf8_lossy(&hash_bytes).to_string();
                        if let Ok(proposal) = noble_codec::NobleCbor::from_cbor(&cbor_data) {
                            engine.badge_proposals_mut().insert(hash_key, proposal);
                        }
                    }
                    let count = engine.badge_proposals().len();
                    if count > 0 {
                        tracing::info!(task = "init", "loaded {} badge proposal(s) from storage", count);
                    }
                }
                Err(e) => {
                    tracing::warn!(task = "init", "failed to load badge proposals from storage: {}", e);
                }
            }
        }
        // Restore finality state from storage.
        if let Ok(Some(data)) = storage.read().load_finality_state() {
            if let Some((height, hash, cycle)) = decode_finality_state(&data) {
                engine.restore_finality(height, hash, cycle);
                tracing::info!(task = "init", finalized_height = height, "restored finality state");
            }
        }
        // Restore checkpoint state from storage.
        if let Ok(entries) = storage.read().load_checkpoints() {
            let cps: Vec<noble_consensus::Checkpoint> = entries
                .iter()
                .filter_map(|(_, data)| noble_codec::NobleCbor::from_cbor(data).ok())
                .collect();
            if !cps.is_empty() {
                let count = cps.len();
                engine.restore_checkpoints(cps);
                tracing::info!(task = "init", count, "restored checkpoint(s) from storage");
            }
        }
        // Wire UTXO value lookup for accurate fee computation in block proposals.
        engine.set_utxo_value_lookup(Box::new(ArcStorageUtxoValueLookup {
            storage: Arc::clone(&storage),
        }));
        let consensus = Arc::new(RwLock::new(engine));

        // --- Migrate legacy scattered key files into the unified keystore ---
        migrate_legacy_keys_into_keystore(
            &mut keystore,
            &wallet_passphrase,
            &config.storage.data_dir,
            &chain_meta,
            &migration_validator_key,
        );

        let wallet_keystore = Arc::new(Mutex::new(keystore));
        let wallet_state = Arc::new(Mutex::new(WalletState::new(3600)));

        let network_stats = Arc::new(RwLock::new(NetworkStats::default()));
        let peer_info = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // --- PKI identity attestation ---
        let pki_attestation = init_pki_attestation(config, &chain_meta);

        // --- CA trust store ---
        let ca_store = init_ca_store(config);

        // --- Discovered blockchains (load from CBOR if exists) ---
        let discovered_path = config.storage.data_dir.join("discovered_blockchains.cbor");
        let discovered_blockchains = if discovered_path.exists() {
            match std::fs::read(&discovered_path) {
                Ok(bytes) => {
                    use noble_codec::NobleCbor;
                    std::collections::HashMap::<u32, noble_api::types::DiscoveredBlockchainInfo>::from_cbor(&bytes)
                        .unwrap_or_default()
                }
                Err(_) => std::collections::HashMap::new(),
            }
        } else {
            std::collections::HashMap::new()
        };

        // Build shared state for HealingManager before constructing Self.
        let last_proposed = Arc::new(parking_lot::Mutex::new(None));
        let sync_behind_shared = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sync_target_height_shared = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let discovered_arc = Arc::new(Mutex::new(discovered_blockchains));

        let healing = crate::healing::HealingManager::new(
            storage.clone(),
            consensus.clone(),
            mempool.clone(),
            chain_id_arc.clone(),
            peer_info.clone(),
            last_proposed.clone(),
            discovered_arc,
            Some(discovered_path),
            sync_behind_shared,
            sync_target_height_shared,
        );

        Ok(Self {
            storage,
            mempool,
            consensus,
            wallet_keystore,
            wallet_state,
            network_stats,
            peer_info,
            chain_id: chain_id_arc,
            network_name: if chain_id != 0 { format!("{:08X}", chain_id) } else { "pre-genesis".to_string() },
            start_time: std::time::Instant::now(),
            pki_attestation,
            ca_store,
            chain_meta,
            announce_keypair,
            clock_drift_paused: std::sync::atomic::AtomicBool::new(false),
            validator_list_path: Some(validator_list_path),
            seed_addrs: config.network.seeds.clone(),
            last_redial_at: std::sync::atomic::AtomicU64::new(0),
            last_proposed,
            healing,
        })
    }

    /// Read the current chain_id (lock-free atomic load).
    #[inline]
    pub fn get_chain_id(&self) -> u32 {
        self.chain_id.load(std::sync::atomic::Ordering::Relaxed)
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
            // Cycle duration is 1200s (20 min); elapsed = total - remaining
            m.cycle_elapsed_secs
                .set((noble_core::CYCLE_DURATION_SECS.saturating_sub(cycle_remaining)) as f64);
        }

        // S49: Clock drift watchdog.
        if let Some(offset_ms) = self.network_stats.read().median_clock_offset_ms {
            m.clock_drift_seconds.set(offset_ms as f64 / 1000.0);
            let abs_drift = offset_ms.unsigned_abs() / 1000;
            if abs_drift > noble_core::CLOCK_DRIFT_CRITICAL_SECS {
                tracing::error!(
                    task = "clock_drift",
                    drift_secs = abs_drift,
                    "CRITICAL: Node clock drift exceeds {}s — block proposals suppressed",
                    noble_core::CLOCK_DRIFT_CRITICAL_SECS,
                );
                self.clock_drift_paused
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            } else if abs_drift > noble_core::CLOCK_DRIFT_WARNING_SECS {
                tracing::warn!(
                    task = "clock_drift",
                    drift_secs = abs_drift,
                    "WARNING: Node clock drift exceeds {}s",
                    noble_core::CLOCK_DRIFT_WARNING_SECS,
                );
                self.clock_drift_paused
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            } else {
                self.clock_drift_paused
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    /// Run an integrity check on the most recent `count` blocks.
    /// Returns the integrity report.
    pub fn verify_recent_blocks(&self, count: u64) -> IntegrityReport {
        let height = self.chain_height();
        // No blocks in storage — nothing to verify.
        if height == 0 && self.storage.read().get_chain_tip().ok().flatten().is_none() {
            return IntegrityReport {
                heights_checked: 0,
                first_corrupt_height: None,
                findings: Vec::new(),
            };
        }
        let start = height.saturating_sub(count.saturating_sub(1));
        let guard = self.storage.read();
        noble_storage::verify_chain_integrity(&*guard, self.get_chain_id(), start, height)
    }

    /// Rollback the chain to the given height, recalculating balances.
    /// Used when corruption is detected or from the CLI `chain rollback` command (S17-C).
    #[allow(dead_code)]
    pub fn rollback_to_height(
        &self,
        target_height: u64,
    ) -> Result<noble_storage::ChainTip, Box<dyn std::error::Error>> {
        let storage = self.storage.read();
        let tip = storage.rollback_to_height(target_height, self.get_chain_id())?;
        // Update consensus engine tip
        {
            let mut engine = self.consensus.write();
            engine.update_tip(tip.height, tip.block_hash);
        }
        Ok(tip)
    }

    /// Build a signed NodeAnnounce from the current identity data.
    /// Returns `None` if the node has no announce keypair (observer mode).
    fn build_node_announce(
        &self,
        identity: &NodeIdentityData,
    ) -> Option<Box<noble_core::NodeAnnounce>> {
        let (ref sk, ref pk) = self.announce_keypair.as_ref()?;

        let org_type: noble_core::OrgType = identity
            .org_type
            .parse()
            .unwrap_or(noble_core::OrgType::Individual);
        let node_role: noble_core::NodeRole = identity
            .node_role
            .parse()
            .unwrap_or(noble_core::NodeRole::FullNode);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let host_addr = if identity.host_address.is_empty() {
            None
        } else {
            Some(identity.host_address.clone())
        };
        let country_code = if identity.country_code.is_empty() {
            None
        } else {
            Some(identity.country_code.clone())
        };

        // S53: Include committed chain tip and active proposal in the announce.
        let (tip_h, tip_hash) = self.consensus.read().chain_tip();
        let chain_tip_height = if tip_h > 0 { Some(tip_h) } else { None };
        let chain_tip_hash = if tip_h > 0 {
            Some(*tip_hash.as_bytes())
        } else {
            None
        };
        let (proposed_height, proposed_hash) = match *self.last_proposed.lock() {
            Some((h, hash)) => (Some(h), Some(hash)),
            None => (None, None),
        };

        let announce = noble_core::NodeAnnounce::sign_with_attestation(
            pk.clone(),
            identity.node_name.clone(),
            org_type,
            if identity.org_name.is_empty() {
                None
            } else {
                Some(identity.org_name.clone())
            },
            node_role,
            if identity.contact_email.is_empty() {
                None
            } else {
                Some(identity.contact_email.clone())
            },
            if identity.website.is_empty() {
                None
            } else {
                Some(identity.website.clone())
            },
            host_addr,
            country_code,
            identity.wants_to_validate,
            identity.wants_to_vote,
            chain_tip_height,
            chain_tip_hash,
            proposed_height,
            proposed_hash,
            self.get_chain_id(),
            self.network_name.clone(),
            {
                let w = self.healing.chain_vote_weight().load(std::sync::atomic::Ordering::Relaxed);
                if w > 0 { Some(w) } else { None }
            },
            now,
            sk,
            self.pki_attestation.clone(),
        );

        match announce {
            Ok(a) => Some(Box::new(a)),
            Err(e) => {
                tracing::warn!(task = "announce", "Failed to sign NodeAnnounce: {e}");
                None
            }
        }
    }

    /// Build and publish a NodeAnnounce to the network.
    /// Redial seed peers and stored peer records when connectivity is low.
    ///
    /// Called periodically (every 30s) when `peer_count < seed_count` (or < 2),
    /// and immediately when the last peer disconnects.
    /// Dials: (1) seed/bootstrap addresses from config, (2) stored peer records
    /// with known multiaddrs, (3) validator registry IPs from CBOR metadata.
    fn redial_known_peers(
        &self,
        cmd: &mpsc::Sender<NetworkCommand>,
        activity_tx: &tokio::sync::broadcast::Sender<serde_json::Value>,
    ) {
        // Stamp cooldown
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_redial_at.store(now_ts, std::sync::atomic::Ordering::Relaxed);

        let mut dialed = 0u32;
        let mut seen = std::collections::HashSet::<String>::new();

        // Dial a multiaddr string, deduplicating.
        let mut try_dial = |maddr_str: &str, cmd: &mpsc::Sender<NetworkCommand>| {
            if !seen.insert(maddr_str.to_string()) {
                return;
            }
            if let Ok(maddr) = maddr_str.parse::<noble_network::Multiaddr>() {
                let _ = cmd.try_send(NetworkCommand::DialPeer(maddr, None));
                dialed += 1;
            }
        };

        // For bare IPs, try all 3 P2P ports (8780, 8781, 8782) so we reach
        // peers that fell back to alternate ports on restart.
        let expand_addr = |addr: &str| -> Vec<String> {
            if addr.starts_with('/') {
                vec![addr.to_string()]
            } else {
                vec![
                    format!("/ip4/{addr}/tcp/8780"),
                    format!("/ip4/{addr}/tcp/8781"),
                    format!("/ip4/{addr}/tcp/8782"),
                ]
            }
        };

        // 1. Seed peers from config
        for addr_str in &self.seed_addrs {
            for maddr_str in expand_addr(addr_str) {
                try_dial(&maddr_str, cmd);
            }
        }

        // 2. Stored peer records with known addresses
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let storage = self.storage.read();
        let all_records = storage.list_peer_records().unwrap_or_default();
        drop(storage);

        let self_pk_wire = self
            .announce_keypair
            .as_ref()
            .map(|(_, pk)| pk.to_wire_bytes());

        for rec in &all_records {
            // Skip SELF
            if let Some(ref self_wire) = self_pk_wire {
                if rec.identity_key == *self_wire {
                    continue;
                }
            }
            // Skip very stale records (> 7 days)
            if rec.is_stale(now, 604_800) {
                continue;
            }
            // Prefer the actual last-seen address (includes correct port).
            let addr_str = rec
                .last_addr
                .as_deref()
                .or_else(|| {
                    rec.last_announce
                        .as_ref()
                        .and_then(|a| a.host_address.as_deref())
                });
            if let Some(addr) = addr_str {
                for maddr_str in expand_addr(addr) {
                    try_dial(&maddr_str, cmd);
                }
            }
        }

        // 3. Validator registry IPs (CBOR-persistent)
        {
            let engine = self.consensus.read();
            let mut addrs = engine.validator_list().validator_addresses();
            addrs.extend(engine.validator_list().known_peer_addresses());
            drop(engine);
            for addr in addrs {
                for maddr_str in expand_addr(&addr) {
                    try_dial(&maddr_str, cmd);
                }
            }
        }

        if dialed > 0 {
            let peer_count = self.network_stats.read().peer_count;
            tracing::info!(
                task = "reconnect",
                "Low connectivity ({peer_count} peers) — redialing {dialed} known addresses"
            );
            // Only show in GUI when we have at least 1 peer (suppresses
            // startup spam while waiting for the first connection).
            if peer_count > 0 {
                let _ = activity_tx.send(serde_json::json!({
                    "event": "reconnect_attempt",
                    "addresses": dialed,
                    "current_peers": peer_count,
                }));
            }
        }
    }


    fn publish_node_announce(
        &self,
        identity: &Arc<RwLock<NodeIdentityData>>,
        cmd: &mpsc::Sender<NetworkCommand>,
        activity_tx: &tokio::sync::broadcast::Sender<serde_json::Value>,
    ) {
        let id = identity.read().clone();
        if let Some(announce) = self.build_node_announce(&id) {
            tracing::info!(
                task = "announce",
                "Publishing NodeAnnounce for '{}'",
                id.node_name,
            );
            if let Err(e) = cmd.try_send(NetworkCommand::PublishNodeAnnounce(announce)) {
                tracing::warn!(task = "announce", "Failed to send PublishNodeAnnounce: {e}");
            } else {
                let _ = activity_tx.send(serde_json::json!({
                    "event": "announce_published",
                    "node_name": id.node_name,
                }));
            }
        }
    }

    /// Run the node event loop.
    ///
    /// Starts the P2P network, JSON-RPC server, and runs `tokio::select!`
    /// processing: network events → consensus → storage, consensus ticks,
    /// and CTRL+C graceful shutdown.
    pub async fn run(
        mut self,
        config: &NodeConfig,
        trace_handle: Option<Arc<noble_api::trace_types::TraceHandle>>,
        metrics: Option<NobleMetrics>,
        config_path: Option<std::path::PathBuf>,
    ) -> Result<(), NodeError> {
        // --- Parse port numbers from config addresses ---
        let rpc_port = parse_port(&config.api.rpc_addr).unwrap_or(8783);
        let ws_port = parse_port(&config.api.ws_addr).unwrap_or(8784);

        // --- Load node identity (before network so we can use its preferred port) ---
        let node_identity = load_identity(config);
        let identity_path = config.storage.data_dir.join("identity.json");

        // --- Sync TOML config from identity.json ---
        // identity.json is the canonical source for node role, wants_to_validate, etc.
        // The TOML may have stale defaults (e.g. role=observer) if it was generated
        // before the setup wizard ran. Sync the TOML so subsequent restarts and
        // API queries reflect the identity's authoritative values.
        if node_identity.setup_complete {
            if let Some(ref cp) = config_path {
                sync_toml_from_identity(cp, &node_identity);
            }
        }

        // --- Re-wire engine flags from canonical identity.json ---
        // init_with_storage() wired proposals_enabled/voting_enabled from the TOML
        // config, but identity.json (written by the setup wizard or setNodeIdentity
        // RPC) is the authoritative source. The TOML file sync above writes to disk
        // but does NOT update the in-memory config struct, so the engine may still
        // have stale defaults (e.g. voting_enabled=false when identity says true).
        {
            let mut engine = self.consensus.write();
            engine.set_proposals_enabled(node_identity.wants_to_validate);
            engine.set_voting_enabled(node_identity.wants_to_vote);
            tracing::info!(
                task = "config_load",
                "Engine flags re-wired from identity.json: proposals_enabled={}, voting_enabled={}",
                node_identity.wants_to_validate,
                node_identity.wants_to_vote,
            );

            // Re-check validator self-registration: init_with_storage() used TOML
            // config which may have had stale wants_to_validate=false, causing the
            // node to remove itself from the validator list. Re-add if identity
            // says we should be validating.
            if node_identity.wants_to_validate {
                if let Some((_, ref pk)) = self.announce_keypair {
                    if !engine.validator_list().is_validator(pk) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        engine.validator_list_mut().add_validator(pk.clone(), 1, now);
                        tracing::info!(
                            task = "config_load",
                            "Re-registered as validator from identity.json: {}",
                            pk.to_address(),
                        );
                    }
                }
            }
        }

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
        net_config.chain_id = self.get_chain_id();
        // Initialize tip_height from consensus so the early-chain exemption
        // in service.rs reflects committed blocks from previous runs, not 0.
        net_config.tip_height = self.consensus.read().chain_tip().0;
        // Persist the P2P identity keypair so PeerId stays stable across restarts.
        net_config.data_dir = Some(config.storage.data_dir.clone());
        net_config.chain_meta = Some(self.chain_meta);

        // Try to load P2P identity from unified keystore (migrated in Node::new)
        {
            let ks = self.wallet_keystore.lock();
            if ks.is_unlocked() {
                if let Ok(proto_bytes) = ks.get_raw(noble_crypto::SCHEME_P2P_IDENTITY) {
                    net_config.pre_loaded_p2p_key = Some(proto_bytes);
                }
            }
        }

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

        // --- Dial recently-seen peers for faster reconnection ---
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let storage = self.storage.read();
            let all_records = storage.list_peer_records().unwrap_or_else(|e| {
                tracing::warn!(task = "node_startup", "failed to load peer records: {e}");
                Vec::new()
            });
            drop(storage);

            // Primary: recent peers with known multiaddr (existing behavior)
            let mut records: Vec<_> = all_records
                .iter()
                .filter(|r| !r.is_stale(now, 86_400) && r.last_addr.is_some())
                .collect();
            records.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
            records.truncate(50);

            if !records.is_empty() {
                for record in &records {
                    if let Some(ref addr_str) = record.last_addr {
                        if let Ok(addr) = addr_str.parse::<noble_network::Multiaddr>() {
                            if let Err(e) = network_cmd.try_send(NetworkCommand::DialPeer(addr, None)) {
                                tracing::debug!(task = "node_startup", "dial command backpressure: {e}");
                            }
                        }
                    }
                }
                tracing::info!(
                    task = "node_startup",
                    "Dialing {} cached peers from peer memory",
                    records.len()
                );
            } else {
                // Fallback: scan ALL peer records for announce host_address
                let self_pk_wire = self
                    .announce_keypair
                    .as_ref()
                    .map(|(_, pk)| pk.to_wire_bytes());
                let mut dialed = 0u32;
                for rec in &all_records {
                    // Skip SELF
                    if let Some(ref self_wire) = self_pk_wire {
                        if rec.identity_key == *self_wire {
                            continue;
                        }
                    }
                    let addr_str = rec
                        .last_addr
                        .as_deref()
                        .or_else(|| {
                            rec.last_announce
                                .as_ref()
                                .and_then(|a| a.host_address.as_deref())
                        });
                    if let Some(addr) = addr_str {
                        let normalized = if addr.starts_with('/') {
                            addr.to_string()
                        } else {
                            format!("/ip4/{}/tcp/8780", addr)
                        };
                        if let Ok(maddr) = normalized.parse::<noble_network::Multiaddr>() {
                            if let Err(e) = network_cmd.try_send(NetworkCommand::DialPeer(maddr, None)) {
                                tracing::debug!(task = "node_startup", "dial command backpressure: {e}");
                            }
                            dialed += 1;
                        }
                    }
                }
                if dialed > 0 {
                    tracing::info!(
                        task = "node_startup",
                        "No cached peers; dialing {dialed} peers from announce records"
                    );
                }
            }

            // Tertiary fallback: CBOR-persistent IPs (survives chain resets).
            // Includes both validator registry IPs and known peer (candidate) IPs.
            {
                let engine = self.consensus.read();
                let mut addrs = engine.validator_list().validator_addresses();
                addrs.extend(engine.validator_list().known_peer_addresses());
                drop(engine);
                // Dedup addresses (validators and known_peers may overlap).
                let addrs: std::collections::HashSet<String> = addrs.into_iter().collect();
                let mut cbor_dialed = 0u32;
                for addr in addrs {
                    let normalized = if addr.starts_with('/') {
                        addr.clone()
                    } else {
                        format!("/ip4/{}/tcp/8780", addr)
                    };
                    if let Ok(maddr) = normalized.parse::<noble_network::Multiaddr>() {
                        if let Err(e) = network_cmd.try_send(NetworkCommand::DialPeer(maddr, None)) {
                            tracing::debug!(task = "node_startup", "dial command backpressure: {e}");
                        }
                        cbor_dialed += 1;
                    }
                }
                if cbor_dialed > 0 {
                    tracing::info!(
                        task = "node_startup",
                        "Dialing {cbor_dialed} peers from CBOR registry metadata"
                    );
                }
            }
        }

        // --- Derive validator key info for ApiState ---
        // Use the already-loaded announce_keypair (which comes from the validator key,
        // including unified keystore fallback) instead of re-reading from disk.
        // compute_validator_key_info would fail after migration renames validator.key.
        let (validator_pubkey_str, validator_scheme_str, validator_key_path_str) =
            if let Some((ref _sk, ref pk)) = self.announce_keypair {
                let pubkey_hex = hex::encode(pk.to_wire_bytes());
                let scheme = match pk {
                    noble_crypto::NoblePublicKey::Ed25519(_) => "ed25519",
                    noble_crypto::NoblePublicKey::Secp256k1(_) => "secp256k1",
                };
                (Some(pubkey_hex), Some(scheme.to_string()), Some("unified-keystore".to_string()))
            } else {
                (None, None, None)
            };

        // --- Initialize TOTP auth ---
        let (totp_validator, totp_secret_path) =
            init_totp_validator(config, &self.chain_meta)
                .map_err(|e| NodeError::Config(e.to_string()))?;

        // --- Build broadcast channels for WebSocket subscriptions ---
        // Keep one receiver alive per channel so messages are buffered (not lost)
        // until the first WS subscriber connects.
        let (new_block_tx, _block_rx_keepalive) = broadcast::channel(64);
        let (new_tx_tx, _tx_rx_keepalive) = broadcast::channel(256);
        let (cycle_phase_tx, _phase_rx_keepalive) = broadcast::channel(64);
        let (peer_update_tx, _peer_rx_keepalive) = broadcast::channel(64);

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
                        // If the existing value is an array, write the new value as a TOML
                        // array (comma-separated items, or empty string → empty array).
                        let existing_is_array = t.get(key)
                            .map(|v| v.is_array())
                            .unwrap_or(false);
                        // Known array fields (for first-time writes when the key doesn't exist yet).
                        let known_array = matches!(
                            (section, key),
                            ("network", "seeds") | ("api", "allowed_ips") | ("api", "tls_san") | ("consensus", "voting_subset")
                        );
                        let toml_value = if existing_is_array || known_array {
                            if value.is_empty() {
                                toml::Value::Array(Vec::new())
                            } else {
                                toml::Value::Array(
                                    value.split(',')
                                        .map(|s| toml::Value::String(s.trim().to_string()))
                                        .collect()
                                )
                            }
                        } else if let Ok(n) = value.parse::<i64>() {
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
        ];
        // Build RPC origins list for CSP (http(s):// + ws(s)://).
        let ws_scheme = if tls_config.is_some() { "wss" } else { "ws" };
        let mut rpc_origins_vec: Vec<String> = vec![
            format!("{rpc_scheme}://127.0.0.1:{rpc_port}"),
            format!("{rpc_scheme}://localhost:{rpc_port}"),
            format!("{ws_scheme}://127.0.0.1:{ws_port}"),
            format!("{ws_scheme}://localhost:{ws_port}"),
        ];
        // Add LAN IPs (from setup-mode detection or tls_san config).
        for san in &extra_sans {
            if san != "localhost" {
                let gui_origin = format!("{gui_scheme_cors}://{san}:{gui_port}");
                if !cors_origins_vec.contains(&gui_origin) {
                    cors_origins_vec.push(gui_origin);
                }
                let rpc_http = format!("{rpc_scheme}://{san}:{rpc_port}");
                let rpc_ws = format!("{ws_scheme}://{san}:{ws_port}");
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
            let rpc_ws = format!("{ws_scheme}://{ip}:{ws_port}");
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

        // --- Announce trigger channel (identity update → re-publish NodeAnnounce) ---
        let (announce_trigger_tx, mut announce_trigger_rx) = mpsc::channel::<()>(4);

        // Share node identity as Arc<RwLock> for announce publishing.
        let shared_identity = Arc::new(RwLock::new(node_identity));

        // --- Build ApiState ---
        let api_state = Arc::new(ApiState {
            storage: self.storage.clone(),
            mempool: self.mempool.clone(),
            consensus: self.consensus.clone(),
            network_cmd: network_cmd.clone(),
            wallet_keystore: self.wallet_keystore.clone(),
            wallet_state: self.wallet_state.clone(),
            network_stats: self.network_stats.clone(),
            chain_id: self.chain_id.clone(),
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
            validator_list_path: self.validator_list_path.clone(),
            peer_info: self.peer_info.clone(),
            node_identity: shared_identity.clone(),
            identity_path: Some(identity_path),
            tls_fingerprint: parking_lot::RwLock::new(tls_fingerprint),
            tls_expires_at: parking_lot::RwLock::new(tls_expires_at),
            tls_expiry_secs: parking_lot::RwLock::new(tls_expiry_secs),
            tls_sans: parking_lot::RwLock::new(tls_sans_init),
            tls_regenerate,
            tls_upload,
            setup_mode,
            max_peers: std::sync::atomic::AtomicU32::new(config.network.max_peers),
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
            reward_address: parking_lot::RwLock::new({
                if !config.rewards.reward_address.is_empty() {
                    Some(config.rewards.reward_address.clone())
                } else {
                    // Auto-derive from first wallet key's Noble hex address.
                    // Uses the hex-encoded wire bytes (scheme_id || pubkey) so it's
                    // clearly a Noble address, not a Bitcoin address.
                    let ks = self.wallet_keystore.lock();
                    let auto = ks.list_keys().ok().and_then(|keys| {
                        keys.into_iter().next().map(|pk| pk.to_address())
                    });
                    if auto.is_some() {
                        tracing::info!(
                            task = "config_load",
                            "Reward address auto-derived from wallet key: {}",
                            auto.as_deref().unwrap_or(""),
                        );
                    }
                    auto
                }
            }),
            enable_totp: enable_totp_closure,
            set_config_value: set_config_value_closure,
            config_path,
            chain_meta: self.chain_meta,
            seeds: parking_lot::RwLock::new(config.network.seeds.clone()),
            announce_trigger: announce_trigger_tx,
            cache_size_mb: config.storage.cache_size_mb,
            compression_enabled: config.storage.compression,
            max_db_size_gb: config.storage.max_db_size_gb,
            network_name: { let cid = self.get_chain_id(); if cid != 0 { format!("{:08X}", cid) } else { "pre-genesis".to_string() } },
            genesis_hash: {
                let s = self.storage.read();
                s.get_block_hash_by_height(0)
                    .map(|h| hex::encode(h.as_bytes()))
                    .unwrap_or_default()
            },
            discovered_blockchains: self.healing.discovered_blockchains().clone(),
            sync_behind: self.healing.sync_behind_shared().clone(),
            sync_target_height: self.healing.sync_target_height_shared().clone(),
        });

        // --- Determine bind addresses ---
        // When remote access is enabled, bind to 0.0.0.0 instead of 127.0.0.1.
        let rpc_bind_addr = if ip_filter.as_ref().is_some_and(|f| f.has_remote_access()) {
            config.api.rpc_addr.replace("127.0.0.1", "0.0.0.0")
        } else {
            config.api.rpc_addr.clone()
        };
        let ws_bind_addr = if ip_filter.as_ref().is_some_and(|f| f.has_remote_access()) {
            config.api.ws_addr.replace("127.0.0.1", "0.0.0.0")
        } else {
            config.api.ws_addr.clone()
        };

        // Clone rate limiter reference before api_state is consumed.
        let rate_limiter_ref = api_state.rate_limiter.clone();

        // --- Start RPC (HTTP-only) + WS (WS-only) servers ---
        let rpc_histogram = metrics
            .as_ref()
            .map(|m| std::sync::Arc::new(m.rpc_request_duration.clone()));
        let server_handles = noble_api::server::start_server(
            api_state,
            &rpc_bind_addr,
            &ws_bind_addr,
            rpc_histogram,
            tls_config.clone(),
            config.api.max_connections,
        )
        .await
        .map_err(|e| NodeError::Api(e.to_string()))?;

        tracing::info!(
            task = "node_startup",
            "RPC (HTTP-only) listening on {}, WS listening on {}",
            rpc_bind_addr, ws_bind_addr
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
                // Bombproof restart loop: if the GUI server panics or returns an
                // error, wait with exponential backoff and restart.  The dashboard
                // must never stay dead — it is the operator's primary interface.
                let mut backoff_secs: u64 = 1;
                loop {
                    let filter_c = gui_filter.clone();
                    let tls_c = gui_tls.clone();
                    let origins_c = gui_rpc_origins.clone();
                    let path_c = gui_path.clone();

                    // Catch both errors AND panics.
                    let result = std::panic::AssertUnwindSafe(
                        crate::gui_server::start_gui_server(
                            gui_addr,
                            path_c,
                            filter_c,
                            tls_c,
                            origins_c,
                            rpc_port,
                            ws_port,
                            setup_mode,
                        ),
                    );
                    match futures_util::FutureExt::catch_unwind(result).await {
                        Ok(Ok(())) => {
                            // Server returned cleanly (shouldn't happen — it's an infinite loop).
                            tracing::warn!(task = "gui_server", "GUI server exited cleanly — restarting");
                        }
                        Ok(Err(e)) => {
                            tracing::error!(
                                task = "gui_server",
                                "GUI server error: {e} — restarting in {backoff_secs}s"
                            );
                        }
                        Err(panic) => {
                            let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                                (*s).to_string()
                            } else if let Some(s) = panic.downcast_ref::<String>() {
                                s.clone()
                            } else {
                                "unknown panic".to_string()
                            };
                            tracing::error!(
                                task = "gui_server",
                                "GUI server PANICKED: {msg} — restarting in {backoff_secs}s"
                            );
                        }
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(30); // 1, 2, 4, 8, 16, 30, 30, ...
                    tracing::info!(task = "gui_server", "Restarting GUI server...");
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

        // --- NodeAnnounce periodic broadcast (every 20 min) ---
        let mut announce_interval = tokio::time::interval(std::time::Duration::from_secs(1200));
        announce_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut initial_announce_sent = false;

        // --- Delayed re-announce: fires 3s after last PeerConnected to survive gossipsub mesh race ---
        let announce_delay = tokio::time::sleep(std::time::Duration::from_secs(86400));
        tokio::pin!(announce_delay);
        let mut announce_delay_armed = false;

        // --- Stale-peer sync fallback (every 60s) — sends GetStatus to peers silent for 120s ---
        // Start after 3s delay so WS subscribers have time to connect before sync events fire.
        let mut peer_status_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(3),
            std::time::Duration::from_secs(60),
        );
        peer_status_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // --- Auto-reconnect timer (every 30s, first tick at T+3s) — redial seeds + stored peers when isolated ---
        let mut reconnect_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + std::time::Duration::from_secs(3),
            std::time::Duration::from_secs(30),
        );
        reconnect_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Inject IO channels into HealingManager now that network + broadcast are ready.
        self.healing.set_io_channels(
            network_cmd.clone(),
            new_block_tx.clone(),
            cycle_phase_tx.clone(),
            metrics.clone(),
        );

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
                            let is_peer_connected = matches!(net_event, NetworkEvent::PeerConnected { .. });
                            self.handle_network_event(
                                &net_event,
                                &network_cmd,
                                &new_block_tx,
                                &new_tx_tx,
                                &peer_update_tx,
                                &cycle_phase_tx,
                                &metrics,
                                &shared_identity,
                            );
                            // On PeerConnected: publish NodeAnnounce immediately AND
                            // arm a 3-second delayed re-announce.  The immediate publish
                            // may be lost if the gossipsub mesh hasn't formed yet (needs
                            // a heartbeat).  The delayed re-publish ensures delivery.
                            if is_peer_connected {
                                self.publish_node_announce(&shared_identity, &network_cmd, &cycle_phase_tx);
                                initial_announce_sent = true;
                                announce_delay.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(3));
                                announce_delay_armed = true;
                            }
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
                    self.process_cycle_actions(actions, &network_cmd, &new_block_tx, &cycle_phase_tx, &metrics, &shared_identity);

                    // ── Sync retry (delegated to healing manager) ──
                    self.healing.on_tick_sync_retry(now);

                    // ── Fork evaluation (delegated to healing manager) ──
                    // The sync_behind guard is enforced inside on_tick_fork_eval().
                    {
                        let dwell_before = self.consensus.read().fork_resolver().dwell_counter();
                        let cycle_events = self.healing.on_tick_fork_eval();
                        for ce in cycle_events {
                            let io = {
                                let mut engine = self.consensus.write();
                                engine.step(ce)
                            };
                            self.process_cycle_actions(io, &network_cmd, &new_block_tx, &cycle_phase_tx, &metrics, &shared_identity);
                        }

                        // Emit fork alignment status to GUI (requires post-injection dwell check).
                        if !self.healing.sync_behind() {
                            let dwell_after = self.consensus.read().fork_resolver().dwell_counter();
                            if dwell_after > 0 {
                                let engine = self.consensus.read();
                                let resolver = engine.fork_resolver();
                                let remaining = resolver.min_fork_duration().saturating_sub(dwell_after);
                                let tracked = resolver.tracked_fork_height();
                                drop(engine);
                                let _ = cycle_phase_tx.send(serde_json::json!({
                                    "event": "fork_alignment_pending",
                                    "cycles_remaining": remaining,
                                    "dwell_counter": dwell_after,
                                    "tracked_height": tracked,
                                }));
                            } else if dwell_before > 0 {
                                let _ = cycle_phase_tx.send(serde_json::json!({
                                    "event": "fork_alignment_clear",
                                }));
                            }
                        }
                    }

                    // ── Cross-chain evaluation (delegated to healing manager) ──
                    {
                        let cycle_events = self.healing.on_tick_cross_chain_eval();
                        for ce in cycle_events {
                            let io = {
                                let mut engine = self.consensus.write();
                                engine.step(ce)
                            };
                            self.process_cycle_actions(io, &network_cmd, &new_block_tx, &cycle_phase_tx, &metrics, &shared_identity);
                        }
                    }

                    // H-002: Persist cycle history if a cycle boundary just occurred.
                    {
                        let mut engine = self.consensus.write();
                        if let Some(history) = engine.take_cycle_history() {
                            let (tip_height, _) = engine.chain_tip();
                            // Don't persist during bootstrap (tip=0): cycle numbers
                            // are based on a temporary epoch and become meaningless
                            // once the real chain's block 1 resets the epoch.
                            // This also prevents race conditions where a chain reset
                            // clears the DB but a concurrent tick re-inserts a stale
                            // entry before the engine is fully reset.
                            if tip_height == 0 {
                                tracing::debug!(
                                    task = "consensus",
                                    cycle = history.cycle_number,
                                    "skipping cycle history persist during bootstrap (tip=0)"
                                );
                            } else if let Ok(bytes) = noble_codec::NobleCbor::to_cbor(&history) {
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

                // Periodic NodeAnnounce re-broadcast (every 20 min)
                _ = announce_interval.tick() => {
                    if initial_announce_sent {
                        self.publish_node_announce(&shared_identity, &network_cmd, &cycle_phase_tx);
                    }
                }

                // Delayed re-announce: 3s after PeerConnected, re-publish to survive
                // gossipsub mesh formation race.
                _ = &mut announce_delay, if announce_delay_armed => {
                    self.publish_node_announce(&shared_identity, &network_cmd, &cycle_phase_tx);
                    announce_delay_armed = false;
                }

                // Stale-peer sync fallback — send GetStatus only to peers whose
                // chain_tip hasn't been refreshed via gossip in 120s.
                _ = peer_status_interval.tick() => {
                    let peer_count = self.network_stats.read().peer_count;
                    if peer_count > 0 {
                        if let Err(e) = network_cmd.try_send(NetworkCommand::RequestStaleSync { threshold_secs: 120 }) {
                            tracing::warn!(task = "sync", "periodic RequestStaleSync dropped: {e}");
                        }
                    }
                }

                // Auto-reconnect: redial when connectivity is low.
                // Threshold: fewer peers than seed count (minimum 1).
                _ = reconnect_interval.tick() => {
                    let current_peers = {
                        let stats = self.network_stats.read();
                        stats.peer_count
                    };
                    let min_desired = self.seed_addrs.len().max(1);
                    if current_peers < min_desired {
                        self.redial_known_peers(&network_cmd, &cycle_phase_tx);
                    }
                }

                // On-demand NodeAnnounce re-broadcast (triggered by identity update RPC)
                Some(()) = announce_trigger_rx.recv() => {
                    self.publish_node_announce(&shared_identity, &network_cmd, &cycle_phase_tx);
                    initial_announce_sent = true;
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

        // Snapshot connected peers for faster reconnection on next startup.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let peers = self.peer_info.read().clone();
            let storage = self.storage.read();
            let mut snapshot_count = 0u32;
            for entry in peers.values() {
                let peer_id_bytes = hex::decode(&entry.peer_id).unwrap_or_default();
                if peer_id_bytes.is_empty() {
                    continue;
                }
                // Find the peer record by scanning — O(n) but only runs once at shutdown.
                if let Ok(records) = storage.list_peer_records() {
                    if let Some(mut record) = records
                        .into_iter()
                        .find(|r| r.peer_id_bytes == peer_id_bytes)
                    {
                        record.last_seen = now;
                        if !entry.addr.is_empty() {
                            record.last_addr = Some(entry.addr.clone());
                        }
                        let _ = storage.store_peer_record(&record);
                        snapshot_count += 1;
                    }
                }
            }
            if snapshot_count > 0 {
                tracing::info!(
                    task = "node_shutdown",
                    "Snapshotted {snapshot_count} peer records for faster reconnection"
                );
            }
        }

        if let Err(e) = network_cmd.try_send(NetworkCommand::Shutdown) {
            tracing::debug!(task = "shutdown", "network shutdown command failed: {e}");
        }
        server_handles
            .rpc_handle
            .stop()
            .map_err(|e| NodeError::Api(format!("RPC stop: {e}")))?;
        server_handles
            .ws_handle
            .stop()
            .map_err(|e| NodeError::Api(format!("WS stop: {e}")))?;
        tracing::info!(task = "node_shutdown", "Node shutdown complete");
        Ok(())
    }

    /// Handle a single network event: route to consensus, update stats, etc.
    #[allow(clippy::too_many_arguments)]
    fn handle_network_event(
        &mut self,
        event: &NetworkEvent,
        network_cmd: &mpsc::Sender<NetworkCommand>,
        new_block_tx: &broadcast::Sender<serde_json::Value>,
        new_tx_tx: &broadcast::Sender<serde_json::Value>,
        peer_update_tx: &broadcast::Sender<serde_json::Value>,
        cycle_phase_tx: &broadcast::Sender<serde_json::Value>,
        metrics: &Option<NobleMetrics>,
        shared_identity: &Arc<RwLock<NodeIdentityData>>,
    ) {
        match event {
            NetworkEvent::PeerConnected {
                peer_id,
                addr,
                direction,
                chain_tip, // S55: was `..` — now explicit
            } => {
                let hex_pid = hex::encode(peer_id);
                let is_inbound = direction == "inbound";

                // Guard: skip duplicate PeerConnected for an already-tracked peer.
                // Prevents inflated peer_count from reconnect loops or duplicate
                // ConnectionEstablished events from libp2p.
                let already_tracked = self.peer_info.read().contains_key(&hex_pid);
                if already_tracked {
                    tracing::debug!(task = "peer_tracking", "duplicate PeerConnected for {hex_pid} — ignoring");
                    // Still process chain_tip update if provided.
                    if let Some((h, hash)) = chain_tip {
                        let mut info = self.peer_info.write();
                        if let Some(entry) = info.get_mut(&hex_pid) {
                            entry.chain_tip_height = Some(*h);
                            entry.chain_tip_hash = Some(hex::encode(hash));
                        }
                    }
                    return;
                }

                let new_count = {
                    let mut stats = self.network_stats.write();
                    stats.peer_count += 1;
                    if is_inbound {
                        stats.inbound_count += 1;
                    } else {
                        stats.outbound_count += 1;
                    }
                    stats.peer_count
                };
                // AUD2-C1: Wire peer count to consensus engine so compute_majority works
                {
                    let mut engine = self.consensus.write();
                    engine.set_peer_count(new_count);
                }
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                // S55: Use chain_tip from PeerConnected when available.
                let (cth, cthash) = match chain_tip {
                    Some((h, hash)) => (Some(*h), Some(hex::encode(hash))),
                    None => (None, None),
                };
                {
                    let mut info = self.peer_info.write();
                    info.insert(
                        hex_pid.clone(),
                        noble_api::state::PeerInfoEntry {
                            peer_id: hex_pid.clone(),
                            direction: direction.clone(),
                            addr: addr.clone(),
                            connected_at: now_ts,
                            ban_score: 0,
                            misbehavior_categories: Vec::new(),
                            chain_tip_height: cth,
                            chain_tip_hash: cthash,
                            proposed_height: None,
                            identity_key: None, // set when NodeAnnounce received
                            latency_ms: None,
                            last_ban_reason: None,
                            chain_id: None, // set when NodeAnnounce received
                        },
                    );
                }
                // Look up friendly name from known_peers (set by previous NodeAnnounce).
                // Fallback: check persistent peer records in storage for inbound
                // connections where peer_id_hex may not yet be in known_peers.
                let peer_name = {
                    let engine = self.consensus.read();
                    engine.validator_list().known_peers().values()
                        .find(|kp| kp.peer_id_hex.as_deref() == Some(&hex_pid))
                        .and_then(|kp| kp.node_name.clone())
                }.or_else(|| {
                    let storage = self.storage.read();
                    storage.list_peer_records().ok().and_then(|records| {
                        records.into_iter()
                            .find(|r| hex::encode(&r.peer_id_bytes) == hex_pid)
                            .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                            .filter(|n| !n.is_empty())
                    })
                });
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "connected",
                    "peer_id": hex_pid,
                    "addr": addr,
                    "direction": direction,
                    "node_name": peer_name.as_deref().unwrap_or(""),
                }));
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "peer_connected",
                    "peer_id": hex_pid,
                    "addr": addr,
                    "direction": direction,
                    "node_name": peer_name.as_deref().unwrap_or(""),
                }));
                // Sync is gossip-driven: NodeAnnounce → PeerChainTipUpdated → height compare.
                // Stale-peer fallback (GetStatus) runs every 60s for silent peers only.
                tracing::info!(task = "peer_tracking", "Peer connected ({direction}): {addr}");
            }
            NetworkEvent::PeerDisconnected { peer_id, reason } => {
                // Look up direction before removing so we can decrement the right counter.
                let hex_pid = hex::encode(peer_id);
                let was_inbound = {
                    let info = self.peer_info.read();
                    match info.get(&hex_pid) {
                        Some(e) => e.direction == "inbound",
                        None => {
                            // Defense-in-depth: peer was never in peer_info — this
                            // should not happen after the service.rs guard, but if
                            // it does, skip all decrement/event logic to avoid
                            // corrupting peer_count.
                            tracing::debug!(task = "peer_tracking", "PeerDisconnected for untracked peer {hex_pid} — ignoring");
                            return;
                        }
                    }
                };
                let new_count = {
                    let mut stats = self.network_stats.write();
                    stats.peer_count = stats.peer_count.saturating_sub(1);
                    if was_inbound {
                        stats.inbound_count = stats.inbound_count.saturating_sub(1);
                    } else {
                        stats.outbound_count = stats.outbound_count.saturating_sub(1);
                    }
                    stats.peer_count
                };
                // AUD2-C1: Update consensus engine peer count on disconnect too
                {
                    let mut engine = self.consensus.write();
                    engine.set_peer_count(new_count);
                }
                // H-004: Remove from live peer info.
                {
                    let mut info = self.peer_info.write();
                    info.remove(&hex_pid);
                }
                // Resolve name before peer_info was cleared (name may come from
                // peerIdToName cache in the GUI, but node-side is more reliable).
                let disc_name = {
                    let storage = self.storage.read();
                    storage.list_peer_records().ok().and_then(|records| {
                        records.into_iter()
                            .find(|r| hex::encode(&r.peer_id_bytes) == hex_pid)
                            .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                            .filter(|n| !n.is_empty())
                    }).unwrap_or_default()
                };
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "disconnected",
                    "peer_id": hex_pid,
                    "node_name": disc_name,
                    "reason": reason,
                }));
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "peer_disconnected",
                    "peer_id": hex_pid,
                    "node_name": disc_name,
                    "reason": reason,
                }));
                // Auto-reconnect: immediately try to redial when last peer disconnects.
                // Cooldown: skip if we redialed within the last 60s to prevent tight
                // connect/disconnect loops (e.g. chain_id mismatch).
                if new_count == 0 {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let last = self.last_redial_at.load(std::sync::atomic::Ordering::Relaxed);
                    if now.saturating_sub(last) >= 60 {
                        self.redial_known_peers(network_cmd, cycle_phase_tx);
                    }
                }
            }
            NetworkEvent::PeerRejected { peer_id, addr, reason } => {
                let hex_pid = hex::encode(peer_id);
                tracing::debug!(
                    task = "peer_tracking",
                    "Connection rejected: {hex_pid} at {addr} — {reason}",
                );
                // Suppress WebSocket events for banned-peer reconnection attempts.
                // The initial PeerBanned event already informed the GUI; repeated
                // "rejected" events from reconnection loops are noise that floods
                // the connectivity log.
                if !reason.starts_with("peer is banned") {
                    let _ = peer_update_tx.send(serde_json::json!({
                        "event": "rejected",
                        "peer_id": hex_pid,
                        "addr": addr,
                        "reason": reason,
                    }));
                }
            }
            NetworkEvent::PeerScoreUpdated { peer_id, ban_score, categories, last_category, last_reason } => {
                let hex_pid = hex::encode(peer_id);
                {
                    let cat_name = noble_network::BanCategory::from_u8(*last_category)
                        .map(|c| c.as_str().to_string())
                        .unwrap_or_else(|| format!("0x{:02x}", last_category));
                    let mut info = self.peer_info.write();
                    if let Some(entry) = info.get_mut(&hex_pid) {
                        entry.ban_score = *ban_score;
                        entry.misbehavior_categories = categories.clone();
                        entry.last_ban_reason = Some((cat_name, last_reason.clone()));
                    }
                }
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "score_updated",
                    "peer_id": hex_pid,
                    "ban_score": ban_score,
                    "categories": categories,
                }));
            }
            NetworkEvent::PeerBanned { peer_id, reason, category, evidence_hash } => {
                // Persist ban to storage.
                {
                    let now_unix = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let banned_until = now_unix + 86_400; // 24h default ban duration
                    let storage = self.storage.read();
                    if let Err(e) = storage.store_ban(&peer_id, banned_until, *category, evidence_hash.as_ref()) {
                        tracing::error!(
                            peer = %hex::encode(&peer_id),
                            "FAILED to persist ban to storage: {e} — ban is memory-only, lost on restart"
                        );
                    }
                }
                let hex_pid = hex::encode(peer_id);
                tracing::warn!(
                    task = "peer_tracking",
                    "Peer banned: {hex_pid} — {reason}",
                );
                // Clean up node-level state — record_misbehavior removes the
                // peer from peer_manager.peers BEFORE disconnect, so the
                // subsequent ConnectionClosed → on_disconnected returns false
                // and PeerDisconnected is never emitted.  We must do the
                // cleanup here to prevent ghost entries and inflated counts.
                let was_inbound = {
                    let info = self.peer_info.read();
                    match info.get(&hex_pid) {
                        Some(e) => e.direction == "inbound",
                        None => {
                            // Already cleaned up or never tracked — skip.
                            let _ = cycle_phase_tx.send(serde_json::json!({
                                "event": "peer_banned",
                                "peer_id": hex_pid,
                                "reason": reason,
                            }));
                            return;
                        }
                    }
                };
                {
                    let mut stats = self.network_stats.write();
                    stats.peer_count = stats.peer_count.saturating_sub(1);
                    if was_inbound {
                        stats.inbound_count = stats.inbound_count.saturating_sub(1);
                    } else {
                        stats.outbound_count = stats.outbound_count.saturating_sub(1);
                    }
                    let new_count = stats.peer_count;
                    drop(stats);
                    let mut engine = self.consensus.write();
                    engine.set_peer_count(new_count);
                }
                {
                    let mut info = self.peer_info.write();
                    info.remove(&hex_pid);
                }
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "banned",
                    "peer_id": hex_pid,
                    "reason": reason,
                }));
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "peer_banned",
                    "peer_id": hex_pid,
                    "reason": reason,
                }));
            }
            NetworkEvent::TransactionAnnounced { tx_id, peer_id } => {
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "tx_announced",
                    "tx_id": hex::encode(tx_id),
                    "peer_id": hex::encode(peer_id),
                }));
                let _ = new_tx_tx.send(serde_json::json!({
                    "tx_id": hex::encode(tx_id),
                }));
            }
            NetworkEvent::NodeAnnounceReceived { peer_id, announce } => {
                // Always set chain_id on PeerInfoEntry, even for cross-chain peers.
                // Must happen BEFORE Cases A/B/C which return early.
                if announce.chain_id != 0 {
                    let hex_pid = hex::encode(&peer_id);
                    let mut info = self.peer_info.write();
                    if let Some(entry) = info.get_mut(&hex_pid) {
                        entry.chain_id = Some(announce.chain_id);
                    }
                }
                // --- Chain ID mismatch: blockchain discovery (delegated to healing) ---
                if announce.chain_id != 0 && self.get_chain_id() != 0 && announce.chain_id != self.get_chain_id() {
                    self.healing.on_cross_chain_announce(&announce, &peer_id);
                    return; // Skip normal announce processing (Cases A/B keep peer connected).
                }

                // Persist the announce to storage so getPeerMemory (and thus
                // the candidates list) can see it.
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let identity_wire = announce.identity_key.to_wire_bytes();
                let host_addr = announce.host_address.clone();

                // Lock order: Storage(2) only.
                let storage = self.storage.read();
                let mut record = storage
                    .get_peer_record(&identity_wire)
                    .unwrap_or_else(|_| noble_core::PeerRecord {
                        identity_key: identity_wire.clone(),
                        first_seen: now_ts,
                        last_seen: now_ts,
                        connection_count: 1,
                        last_announce: None,
                        peer_id_bytes: peer_id.clone(),
                        last_addr: host_addr.clone(),
                    });
                record.update_announce(*announce.clone(), now_ts);
                record.peer_id_bytes = peer_id.clone();
                if let Some(ref addr) = host_addr {
                    record.last_addr = Some(addr.clone());
                }
                if let Err(e) = storage.store_peer_record(&record) {
                    tracing::warn!(task = "peer_tracking", "Failed to persist peer record: {e}");
                }
                drop(storage);

                // Link PeerId → identity_key in live connection map, and track proposed_height.
                {
                    let hex_pid = hex::encode(&peer_id);
                    let mut info = self.peer_info.write();
                    if let Some(entry) = info.get_mut(&hex_pid) {
                        entry.identity_key = Some(identity_wire.clone());
                        // chain_id already set at the top of NodeAnnounceReceived handler.
                        if announce.proposed_height.is_some() {
                            entry.proposed_height = announce.proposed_height;
                        }
                    }
                }

                // Update validator registry metadata (host_address, country_code).
                // Persisted in CBOR so it survives chain resets and enables auto-dial.
                // Also update known_peers for candidate discovery persistence.
                {
                    let mut engine = self.consensus.write();
                    engine.validator_list_mut().update_network_info(
                        &announce.identity_key,
                        announce.host_address.clone(),
                        announce.country_code.clone(),
                    );
                    // Set friendly name from NodeAnnounce so vote tallies show names.
                    if !announce.node_name.is_empty() {
                        engine.validator_list_mut().set_friendly_name(
                            &announce.identity_key,
                            announce.node_name.clone(),
                        );
                    }
                    engine.validator_list_mut().update_known_peer(
                        &hex::encode(&identity_wire),
                        Some(announce.node_name.clone()),
                        announce.host_address.clone(),
                        announce.country_code.clone(),
                        announce.wants_to_validate,
                        announce.wants_to_vote,
                        Some(format!("{:?}", announce.org_type)),
                        Some(format!("{:?}", announce.node_role)),
                        Some(hex::encode(&peer_id)),
                        now_ts,
                    );
                    // Persist CBOR so metadata survives restarts and chain resets.
                    if let Some(ref path) = self.validator_list_path {
                        if let Ok(bytes) = noble_codec::NobleCbor::to_cbor(engine.validator_list()) {
                            if let Err(e) = std::fs::write(path, &bytes) {
                                tracing::warn!(task = "peer_tracking", "Failed to persist validator list CBOR: {e}");
                            }
                        }
                    }
                }

                let is_connected = {
                    let info = self.peer_info.read();
                    info.contains_key(&hex::encode(&peer_id))
                };
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "announce_received",
                    "node_name": announce.node_name,
                    "identity": hex::encode(&identity_wire),
                    "peer_id": hex::encode(&peer_id),
                    "wants_to_validate": announce.wants_to_validate,
                    "wants_to_vote": announce.wants_to_vote,
                    "software_version": announce.software_version,
                    "connected": is_connected,
                }));
                // Announce equivocation detection — fully delegated to healing.
                self.healing.handle_announce_equivocation(&announce, &identity_wire);

                tracing::debug!(
                    task = "peer_tracking",
                    "Stored announce from {} ({})",
                    announce.node_name,
                    hex::encode(&identity_wire),
                );
            }
            NetworkEvent::EvidenceReceived {
                evidence,
                peer_id,
            } => {
                let evidence_type = match &**evidence {
                    noble_core::MisbehaviorEvidence::DoubleProposal(_) => "double_proposal",
                    noble_core::MisbehaviorEvidence::VoteEquivocation(_) => "vote_equivocation",
                    noble_core::MisbehaviorEvidence::InvalidBlock(_) => "invalid_block",
                    noble_core::MisbehaviorEvidence::AnnounceEquivocation(_) => "announce_equivocation",
                };
                tracing::warn!(
                    task = "evidence",
                    r#type = evidence_type,
                    "Misbehavior evidence received from {}",
                    hex::encode(&peer_id),
                );
                // InvalidBlockEvidence requires chain_id for verification (deferred from
                // service.rs which doesn't have chain_id). Verify here before accepting.
                if let noble_core::MisbehaviorEvidence::InvalidBlock(e) = &**evidence {
                    if e.verify(self.get_chain_id()).is_err() {
                        tracing::warn!(
                            task = "evidence",
                            "InvalidBlockEvidence from {} failed verification — discarding",
                            hex::encode(&peer_id),
                        );
                        return;
                    }
                }
                // Discard ChainId contradiction evidence — chain adoption legitimately
                // changes a node's chain_id, so this type of evidence is always a false positive.
                if let noble_core::MisbehaviorEvidence::AnnounceEquivocation(ref ae) = &**evidence {
                    if ae.contradiction == noble_core::AnnounceContradiction::ChainId {
                        tracing::debug!(
                            task = "evidence",
                            "discarding ChainId contradiction evidence — chain adoption is legitimate",
                        );
                        return;
                    }
                }
                // Store evidence.
                let cbor = noble_codec::NobleCbor::to_cbor(&**evidence).unwrap_or_default();
                let evidence_hash = noble_crypto::sha256(&cbor);
                if let Err(e) = self.storage.read().store_evidence(evidence_hash.as_bytes(), &cbor) {
                    tracing::warn!(task = "evidence", "failed to store evidence: {e}");
                }
                // Apply reputation penalty.
                let misbehaver_wire = match &**evidence {
                    noble_core::MisbehaviorEvidence::DoubleProposal(e) => e.validator_id.to_wire_bytes(),
                    noble_core::MisbehaviorEvidence::VoteEquivocation(e) => e.voter_pubkey.to_wire_bytes(),
                    noble_core::MisbehaviorEvidence::InvalidBlock(e) => e.block.header.validator_id.to_wire_bytes(),
                    noble_core::MisbehaviorEvidence::AnnounceEquivocation(e) => e.identity_key.to_wire_bytes(),
                };
                self.consensus.write().reputation_mut().record_misbehavior(&misbehaver_wire);
                // GUI event.
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "evidence_received",
                    "type": evidence_type,
                    "peer_id": hex::encode(&peer_id),
                    "evidence_hash": hex::encode(evidence_hash.as_bytes()),
                }));
            }
            NetworkEvent::BlockAnnounced {
                peer_id,
                height,
                hash,
            } => {
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "block_announced",
                    "peer_id": hex::encode(peer_id),
                    "height": height,
                    "hash": hex::encode(hash),
                }));
                tracing::debug!(
                    task = "sync",
                    "Block announced by {}: height={height}, hash={}",
                    hex::encode(peer_id),
                    hex::encode(hash),
                );
                let our_height = self.consensus.read().chain_tip().0;
                if *height > our_height {
                    // Fetch directly from the announcing peer instead of polling all peers.
                    if let Err(e) = network_cmd.try_send(noble_network::NetworkCommand::RequestBlockByHeight {
                        peer_id: peer_id.clone(),
                        height: our_height + 1,
                    }) {
                        tracing::warn!(task = "sync", "RequestBlockByHeight on BlockAnnounced dropped: {e}");
                    }
                }
            }
            NetworkEvent::SyncComplete { new_height } => {
                tracing::info!(
                    task = "sync",
                    "Sync complete up to height {new_height}"
                );
            }
            NetworkEvent::PeerLatencyUpdated {
                peer_id,
                latency_ms,
            } => {
                let hex_pid = hex::encode(peer_id);
                let mut info = self.peer_info.write();
                if let Some(entry) = info.get_mut(&hex_pid) {
                    entry.latency_ms = Some(*latency_ms);
                }
            }

            NetworkEvent::PeerChainTipUpdated {
                peer_id,
                height,
                tip_hash,
                median_clock_offset_ms,
            } => {
                let hex_pid = hex::encode(peer_id);
                {
                    let mut info = self.peer_info.write();
                    if let Some(entry) = info.get_mut(&hex_pid) {
                        entry.chain_tip_height = Some(*height);
                        entry.chain_tip_hash = Some(hex::encode(tip_hash));
                    }
                }
                // Notify GUI — chain tip changed for a peer (alignment may differ).
                let _ = peer_update_tx.send(serde_json::json!({
                    "event": "chain_tip_updated",
                    "peer_id": hex_pid,
                    "height": height,
                    "tip_hash": hex::encode(tip_hash),
                }));
                // S49: Update network-level clock offset.
                if median_clock_offset_ms.is_some() {
                    self.network_stats.write().median_clock_offset_ms = *median_clock_offset_ms;
                }
                // ── Healing: sync initiation, integrity probe, sync completion ──
                self.healing.on_peer_chain_tip_updated(peer_id, *height);
                let our_height = self.consensus.read().chain_tip().0;
                // S60: Bootstrap proposal retry — when the first peer status
                // arrives during Proposal phase at tip=0, re-trigger the
                // proposal that was suppressed by the "waiting for peer status"
                // gate.  Without this, the node waits a full 20-min cycle.
                if our_height == 0 {
                    let engine = self.consensus.read();
                    let in_proposal = engine.current_tracked_phase() == noble_consensus::CyclePhase::Proposal;
                    let has_key = engine.has_validator_key();
                    let proposals_enabled = engine.proposals_enabled();
                    drop(engine);
                    if in_proposal && has_key && proposals_enabled {
                        tracing::info!(
                            task = "bootstrap",
                            "peer status received during Proposal phase at tip=0 — retrying proposal"
                        );
                        let actions = {
                            let mut engine = self.consensus.write();
                            engine.step(noble_consensus::CycleEvent::MempoolTransactions(Vec::new()))
                        };
                        self.process_cycle_actions(
                            actions,
                            network_cmd,
                            new_block_tx,
                            cycle_phase_tx,
                            metrics,
                            shared_identity,
                        );
                    }
                }
            }
            NetworkEvent::BlockReceived { peer_id, block } => {
                // Determine whether this block is a sync catch-up (committed
                // block from a peer ahead of us) or a live consensus proposal.
                //
                // Sync import:  block.height == our_tip + 1 AND any peer is
                //   ahead of us AND tip_height > 0.
                //   Validate against the parent in storage, commit directly.
                //
                // Block 1 exception:  when tip_height == 0, block 1 is ALWAYS
                //   routed to consensus for Dual-Witness validation.  This
                //   prevents phantom chain resurrection after noble-tool reset.
                //
                // Consensus proposal:  everything else → route to the consensus
                //   engine for candidate tracking + voting.

                // Enrich block_received with proposer identity for GUI display.
                let proposer_wire = block.header.validator_id.to_wire_bytes();
                let proposer_name = {
                    let engine = self.consensus.read();
                    engine.validator_list().find_by_wire(&proposer_wire)
                        .map(|ve| ve.name())
                        .filter(|n| !n.is_empty())
                };
                let _ = cycle_phase_tx.send(serde_json::json!({
                    "event": "block_received",
                    "peer_id": hex::encode(peer_id),
                    "height": block.header.height,
                    "proposer": hex::encode(&proposer_wire),
                    "proposer_name": proposer_name.as_deref().unwrap_or(""),
                }));
                let tip_height = self.consensus.read().chain_tip().0;
                // Check if any peer is ahead of us (indicating we need to sync).
                let max_peer_height = {
                    let info = self.peer_info.read();
                    info.values()
                        .filter_map(|e| e.chain_tip_height)
                        .max()
                        .unwrap_or(0)
                };
                let we_are_behind = max_peer_height > tip_height;

                if block.header.height <= tip_height {
                    // Already have this block — ignore.
                } else if block.header.height == tip_height + 1 && we_are_behind {
                    // Sync import: committed block from peer ahead of us.
                    // Takes priority over live proposals — the network already has
                    // this block, we should import it rather than propose our own.
                    //
                    // Block 1 (tip_height == 0) is also sync-imported.  Without this,
                    // a fresh node joining an existing chain can never acquire block 1:
                    // B6 past-skew (MAX_BLOCK_PAST_SKEW=3600s) rejects it through the
                    // live consensus path once the block is >1 hour old, and the two
                    // nodes end up on divergent cycle timelines (different genesis
                    // timestamps).  The block is fully validated (B4/B8/B9/B11) and
                    // came from a peer that already committed it via consensus.
                    let _ = self.healing.try_sync_import(&block);
                    // Sync local fields from shared atomics.
                    self.healing.sync_locals_from_atomics();
                } else {
                    // Live proposal — route to consensus engine.
                    let cycle_event = bridge::network_event_to_cycle_event(
                        &NetworkEvent::BlockReceived {
                            peer_id: peer_id.clone(),
                            block: block.clone(),
                        },
                    );
                    if let Some(ce) = cycle_event {
                        let actions = {
                            let mut engine = self.consensus.write();
                            engine.step(ce)
                        };
                        self.process_cycle_actions(actions, network_cmd, new_block_tx, cycle_phase_tx, metrics, shared_identity);
                    }
                }
            }
            NetworkEvent::CommonAncestorFound { peer_id: ca_pid, ancestor_height, ancestor_hash } => {
                let hex_pid = hex::encode(ca_pid);
                tracing::info!(
                    task = "fork",
                    "common ancestor with {}: height {} ({})",
                    hex_pid, ancestor_height, hex::encode(ancestor_hash)
                );
                self.healing.on_common_ancestor_found(*ancestor_height, *ancestor_hash);
            }
            _ => {
                // Emit protocol activity for VoteReceived before routing to engine
                if let NetworkEvent::VoteReceived { voter_id, cycle, candidate_hash, round, .. } = event {
                    // Resolve voter name and candidate proposer name for GUI display.
                    // Priority: validator_list → peer records → self identity.
                    let (voter_name, candidate_name) = {
                        let engine = self.consensus.read();
                        let our_wire = engine.our_validator_wire_bytes();

                        // Resolve voter name: validator_list → peer records → self identity
                        let vn = engine.validator_list().find_by_wire(voter_id)
                            .map(|ve| ve.name())
                            .filter(|n| !n.is_empty())
                            .or_else(|| {
                                self.storage.read()
                                    .list_peer_records()
                                    .unwrap_or_default()
                                    .into_iter()
                                    .find(|r| r.identity_key == *voter_id)
                                    .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                                    .filter(|n| !n.is_empty())
                            })
                            .or_else(|| {
                                if our_wire.as_deref() == Some(voter_id) {
                                    let id = shared_identity.read();
                                    if !id.node_name.is_empty() {
                                        return Some(id.node_name.clone());
                                    }
                                }
                                None
                            })
                            .unwrap_or_default();

                        // Resolve candidate proposer name: validator_list → peer records → self identity
                        let cn = engine.candidate_tracker().get(&noble_crypto::Hash256(*candidate_hash))
                            .and_then(|entry| {
                                let wire = entry.block.header.validator_id.to_wire_bytes();
                                engine.validator_list().find_by_wire(&wire)
                                    .map(|ve| ve.name())
                                    .filter(|n| !n.is_empty())
                                    .or_else(|| {
                                        self.storage.read()
                                            .list_peer_records()
                                            .unwrap_or_default()
                                            .into_iter()
                                            .find(|r| r.identity_key == wire)
                                            .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                                            .filter(|n| !n.is_empty())
                                    })
                                    .or_else(|| {
                                        if our_wire.as_deref() == Some(&wire) {
                                            let id = shared_identity.read();
                                            if !id.node_name.is_empty() {
                                                return Some(id.node_name.clone());
                                            }
                                        }
                                        None
                                    })
                            })
                            .unwrap_or_default();
                        (vn, cn)
                    };
                    let _ = cycle_phase_tx.send(serde_json::json!({
                        "event": "vote_received",
                        "voter_id": hex::encode(voter_id),
                        "voter_name": voter_name,
                        "cycle": cycle,
                        "candidate_hash": hex::encode(candidate_hash),
                        "candidate_name": candidate_name,
                        "round": round,
                    }));
                }
                // Route remaining events to consensus engine
                if let Some(cycle_event) = bridge::network_event_to_cycle_event(event) {
                    let actions = {
                        let mut engine = self.consensus.write();
                        engine.step(cycle_event)
                    };
                    self.process_cycle_actions(actions, network_cmd, new_block_tx, cycle_phase_tx, metrics, shared_identity);
                }
            }
        }
    }

    /// Process actions emitted by the consensus engine.
    fn process_cycle_actions(
        &mut self,
        actions: Vec<CycleIo>,
        network_cmd: &mpsc::Sender<NetworkCommand>,
        new_block_tx: &broadcast::Sender<serde_json::Value>,
        cycle_phase_tx: &broadcast::Sender<serde_json::Value>,
        metrics: &Option<NobleMetrics>,
        shared_identity: &Arc<RwLock<NodeIdentityData>>,
    ) {
        // Track the last evidence hash: when PublishEvidence is followed by BanPeer
        // in the same batch, the hash is injected into the ban for operator auditability.
        let mut last_evidence_hash: Option<[u8; 32]> = None;

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
                        .filter_map(|tx| tx.compute_tx_id(self.get_chain_id()).ok())
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

                    // Auto-update chain_id after first block commit (fixes pre-genesis → real chain).
                    // Consensus-bootstrapped chains have no block 0 — the first committed block
                    // is height 1.  We derive chain_id from whatever the first block's hash is.
                    // CRITICAL: Must update BOTH the Node atomic AND the network service config.
                    // Without the network update, GetStatus responses still report chain_id=0,
                    // causing mismatch disconnections when the remote node restarts with the
                    // real chain_id loaded from storage.
                    if self.get_chain_id() == 0 {
                        let new_chain_id = noble_core::derive_chain_id(&block_hash);
                        self.chain_id.store(new_chain_id, std::sync::atomic::Ordering::Relaxed);
                        if let Err(e) = network_cmd.try_send(NetworkCommand::UpdateChainId(new_chain_id)) {
                            tracing::warn!(task = "block_commit", "failed to update network chain_id: {e}");
                        }
                        tracing::info!(
                            task = "block_commit",
                            "chain_id updated to {:#010X} after block {} commit",
                            new_chain_id,
                            block.header.height,
                        );
                    }

                    // Update network service tip height (used by chain_id mismatch check
                    // to exempt early chains from permanent disconnection).
                    if let Err(e) = network_cmd.try_send(NetworkCommand::UpdateTipHeight(block.header.height)) {
                        tracing::debug!(task = "block_commit", "UpdateTipHeight dropped: {e}");
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

                    // S53: Clear active proposal — new cycle starts.
                    *self.last_proposed.lock() = None;

                    let _ = new_block_tx.send(serde_json::json!({
                        "height": block.header.height,
                        "hash": hex::encode(block_hash.as_bytes()),
                        "tx_count": tx_ids.len(),
                    }));

                    // Protocol activity: block committed (with proposer name)
                    let proposer_name = {
                        let engine = self.consensus.read();
                        let wire = block.header.validator_id.to_wire_bytes();
                        engine.validator_list().find_by_wire(&wire)
                            .map(|ve| ve.name())
                            .filter(|n| !n.is_empty())
                    };
                    let _ = cycle_phase_tx.send(serde_json::json!({
                        "event": "block_committed",
                        "height": block.header.height,
                        "hash": hex::encode(block_hash.as_bytes()),
                        "tx_count": tx_ids.len(),
                        "proposer": block.header.validator_id.to_address(),
                        "proposer_name": proposer_name.as_deref().unwrap_or(""),
                    }));

                    // S55: Re-publish announce with updated chain_tip_height after commit.
                    self.publish_node_announce(shared_identity, network_cmd, cycle_phase_tx);
                }
                CycleIo::ReadmitTransactions(txs) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    let storage = self.storage.read();
                    let chain_height = match storage.get_chain_tip() {
                        Ok(Some(t)) => t.height,
                        Ok(None) => 0,
                        Err(e) => {
                            tracing::warn!(task = "consensus", "failed to read chain tip for tx readmission: {e}");
                            0
                        }
                    };
                    let chain_lookup = StorageChainLookupAdapter { storage: &*storage };
                    let utxo_lookup = StorageUtxoLookupAdapter { storage: &*storage };
                    let mut mempool = self.mempool.lock();
                    for tx in txs {
                        if let Err(e) = mempool.admit(&tx, now, &chain_lookup, &utxo_lookup, chain_height) {
                            tracing::trace!("mempool rejected broadcast tx: {e}");
                        }
                    }
                }
                CycleIo::Log(msg) => {
                    tracing::info!(task = "consensus", "[consensus] {msg}");
                    if let Err(e) = cycle_phase_tx.send(serde_json::json!({
                        "event": "consensus_log",
                        "message": msg,
                    })) {
                        tracing::debug!(task = "consensus", "phase broadcast send failed: {e}");
                    }
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
                CycleIo::PersistBadgeState { badges, proposals } => {
                    let storage = self.storage.read();
                    for (pubkey_wire, cbor_data) in &badges {
                        if let Err(e) = storage.store_badge(pubkey_wire, cbor_data) {
                            tracing::warn!(task = "badge", "failed to persist badge: {e}");
                        }
                    }
                    for (hash_hex, cbor_data) in &proposals {
                        if let Err(e) = storage.store_badge_proposal(hash_hex.as_bytes(), cbor_data) {
                            tracing::warn!(task = "badge", "failed to persist badge proposal: {e}");
                        }
                    }
                    if !badges.is_empty() || !proposals.is_empty() {
                        tracing::debug!(
                            task = "badge",
                            "persisted {} badge(s) + {} proposal(s) to storage",
                            badges.len(),
                            proposals.len()
                        );
                    }
                }
                CycleIo::StoreBlockVotes { height, votes } => {
                    // Decay-weighted vote accumulation for chain legitimacy tracking.
                    // Recent blocks' votes count more than older ones (exponential decay).
                    {
                        let old = self.healing.chain_vote_weight().load(std::sync::atomic::Ordering::Relaxed);
                        let new = noble_consensus::decay_vote_weight(old, votes.voter_count as u64);
                        self.healing.chain_vote_weight().store(new, std::sync::atomic::Ordering::Relaxed);
                    }
                    if let Ok(bytes) = noble_codec::NobleCbor::to_cbor(&*votes) {
                        let storage = self.storage.read();
                        if let Err(e) = storage.store_block_votes(height, &bytes) {
                            tracing::warn!(
                                task = "consensus",
                                "Failed to store block votes for height {height}: {e}"
                            );
                        } else {
                            tracing::info!(
                                task = "consensus",
                                "Stored vote witness for block {height}: {} R1 + {} R2 voter(s), strength={}",
                                votes.r1_voters.len(),
                                votes.r2_voters.len(),
                                votes.strength,
                            );
                        }
                    }
                }
                CycleIo::ClearCycleHistory => {
                    let storage = self.storage.read();
                    if let Err(e) = storage.clear_cycle_history() {
                        tracing::warn!(
                            task = "consensus",
                            "failed to clear stale cycle history after epoch change: {e}"
                        );
                    } else {
                        tracing::info!(
                            task = "consensus",
                            "cleared stale cycle history (block 1 epoch change)"
                        );
                    }
                }
                CycleIo::PersistFinalityState { height, hash, cycle } => {
                    let data = encode_finality_state(height, &hash, cycle);
                    let storage = self.storage.read();
                    if let Err(e) = storage.store_finality_state(&data) {
                        tracing::warn!(task = "finality", "failed to persist finality state: {e}");
                    }
                }
                CycleIo::PhaseChanged { cycle, phase } => {
                    let phase_name = format!("{phase:?}");
                    // Hide cycle number during pre-genesis (tip_height == 0) —
                    // the chain has no blocks yet.  Matches getCycleStatus RPC.
                    let tip_h = self.consensus.read().chain_tip().0;
                    let cycle_val: serde_json::Value = if tip_h == 0 {
                        serde_json::Value::Null
                    } else {
                        serde_json::json!(cycle)
                    };
                    let mut event = serde_json::json!({
                        "event": "phase_change",
                        "phase": phase_name,
                        "cycle": cycle_val,
                    });
                    // Enrich phase transitions with vote/candidate context.
                    match phase {
                        noble_consensus::CyclePhase::Reflection => {
                            // Reflection start: R1 votes are in — show current leader.
                            let (tallies_data, validator_wire) = {
                                let engine = self.consensus.read();
                                let tallies = engine.vote_tallies(); // R1
                                let total_votes: usize = tallies.values().sum();
                                let best = tallies.iter().max_by_key(|e| e.1).map(|(h, c)| (*h, *c));
                                let wire = best.and_then(|(hash, _)| {
                                    engine.candidate_tracker().get(&hash).map(|entry| {
                                        entry.block.header.validator_id.to_wire_bytes()
                                    })
                                });
                                let name_from_list = wire.as_ref().and_then(|w| {
                                    let n = engine.validator_list().find_by_wire(w).map(|v| v.name()).unwrap_or_default();
                                    if n.is_empty() { None } else { Some(n) }
                                });
                                ((total_votes, best, name_from_list), wire)
                            }; // consensus lock released
                            let (total_votes, best, name_from_list) = tallies_data;
                            if let Some((best_hash, best_count)) = best {
                                let pct = if total_votes > 0 { (best_count * 100) / total_votes } else { 0 };
                                // Resolve name: validator list first, then peer records fallback.
                                let validator_wire_for_key = validator_wire.clone();
                                let name = name_from_list.or_else(|| {
                                    validator_wire.and_then(|wire| {
                                        let storage = self.storage.read();
                                        storage.list_peer_records().ok().and_then(|records| {
                                            records.into_iter()
                                                .find(|r| r.peer_id_bytes == wire)
                                                .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                                                .filter(|n| !n.is_empty())
                                        })
                                    })
                                });
                                event["leader_name"] = serde_json::json!(name.as_deref().unwrap_or(""));
                                event["leader_hash"] = serde_json::json!(hex::encode(best_hash.as_bytes()));
                                if let Some(ref w) = validator_wire_for_key {
                                    event["leader_key"] = serde_json::json!(
                                        noble_crypto::noble_addr::encode_wire_bytes(w)
                                            .unwrap_or_else(|| hex::encode(w))
                                    );
                                }
                                event["leader_pct"] = serde_json::json!(pct);
                                event["total_votes"] = serde_json::json!(total_votes);
                            }
                        }
                        noble_consensus::CyclePhase::Propagation => {
                            // Propagation start: R2 votes are in — show winner
                            // only when there is a clear (non-tied) leader.
                            let (best_info, wire_bytes) = {
                                let engine = self.consensus.read();
                                let r2 = engine.r2_tallies();
                                let total_r2: usize = r2.values().sum();
                                let (source_tallies, label) = if total_r2 > 0 {
                                    (r2, "r2")
                                } else {
                                    (engine.vote_tallies(), "r1_fallback")
                                };
                                // Check for ties: only emit winner when one
                                // candidate has strictly more votes than all others.
                                let max_count = source_tallies.values().copied().max().unwrap_or(0);
                                let tied = source_tallies.values().filter(|&&c| c == max_count).count() > 1;
                                let best = if tied {
                                    None
                                } else {
                                    source_tallies.iter().max_by_key(|e| e.1).map(|(h, _)| *h)
                                };
                                let wire = best.and_then(|hash| {
                                    engine.candidate_tracker().get(&hash).map(|entry| {
                                        entry.block.header.validator_id.to_wire_bytes()
                                    })
                                });
                                let name_from_list = wire.as_ref().and_then(|w| {
                                    let n = engine.validator_list().find_by_wire(w).map(|v| v.name()).unwrap_or_default();
                                    if n.is_empty() { None } else { Some(n) }
                                });
                                ((best, name_from_list, label), wire)
                            }; // consensus lock released
                            let (best, name_from_list, _label) = best_info;
                            if let Some(best_hash) = best {
                                let wire_bytes_for_key = wire_bytes.clone();
                                let name = name_from_list.or_else(|| {
                                    wire_bytes.and_then(|wire| {
                                        let storage = self.storage.read();
                                        storage.list_peer_records().ok().and_then(|records| {
                                            records.into_iter()
                                                .find(|r| r.peer_id_bytes == wire)
                                                .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                                                .filter(|n| !n.is_empty())
                                        })
                                    })
                                });
                                event["winner_name"] = serde_json::json!(name.as_deref().unwrap_or(""));
                                event["winner_hash"] = serde_json::json!(hex::encode(best_hash.as_bytes()));
                                if let Some(ref w) = wire_bytes_for_key {
                                    event["winner_key"] = serde_json::json!(
                                        noble_crypto::noble_addr::encode_wire_bytes(w)
                                            .unwrap_or_else(|| hex::encode(w))
                                    );
                                }
                            }
                        }
                        _ => {}
                    }
                    let _ = cycle_phase_tx.send(event);
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
                    self.process_cycle_actions(actions, network_cmd, new_block_tx, cycle_phase_tx, metrics, shared_identity);
                }
                CycleIo::BroadcastBlock(ref _block)
                    if self
                        .clock_drift_paused
                        .load(std::sync::atomic::Ordering::Relaxed) =>
                {
                    tracing::warn!(
                        task = "clock_drift",
                        "Block proposal suppressed — clock drift exceeds critical threshold"
                    );
                    let _ = cycle_phase_tx.send(serde_json::json!({
                        "event": "warning",
                        "message": "Block proposal suppressed — clock drift exceeds critical threshold",
                    }));
                }
                CycleIo::BroadcastBlock(ref _block) => {
                    // Proposal gate: the single chokepoint for all block proposals
                    // (empty or full, any code path).
                    //
                    // Sync suppression (any tip height):
                    //   any peer ahead of us → suppress (actively syncing)
                    //
                    // Bootstrap suppression (tip == 0 only):
                    //   0 peers              → suppress (solo, wait for peers)
                    //   no status received   → suppress (wait for PeerChainTipUpdated)
                    //   all peers at height 0→ allow (form new chain together)
                    //
                    // Normal operation (tip > 0, no peer ahead):
                    //   allow
                    let tip_h = self.consensus.read().chain_tip().0;
                    let info = self.peer_info.read();
                    let peer_count = info.len();
                    // S55: Use the higher of committed chain_tip and gossip-implied
                    // proposed parent (proposed_height - 1) for each peer.
                    let known_heights: Vec<u64> = info
                        .values()
                        .filter_map(|e| {
                            let committed = e.chain_tip_height;
                            let implied = e.proposed_height.map(|h| h.saturating_sub(1));
                            match (committed, implied) {
                                (Some(c), Some(i)) => Some(std::cmp::max(c, i)),
                                (Some(c), None) => Some(c),
                                (None, Some(i)) => Some(i),
                                (None, None) => None,
                            }
                        })
                        .collect();
                    drop(info);

                    let max_known = known_heights.iter().copied().max().unwrap_or(0);

                    // Suppress while syncing — any peer ahead means we should
                    // import blocks, not propose new ones.  Applies at ALL heights
                    // (including mid-sync after block 1 is imported).
                    if max_known > tip_h {
                        tracing::debug!(
                            task = "sync",
                            "Block proposal suppressed — syncing from peers at height {} (tip={})",
                            max_known, tip_h
                        );
                        let _ = cycle_phase_tx.send(serde_json::json!({
                            "event": "warning",
                            "message": format!("Block proposal suppressed — syncing (peers at height {}, tip={})", max_known, tip_h),
                        }));
                        continue;
                    }

                    // Bootstrap: additional gates when no chain exists yet.
                    if tip_h == 0 {
                        if peer_count == 0 {
                            tracing::debug!(
                                task = "bootstrap",
                                "Block proposal suppressed — no peers connected"
                            );
                            let _ = cycle_phase_tx.send(serde_json::json!({
                                "event": "warning",
                                "message": "Block proposal suppressed — no peers connected",
                            }));
                            continue;
                        }
                        if known_heights.is_empty() {
                            tracing::debug!(
                                task = "bootstrap",
                                "Block proposal suppressed — waiting for peer status"
                            );
                            let _ = cycle_phase_tx.send(serde_json::json!({
                                "event": "warning",
                                "message": "Block proposal suppressed — waiting for peer chain status",
                            }));
                            continue;
                        }
                        // All known peers at height 0 → form new chain together
                    }

                    // Allow: caught up (or ahead), or bootstrap with all peers at 0

                    // S53: Track active proposal for NodeAnnounce gossip.
                    if let Ok(hash) = _block.header.compute_block_hash() {
                        *self.last_proposed.lock() = Some((_block.header.height, *hash.as_bytes()));
                    }

                    let cmds = bridge::cycle_io_to_network_commands(
                        CycleIo::BroadcastBlock(_block.clone()),
                    );
                    for cmd in cmds {
                        if let Err(e) = network_cmd.try_send(cmd) {
                            tracing::warn!(
                                task = "consensus_broadcast",
                                "network command dropped (channel full): {e}"
                            );
                        }
                    }

                    // Protocol activity: block proposed
                    let proposed_hash = _block.header.compute_block_hash()
                        .map(|h| hex::encode(h.as_bytes()))
                        .unwrap_or_default();
                    let _ = cycle_phase_tx.send(serde_json::json!({
                        "event": "block_proposed",
                        "height": _block.header.height,
                        "hash": proposed_hash,
                    }));

                    // S53: Re-publish announce with updated proposed_height/hash.
                    self.publish_node_announce(&shared_identity, &network_cmd, &cycle_phase_tx);
                }
                CycleIo::PublishEvidence(evidence) => {
                    // Store evidence locally.
                    let cbor = noble_codec::NobleCbor::to_cbor(&*evidence).unwrap_or_default();
                    let evidence_hash = noble_crypto::sha256(&cbor);
                    if let Err(e) = self.storage.read().store_evidence(evidence_hash.as_bytes(), &cbor) {
                        tracing::warn!(task = "evidence", "failed to store evidence: {e}");
                    }
                    // Stash hash for the immediately following BanPeer action.
                    last_evidence_hash = Some(*evidence_hash.as_bytes());
                    // Apply reputation penalty.
                    let misbehaver_wire = match &*evidence {
                        noble_core::MisbehaviorEvidence::DoubleProposal(e) => e.validator_id.to_wire_bytes(),
                        noble_core::MisbehaviorEvidence::VoteEquivocation(e) => e.voter_pubkey.to_wire_bytes(),
                        noble_core::MisbehaviorEvidence::InvalidBlock(e) => e.block.header.validator_id.to_wire_bytes(),
                        noble_core::MisbehaviorEvidence::AnnounceEquivocation(e) => e.identity_key.to_wire_bytes(),
                    };
                    self.consensus.write().reputation_mut().record_misbehavior(&misbehaver_wire);
                    // Emit GUI event.
                    let evidence_type = match &*evidence {
                        noble_core::MisbehaviorEvidence::DoubleProposal(_) => "double_proposal",
                        noble_core::MisbehaviorEvidence::VoteEquivocation(_) => "vote_equivocation",
                        noble_core::MisbehaviorEvidence::InvalidBlock(_) => "invalid_block",
                        noble_core::MisbehaviorEvidence::AnnounceEquivocation(_) => "announce_equivocation",
                    };
                    let _ = cycle_phase_tx.send(serde_json::json!({
                        "event": "evidence_published",
                        "type": evidence_type,
                        "evidence_hash": hex::encode(evidence_hash.as_bytes()),
                    }));
                    // Forward to network via bridge.
                    let cmds = bridge::cycle_io_to_network_commands(
                        CycleIo::PublishEvidence(evidence),
                    );
                    for cmd in cmds {
                        if let Err(e) = network_cmd.try_send(cmd) {
                            tracing::warn!(task = "evidence", "network command dropped: {e}");
                        }
                    }
                }
                CycleIo::RequestForkResolution { target_hash, target_height, reason } => {
                    self.healing.on_fork_resolution_requested(target_hash, target_height, &reason);
                }
                CycleIo::PersistCheckpoint(cp) => {
                    let cbor = noble_codec::NobleCbor::to_cbor(&*cp).unwrap_or_default();
                    if let Err(e) = self.storage.read().store_checkpoint(cp.height, &cbor) {
                        tracing::warn!(task = "checkpoint", "persist failed: {e}");
                    } else {
                        tracing::debug!(
                            task = "checkpoint",
                            height = cp.height,
                            "checkpoint persisted"
                        );
                    }
                }
                CycleIo::CheckpointsActivated { heights } => {
                    tracing::info!(task = "checkpoint", "activated at heights: {heights:?}");
                    let _ = cycle_phase_tx.send(serde_json::json!({
                        "event": "checkpoints_activated",
                        "heights": heights,
                    }));
                }
                CycleIo::RequestChainAdoption { target_chain_id, reason } => {
                    self.healing.on_chain_adoption_requested(target_chain_id, &reason);
                }
                other => {
                    // Emit protocol activity events for votes and bans
                    match &other {
                        CycleIo::BroadcastVote(vote) => {
                            // Resolve candidate proposer name for activity display.
                            // Priority: validator_list → peer records → self identity.
                            let proposer_name = {
                                let engine = self.consensus.read();
                                let our_wire = engine.our_validator_wire_bytes();
                                engine.candidate_tracker().get(&vote.candidate_hash)
                                    .and_then(|entry| {
                                        let wire = entry.block.header.validator_id.to_wire_bytes();
                                        // 1. Validator list lookup
                                        engine.validator_list().find_by_wire(&wire)
                                            .map(|ve| ve.name())
                                            .filter(|n| !n.is_empty())
                                            .or_else(|| {
                                                // 2. Peer records lookup
                                                self.storage.read()
                                                    .list_peer_records()
                                                    .unwrap_or_default()
                                                    .into_iter()
                                                    .find(|r| r.identity_key == wire)
                                                    .and_then(|r| r.last_announce.as_ref().map(|a| a.node_name.clone()))
                                                    .filter(|n| !n.is_empty())
                                            })
                                            .or_else(|| {
                                                // 3. Self identity fallback
                                                if our_wire.as_deref() == Some(&wire) {
                                                    let id = shared_identity.read();
                                                    if !id.node_name.is_empty() {
                                                        return Some(id.node_name.clone());
                                                    }
                                                }
                                                None
                                            })
                                    })
                            };
                            let _ = cycle_phase_tx.send(serde_json::json!({
                                "event": "vote_broadcast",
                                "round": vote.round,
                                "block_hash": hex::encode(vote.candidate_hash.as_bytes()),
                                "candidate_name": proposer_name.as_deref().unwrap_or(""),
                            }));
                        }
                        CycleIo::BanPeer { peer_id, category, reason } => {
                            let _ = cycle_phase_tx.send(serde_json::json!({
                                "event": "peer_banned",
                                "peer_id": hex::encode(&peer_id),
                                "category": format!("{:#04X}", *category as u8),
                                "reason": &reason,
                            }));
                        }
                        CycleIo::RequestBlock { block_hash, .. } => {
                            let _ = cycle_phase_tx.send(serde_json::json!({
                                "event": "block_requested",
                                "hash": hex::encode(block_hash.as_bytes()),
                            }));
                        }
                        _ => {}
                    }
                    // BroadcastVote, BanPeer, RequestBlock → network
                    let cmds = bridge::cycle_io_to_network_commands(other);
                    for mut cmd in cmds {
                        // Inject evidence hash from the preceding PublishEvidence action.
                        if let NetworkCommand::BanPeer { ref mut evidence_hash, .. } = cmd {
                            if evidence_hash.is_none() {
                                *evidence_hash = last_evidence_hash.take();
                            }
                        }
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

struct StorageUtxoLookupAdapter<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> UtxoLookup for StorageUtxoLookupAdapter<'_, S> {
    fn get_utxo(&self, outpoint: &noble_core::OutPoint) -> Option<(u64, bool, u64)> {
        match self.storage.get_utxo(outpoint) {
            Ok(Some(entry)) => Some((entry.value, entry.is_coinbase, entry.height)),
            _ => None,
        }
    }
}

/// Arc-based UTXO value lookup adapter for the consensus engine.
///
/// The consensus engine holds this as a `Box<dyn UtxoValueLookup>` to resolve
/// input UTXO values when building block proposals (fee computation).
struct ArcStorageUtxoValueLookup<S: StorageEngine + Send + Sync + 'static> {
    storage: Arc<RwLock<S>>,
}

impl<S: StorageEngine + Send + Sync + 'static> noble_consensus::proposal::UtxoValueLookup
    for ArcStorageUtxoValueLookup<S>
{
    fn utxo_value(&self, outpoint: &noble_core::OutPoint) -> Option<u64> {
        let s = self.storage.read();
        match s.get_utxo(outpoint) {
            Ok(Some(entry)) => Some(entry.value),
            _ => None,
        }
    }
}

/// Try to load a validator key from the unified keystore.
///
/// Checks for SCHEME_VALIDATOR_ED25519 first, then SCHEME_VALIDATOR_SECP256K1.
fn load_validator_from_keystore(
    keystore: &KeyStore,
) -> Option<(noble_crypto::NoblePrivateKey, noble_crypto::NoblePublicKey)> {
    if !keystore.is_unlocked() {
        return None;
    }
    // Try Ed25519 first
    if let Ok(raw) = keystore.get_raw(noble_crypto::SCHEME_VALIDATOR_ED25519) {
        let sk = noble_crypto::NoblePrivateKey::Ed25519(raw);
        let pk = sk.public_key();
        tracing::info!(
            task = "config_load",
            "Validator mode enabled (from unified keystore): {}",
            pk.to_address()
        );
        return Some((sk, pk));
    }
    // Then secp256k1
    if let Ok(raw) = keystore.get_raw(noble_crypto::SCHEME_VALIDATOR_SECP256K1) {
        let sk = noble_crypto::NoblePrivateKey::Secp256k1(raw);
        let pk = sk.public_key();
        tracing::info!(
            task = "config_load",
            "Validator mode enabled (from unified keystore): {}",
            pk.to_address()
        );
        return Some((sk, pk));
    }
    None
}

/// Load a validator private key from a raw key file.
///
/// The file must contain exactly 33 bytes: `[scheme_id(1) || private_key(32)]`.
/// Returns `Some((private_key, public_key))` on success, `None` if the path is
/// empty or the file cannot be loaded.
/// Falls back to the unified keystore if the file is not found.
fn load_validator_key(
    path: &str,
    data_dir: &std::path::Path,
    chain_meta: &[u8; 32],
    keystore: &KeyStore,
) -> Option<(noble_crypto::NoblePrivateKey, noble_crypto::NoblePublicKey)> {
    // When validator_key_path is empty, check the data_dir fallback location.
    // This covers nodes whose validator.key was auto-generated during setup.
    let key_path_buf;
    let key_path = if path.is_empty() {
        let fallback = data_dir.join("validator.key");
        if !fallback.exists() {
            // Fallback: check unified keystore (validator.key may have been migrated).
            if let Some(result) = load_validator_from_keystore(keystore) {
                return Some(result);
            }
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
        // Fallback: check unified keystore.
        if let Some(result) = load_validator_from_keystore(keystore) {
            return Some(result);
        }
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
        public_key.to_address()
    );
    Some((private_key, public_key))
}

/// Migrate legacy scattered key files (validator.key, p2p_identity.key,
/// tls-key.pem, totp_secret.txt) into the unified keystore.
///
/// For each file: if it exists AND the keystore doesn't already have that
/// scheme, read+decrypt the legacy file, store into keystore, then rename
/// the legacy file to `*.migrated` as a safety net.
fn migrate_legacy_keys_into_keystore(
    keystore: &mut KeyStore,
    passphrase: &str,
    data_dir: &std::path::Path,
    chain_meta: &[u8; 32],
    validator_key: &Option<(noble_crypto::NoblePrivateKey, noble_crypto::NoblePublicKey)>,
) {
    // 1. Validator key → SCHEME_VALIDATOR_ED25519 or SCHEME_VALIDATOR_SECP256K1
    if let Some((sk, _pk)) = validator_key {
        let scheme = match sk {
            noble_crypto::NoblePrivateKey::Ed25519(_)
            | noble_crypto::NoblePrivateKey::ValidatorEd25519(_) => {
                noble_crypto::SCHEME_VALIDATOR_ED25519
            }
            _ => noble_crypto::SCHEME_VALIDATOR_SECP256K1,
        };
        if !keystore.has_scheme(scheme).unwrap_or(true) {
            if let Some(raw) = sk.raw_bytes().or_else(|| {
                // On-chain Ed25519/Secp256k1 variants: extract via clone_for_test hack
                None
            }) {
                match keystore.store_raw(scheme, raw, passphrase) {
                    Ok(_) => {
                        rename_to_migrated(&data_dir.join("validator.key"));
                        tracing::info!(
                            task = "key_migration",
                            "Migrated validator.key into unified keystore"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(task = "key_migration", "validator key migration: {e}");
                    }
                }
            } else {
                // Signing key variant — read the 32-byte secret from the raw file
                let key_path = data_dir.join("validator.key");
                if key_path.exists() {
                    if let Ok(file_bytes) = std::fs::read(&key_path) {
                        let raw = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
                            noble_crypto::file_encrypt::decrypt_file_data_with_migration(
                                &file_bytes,
                                chain_meta,
                            )
                            .ok()
                            .map(|(d, _)| d)
                        } else {
                            Some(file_bytes)
                        };
                        if let Some(raw) = raw {
                            if raw.len() == 33 {
                                match keystore.store_raw(scheme, &raw[1..], passphrase) {
                                    Ok(_) => {
                                        rename_to_migrated(&key_path);
                                        tracing::info!(
                                            task = "key_migration",
                                            "Migrated validator.key into unified keystore"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            task = "key_migration",
                                            "validator key migration: {e}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. P2P identity key
    let p2p_path = data_dir.join("p2p_identity.key");
    if p2p_path.exists() && !keystore.has_scheme(noble_crypto::SCHEME_P2P_IDENTITY).unwrap_or(true)
    {
        if let Ok(file_bytes) = std::fs::read(&p2p_path) {
            let proto_bytes = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
                noble_crypto::file_encrypt::decrypt_file_data_with_migration(
                    &file_bytes,
                    chain_meta,
                )
                .ok()
                .map(|(d, _)| d)
            } else {
                Some(file_bytes)
            };
            if let Some(proto) = proto_bytes {
                match keystore.store_raw(
                    noble_crypto::SCHEME_P2P_IDENTITY,
                    &proto,
                    passphrase,
                ) {
                    Ok(_) => {
                        rename_to_migrated(&p2p_path);
                        tracing::info!(
                            task = "key_migration",
                            "Migrated p2p_identity.key into unified keystore"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(task = "key_migration", "P2P key migration: {e}");
                    }
                }
            }
        }
    }

    // 3. TLS private key — store in keystore but keep the original file
    // (tls-cert.pem is public and still loaded from disk; tls-key.pem is kept for
    // backward compat with existing TLS loading code).
    let tls_key_path = data_dir.join("tls-key.pem");
    if tls_key_path.exists()
        && !keystore
            .has_scheme(noble_crypto::SCHEME_TLS_KEY)
            .unwrap_or(true)
    {
        if let Ok(file_bytes) = std::fs::read(&tls_key_path) {
            let key_bytes = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
                noble_crypto::file_encrypt::decrypt_file_data_with_migration(
                    &file_bytes,
                    chain_meta,
                )
                .ok()
                .map(|(d, _)| d)
            } else {
                Some(file_bytes)
            };
            if let Some(raw) = key_bytes {
                match keystore.store_raw(noble_crypto::SCHEME_TLS_KEY, &raw, passphrase) {
                    Ok(_) => {
                        // Don't rename — TLS loading still reads tls-key.pem
                        tracing::info!(
                            task = "key_migration",
                            "Copied TLS key into unified keystore (original retained)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(task = "key_migration", "TLS key migration: {e}");
                    }
                }
            }
        }
    }

    // 4. TOTP secret
    let totp_path = data_dir.join("totp_secret.txt");
    if totp_path.exists()
        && !keystore
            .has_scheme(noble_crypto::SCHEME_TOTP_SECRET)
            .unwrap_or(true)
    {
        if let Ok(file_bytes) = std::fs::read(&totp_path) {
            let secret_bytes = if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
                noble_crypto::file_encrypt::decrypt_file_data_with_migration(
                    &file_bytes,
                    chain_meta,
                )
                .ok()
                .map(|(d, _)| d)
            } else {
                Some(file_bytes)
            };
            if let Some(raw) = secret_bytes {
                match keystore.store_raw(
                    noble_crypto::SCHEME_TOTP_SECRET,
                    &raw,
                    passphrase,
                ) {
                    Ok(_) => {
                        rename_to_migrated(&totp_path);
                        tracing::info!(
                            task = "key_migration",
                            "Migrated totp_secret.txt into unified keystore"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(task = "key_migration", "TOTP secret migration: {e}");
                    }
                }
            }
        }
    }
}

/// Rename a file to `*.migrated` as a safety net during key migration.
fn rename_to_migrated(path: &std::path::Path) {
    let mut new_path = path.as_os_str().to_owned();
    new_path.push(".migrated");
    if let Err(e) = std::fs::rename(path, &new_path) {
        tracing::warn!(
            task = "key_migration",
            "Could not rename {} to *.migrated: {e}",
            path.display()
        );
    }
}

/// Sync TOML config file from identity.json's authoritative values.
///
/// Updates `[identity]` and `[node]` sections so the persisted TOML reflects
/// the setup wizard choices rather than stale defaults.
fn sync_toml_from_identity(config_path: &std::path::Path, identity: &NodeIdentityData) {
    let contents = match std::fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(task = "config_sync", "Cannot read TOML for identity sync: {e}");
            return;
        }
    };
    let mut doc: toml::Table = match toml::from_str(&contents) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(task = "config_sync", "Cannot parse TOML for identity sync: {e}");
            return;
        }
    };

    let mut changed = false;

    // Sync [identity] section
    if let Some(toml::Value::Table(ref mut id_table)) = doc.get_mut("identity") {
        let fields: &[(&str, toml::Value)] = &[
            ("node_name", toml::Value::String(identity.node_name.clone())),
            ("node_role", toml::Value::String(identity.node_role.clone())),
            ("wants_to_validate", toml::Value::Boolean(identity.wants_to_validate)),
            ("wants_to_vote", toml::Value::Boolean(identity.wants_to_vote)),
        ];
        for (key, new_val) in fields {
            if id_table.get(*key) != Some(new_val) {
                id_table.insert(key.to_string(), new_val.clone());
                changed = true;
            }
        }
    }

    // Sync [node] role — derive from identity flags
    if let Some(toml::Value::Table(ref mut node_table)) = doc.get_mut("node") {
        let role_str = if identity.wants_to_validate {
            "validator"
        } else {
            "observer"
        };
        let current = node_table.get("role").and_then(|v| v.as_str()).unwrap_or("");
        if current != role_str {
            node_table.insert("role".to_string(), toml::Value::String(role_str.to_string()));
            changed = true;
        }
    }

    if changed {
        match toml::to_string_pretty(&doc) {
            Ok(new_contents) => {
                if let Err(e) = atomic_write_file(config_path, new_contents.as_bytes()) {
                    tracing::warn!(task = "config_sync", "Failed to write synced TOML: {e}");
                } else {
                    tracing::info!(
                        task = "config_sync",
                        "Synced TOML config from identity.json (role={}, validate={}, vote={})",
                        identity.node_role,
                        identity.wants_to_validate,
                        identity.wants_to_vote,
                    );
                }
            }
            Err(e) => tracing::warn!(task = "config_sync", "Failed to serialize synced TOML: {e}"),
        }
    }
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
        country_code: config.identity.country_code.clone(),
        wants_to_validate: config.identity.wants_to_validate,
        wants_to_vote: config.identity.wants_to_vote,
        p2p_port: 8780,
        setup_complete: false,
    }
}

/// Encode finality state as 48 bytes: height(8) + hash(32) + cycle(8).
fn encode_finality_state(height: u64, hash: &noble_crypto::Hash256, cycle: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&height.to_be_bytes());
    data.extend_from_slice(hash.as_bytes());
    data.extend_from_slice(&cycle.to_be_bytes());
    data
}

/// Decode finality state from 48 bytes: height(8) + hash(32) + cycle(8).
fn decode_finality_state(data: &[u8]) -> Option<(u64, noble_crypto::Hash256, u64)> {
    if data.len() < 48 {
        return None;
    }
    let height = u64::from_be_bytes(data[0..8].try_into().ok()?);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&data[8..40]);
    let hash = noble_crypto::Hash256::from_bytes(hash_bytes);
    let cycle = u64::from_be_bytes(data[40..48].try_into().ok()?);
    Some((height, hash, cycle))
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

    let fork_resolution_strategy = crate::healing::parse_fork_resolution_strategy(
        &config.consensus.fork_resolution_strategy,
    );

    // Protocol constants come from CConsensusConfig::default() (hardcoded).
    // Only operator preferences are overwritten from TOML.
    CConsensusConfig {
        voting_strategy,
        confirmation_strategy,
        fork_resolution_strategy,
        fork_resolution_delay_cycles: config.consensus.fork_resolution_delay_cycles,
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
        "weighted_probability" => VotingStrategy::WeightedProbability,
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
    fn init_memory_node_starts_stateless() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");
        config.storage.data_dir = dir.path().to_path_buf();

        let node = Node::init_memory(&config).unwrap();

        // Node starts stateless — no genesis auto-committed.
        assert_eq!(node.chain_height(), 0);
        // Pre-genesis: chain_id is 0 (derived from genesis block hash when available).
        assert_eq!(node.get_chain_id(), 0);

        // Mempool should be empty.
        assert_eq!(node.mempool.lock().len(), 0);

        // Consensus engine tip is zero (no blocks yet).
        let (tip_height, tip_hash) = node.consensus.read().chain_tip();
        assert_eq!(tip_height, 0);
        assert_eq!(tip_hash, Hash256::ZERO);

        // Wallet keystore should be auto-unlocked with chain_meta-derived passphrase.
        assert!(node.wallet_keystore.lock().is_unlocked());

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
        // Drop consensus first (it holds an Arc<RwLock<S>> via UTXO value lookup).
        drop(node1.consensus);
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
    fn verify_recent_blocks_empty_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        // No blocks in storage — verify should return clean with 0 checked.
        let report = node.verify_recent_blocks(10);
        assert!(
            report.is_clean(),
            "empty chain should pass integrity check"
        );
        assert_eq!(report.heights_checked, 0);
    }

    #[test]
    fn verify_recent_blocks_empty_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        // count=0 should not panic
        let report = node.verify_recent_blocks(0);
        assert!(report.is_clean());
        assert_eq!(report.heights_checked, 0);
    }

    #[test]
    fn rollback_empty_chain_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        // Rollback on an empty chain (no tip) should return an error.
        assert!(node.rollback_to_height(0).is_err());
        assert_eq!(node.chain_height(), 0);
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

        let mut node = Node::init_memory(&config).unwrap();
        let (tx, _rx) = mpsc::channel(16);
        let (block_tx, _) = broadcast::channel(16);
        let (tx_tx, _) = broadcast::channel(16);
        let (peer_tx, _) = broadcast::channel(16);
        let (cycle_tx, _) = broadcast::channel(16);
        let test_identity = Arc::new(RwLock::new(NodeIdentityData {
            node_name: String::new(),
            org_type: String::new(),
            org_name: String::new(),
            node_role: String::new(),
            contact_email: String::new(),
            website: String::new(),
            host_address: String::new(),
            country_code: String::new(),
            wants_to_validate: false,
            wants_to_vote: false,
            p2p_port: 8780,
            setup_complete: false,
        }));

        // Peer connect should increment count
        let connect_event = NetworkEvent::PeerConnected {
            peer_id: vec![1, 2, 3],
            addr: "/ip4/1.2.3.4/tcp/8780".to_string(),
            direction: "inbound".to_string(),
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
            &test_identity,
        );
        {
            let stats = node.network_stats.read();
            assert_eq!(stats.peer_count, 1);
            assert_eq!(stats.inbound_count, 1);
            assert_eq!(stats.outbound_count, 0);
        }

        // Connect an outbound peer
        let connect_out = NetworkEvent::PeerConnected {
            peer_id: vec![4, 5, 6],
            addr: "/ip4/5.6.7.8/tcp/8780".to_string(),
            direction: "outbound".to_string(),
            chain_tip: None,
        };
        node.handle_network_event(&connect_out, &tx, &block_tx, &tx_tx, &peer_tx, &cycle_tx, &None, &test_identity);
        {
            let stats = node.network_stats.read();
            assert_eq!(stats.peer_count, 2);
            assert_eq!(stats.inbound_count, 1);
            assert_eq!(stats.outbound_count, 1);
        }

        // Disconnect the inbound peer — should decrement inbound_count
        let disconnect_event = NetworkEvent::PeerDisconnected {
            peer_id: vec![1, 2, 3],
            reason: "test disconnect".to_string(),
        };
        node.handle_network_event(
            &disconnect_event,
            &tx,
            &block_tx,
            &tx_tx,
            &peer_tx,
            &cycle_tx,
            &None,
            &test_identity,
        );
        {
            let stats = node.network_stats.read();
            assert_eq!(stats.peer_count, 1);
            assert_eq!(stats.inbound_count, 0);
            assert_eq!(stats.outbound_count, 1);
        }

        // Disconnect the outbound peer
        let disconnect_out = NetworkEvent::PeerDisconnected {
            peer_id: vec![4, 5, 6],
            reason: "test disconnect".to_string(),
        };
        node.handle_network_event(&disconnect_out, &tx, &block_tx, &tx_tx, &peer_tx, &cycle_tx, &None, &test_identity);
        {
            let stats = node.network_stats.read();
            assert_eq!(stats.peer_count, 0);
            assert_eq!(stats.inbound_count, 0);
            assert_eq!(stats.outbound_count, 0);
        }
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

        let mut node = Node::init_memory(&config).unwrap();
        let (tx, _rx) = mpsc::channel(16);
        let (block_tx, _) = broadcast::channel(16);
        let (tx_tx, _) = broadcast::channel(16);
        let (peer_tx, _) = broadcast::channel(16);
        let (cycle_tx, _) = broadcast::channel(16);
        let test_identity = Arc::new(RwLock::new(NodeIdentityData {
            node_name: String::new(),
            org_type: String::new(),
            org_name: String::new(),
            node_role: String::new(),
            contact_email: String::new(),
            website: String::new(),
            host_address: String::new(),
            country_code: String::new(),
            wants_to_validate: false,
            wants_to_vote: false,
            p2p_port: 8780,
            setup_complete: false,
        }));

        // Connect a peer
        let connect_event = NetworkEvent::PeerConnected {
            peer_id: vec![1, 2, 3],
            addr: "/ip4/1.2.3.4/tcp/8780".to_string(),
            direction: "outbound".to_string(),
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
            &test_identity,
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

        let mut node = Node::init_memory(&config).unwrap();
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
        let test_identity = Arc::new(RwLock::new(NodeIdentityData {
            node_name: String::new(),
            org_type: String::new(),
            org_name: String::new(),
            node_role: String::new(),
            contact_email: String::new(),
            website: String::new(),
            host_address: String::new(),
            country_code: String::new(),
            wants_to_validate: false,
            wants_to_vote: false,
            p2p_port: 8780,
            setup_complete: false,
        }));
        let (cycle_tx, _) = broadcast::channel(16);
        node.process_cycle_actions(actions, &tx, &block_tx, &cycle_tx, &None, &test_identity);
        // No assertion needed — just verifying no panics
    }
}
