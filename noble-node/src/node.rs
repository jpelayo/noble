// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node orchestrator — ties all subsystems together.
//!
//! The `Node` struct owns shared references to storage, mempool, consensus,
//! wallet, and network stats. It is initialized from a `NodeConfig` and provides
//! the foundation for the async event loop (to be wired in a future sprint).

use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use noble_api::auth::TotpValidator;
use noble_api::NetworkStats;
use noble_consensus::{ConsensusConfig as CConsensusConfig, CycleEngine, ValidatorList};
use noble_core::MAINNET_CHAIN_ID;
use noble_crypto::Hash256;
use noble_mempool::Mempool;
use noble_storage::{IntegrityReport, MemoryStorage, StorageEngine};
use noble_wallet::{KeyStore, WalletState};

use crate::config::NodeConfig;

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
    /// Active chain ID.
    pub chain_id: u32,
    /// Timestamp when the node was started.
    pub start_time: std::time::Instant,
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

        // Ensure genesis block is committed if the chain is empty.
        {
            let s = storage.read().map_err(|e| format!("storage lock: {e}"))?;
            if s.get_chain_tip()?.is_none() {
                let genesis = noble_core::genesis_block();
                let block_hash = genesis
                    .header
                    .compute_block_hash()
                    .map_err(|e| format!("genesis hash error: {e}"))?;
                let tx_ids: Vec<_> = genesis
                    .transactions
                    .iter()
                    .map(|tx| tx.compute_tx_id(MAINNET_CHAIN_ID))
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

        // Create consensus engine (observation mode — no validator key yet).
        let consensus_config = CConsensusConfig::default();
        let validator_list = ValidatorList::new();
        let consensus = Arc::new(RwLock::new(CycleEngine::new(
            consensus_config,
            validator_list,
            tip.height,
            tip.block_hash,
            MAINNET_CHAIN_ID,
            None, // no validator key — observation mode
        )));

        // Create wallet keystore.
        let keystore = KeyStore::new(&config.wallet.keystore_path)?;
        let wallet_keystore = Arc::new(Mutex::new(keystore));
        let wallet_state = Arc::new(Mutex::new(WalletState::new(3600)));

        let network_stats = Arc::new(RwLock::new(NetworkStats::default()));

        Ok(Self {
            storage,
            mempool,
            consensus,
            wallet_keystore,
            wallet_state,
            network_stats,
            chain_id: MAINNET_CHAIN_ID,
            start_time: std::time::Instant::now(),
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
        let storage = self.storage.read().unwrap();
        noble_storage::verify_chain_integrity(&*storage, self.chain_id, start, height)
    }

    /// Rollback the chain to the given height, recalculating balances.
    /// Used when corruption is detected.
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
        tracing::info!(
            "TOTP auth: new secret generated at {}",
            secret_path.display()
        );
        tracing::info!("TOTP secret (base32): {}", base32);
        tracing::info!("otpauth URI: {}", v.otpauth_uri("NOBLE Node"));
        (v, base32)
    };

    let _ = base32; // used only for logging/file write above
    Ok((Some(Arc::new(RwLock::new(validator))), Some(secret_path)))
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
        assert_eq!(node.chain_id, MAINNET_CHAIN_ID);

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
        assert_eq!(config.api.rpc_addr, "127.0.0.1:9933");
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
    fn node_chain_id_is_mainnet() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.wallet.keystore_path = dir.path().join("keystore");

        let node = Node::init_memory(&config).unwrap();
        assert_eq!(node.chain_id, MAINNET_CHAIN_ID);
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
}
