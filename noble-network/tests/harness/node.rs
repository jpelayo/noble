// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! `TestNode`: a self-contained node bundling storage, mempool, consensus engine,
//! and a network handle for integration testing.

use std::sync::Arc;

use noble_consensus::{
    ConsensusConfig, ConsensusStateMachine, CycleEngine, CycleEvent, CycleIo, ValidatorList,
};
use noble_core::{Block, BlockHeader, Transaction};
use noble_test_utils::fixtures::test_chain_id;
use noble_crypto::{Hash256, NoblePrivateKey, NoblePublicKey};
use noble_mempool::{Mempool, MempoolConfig, NoUtxoLookup, NoChainLookup};
use noble_network::config::NetworkConfig;
use noble_network::messages::{NetworkCommand, NetworkEvent};
use noble_network::service::NetworkHandle;
use noble_network::traits::{BlockProvider, TxProvider};
use noble_storage::{MemoryStorage, StorageEngine};

/// A `StorageEngine`-backed implementation of [`BlockProvider`].
pub struct StorageBlockProvider {
    storage: Arc<MemoryStorage>,
}

impl BlockProvider for StorageBlockProvider {
    fn get_block(&self, hash: &[u8; 32]) -> Option<Block> {
        let h = Hash256(*hash);
        self.storage.get_block(&h).ok()
    }

    fn get_block_by_height(&self, height: u64) -> Option<Block> {
        let hash = self.storage.get_block_hash_by_height(height).ok()?;
        self.storage.get_block(&hash).ok()
    }

    fn get_block_header(&self, hash: &[u8; 32]) -> Option<BlockHeader> {
        let h = Hash256(*hash);
        self.storage.get_block_header(&h).ok()
    }

    fn get_block_hash_by_height(&self, height: u64) -> Option<[u8; 32]> {
        self.storage.get_block_hash_by_height(height).ok().map(|h| *h.as_bytes())
    }

    fn chain_tip(&self) -> (u64, [u8; 32]) {
        self.storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|tip| (tip.height, *tip.block_hash.as_bytes()))
            .unwrap_or((0, [0; 32]))
    }
}

/// A `StorageEngine`-backed implementation of [`TxProvider`].
pub struct StorageTxProvider {
    storage: Arc<MemoryStorage>,
}

impl TxProvider for StorageTxProvider {
    fn get_transaction(&self, tx_id: &[u8; 32]) -> Option<Transaction> {
        let h = Hash256(*tx_id);
        self.storage.get_transaction(&h).ok()
    }

    fn has_transaction(&self, tx_id: &[u8; 32]) -> bool {
        let h = Hash256(*tx_id);
        self.storage.has_transaction(&h).unwrap_or(false)
    }
}

/// A test node bundling all subsystems for integration testing.
pub struct TestNode {
    pub storage: Arc<MemoryStorage>,
    pub mempool: Mempool,
    pub engine: CycleEngine,
    pub handle: NetworkHandle,
    pub private_key: NoblePrivateKey,
    pub public_key: NoblePublicKey,
    /// Blocks committed during this test run.
    pub committed_blocks: Vec<Block>,
}

impl TestNode {
    /// Create a new test node with a running network.
    pub async fn start(
        private_key: NoblePrivateKey,
        public_key: NoblePublicKey,
        validator_list: ValidatorList,
        consensus_config: ConsensusConfig,
        network_config: NetworkConfig,
    ) -> Self {
        let storage = Arc::new(MemoryStorage::new());

        let bp: Arc<dyn BlockProvider> = Arc::new(StorageBlockProvider {
            storage: storage.clone(),
        });
        let tp: Arc<dyn TxProvider> = Arc::new(StorageTxProvider {
            storage: storage.clone(),
        });

        let handle = noble_network::service::start_network(network_config, bp, tp)
            .await
            .expect("network should start");

        let snap = {
            let mut reg = noble_consensus::ValidatorRegistry::new(validator_list, None);
            reg.create_snapshot()
        };
        let mut engine = CycleEngine::new(
            consensus_config,
            0,
            Hash256::ZERO,
            test_chain_id(),
            Some((private_key.clone_for_test(), public_key.clone())),
            Some(0), // tests: genesis at epoch 0
        );
        engine.set_validator_snapshot(snap);

        let mempool = Mempool::new(MempoolConfig::default());

        Self {
            storage,
            mempool,
            engine,
            handle,
            private_key,
            public_key,
            committed_blocks: Vec::new(),
        }
    }

    /// Process one consensus event and dispatch resulting CycleIo actions.
    pub async fn step(&mut self, event: CycleEvent) {
        let outputs = self.engine.step(event);
        for io in outputs {
            self.dispatch_io(io).await;
        }
    }

    /// Propose a block using the consensus proposal builder.
    pub fn propose_block(&mut self, timestamp: u64) -> Result<Block, String> {
        let (tip_height, tip_hash) = self.engine.chain_tip();
        let txs: Vec<Transaction> = self
            .mempool
            .iter_by_fee_desc()
            .take(100)
            .map(|e| e.tx.clone())
            .collect();
        struct NoopLookup;
        impl noble_consensus::proposal::UtxoValueLookup for NoopLookup {
            fn utxo_value(&self, _: &noble_core::OutPoint) -> Option<u64> { None }
        }
        noble_consensus::propose_block(
            &txs,
            tip_hash,
            tip_height + 1,
            timestamp,
            test_chain_id(),
            &self.private_key,
            &self.public_key,
            4 * 1024 * 1024,
            &NoopLookup,
            None,
        )
    }

    /// Process one incoming network event through the consensus engine.
    #[allow(dead_code)]
    pub async fn process_network_event(&mut self, event: NetworkEvent) {
        // Update peer count on connect/disconnect.
        match &event {
            NetworkEvent::PeerConnected { .. } => {
                let current = self.engine.validator_snapshot().map(|s| s.len()).unwrap_or(0);
                self.engine.set_peer_count(current);
            }
            NetworkEvent::PeerDisconnected { .. } => {}
            _ => {}
        }

        if let Some(cycle_event) = super::network_event_to_cycle_event(&event) {
            self.step(cycle_event).await;
        }
    }

    /// Dispatch a CycleIo action: send network commands, commit blocks, readmit txs.
    async fn dispatch_io(&mut self, io: CycleIo) {
        match io {
            CycleIo::CommitBlock(block) => {
                let block_hash = block.header.compute_block_hash().unwrap_or(Hash256::ZERO);
                let tx_ids: Vec<Hash256> = block
                    .transactions
                    .iter()
                    .filter_map(|tx| tx.compute_tx_id(test_chain_id()).ok())
                    .collect();
                let _ = self.storage.commit_block(&block, &block_hash, &tx_ids);
                self.committed_blocks.push(*block);
            }
            CycleIo::ReadmitTransactions(txs) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                for tx in &txs {
                    let _ = self
                        .mempool
                        .admit(tx, now, &NoChainLookup, &NoUtxoLookup, 0);
                }
            }
            CycleIo::EvictTransactions(tx_ids) => {
                for tx_id in &tx_ids {
                    self.mempool.remove(tx_id);
                }
            }
            CycleIo::SetTimer { .. } | CycleIo::EmitMetric { .. } | CycleIo::Log(_) => {
                // No action needed in tests.
            }
            other => {
                // Convert to network commands and send.
                let cmds = super::cycle_io_to_network_commands(other);
                for cmd in cmds {
                    let _ = self.handle.command_sender().send(cmd).await;
                }
            }
        }
    }

    /// Send a shutdown command to the network service.
    pub async fn shutdown(&self) {
        let _ = self
            .handle
            .command_sender()
            .send(NetworkCommand::Shutdown)
            .await;
    }
}
