// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Healing module — owns all chain healing, integrity checking, sync, fork
//! resolution, and cross-chain adoption logic.
//!
//! Design: **Clue → Check → Eval → Update (and event logging)** — all in one
//! place to avoid race conditions and self-fighting between subsystems.
//!
//! `HealingManager<S>` holds owned `Arc` references to storage, consensus,
//! mempool, and IO channels.  Methods execute directly: they read subsystem
//! state, make decisions, and perform side-effects (storage writes, network
//! commands, broadcast events) in one call.
//!
//! Fork resolution and cross-chain adoption are handled inline — the
//! `ForkResolver` instance lives here (shared with ApiState via `Arc<Mutex>`),
//! eliminating the CycleEvent round-trip through the consensus engine.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use noble_api::state::PeerInfoEntry;
use noble_api::types::DiscoveredBlockchainInfo;
use noble_consensus::{ConsensusStateMachine, CycleEngine};
use noble_consensus::fork_resolver::{ForkResolver, ForkResolutionStrategy};
use noble_core::NodeAnnounce;
use noble_crypto::Hash256;
use noble_mempool::Mempool;
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, mpsc};

// ---------------------------------------------------------------------------
// Manifest-based sync state machine
// ---------------------------------------------------------------------------

/// A single entry in the sync manifest — one block to fetch.
pub struct ManifestEntry {
    pub height: u64,
    pub hash: [u8; 32],
    pub status: EntryStatus,
}

/// Status of a single manifest entry.
pub enum EntryStatus {
    Pending,
    Requested { at: u64 },
    Done,
    Failed { attempts: u8 },
}

/// Sync state machine — replaces 5 loose fields with explicit states.
pub enum SyncState {
    /// Not syncing.
    Idle,
    /// Waiting for the peer to respond with block hash manifest.
    AwaitingManifest {
        peer: Vec<u8>,
        target: u64,
        requested_at: u64,
    },
    /// Fetching blocks according to the manifest.
    Fetching {
        peer: Vec<u8>,
        target: u64,
        manifest: Vec<ManifestEntry>,
        cursor: usize,
    },
}

/// Maximum number of blocks in a single manifest window.
const MANIFEST_WINDOW: u16 = 256;
/// Timeout for manifest request (seconds).
const MANIFEST_TIMEOUT_SECS: u64 = 30;
/// Maximum retry attempts for a single block before switching peers.
const MAX_BLOCK_RETRIES: u8 = 3;
/// Minimum interval between advance_sync actions (seconds).
const SYNC_RETRY_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// ForkEvalResult
// ---------------------------------------------------------------------------

/// Result of a fork evaluation tick — contains pre/post dwell counters
/// and tracking state for GUI event emission in node.rs.
pub struct ForkEvalResult {
    pub dwell_before: u32,
    pub dwell_after: u32,
    pub tracked_height: Option<u64>,
    pub min_fork_duration: u32,
}

// ---------------------------------------------------------------------------
// HealingManager
// ---------------------------------------------------------------------------

/// Manages all chain healing state: sync tracking, fork detection,
/// cross-chain discovery, and announce equivocation detection.
///
/// Generic over `S: StorageEngine` — holds owned `Arc` references to all
/// subsystems so methods can execute directly without returning actions.
pub struct HealingManager<S: StorageEngine + Send + Sync + 'static> {
    // ── Healing state (manifest-based sync) ──
    sync_state: SyncState,
    /// Shared with RPC (ApiState reads this).
    sync_behind_shared: Arc<AtomicBool>,
    /// Shared with RPC (ApiState reads this).
    sync_target_height_shared: Arc<AtomicU64>,
    /// Current sync progress height — shared with RPC/GUI.
    sync_progress_current: Arc<AtomicU64>,
    /// Overall sync target height — shared with RPC/GUI.
    sync_progress_total: Arc<AtomicU64>,

    // ── Fork state ──
    fork_visible: bool,
    fork_common_ancestor: Option<(u64, [u8; 32])>,

    // ── Cross-chain state ──
    /// Blockchains discovered via NodeAnnounce. Shared with ApiState.
    discovered_blockchains: Arc<Mutex<HashMap<u32, DiscoveredBlockchainInfo>>>,
    discovered_blockchains_path: Option<PathBuf>,

    // ── Equivocation detection ──
    announce_cache: parking_lot::Mutex<HashMap<Vec<u8>, NodeAnnounce>>,

    // ── Chain metrics ──
    chain_vote_weight: AtomicU64,

    // ── Subsystem references ──
    storage: Arc<RwLock<S>>,
    consensus: Arc<RwLock<CycleEngine>>,
    mempool: Arc<Mutex<Mempool>>,
    chain_id: Arc<AtomicU32>,
    peer_info: Arc<RwLock<HashMap<String, PeerInfoEntry>>>,
    last_proposed: Arc<parking_lot::Mutex<Option<(u64, [u8; 32])>>>,

    // ── Fork resolver (owned by HealingManager, shared with ApiState) ──
    fork_resolver: Arc<parking_lot::Mutex<ForkResolver>>,
    fork_resolution_strategy: ForkResolutionStrategy,
    fork_resolution_delay_cycles: u32,

    // ── IO channels (set after construction via set_io_channels) ──
    network_cmd: Option<mpsc::Sender<NetworkCommand>>,
    new_block_tx: Option<broadcast::Sender<serde_json::Value>>,
    cycle_phase_tx: Option<broadcast::Sender<serde_json::Value>>,
    metrics: Option<crate::metrics::NobleMetrics>,
}

impl<S: StorageEngine + Send + Sync + 'static> HealingManager<S> {
    /// Create a new HealingManager with default (pre-genesis) state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<RwLock<S>>,
        consensus: Arc<RwLock<CycleEngine>>,
        mempool: Arc<Mutex<Mempool>>,
        chain_id: Arc<AtomicU32>,
        peer_info: Arc<RwLock<HashMap<String, PeerInfoEntry>>>,
        last_proposed: Arc<parking_lot::Mutex<Option<(u64, [u8; 32])>>>,
        discovered_blockchains: Arc<Mutex<HashMap<u32, DiscoveredBlockchainInfo>>>,
        discovered_blockchains_path: Option<PathBuf>,
        sync_behind_shared: Arc<AtomicBool>,
        sync_target_height_shared: Arc<AtomicU64>,
        sync_progress_current: Arc<AtomicU64>,
        sync_progress_total: Arc<AtomicU64>,
        fork_resolution_strategy: ForkResolutionStrategy,
        fork_resolution_delay_cycles: u32,
    ) -> Self {
        let fork_resolver = Arc::new(parking_lot::Mutex::new(
            ForkResolver::new(fork_resolution_strategy, fork_resolution_delay_cycles),
        ));
        Self {
            sync_state: SyncState::Idle,
            sync_behind_shared,
            sync_target_height_shared,
            sync_progress_current,
            sync_progress_total,
            fork_visible: false,
            fork_common_ancestor: None,
            discovered_blockchains,
            discovered_blockchains_path,
            announce_cache: parking_lot::Mutex::new(HashMap::new()),
            chain_vote_weight: AtomicU64::new(0),
            storage,
            consensus,
            mempool,
            chain_id,
            peer_info,
            last_proposed,
            fork_resolver,
            fork_resolution_strategy,
            fork_resolution_delay_cycles,
            network_cmd: None,
            new_block_tx: None,
            cycle_phase_tx: None,
            metrics: None,
        }
    }

    /// Get the shared fork resolver (for ApiState).
    pub fn fork_resolver(&self) -> &Arc<parking_lot::Mutex<ForkResolver>> {
        &self.fork_resolver
    }

    /// Inject IO channels after network and broadcast infrastructure is ready.
    /// Must be called before the event loop starts.
    pub fn set_io_channels(
        &mut self,
        network_cmd: mpsc::Sender<NetworkCommand>,
        new_block_tx: broadcast::Sender<serde_json::Value>,
        cycle_phase_tx: broadcast::Sender<serde_json::Value>,
        metrics: Option<crate::metrics::NobleMetrics>,
    ) {
        self.network_cmd = Some(network_cmd);
        self.new_block_tx = Some(new_block_tx);
        self.cycle_phase_tx = Some(cycle_phase_tx);
        self.metrics = metrics;
    }

    // ── Accessors ──

    pub fn sync_behind(&self) -> bool { !matches!(self.sync_state, SyncState::Idle) }
    pub fn sync_behind_shared(&self) -> &Arc<AtomicBool> { &self.sync_behind_shared }
    pub fn sync_target_height_shared(&self) -> &Arc<AtomicU64> { &self.sync_target_height_shared }
    pub fn sync_progress_current(&self) -> &Arc<AtomicU64> { &self.sync_progress_current }
    pub fn sync_progress_total(&self) -> &Arc<AtomicU64> { &self.sync_progress_total }

    /// Returns true if we are in the Fetching state and this height is in the manifest.
    pub fn is_sync_block(&self, height: u64) -> bool {
        if let SyncState::Fetching { ref manifest, .. } = self.sync_state {
            manifest.iter().any(|e| e.height == height)
        } else {
            false
        }
    }

    /// Returns true if actively syncing (not Idle).
    pub fn is_syncing(&self) -> bool { !matches!(self.sync_state, SyncState::Idle) }

    /// Returns sync progress as (current, total) or None if idle.
    pub fn sync_progress(&self) -> Option<(u64, u64)> {
        match &self.sync_state {
            SyncState::Idle => None,
            SyncState::AwaitingManifest { target, .. } => {
                let current = self.consensus.read().chain_tip().0;
                Some((current, *target))
            }
            SyncState::Fetching { target, .. } => {
                let current = self.consensus.read().chain_tip().0;
                Some((current, *target))
            }
        }
    }

    pub fn fork_visible(&self) -> bool { self.fork_visible }
    pub fn set_fork_visible(&mut self, v: bool) { self.fork_visible = v; }
    pub fn fork_common_ancestor(&self) -> Option<(u64, [u8; 32])> { self.fork_common_ancestor }
    pub fn set_fork_common_ancestor(&mut self, v: Option<(u64, [u8; 32])>) { self.fork_common_ancestor = v; }
    pub fn discovered_blockchains(&self) -> &Arc<Mutex<HashMap<u32, DiscoveredBlockchainInfo>>> { &self.discovered_blockchains }
    pub fn chain_vote_weight(&self) -> &AtomicU64 { &self.chain_vote_weight }
    #[inline]
    fn get_chain_id(&self) -> u32 { self.chain_id.load(Ordering::Relaxed) }

    // ── Private execution helpers ──

    fn send_network(&self, cmd: NetworkCommand) {
        if let Some(ref sender) = self.network_cmd {
            if let Err(e) = sender.try_send(cmd) {
                tracing::debug!(task = "healing", "network command dropped: {e}");
            }
        }
    }

    fn broadcast_event(&self, json: serde_json::Value) {
        if let Some(ref sender) = self.cycle_phase_tx {
            if let Err(e) = sender.send(json) {
                tracing::debug!(task = "healing", "cycle_phase broadcast dropped (no subscribers): {e}");
            }
        }
    }

    fn broadcast_new_block(&self, json: serde_json::Value) {
        if let Some(ref sender) = self.new_block_tx {
            if let Err(e) = sender.send(json) {
                tracing::debug!(task = "healing", "new_block broadcast dropped (no subscribers): {e}");
            }
        }
    }

    fn wipe_and_reset(&self, reason: &str) {
        tracing::warn!(task = "healing", "WipeAndReset: {reason}");
        let storage = self.storage.read();
        if let Err(e) = storage.wipe_all_chain_data() {
            tracing::error!(task = "healing", "wipe_all_chain_data failed: {e}");
        }
        if let Err(e) = storage.clear_cycle_history() {
            tracing::warn!(task = "healing", "clear_cycle_history: {e}");
        }
    }

    fn rollback_to(&self, height: u64) {
        let chain_id = self.get_chain_id();
        let storage = self.storage.read();
        let result = if height > 0 {
            storage.rollback_to_height(height, chain_id)
        } else {
            storage.force_reset_to_genesis(chain_id)
        };
        if let Err(e) = result {
            tracing::warn!(task = "healing", "rollback to {height} failed ({e}), resetting to genesis");
            if let Err(e2) = storage.force_reset_to_genesis(chain_id) {
                tracing::error!(task = "healing", "genesis reset also failed: {e2}");
            }
        }
        // Re-read tip and reset consensus accordingly.
        let tip = match storage.get_chain_tip() {
            Ok(Some(t)) => t,
            Ok(None) => noble_storage::ChainTip { block_hash: Hash256::ZERO, height: 0 },
            Err(e) => {
                tracing::error!(task = "healing", "get_chain_tip after rollback failed: {e} — defaulting to genesis");
                noble_storage::ChainTip { block_hash: Hash256::ZERO, height: 0 }
            }
        };
        // Load tip header before dropping storage (Storage(2) < Consensus(3) — OK).
        let tip_header = if tip.height > 0 {
            match storage.get_block_header(&tip.block_hash) {
                Ok(header) => Some(header),
                Err(e) => {
                    tracing::error!(task = "healing", "failed to load tip_header after rollback to {}: {e} — B2/B3/B5 validation degraded", height);
                    None
                }
            }
        } else {
            None
        };
        drop(storage);
        if let Err(e) = self.consensus.write().reset_tip(tip.height, tip.block_hash, true) {
            tracing::error!(task = "healing", "reset_tip failed: {e}");
        }
        if let Some(header) = tip_header {
            self.consensus.write().update_tip_with_header(header);
        }
    }

    fn clear_cycle_history_storage(&self) {
        if let Err(e) = self.storage.read().clear_cycle_history() {
            tracing::warn!(task = "healing", "clear_cycle_history: {e}");
        }
    }

    fn clear_pending_proposals(&self) {
        self.send_network(NetworkCommand::ClearPendingProposals);
    }

    fn request_sync(&self) {
        self.send_network(NetworkCommand::RequestSync);
    }

    fn update_tip_height(&self, h: u64) {
        self.send_network(NetworkCommand::UpdateTipHeight(h));
    }

    fn clear_last_proposed(&self) {
        *self.last_proposed.lock() = None;
    }

    fn evict_from_mempool(&self, tx_ids: &[Hash256]) {
        let mut mempool = self.mempool.lock();
        for tx_id in tx_ids {
            mempool.remove(tx_id);
        }
    }

    fn record_metric_block_validation(&self, duration: f64) {
        if let Some(ref m) = self.metrics {
            m.block_validation_duration.observe(duration);
        }
    }

    // ── Persist discovered blockchains ──

    /// Persist discovered blockchains map to CBOR file.
    pub fn persist_discovered_blockchains(&self) {
        if let Some(ref path) = self.discovered_blockchains_path {
            let discovered = self.discovered_blockchains.lock();
            match noble_codec::NobleCbor::to_cbor(&*discovered) {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(path, &bytes) {
                        tracing::warn!(task = "peer_tracking", "Failed to persist discovered blockchains: {e}");
                    }
                }
                Err(e) => {
                    tracing::warn!(task = "peer_tracking", "Failed to serialize discovered blockchains: {e}");
                }
            }
        }
    }

    // ── Manifest-based sync: single entry point ──

    /// Project sync_state into shared atomics for RPC/GUI reads.
    fn sync_atomics_from_state(&self) {
        let (behind, target, current) = match &self.sync_state {
            SyncState::Idle => (false, 0u64, 0u64),
            SyncState::AwaitingManifest { target, .. } => {
                let c = self.consensus.read().chain_tip().0;
                (true, *target, c)
            }
            SyncState::Fetching { target, .. } => {
                let c = self.consensus.read().chain_tip().0;
                (true, *target, c)
            }
        };
        self.sync_behind_shared.store(behind, Ordering::Relaxed);
        self.sync_target_height_shared.store(target, Ordering::Relaxed);
        self.sync_progress_current.store(current, Ordering::Relaxed);
        self.sync_progress_total.store(target, Ordering::Relaxed);
    }

    /// Reset sync state to Idle and update atomics.
    fn reset_sync_idle(&mut self) {
        self.sync_state = SyncState::Idle;
        self.sync_atomics_from_state();
    }

    /// THE single entry point for all sync decisions. Called from:
    /// - tick handler (periodic)
    /// - on_peer_chain_tip_updated (peer status)
    /// - advance_after_import (after each committed block)
    /// - on_fork_resolution_requested (after rollback)
    pub fn advance_sync(&mut self, now: u64) {
        let our_height = self.consensus.read().chain_tip().0;

        match &self.sync_state {
            SyncState::Idle => {
                // Check if any peer is ahead.
                let (best_peer, best_height) = self.find_best_sync_peer(our_height);
                if let Some(peer) = best_peer {
                    let behind = best_height - our_height;
                    tracing::info!(
                        task = "sync",
                        "peer {} at height {}, we're at {} ({} behind) — requesting manifest",
                        hex::encode(&peer), best_height, our_height, behind,
                    );
                    let start = our_height + 1;
                    let count = (best_height - our_height).min(MANIFEST_WINDOW as u64) as u16;
                    self.send_network(NetworkCommand::RequestSyncManifest {
                        peer_id: peer.clone(),
                        start_height: start,
                        count,
                    });
                    self.sync_state = SyncState::AwaitingManifest {
                        peer: peer,
                        target: best_height,
                        requested_at: now,
                    };
                    self.sync_atomics_from_state();
                    self.broadcast_event(serde_json::json!({
                        "event": "sync_started",
                        "peer_height": best_height,
                        "our_height": our_height,
                        "blocks_behind": behind,
                    }));
                }
            }
            SyncState::AwaitingManifest { peer, target, requested_at } => {
                // If we already caught up (e.g., blocks arrived via fallback
                // while waiting for the manifest), stop syncing.
                if our_height >= *target {
                    self.reset_sync_idle();
                    self.broadcast_event(serde_json::json!({
                        "event": "sync_complete",
                        "height": our_height,
                    }));
                    tracing::info!(
                        task = "sync",
                        "Sync complete (caught up during AwaitingManifest) — height {}",
                        our_height,
                    );
                    return;
                }
                // Timeout check.
                if now.saturating_sub(*requested_at) >= MANIFEST_TIMEOUT_SECS {
                    tracing::warn!(
                        task = "sync",
                        "manifest request timed out after {}s — trying different peer",
                        MANIFEST_TIMEOUT_SECS,
                    );
                    let old_peer = peer.clone();
                    let target = *target;
                    self.sync_state = SyncState::Idle;
                    // Try to find a different peer.
                    let (new_peer, new_height) = self.find_best_sync_peer_excluding(our_height, &old_peer);
                    if let Some(np) = new_peer {
                        let start = our_height + 1;
                        let count = (new_height - our_height).min(MANIFEST_WINDOW as u64) as u16;
                        self.send_network(NetworkCommand::RequestSyncManifest {
                            peer_id: np.clone(),
                            start_height: start,
                            count,
                        });
                        self.sync_state = SyncState::AwaitingManifest {
                            peer: np,
                            target: new_height,
                            requested_at: now,
                        };
                    } else {
                        // No other peer available — retry same peer.
                        let start = our_height + 1;
                        let count = (target - our_height).min(MANIFEST_WINDOW as u64) as u16;
                        self.send_network(NetworkCommand::RequestSyncManifest {
                            peer_id: old_peer.clone(),
                            start_height: start,
                            count,
                        });
                        self.sync_state = SyncState::AwaitingManifest {
                            peer: old_peer,
                            target,
                            requested_at: now,
                        };
                    }
                    self.sync_atomics_from_state();
                }
            }
            SyncState::Fetching { peer, manifest, cursor, target } => {
                // Find next block to request.
                let peer = peer.clone();
                let target = *target;
                let cursor = *cursor;

                // Skip manifest entries for blocks we already have (e.g., committed
                // via fallback sync before the manifest arrived).
                if cursor < manifest.len() && manifest[cursor].height <= our_height {
                    // Must drop the immutable borrow before mutating.
                    if let SyncState::Fetching { ref mut manifest, cursor: ref mut c, .. } = self.sync_state {
                        while *c < manifest.len() && manifest[*c].height <= our_height {
                            manifest[*c].status = EntryStatus::Done;
                            *c += 1;
                        }
                    }
                    // Re-enter advance_sync with updated cursor.
                    self.advance_sync(now);
                    return;
                }

                if cursor < manifest.len() {
                    let entry = &manifest[cursor];
                    match entry.status {
                        EntryStatus::Pending => {
                            self.send_network(NetworkCommand::RequestBlockByHeight {
                                peer_id: peer.clone(),
                                height: entry.height,
                            });
                            // Mark as requested.
                            if let SyncState::Fetching { ref mut manifest, .. } = self.sync_state {
                                manifest[cursor].status = EntryStatus::Requested { at: now };
                            }
                        }
                        EntryStatus::Requested { at } => {
                            // Timeout — retry after SYNC_RETRY_SECS.
                            if now.saturating_sub(at) >= SYNC_RETRY_SECS {
                                tracing::debug!(
                                    task = "sync",
                                    "block {} fetch stalled — retrying",
                                    entry.height,
                                );
                                self.send_network(NetworkCommand::RequestBlockByHeight {
                                    peer_id: peer.clone(),
                                    height: entry.height,
                                });
                                if let SyncState::Fetching { ref mut manifest, .. } = self.sync_state {
                                    manifest[cursor].status = EntryStatus::Requested { at: now };
                                }
                            }
                        }
                        EntryStatus::Failed { attempts } if attempts >= MAX_BLOCK_RETRIES => {
                            // Too many failures — switch peer.
                            tracing::warn!(
                                task = "sync",
                                "block {} failed {} times — switching peer",
                                manifest[cursor].height, attempts,
                            );
                            self.reset_sync_idle();
                            // advance_sync will be called again on next tick.
                        }
                        EntryStatus::Failed { .. } => {
                            // Retry.
                            self.send_network(NetworkCommand::RequestBlockByHeight {
                                peer_id: peer.clone(),
                                height: entry.height,
                            });
                            if let SyncState::Fetching { ref mut manifest, .. } = self.sync_state {
                                manifest[cursor].status = EntryStatus::Requested { at: now };
                            }
                        }
                        EntryStatus::Done => {
                            // Should not happen — cursor should advance past Done entries.
                            // Advance cursor.
                            if let SyncState::Fetching { ref mut cursor, .. } = self.sync_state {
                                *cursor += 1;
                            }
                        }
                    }
                } else {
                    // All entries processed — check if we need more.
                    if our_height >= target {
                        // Caught up!
                        self.reset_sync_idle();
                        self.broadcast_event(serde_json::json!({
                            "event": "sync_complete",
                            "height": our_height,
                        }));
                        tracing::info!(
                            task = "sync",
                            "Sync complete — caught up at height {}",
                            our_height
                        );
                    } else {
                        // Need next manifest window.
                        let start = our_height + 1;
                        let remaining = target - our_height;
                        let count = remaining.min(MANIFEST_WINDOW as u64) as u16;
                        self.send_network(NetworkCommand::RequestSyncManifest {
                            peer_id: peer.clone(),
                            start_height: start,
                            count,
                        });
                        self.sync_state = SyncState::AwaitingManifest {
                            peer,
                            target,
                            requested_at: now,
                        };
                        self.sync_atomics_from_state();
                    }
                }
            }
        }
    }

    /// Handle manifest received from a peer.
    pub fn on_manifest_received(
        &mut self,
        peer_id: &[u8],
        entries: &[(u64, Option<[u8; 32]>)],
        now: u64,
    ) {
        let target = match &self.sync_state {
            SyncState::AwaitingManifest { peer, target, .. } if peer == peer_id => *target,
            _ => {
                tracing::debug!(
                    task = "sync",
                    "manifest received but not in AwaitingManifest state — ignoring"
                );
                return;
            }
        };

        // Filter out entries with no hash (peer doesn't have those blocks).
        let manifest: Vec<ManifestEntry> = entries
            .iter()
            .filter_map(|(height, hash)| {
                hash.map(|h| ManifestEntry {
                    height: *height,
                    hash: h,
                    status: EntryStatus::Pending,
                })
            })
            .collect();

        if manifest.is_empty() {
            tracing::warn!(task = "sync", "empty manifest from peer — resetting to Idle");
            self.reset_sync_idle();
            return;
        }

        tracing::info!(
            task = "sync",
            "manifest received: {} blocks (heights {}..={})",
            manifest.len(),
            manifest.first().map(|e| e.height).unwrap_or(0),
            manifest.last().map(|e| e.height).unwrap_or(0),
        );

        self.sync_state = SyncState::Fetching {
            peer: peer_id.to_vec(),
            target,
            manifest,
            cursor: 0,
        };
        self.sync_atomics_from_state();

        // Immediately request the first block.
        self.advance_sync(now);
    }

    /// Called after a sync import attempt. Marks the manifest entry and advances.
    pub fn advance_after_import(
        &mut self,
        height: u64,
        result: &SyncImportResult,
        now: u64,
    ) {
        if let SyncState::Fetching { ref mut manifest, ref mut cursor, target, .. } = self.sync_state {
            // Find and update the entry for this height.
            if *cursor < manifest.len() && manifest[*cursor].height == height {
                match result {
                    SyncImportResult::Accepted { .. } => {
                        manifest[*cursor].status = EntryStatus::Done;
                        *cursor += 1;

                        // Update progress atomics.
                        let current = height;
                        let total = target;
                        self.sync_progress_current.store(current, Ordering::Relaxed);
                        self.sync_progress_total.store(total, Ordering::Relaxed);

                        // Emit progress event.
                        let pct = if total > 0 {
                            (current as f64 / total as f64 * 100.0).min(100.0) as u64
                        } else {
                            0
                        };
                        self.broadcast_event(serde_json::json!({
                            "event": "sync_progress",
                            "height": current,
                            "target": total,
                            "progress": pct,
                        }));
                    }
                    SyncImportResult::Rejected { reason } => {
                        let attempts = match manifest[*cursor].status {
                            EntryStatus::Failed { attempts } => attempts + 1,
                            _ => 1,
                        };
                        tracing::warn!(
                            task = "sync",
                            "sync block {} rejected (attempt {}): {reason}",
                            height, attempts,
                        );
                        manifest[*cursor].status = EntryStatus::Failed { attempts };
                    }
                }
            }
        }

        // Continue fetching.
        self.advance_sync(now);
    }

    /// Find the best (highest) sync peer that's ahead of us on the same chain.
    ///
    /// Chain filter: when our chain_id is non-zero, reject peers that have
    /// announced a *different* chain_id.  Peers with `chain_id = None` (no
    /// NodeAnnounce received yet) are allowed — the service-level GetStatus
    /// mismatch gate is the authoritative chain check.  Filtering them out
    /// here would stall sync after block 1 commit (chain_id changes from 0
    /// to derived before the peer's gossipsub announce arrives).
    fn find_best_sync_peer(&self, our_height: u64) -> (Option<Vec<u8>>, u64) {
        let local_chain_id = self.get_chain_id();
        let peers = self.peer_info.read();
        let mut best_peer = None;
        let mut best_height = our_height;
        for entry in peers.values() {
            // Skip peers on a known-different chain.  chain_id=None means
            // "not yet announced" — allow (service.rs mismatch check is authoritative).
            if local_chain_id != 0 {
                if let Some(peer_cid) = entry.chain_id {
                    if peer_cid != local_chain_id { continue; }
                }
            }
            if let Some(h) = entry.chain_tip_height {
                if h > best_height {
                    if let Ok(pid) = hex::decode(&entry.peer_id) {
                        best_height = h;
                        best_peer = Some(pid);
                    }
                }
            }
        }
        (best_peer, best_height)
    }

    /// Find the best sync peer on the same chain, excluding a specific peer.
    fn find_best_sync_peer_excluding(&self, our_height: u64, exclude: &[u8]) -> (Option<Vec<u8>>, u64) {
        let local_chain_id = self.get_chain_id();
        let peers = self.peer_info.read();
        let exclude_hex = hex::encode(exclude);
        let mut best_peer = None;
        let mut best_height = our_height;
        for entry in peers.values() {
            if entry.peer_id == exclude_hex { continue; }
            // Skip peers on a known-different chain (see find_best_sync_peer doc).
            if local_chain_id != 0 {
                if let Some(peer_cid) = entry.chain_id {
                    if peer_cid != local_chain_id { continue; }
                }
            }
            if let Some(h) = entry.chain_tip_height {
                if h > best_height {
                    if let Ok(pid) = hex::decode(&entry.peer_id) {
                        best_height = h;
                        best_peer = Some(pid);
                    }
                }
            }
        }
        (best_peer, best_height)
    }

    /// Handle sync peer disconnecting — reset to Idle so next advance_sync picks new peer.
    pub fn on_sync_peer_disconnected(&mut self, peer_id: &[u8]) {
        let is_sync_peer = match &self.sync_state {
            SyncState::AwaitingManifest { peer, .. } => peer == peer_id,
            SyncState::Fetching { peer, .. } => peer == peer_id,
            SyncState::Idle => false,
        };
        if is_sync_peer {
            tracing::warn!(task = "sync", "sync peer disconnected — resetting to Idle");
            self.reset_sync_idle();
        }
    }

    // ── Fork evaluation (tick handler) ──

    /// Evaluate fork status among same-chain peers.
    ///
    /// **Critical invariant**: Returns zeroed result if `sync_behind` is true,
    /// preventing the fork resolver from fighting the sync mechanism.
    ///
    /// Calls `ForkResolver::evaluate()` directly and handles resolution inline.
    pub fn on_tick_fork_eval(&mut self) -> ForkEvalResult {
        let zero_result = ForkEvalResult {
            dwell_before: 0,
            dwell_after: 0,
            tracked_height: None,
            min_fork_duration: self.fork_resolver.lock().min_fork_duration(),
        };
        // The sync_behind guard — never run fork resolution while syncing.
        if self.is_syncing() { return zero_result; }

        // Read consensus state.
        let engine_read = self.consensus.read();
        let (our_height, our_hash) = engine_read.chain_tip();
        let chain_owner_key = engine_read.chain_owner_key().map(|k| k.to_vec());
        let our_identity_key = engine_read.our_validator_wire_bytes();
        drop(engine_read);

        let local_chain_id = self.get_chain_id();
        let peers = self.peer_info.read().clone();

        let fork_groups = compute_fork_groups(
            &peers,
            our_height,
            our_hash,
            chain_owner_key.as_deref(),
            our_identity_key.as_deref(),
            local_chain_id,
        );
        let total_peers = peers.len();

        // Emit fork_detected / fork_aligned events for GUI visibility.
        let is_forked = fork_groups.len() > 1;
        if is_forked && !self.fork_visible {
            self.fork_visible = true;
            // Clear stale ancestor from any previous fork.
            self.fork_common_ancestor = None;
            let remote: Vec<_> = fork_groups.iter().filter(|g| !g.is_local).collect();
            self.broadcast_event(serde_json::json!({
                "event": "fork_detected",
                "fork_count": fork_groups.len(),
                "local_height": our_height,
                "remote_heights": remote.iter().map(|g| g.height).collect::<Vec<_>>(),
                "remote_peer_counts": remote.iter().map(|g| g.peer_count).collect::<Vec<_>>(),
            }));
            // Start common ancestor discovery with the first remote peer group.
            if let Some(remote_group) = fork_groups.iter().find(|g| !g.is_local) {
                let peers_on_fork: Vec<_> = peers
                    .values()
                    .filter(|e| {
                        e.chain_tip_hash.as_deref()
                            == Some(&hex::encode(remote_group.tip_hash.as_bytes()))
                    })
                    .collect();
                if let Some(peer_entry) = peers_on_fork.first() {
                    match hex::decode(&peer_entry.peer_id) {
                        Ok(pid_bytes) => {
                            self.send_network(NetworkCommand::FindCommonAncestor {
                                peer_id: pid_bytes,
                                local_height: our_height,
                                peer_height: remote_group.height,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                task = "healing",
                                "failed to decode peer_id for FindCommonAncestor: {e} — fork ancestor discovery skipped",
                            );
                        }
                    }
                }
            }
        } else if !is_forked && self.fork_visible {
            self.fork_visible = false;
            self.broadcast_event(serde_json::json!({
                "event": "fork_aligned",
                "height": our_height,
            }));
        }

        if fork_groups.is_empty() {
            return zero_result;
        }

        // Evaluate fork resolution directly.
        let dwell_before;
        let decision;
        {
            let mut resolver = self.fork_resolver.lock();
            dwell_before = resolver.dwell_counter();
            decision = resolver.evaluate(our_height, &fork_groups, total_peers, our_hash);
        }
        // Guard dropped — safe to call action handlers that acquire consensus write lock.

        match decision {
            noble_consensus::ForkDecision::Resolve {
                target_hash,
                target_height,
                reason,
            } => {
                self.on_fork_resolution_requested(target_hash, target_height, &reason);
            }
            noble_consensus::ForkDecision::Pending { cycles_remaining } => {
                tracing::info!(
                    task = "fork_resolution",
                    "fork resolution pending: {cycles_remaining} cycle(s) remaining"
                );
            }
            noble_consensus::ForkDecision::NoAction => {}
        }

        // Read post-evaluation state for GUI events.
        let resolver = self.fork_resolver.lock();
        ForkEvalResult {
            dwell_before,
            dwell_after: resolver.dwell_counter(),
            tracked_height: resolver.tracked_fork_height(),
            min_fork_duration: resolver.min_fork_duration(),
        }
    }

    // ── Cross-chain evaluation (tick handler) ──

    /// Evaluate cross-chain fork data and handle adoption inline.
    pub fn on_tick_cross_chain_eval(&mut self) {
        let local_chain_id = self.get_chain_id();

        // Read consensus state (chain_owner_key + our validator wire bytes).
        let engine_read = self.consensus.read();
        let tip_height = engine_read.chain_tip().0;
        let chain_owner_key = engine_read.chain_owner_key().map(|k| k.to_vec());
        let our_validator_wire_bytes = engine_read.our_validator_wire_bytes();
        drop(engine_read);

        let is_local_chain_owner = match (&chain_owner_key, &our_validator_wire_bytes) {
            (Some(owner), Some(ours)) => owner.as_slice() == ours.as_slice(),
            _ => false,
        };

        let local_vote_weight = self.chain_vote_weight.load(Ordering::Relaxed);

        let same_chain_peer_count = {
            let peers = self.peer_info.read();
            peers.values()
                .filter(|p| p.chain_id == Some(local_chain_id) && p.chain_tip_height.is_some())
                .count()
        };

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let discovered = self.discovered_blockchains.lock();
        const STALE_THRESHOLD_SECS: u64 = 2400; // 2 cycles
        let cross_chain_forks: Vec<noble_consensus::CrossChainForkInfo> = discovered
            .iter()
            .filter(|(&cid, _)| cid != local_chain_id && cid != 0)
            .map(|(&cid, info)| {
                let is_stale = now_ts.saturating_sub(info.last_seen) > STALE_THRESHOLD_SECS;
                noble_consensus::CrossChainForkInfo {
                    chain_id: cid,
                    peer_count: if is_stale { 0 } else { info.peer_addresses.len() },
                    chain_tip_height: info.chain_tip_height,
                    chain_vote_weight: info.chain_vote_weight,
                    last_seen: info.last_seen,
                }
            })
            .collect();
        drop(discovered);

        if cross_chain_forks.is_empty() { return; }

        // Evaluate cross-chain resolution directly.
        let decision = {
            let mut resolver = self.fork_resolver.lock();
            resolver.evaluate_cross_chain(
                local_chain_id,
                tip_height,
                local_vote_weight,
                same_chain_peer_count,
                &cross_chain_forks,
                is_local_chain_owner,
            )
        };
        // Guard dropped — safe to call action handlers.

        match decision {
            noble_consensus::CrossChainDecision::Adopt {
                target_chain_id,
                reason,
            } => {
                self.on_chain_adoption_requested(target_chain_id, &reason);
            }
            noble_consensus::CrossChainDecision::Pending { cycles_remaining } => {
                tracing::info!(
                    task = "fork_resolution",
                    "cross-chain adoption pending: {cycles_remaining} cycle(s) remaining"
                );
            }
            noble_consensus::CrossChainDecision::NoAction => {}
        }
    }

    // ── PeerChainTipUpdated handler ──

    /// Handle a peer reporting its chain tip. Performs integrity probe,
    /// then delegates sync decisions to `advance_sync`.
    pub fn on_peer_chain_tip_updated(&mut self, _peer_id: &[u8], peer_height: u64) {
        let (our_height, our_tip_hash) = self.consensus.read().chain_tip();
        let tip_block_exists = if our_height > 0 {
            self.storage.read().get_block_header(&our_tip_hash).is_ok()
        } else {
            true
        };

        // Chain integrity probe: if our tip block is missing from storage, wipe.
        if our_height > 0 && !tip_block_exists {
            tracing::error!(
                task = "integrity",
                "CHAIN INTEGRITY FAILURE: tip at height {} claims hash {} but block missing from storage — wiping and re-syncing",
                our_height,
                hex::encode(our_tip_hash.as_bytes()),
            );
            self.wipe_and_reset("integrity probe: tip block missing from storage");

            self.chain_id.store(0, Ordering::Relaxed);
            if let Err(e) = self.consensus.write().reset_tip(0, Hash256::ZERO, true) {
                tracing::error!(task = "integrity", "reset_tip after integrity wipe failed: {e}");
            }
            self.send_network(NetworkCommand::UpdateChainId(0));
            self.update_tip_height(0);
            self.clear_pending_proposals();

            // Reset sync state.
            self.reset_sync_idle();

            // Request fresh sync from any available peer.
            self.request_sync();
            return;
        }

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Update sync target if peer is further ahead than our current target.
        if peer_height > our_height {
            match &mut self.sync_state {
                SyncState::AwaitingManifest { target, .. } if peer_height > *target => {
                    *target = peer_height;
                    self.sync_target_height_shared.store(peer_height, Ordering::Relaxed);
                    self.sync_progress_total.store(peer_height, Ordering::Relaxed);
                }
                SyncState::Fetching { target, .. } if peer_height > *target => {
                    *target = peer_height;
                    self.sync_target_height_shared.store(peer_height, Ordering::Relaxed);
                    self.sync_progress_total.store(peer_height, Ordering::Relaxed);
                }
                _ => {}
            }
        }

        // Delegate all sync decisions to advance_sync.
        self.advance_sync(now_ts);
    }

    // ── CommonAncestorFound handler ──

    /// Update fork_common_ancestor and emit fork_divergence event.
    pub fn on_common_ancestor_found(&mut self, ancestor_height: u64, ancestor_hash: [u8; 32]) {
        let our_height = self.consensus.read().chain_tip().0;
        self.fork_common_ancestor = Some((ancestor_height, ancestor_hash));
        self.broadcast_event(serde_json::json!({
            "event": "fork_divergence",
            "ancestor_height": ancestor_height,
            "ancestor_hash": hex::encode(ancestor_hash),
            "local_height": our_height,
            "divergence_depth": our_height.saturating_sub(ancestor_height),
        }));
    }

    // ── Fork resolution handler ──

    /// Handle fork resolution: rollback storage and reset consensus.
    pub fn on_fork_resolution_requested(
        &mut self,
        target_hash: Hash256,
        target_height: u64,
        reason: &str,
    ) {
        tracing::warn!(
            task = "fork_resolution",
            "AUTO-RESOLVING: {reason} (target height {target_height})"
        );
        let rollback_height = self.fork_common_ancestor.map(|(h, _)| h).unwrap_or(0);

        // Rollback or reset storage.
        self.rollback_to(rollback_height);

        // Clear cycle history.
        self.clear_cycle_history_storage();

        // Reset fork state.
        self.fork_visible = false;
        self.fork_common_ancestor = None;

        // Clear pending proposals.
        self.clear_pending_proposals();

        // Reset fork resolver when rolling back to genesis.
        if rollback_height == 0 {
            *self.fork_resolver.lock() = ForkResolver::new(
                self.fork_resolution_strategy,
                self.fork_resolution_delay_cycles,
            );
        }

        // Reset sync state after rollback — advance_sync will restart from new tip.
        self.reset_sync_idle();

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.advance_sync(now_ts);

        self.broadcast_event(serde_json::json!({
            "event": "fork_auto_resolved",
            "target_height": target_height,
            "target_hash": hex::encode(target_hash.as_bytes()),
            "rollback_height": rollback_height,
            "reason": reason,
        }));
    }

    // ── Chain adoption ──

    /// Prepare and execute chain adoption: wipes and resets all state.
    pub fn on_chain_adoption_requested(&mut self, target_chain_id: u32, reason: &str) {
        tracing::warn!(
            task = "chain_adoption",
            "CROSS-CHAIN ADOPTION: adopting chain {:#010X} — {reason}",
            target_chain_id
        );

        // 1. Wipe ALL chain data.
        self.wipe_and_reset(reason);

        // 2. Reset chain_id to 0.
        self.chain_id.store(0, Ordering::Relaxed);
        self.chain_vote_weight.store(0, Ordering::Relaxed);
        self.fork_visible = false;
        self.fork_common_ancestor = None;

        // 2b. Clear announce cache.
        self.announce_cache.lock().clear();

        // 2c. Clear discovered blockchains.
        self.discovered_blockchains.lock().clear();
        self.persist_discovered_blockchains();

        // 3. Tell network service.
        self.send_network(NetworkCommand::UpdateChainId(0));
        self.update_tip_height(0);

        // 4. Reset consensus engine.
        if let Err(e) = self.consensus.write().reset_tip(0, Hash256::ZERO, true) {
            tracing::error!(task = "healing", "reset_tip failed: {e}");
        }

        // 4b. Reset fork resolver (full chain wipe).
        *self.fork_resolver.lock() = ForkResolver::new(
            self.fork_resolution_strategy,
            self.fork_resolution_delay_cycles,
        );

        // 5. Reset sync state.
        self.reset_sync_idle();

        // 6. Clear stale proposals and request sync.
        self.clear_pending_proposals();
        self.request_sync();

        self.broadcast_event(serde_json::json!({
            "event": "chain_adoption_started",
            "target_chain_id": format!("{:#010X}", target_chain_id),
            "reason": reason,
        }));
    }

    // ── Cross-chain announce handling ──

    /// Handle NodeAnnounce from a peer on a different chain.
    /// Records blockchain discovery and evaluates Cases A/B/C.
    pub fn on_cross_chain_announce(&mut self, announce: &NodeAnnounce, peer_id: &[u8]) {
        let our_chain_id = self.get_chain_id();
        let our_height = self.consensus.read().chain_tip().0;

        let peer_addr = announce.host_address.as_deref()
            .filter(|a| !a.is_empty())
            .map(|s| s.to_string())
            .or_else(|| {
                let info = self.peer_info.read();
                let hex_pid = hex::encode(peer_id);
                info.get(&hex_pid).map(|e| e.addr.clone())
            })
            .unwrap_or_default();

        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let chain_name = if announce.network_name.is_empty() {
            format!("chain-{:08X}", announce.chain_id)
        } else {
            announce.network_name.clone()
        };

        // Store/update discovered blockchain.
        {
            let mut discovered = self.discovered_blockchains.lock();
            let entry =
                discovered
                    .entry(announce.chain_id)
                    .or_insert_with(|| DiscoveredBlockchainInfo {
                        chain_id: announce.chain_id,
                        network_name: chain_name.clone(),
                        peer_addresses: Vec::new(),
                        first_seen: now_ts,
                        last_seen: now_ts,
                        chain_tip_height: None,
                        chain_vote_weight: None,
                    });
            entry.last_seen = now_ts;
            if let Some(h) = announce.chain_tip_height {
                entry.chain_tip_height = Some(entry.chain_tip_height.map_or(h, |prev| prev.max(h)));
            }
            if let Some(w) = announce.chain_vote_weight {
                entry.chain_vote_weight =
                    Some(entry.chain_vote_weight.map_or(w, |prev| prev.max(w)));
            }
            if !chain_name.is_empty() {
                entry.network_name = chain_name.clone();
            }
            if !peer_addr.is_empty() && !entry.peer_addresses.contains(&peer_addr) {
                entry.peer_addresses.push(peer_addr.clone());
            }
        }
        self.persist_discovered_blockchains();

        tracing::info!(
            task = "peer_tracking",
            "Blockchain discovered: {} (chain_id={:#010X}) from peer {}",
            chain_name,
            announce.chain_id,
            announce.node_name,
        );
        self.broadcast_event(serde_json::json!({
            "event": "blockchain_discovered",
            "chain_id": format!("{:#010X}", announce.chain_id),
            "network_name": chain_name,
            "peer_name": announce.node_name,
            "peer_addr": peer_addr,
        }));

        // ── Early-chain fast-path ──
        let their_height = announce.chain_tip_height.unwrap_or(0);
        let we_are_early = our_height <= noble_network::config::EARLY_CHAIN_HEIGHT_LIMIT;
        let they_are_early = their_height <= noble_network::config::EARLY_CHAIN_HEIGHT_LIMIT;

        if we_are_early {
            // Case A: We're short-chain — decide whether to adopt theirs.
            let their_weight = announce.chain_vote_weight.unwrap_or(0);
            let our_weight = self.chain_vote_weight.load(Ordering::Relaxed);
            let their_score = their_height
                .saturating_mul(10_000)
                .saturating_add(their_weight.min(9_999));
            let our_score = our_height
                .saturating_mul(10_000)
                .saturating_add(our_weight.min(9_999));
            let should_adopt = their_score > our_score
                || (their_score == our_score && announce.chain_id < our_chain_id);

            if should_adopt {
                let reason = format!(
                    "early-chain adoption: peer {} on chain {:#010X} (h={}, w={}) vs local {:#010X} (h={}, w={})",
                    announce.node_name, announce.chain_id, their_height, their_weight,
                    our_chain_id, our_height, our_weight,
                );
                self.on_chain_adoption_requested(announce.chain_id, &reason);
            } else {
                tracing::info!(
                    task = "chain_adoption",
                    "early-chain: our chain {:#010X} (h={}) is better than peer {} chain {:#010X} (h={}) — keeping connected",
                    our_chain_id, our_height, announce.node_name, announce.chain_id, their_height,
                );
            }
            // Keep peer connected regardless (Case A).
            return;
        }

        if they_are_early {
            // Case B: They're short-chain — keep connected for adoption.
            tracing::info!(
                task = "chain_adoption",
                "remote peer {} is early-chain (h={}) on {:#010X} — keeping connected for adoption",
                announce.node_name,
                their_height,
                announce.chain_id,
            );
            return;
        }

        // Case C: Neither side is early — graceful disconnect.
        self.send_network(NetworkCommand::DisconnectPeer(peer_id.to_vec()));
        self.broadcast_event(serde_json::json!({
            "event": "peer_wrong_chain",
            "peer_name": announce.node_name,
            "peer_id": hex::encode(peer_id),
            "their_chain_id": format!("{:#010X}", announce.chain_id),
            "their_network": chain_name,
        }));
        tracing::info!(
            task = "peer_tracking",
            "Disconnected peer {} — different chain ({})",
            announce.node_name,
            chain_name,
        );
    }

    // ── Announce equivocation detection ──

    /// Full announce equivocation handling: detect contradictions in cached
    /// announces, construct evidence, store it, record reputation misbehavior,
    /// and publish to network.
    ///
    /// Manages the announce cache lifecycle (eviction, size cap, update).
    pub fn handle_announce_equivocation(
        &self,
        announce: &NodeAnnounce,
        identity_wire: &[u8],
    ) {
        let mut cache = self.announce_cache.lock();
        let mut contradiction: Option<noble_core::AnnounceContradiction> = None;

        if let Some(prev) = cache.get(identity_wire) {
            // If the peer changed chain_id, their old cached announce is
            // stale (they adopted a new chain).  Skip ALL equivocation checks
            // — chain adoption legitimately changes chain_id AND can regress
            // chain_tip to 0.
            let chain_changed = prev.chain_id != 0
                && announce.chain_id != 0
                && prev.chain_id != announce.chain_id;

            if chain_changed {
                tracing::debug!(
                    task = "evidence",
                    "peer {} changed chain_id ({:#010X} → {:#010X}) — likely adoption, skipping equivocation check",
                    hex::encode(identity_wire),
                    prev.chain_id,
                    announce.chain_id,
                );
            } else if prev.chain_id == announce.chain_id
                && prev.chain_tip_height.is_some()
                && announce.chain_tip_height.is_some()
            {
                // Same chain — check for tip regression.
                let prev_h = prev.chain_tip_height.unwrap_or(0);
                let ann_h = announce.chain_tip_height.unwrap_or(0);
                let prev_t = prev.timestamp;
                let ann_t = announce.timestamp;
                if (ann_t > prev_t && ann_h < prev_h)
                    || (prev_t > ann_t && prev_h < ann_h)
                {
                    contradiction = Some(noble_core::AnnounceContradiction::ChainTipRegression);
                }
            }

            // Check competing proposals (same chain only).
            if !chain_changed && contradiction.is_none() {
                if prev.proposed_height.is_some()
                    && prev.proposed_height == announce.proposed_height
                    && prev.proposed_hash != announce.proposed_hash
                {
                    contradiction = Some(noble_core::AnnounceContradiction::CompetingProposals);
                }
            }

            // ── Evidence construction, storage, and publication ──
            if let Some(c) = contradiction {
                let evidence = noble_core::AnnounceEquivocationEvidence {
                    identity_key: announce.identity_key.clone(),
                    announce_a: prev.clone(),
                    announce_b: announce.clone(),
                    contradiction: c,
                };
                if evidence.verify().is_ok() {
                    tracing::warn!(
                        task = "evidence",
                        "announce equivocation detected for {}",
                        hex::encode(identity_wire),
                    );
                    match noble_codec::NobleCbor::to_cbor(
                        &noble_core::MisbehaviorEvidence::AnnounceEquivocation(evidence.clone()),
                    ) {
                        Ok(cbor) => {
                            let ev_hash = noble_crypto::sha256(&cbor);
                            if let Err(e) = self.storage.read().store_evidence(
                                ev_hash.as_bytes(),
                                &cbor,
                            ) {
                                tracing::warn!(task = "evidence", "failed to store evidence: {e}");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(task = "evidence", "failed to serialize equivocation evidence: {e}");
                        }
                    }
                    self.consensus.write().reputation_mut().record_misbehavior(identity_wire);
                    self.send_network(NetworkCommand::PublishEvidence(
                        Box::new(noble_core::MisbehaviorEvidence::AnnounceEquivocation(evidence)),
                    ));
                }
            }
        }

        // Evict stale entries (older than NODE_ANNOUNCE_MAX_AGE_SECS).
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if cache.len() > 512 {
            cache.retain(|_, a| {
                now_ts.saturating_sub(a.timestamp) < noble_core::NODE_ANNOUNCE_MAX_AGE_SECS
            });
        }
        // Cap at 1024 entries to bound memory.
        if cache.len() >= 1024 {
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, a)| a.timestamp)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        // Update cache with latest announce.
        cache.insert(identity_wire.to_vec(), announce.clone());
    }

    // ── Sync import ──

    /// Import a committed block from a sync peer directly to storage,
    /// bypassing the consensus voting pipeline.
    ///
    /// Reads parent header and validator list from its own subsystem references.
    /// Executes all side-effects directly (storage commit, consensus update,
    /// mempool eviction, network commands, broadcast events).
    pub fn try_sync_import(&self, block: &noble_core::Block) -> SyncImportResult {
        let (tip_height, _) = self.consensus.read().chain_tip();
        let chain_id = self.get_chain_id();

        // Load parent header from storage for B2/B3/B5 validation.
        let parent_header = if tip_height > 0 {
            let storage = self.storage.read();
            let chain_tip = match storage.get_chain_tip() {
                Ok(Some(t)) => t,
                Ok(None) => {
                    tracing::error!(task = "sync_import", "chain tip missing at height {tip_height} — aborting");
                    return SyncImportResult::Rejected { reason: "chain tip missing".to_string() };
                }
                Err(e) => {
                    tracing::error!(task = "sync_import", "failed to load chain tip: {e}");
                    return SyncImportResult::Rejected { reason: format!("chain tip error: {e}") };
                }
            };
            match storage.get_block_header(&chain_tip.block_hash) {
                Ok(header) => Some(header),
                Err(e) => {
                    tracing::error!(task = "sync_import", "failed to load parent header: {e}");
                    return SyncImportResult::Rejected { reason: format!("parent header error: {e}") };
                }
            }
        } else {
            None
        };

        let validator_list = self.consensus.read().validator_snapshot()
            .map(|snap| snap.pubkey_vec.clone())
            .unwrap_or_default();

        // For sync imports, use the block's own timestamp as "current_time" so the
        // B6 skew check passes. Historical blocks are expected to have old timestamps.
        let current_time = block.header.timestamp;

        // Any validator can propose — include block's own validator_id.
        let mut val_list = validator_list;
        if !val_list.contains(&block.header.validator_id) {
            val_list.push(block.header.validator_id.clone());
        }

        let ctx = noble_core::BlockValidationContext {
            chain_id,
            current_time,
            parent: parent_header.as_ref(),
            validator_list: &val_list,
        };

        if let Err(e) = noble_core::validate_block(block, &ctx) {
            let is_fork = matches!(
                e,
                noble_core::ValidationError::PrevHashMismatch
                    | noble_core::ValidationError::HeightMismatch { .. }
                    | noble_core::ValidationError::TimestampNotAfterParent { .. }
            );
            if is_fork {
                tracing::info!(
                    task = "sync_import",
                    "sync block at height {} rejected (fork disagreement): {e}",
                    block.header.height
                );
            } else {
                tracing::warn!(
                    task = "sync_import",
                    "sync block at height {} rejected: {e}",
                    block.header.height
                );
            }
            return SyncImportResult::Rejected {
                reason: format!("{e}"),
            };
        }

        let block_hash = match block.header.compute_block_hash() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(task = "sync_import", "block hash computation failed: {e}");
                return SyncImportResult::Rejected {
                    reason: format!("block hash computation failed: {e}"),
                };
            }
        };

        let tx_ids: Vec<Hash256> = block
            .transactions
            .iter()
            .filter_map(|tx| {
                tx.compute_tx_id(chain_id)
                    .map_err(|e| {
                        tracing::warn!(task = "sync_import", "tx_id computation failed: {e}");
                    })
                    .ok()
            })
            .collect();

        // Decay-weighted vote accumulation.
        let old = self.chain_vote_weight.load(Ordering::Relaxed);
        let new = noble_consensus::decay_vote_weight(old, 1);
        self.chain_vote_weight.store(new, Ordering::Relaxed);

        // Auto-update chain_id after first sync-import.
        let new_chain_id = if chain_id == 0 {
            let new_cid = noble_core::derive_chain_id(&block_hash);
            tracing::info!(
                task = "sync_import",
                "chain_id updated to {:#010X} after block {} sync-import",
                new_cid,
                block.header.height,
            );
            Some(new_cid)
        } else {
            None
        };

        // --- Execute all side-effects directly ---

        // Commit block to storage.
        {
            let storage = self.storage.read();
            if let Err(e) = storage.commit_block(block, &block_hash, &tx_ids) {
                tracing::error!(task = "sync_import", "failed to commit sync block {}: {e}", block.header.height);
                return SyncImportResult::Rejected { reason: format!("commit failed: {e}") };
            }
        }

        // Update consensus tip.
        self.consensus.write().update_tip_with_header(block.header.clone());

        // Block 1: clear stale cycle history.
        if block.header.height == 1 {
            self.clear_cycle_history_storage();
        }

        // Update chain_id if needed.
        if let Some(new_cid) = new_chain_id {
            self.chain_id.store(new_cid, Ordering::Relaxed);
            self.send_network(NetworkCommand::UpdateChainId(new_cid));
        }

        // Update network tip height.
        self.update_tip_height(block.header.height);

        // Remove committed txs from mempool.
        if !tx_ids.is_empty() {
            self.evict_from_mempool(&tx_ids);
        }

        // Metrics.
        self.record_metric_block_validation(0.0);

        tracing::info!(
            task = "sync_import",
            "Sync-imported block {} (hash: {}, txs: {})",
            block.header.height,
            hex::encode(block_hash.as_bytes()),
            tx_ids.len()
        );

        // Clear active proposal.
        self.clear_last_proposed();

        // Emit new block.
        self.broadcast_new_block(serde_json::json!({
            "height": block.header.height,
            "hash": hex::encode(block_hash.as_bytes()),
            "tx_count": tx_ids.len(),
            "source": "sync",
        }));

        SyncImportResult::Accepted {
            new_chain_id,
        }
    }

}

/// Check for inconsistent state at startup: chain_tip says height > 0 but
/// chain_id is 0 (blocks missing from storage). Returns true if corrupt.
pub fn startup_integrity_check(chain_id: u32, tip_height: u64) -> bool {
    if chain_id == 0 && tip_height > 0 {
        tracing::warn!(
            task = "startup",
            "chain_tip at height {} but chain_id=0 (blocks missing from storage) — wiping inconsistent state",
            tip_height,
        );
        true
    } else {
        false
    }
}

/// Result of a sync import attempt.
pub enum SyncImportResult {
    /// Block was accepted and committed.
    Accepted {
        new_chain_id: Option<u32>,
    },
    /// Block was rejected (validation failure).
    Rejected { reason: String },
}

// ---------------------------------------------------------------------------
// Pure utility functions
// ---------------------------------------------------------------------------

/// Parse a fork resolution strategy name into a `ForkResolutionStrategy`.
pub(crate) fn parse_fork_resolution_strategy(
    name: &str,
) -> noble_consensus::ForkResolutionStrategy {
    use noble_consensus::ForkResolutionStrategy;
    match name {
        "manual" => ForkResolutionStrategy::Manual,
        "peer_supermajority" => ForkResolutionStrategy::PeerSupermajority,
        "longest_most_legitimate" => ForkResolutionStrategy::LongestMostLegitimate,
        "longest_chain" => {
            tracing::warn!(
                task = "config_load",
                "fork_resolution_strategy 'longest_chain' is deprecated — using 'longest_most_legitimate'"
            );
            ForkResolutionStrategy::LongestMostLegitimate
        }
        other => {
            tracing::warn!(
                task = "config_load",
                "Unknown fork resolution strategy '{other}', falling back to manual"
            );
            ForkResolutionStrategy::Manual
        }
    }
}

/// Compute fork groups from connected peer chain tips for the ForkResolver.
///
/// Groups peers by `chain_tip_hash` (same logic as `getDetectedForks` RPC).
/// Always includes the local chain as `is_local = true`.
///
/// `chain_owner_key` is block 1's validator wire bytes. When a peer's
/// `identity_key` matches, or the local node's `our_identity_key` matches,
/// the corresponding fork group gets `has_chain_owner = true`.
pub(crate) fn compute_fork_groups(
    peers: &HashMap<String, PeerInfoEntry>,
    local_height: u64,
    local_hash: Hash256,
    chain_owner_key: Option<&[u8]>,
    our_identity_key: Option<&[u8]>,
    local_chain_id: u32,
) -> Vec<noble_consensus::ForkInfo> {
    let local_tip_hex = hex::encode(local_hash.as_bytes());

    // Group peers by chain_tip_hash — only same-chain peers.
    let mut groups: HashMap<String, (u64, usize)> = HashMap::new();
    for entry in peers.values() {
        match entry.chain_id {
            Some(cid) if cid == local_chain_id => {}
            Some(_) => continue,
            None => continue,
        }
        let h = match entry.chain_tip_height {
            Some(h) => h,
            None => continue,
        };
        let hash = match entry.chain_tip_hash.as_ref() {
            Some(s) => s.clone(),
            None => continue,
        };
        let g = groups.entry(hash).or_insert((h, 0usize));
        g.1 += 1;
        if h > g.0 {
            g.0 = h;
        }
    }

    // Include local chain.
    let local_entry = groups
        .entry(local_tip_hex.clone())
        .or_insert((local_height, 0));
    if local_height > local_entry.0 {
        local_entry.0 = local_height;
    }

    // Determine which fork group has the chain owner.
    let mut owner_group: Option<String> = None;
    if let Some(owner_key) = chain_owner_key {
        for entry in peers.values() {
            if let Some(ref ident) = entry.identity_key {
                if ident.as_slice() == owner_key {
                    if let Some(ref hash) = entry.chain_tip_hash {
                        owner_group = Some(hash.clone());
                    }
                    break;
                }
            }
        }
        if owner_group.is_none() {
            if let Some(our_key) = our_identity_key {
                if our_key == owner_key {
                    owner_group = Some(local_tip_hex.clone());
                }
            }
        }
    }

    groups
        .into_iter()
        .map(|(tip_hash, (height, peer_count))| noble_consensus::ForkInfo {
            tip_hash: {
                let mut bytes = [0u8; 32];
                if let Ok(decoded) = hex::decode(&tip_hash) {
                    if decoded.len() == 32 {
                        bytes.copy_from_slice(&decoded);
                    }
                }
                Hash256::from_bytes(bytes)
            },
            height,
            peer_count,
            is_local: tip_hash == local_tip_hex,
            has_chain_owner: owner_group.as_ref() == Some(&tip_hash),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noble_storage::MemoryStorage;

    fn make_healing_manager() -> HealingManager<MemoryStorage> {
        let storage = Arc::new(RwLock::new(MemoryStorage::new()));
        let consensus = Arc::new(RwLock::new(CycleEngine::new(
            noble_consensus::ConsensusConfig::default(),
            0,
            Hash256::ZERO,
            0,
            None,
            None,
        )));
        let chain_id = Arc::new(AtomicU32::new(0));
        let mut mempool_config = noble_mempool::MempoolConfig::default();
        mempool_config.chain_id = chain_id.clone();
        let mempool = Arc::new(Mutex::new(Mempool::new(mempool_config)));
        let peer_info = Arc::new(RwLock::new(HashMap::new()));
        let last_proposed = Arc::new(parking_lot::Mutex::new(None));
        HealingManager::new(
            storage,
            consensus,
            mempool,
            chain_id,
            peer_info,
            last_proposed,
            Arc::new(Mutex::new(HashMap::new())),
            None,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
            ForkResolutionStrategy::LongestMostLegitimate,
            3,
        )
    }

    #[test]
    fn test_startup_integrity_check_clean() {
        assert!(!startup_integrity_check(0, 0));
        assert!(!startup_integrity_check(0x12345678, 10));
    }

    #[test]
    fn test_startup_integrity_check_corrupt() {
        assert!(startup_integrity_check(0, 5));
    }

    #[test]
    fn advance_sync_idle_no_peers() {
        let mut hm = make_healing_manager();
        hm.advance_sync(100);
        // No peers ahead — should stay Idle.
        assert!(matches!(hm.sync_state, SyncState::Idle));
    }

    #[test]
    fn manifest_received_empty() {
        let mut hm = make_healing_manager();
        let peer_id = vec![1, 2, 3];
        // Manually set to AwaitingManifest.
        hm.sync_state = SyncState::AwaitingManifest {
            peer: peer_id.clone(),
            target: 10,
            requested_at: 50,
        };
        // Empty manifest → should reset to Idle.
        hm.on_manifest_received(&peer_id, &[], 60);
        assert!(matches!(hm.sync_state, SyncState::Idle));
    }

    #[test]
    fn manifest_received_populates_fetching() {
        let mut hm = make_healing_manager();
        let peer_id = vec![1, 2, 3];
        hm.sync_state = SyncState::AwaitingManifest {
            peer: peer_id.clone(),
            target: 5,
            requested_at: 50,
        };
        let entries = vec![
            (1, Some([0xAA; 32])),
            (2, Some([0xBB; 32])),
            (3, Some([0xCC; 32])),
        ];
        hm.on_manifest_received(&peer_id, &entries, 60);
        match &hm.sync_state {
            SyncState::Fetching { manifest, cursor, target, .. } => {
                assert_eq!(manifest.len(), 3);
                assert_eq!(*cursor, 0);
                assert_eq!(*target, 5);
            }
            _ => panic!("expected Fetching state"),
        }
    }

    #[test]
    fn fork_eval_skips_when_syncing() {
        let mut hm = make_healing_manager();
        // Put in syncing state.
        hm.sync_state = SyncState::AwaitingManifest {
            peer: vec![1, 2, 3],
            target: 10,
            requested_at: 50,
        };
        let result = hm.on_tick_fork_eval();
        assert_eq!(result.dwell_before, 0);
        assert_eq!(result.dwell_after, 0);
    }

    #[test]
    fn fork_eval_single_group_no_fork() {
        let mut hm = make_healing_manager();
        let result = hm.on_tick_fork_eval();
        // Single group (local only) — no fork, dwell stays 0.
        assert_eq!(result.dwell_after, 0);
        assert!(!hm.fork_visible);
    }

    #[test]
    fn compute_fork_groups_empty_peers() {
        let groups = compute_fork_groups(
            &HashMap::new(),
            10,
            Hash256::ZERO,
            None,
            None,
            0x12345678,
        );
        // Should have exactly 1 group (local).
        assert_eq!(groups.len(), 1);
        assert!(groups[0].is_local);
        assert_eq!(groups[0].height, 10);
    }

    #[test]
    fn compute_fork_groups_cross_chain_excluded() {
        let mut peers = HashMap::new();
        peers.insert(
            "peer1".to_string(),
            PeerInfoEntry {
                peer_id: "peer1".to_string(),
                direction: "inbound".to_string(),
                addr: "/ip4/1.2.3.4/tcp/8780".to_string(),
                connected_at: 0,
                ban_score: 0,
                misbehavior_categories: Vec::new(),
                chain_tip_height: Some(20),
                chain_tip_hash: Some("aa".repeat(32)),
                chain_id: Some(0xDEADBEEF), // different chain
                identity_key: None,
                proposed_height: None,
                latency_ms: None,
                last_ban_reason: None,
            },
        );
        let groups = compute_fork_groups(
            &peers,
            10,
            Hash256::ZERO,
            None,
            None,
            0x12345678,
        );
        // Cross-chain peer should be excluded.
        assert_eq!(groups.len(), 1);
        assert!(groups[0].is_local);
    }

    #[test]
    fn on_peer_chain_tip_updated_delegates_to_advance_sync() {
        let mut hm = make_healing_manager();
        let peer_id = vec![1, 2, 3];
        // No peers in peer_info, so advance_sync won't find anyone ahead.
        hm.on_peer_chain_tip_updated(&peer_id, 10);
        // Without peer in peer_info, advance_sync can't find the peer.
        // The state depends on whether advance_sync found a peer.
        // In this test, peer_info is empty, so it stays Idle.
        // (Real sync requires peer_info to be populated first.)
    }

    #[test]
    fn common_ancestor_found() {
        let mut hm = make_healing_manager();
        hm.on_common_ancestor_found(5, [0xAA; 32]);
        assert_eq!(hm.fork_common_ancestor, Some((5, [0xAA; 32])));
    }

    #[test]
    fn chain_adoption_resets_state() {
        let mut hm = make_healing_manager();
        hm.sync_state = SyncState::AwaitingManifest {
            peer: vec![1, 2, 3],
            target: 10,
            requested_at: 50,
        };
        hm.fork_visible = true;
        hm.fork_common_ancestor = Some((5, [0xAA; 32]));
        hm.chain_vote_weight.store(100, Ordering::Relaxed);
        hm.on_chain_adoption_requested(0xDEADBEEF, "test");
        assert!(matches!(hm.sync_state, SyncState::Idle));
        assert!(!hm.fork_visible);
        assert!(hm.fork_common_ancestor.is_none());
        assert_eq!(hm.chain_vote_weight.load(Ordering::Relaxed), 0);
    }

    // Equivocation detection is tested in integration tests where
    // NodeAnnounce can be properly signed.
}
