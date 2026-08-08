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

use noble_api::lock_order::{TrackedMutex, TrackedRwLock};
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
#[derive(Clone, Copy)]
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
/// Manifest request timeout (seconds).  Relaxed from 30s to accommodate large chains.
const SYNC_MANIFEST_TIMEOUT_SECS: u64 = 60;
/// Maximum retry attempts for a single block before escalating.
/// Relaxed from 3 to 5 — transient network issues during long syncs need more headroom.
/// Post-sync verification is the safety net.
const SYNC_MAX_BLOCK_RETRIES: u8 = 5;
/// Minimum interval between advance_sync actions (seconds).
const SYNC_RETRY_SECS: u64 = 10;
/// Consecutive failed sync requests to the same peer (fast request-response
/// failures + 60s manifest timeouts) before its connection is force-dropped and
/// redialed. 2 keeps a wedged channel from lingering — with the ≤10s fast-fail
/// signal the rebuild happens in ~20s — while tolerating a single transient blip.
const SYNC_PEER_MAX_FAILURES: u32 = 2;

/// K3-04: max per-peer tip-failure records kept (bounded memory).
const TIP_QUARANTINE_CAP: usize = 256;
/// K3-04: base quarantine after repeated failed tip substantiation (secs).
const TIP_QUARANTINE_BASE_SECS: u64 = 60;
/// K3-04: quarantine ceiling (secs).
const TIP_QUARANTINE_MAX_SECS: u64 = 3600;

/// Per-peer record of failed attempts to substantiate a claimed chain tip
/// (K3-04). Survives disconnect; cleared on any successful import.
#[derive(Debug, Clone, Copy, Default)]
struct TipFailureRecord {
    failures: u32,
    /// Epoch secs until which this peer's ADVERTISED tips are ignored for
    /// sync selection and proposal suppression. 0 = not quarantined.
    until: u64,
}
/// Backstop: if we remain behind a known-ahead peer with NO tip progress for
/// this long, the per-peer recovery (Layers 1-4) has somehow failed. Fire a
/// CRITICAL alarm and force a full re-sync. This must never trigger if the
/// other layers work — it exists so a wedge can never persist *silently* (the
/// 26-day failure mode). Re-fires (and retries recovery) once per window while
/// stuck; cleared on any progress.
const SYNC_STALL_ALARM_SECS: u64 = 300;
/// Height gap (blocks) beyond which alignment REPORTS Syncing. Sync itself
/// engages at any gap ≥ 1 (`find_best_sync_peer` picks any peer ahead) — this
/// constant only governs the displayed state. 2 blocks ≈ 32 min at 960 s
/// cycles: enough to absorb the normal one-block tip race without hiding real
/// lag (the previous literal of 10 hid ~2.7 h of catch-up behind an "Aligned"
/// badge).
const ALIGNMENT_SYNC_GAP_BLOCKS: u64 = 2;

// ---------------------------------------------------------------------------
// Sync Import Identity
// ---------------------------------------------------------------------------

/// Which healing case triggered this sync import.
/// Determines per-case error handling and tolerance behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncImportKind {
    /// Same chain, peer is ahead — normal catch-up.
    CatchUp,
    /// Minority fork → majority fork (post-rollback to common ancestor).
    ForkResolution,
    /// Different chain entirely (post-wipe to genesis).
    CrossChainAdoption,
    /// Fresh node joining an existing chain.
    Bootstrap,
}

/// Result of post-sync range verification.
#[derive(Debug)]
pub enum SyncVerifyResult {
    /// Chain integrity and peer alignment verified.
    Ok,
    /// Storage corruption detected in synced range.
    IntegrityFailure {
        first_corrupt: u64,
        findings_count: usize,
    },
    /// Our tip doesn't match any connected peer.
    MisalignedWithPeers {
        our_height: u64,
        peer_count: usize,
    },
}

// ---------------------------------------------------------------------------
// Healing Clue System
// ---------------------------------------------------------------------------

/// What the healing system is currently doing.
/// This is the single source of truth for healing coordination.
/// All detection paths ingest clues; only `evaluate_and_execute()` transitions this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealingPhase {
    /// Nothing active — ready to accept healing actions.
    Idle,
    /// Manifest-based sync is fetching blocks from a peer.
    Syncing,
    /// Fork resolution is in progress (rollback + re-sync).
    Resolving,
    /// Cross-chain adoption is in progress (wipe + re-sync).
    Adopting,
}

/// A clue ingested from any detection source.
#[derive(Debug, Clone)]
pub enum HealingClue {
    /// Fork resolver determined we should switch to a dominant fork.
    ForkResolve {
        target_hash: Hash256,
        target_height: u64,
        reason: String,
    },
    /// Sync import rejected a block due to chain disagreement.
    SyncChainMismatch {
        rejected_height: u64,
        sync_target: u64,
        reason: String,
    },
    /// Consensus engine rejected a proposed block (different parent chain).
    ProposedBlockRejected {
        peer_id: Vec<u8>,
        block_height: u64,
        reason: String,
    },
    /// Cross-chain evaluation determined we should adopt a different chain.
    CrossChainAdopt {
        target_chain_id: u32,
        reason: String,
    },
    /// Sync conveyor is persistently stalled — block fetches keep failing.
    SyncStall {
        stalled_height: u64,
        target_height: u64,
        reason: String,
    },
}

/// Collects clues from all detection sources within a tick, then
/// dispatches a single coordinated healing action.
pub struct ClueCollector {
    clues: Vec<HealingClue>,
}

impl ClueCollector {
    pub fn new() -> Self {
        Self { clues: Vec::new() }
    }

    /// Ingest a clue. Duplicates and lower-priority clues are kept —
    /// `evaluate()` picks the best action from all accumulated evidence.
    pub fn ingest(&mut self, clue: HealingClue) {
        self.clues.push(clue);
    }

    /// True if any clues have been ingested since last drain.
    pub fn has_clues(&self) -> bool {
        !self.clues.is_empty()
    }

    /// Take all accumulated clues, leaving the collector empty.
    pub fn drain(&mut self) -> Vec<HealingClue> {
        std::mem::take(&mut self.clues)
    }
}

/// Action determined by `evaluate_and_execute` from accumulated clues.
#[derive(Debug)]
pub enum HealingAction {
    /// No action needed.
    None,
    /// Fork resolution: rollback to common ancestor and re-sync.
    Resolve {
        target_hash: Hash256,
        target_height: u64,
        reason: String,
    },
    /// Cross-chain adoption: wipe all data and sync from a different chain.
    Adopt {
        target_chain_id: u32,
        reason: String,
    },
}

/// Pick the highest-priority action from a set of clues.
/// Priority: Adopt > Resolve/SyncMismatch > SyncStall(bootstrap) > ProposedBlockRejected(bootstrap) > None.
fn pick_healing_action(clues: &[HealingClue], local_height: u64) -> HealingAction {
    // Priority 1: Cross-chain adoption (most drastic).
    for clue in clues {
        if let HealingClue::CrossChainAdopt { target_chain_id, reason } = clue {
            return HealingAction::Adopt {
                target_chain_id: *target_chain_id,
                reason: reason.clone(),
            };
        }
    }

    // Priority 2: Fork resolution (rollback + re-sync).
    for clue in clues {
        if let HealingClue::ForkResolve { target_hash, target_height, reason } = clue {
            return HealingAction::Resolve {
                target_hash: *target_hash,
                target_height: *target_height,
                reason: reason.clone(),
            };
        }
    }

    // Priority 3: Sync chain mismatch → escalate to fork resolution.
    for clue in clues {
        if let HealingClue::SyncChainMismatch { sync_target, reason, .. } = clue {
            return HealingAction::Resolve {
                target_hash: Hash256::ZERO,
                target_height: *sync_target,
                reason: reason.clone(),
            };
        }
    }

    // Priority 4: Sync stall — during bootstrap, force resolution to retry from scratch.
    // During steady state, the conveyor peer-switch handles it.
    for clue in clues {
        if let HealingClue::SyncStall { target_height, reason, .. } = clue {
            if local_height < 10 {
                return HealingAction::Resolve {
                    target_hash: Hash256::ZERO,
                    target_height: *target_height,
                    reason: reason.clone(),
                };
            }
        }
    }

    // Priority 5: Proposed block rejected — only resolve during bootstrap.
    for clue in clues {
        if let HealingClue::ProposedBlockRejected { block_height, reason, .. } = clue {
            if local_height < 10 {
                return HealingAction::Resolve {
                    target_hash: Hash256::ZERO,
                    target_height: *block_height,
                    reason: reason.clone(),
                };
            }
        }
    }

    HealingAction::None
}

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

// AlignmentState + AlignmentSnapshot live in noble-consensus::alignment
// (shared between noble-node and noble-api).
use noble_consensus::{AlignmentSnapshot, AlignmentState};

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

    // ── Healing coordination ──
    /// Unified state machine for all healing operations.
    healing_phase: HealingPhase,
    /// Accumulates clues from all detection sources within a tick.
    clue_collector: ClueCollector,
    /// Which healing case triggered the current sync (for per-case error handling).
    sync_import_kind: SyncImportKind,
    /// Height at which the current sync session started (for post-sync range verification).
    sync_start_height: u64,
    /// Consecutive post-sync verification failures (for ancestor depth escalation).
    sync_verify_retries: u8,
    /// Consecutive failed sync requests to the active sync peer — counts both
    /// fast request-response failures (`on_sync_request_failed`) and 60s manifest
    /// timeouts. Once it reaches [`SYNC_PEER_MAX_FAILURES`] the peer's connection
    /// is force-dropped (and then redialed) to rebuild a wedged channel rather
    /// than retrying the same dead one forever. Reset to 0 on any sync progress.
    sync_failure_streak: u32,
    /// K3-04: per-peer memory of failed tip substantiation, surviving
    /// disconnect/reconnect (the global streak resets on disconnect — a false-
    /// tip peer could previously reconnect and repeat forever). Keyed by hex
    /// peer_id; bounded at [`TIP_QUARANTINE_CAP`] (oldest-`until` evicted).
    /// `failures` drives exponential quarantine: 60s × 2^(n-1), cap 3600s.
    tip_quarantine: HashMap<String, TipFailureRecord>,
    /// Tip height observed when the current "behind a peer" episode began
    /// (stall watchdog, Layer 6). Reset on progress / catch-up.
    stall_watch_height: u64,
    /// Unix secs when the current stall episode began (0 = not watching).
    stall_watch_since: u64,

    // ── Cross-chain state ──
    /// Blockchains discovered via NodeAnnounce. Shared with ApiState.
    discovered_blockchains: Arc<Mutex<HashMap<u32, DiscoveredBlockchainInfo>>>,
    discovered_blockchains_path: Option<PathBuf>,

    // ── Equivocation detection ──
    announce_cache: parking_lot::Mutex<HashMap<Vec<u8>, NodeAnnounce>>,

    // ── Chain metrics ──
    chain_vote_weight: AtomicU64,

    // ── Subsystem references ──
    storage: Arc<TrackedRwLock<S>>,
    consensus: Arc<TrackedRwLock<CycleEngine>>,
    mempool: Arc<TrackedMutex<Mempool>>,
    chain_id: Arc<AtomicU32>,
    peer_info: Arc<TrackedRwLock<HashMap<String, PeerInfoEntry>>>,
    last_proposed: Arc<parking_lot::Mutex<Option<(u64, [u8; 32])>>>,

    // ── Fork resolver (owned by HealingManager, shared with ApiState) ──
    fork_resolver: Arc<parking_lot::Mutex<ForkResolver>>,
    fork_resolution_strategy: ForkResolutionStrategy,
    fork_resolution_delay_cycles: u32,

    // ── Alignment state (shared with ApiState — single source of truth) ──
    alignment: Arc<RwLock<AlignmentSnapshot>>,

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
        storage: Arc<TrackedRwLock<S>>,
        consensus: Arc<TrackedRwLock<CycleEngine>>,
        mempool: Arc<TrackedMutex<Mempool>>,
        chain_id: Arc<AtomicU32>,
        peer_info: Arc<TrackedRwLock<HashMap<String, PeerInfoEntry>>>,
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
            healing_phase: HealingPhase::Idle,
            clue_collector: ClueCollector::new(),
            sync_import_kind: SyncImportKind::CatchUp,
            sync_start_height: 0,
            sync_verify_retries: 0,
            sync_failure_streak: 0,
            tip_quarantine: HashMap::new(),
            stall_watch_height: 0,
            stall_watch_since: 0,
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
            alignment: Arc::new(RwLock::new(AlignmentSnapshot::default())),
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

    /// Lowest height an AUTOMATIC rollback may reach (H9).
    ///
    /// Finality is the guarantee that committed history stops moving; a
    /// rollback below it would rewrite blocks the node already declared
    /// immutable. Checkpoints are the same promise at a coarser granularity,
    /// so the floor is whichever is higher.
    ///
    /// Snapshot-and-drop: the fork-resolver mutex is taken and released inside
    /// this call, so callers never hold it across the rollback work.
    fn rollback_floor(&self) -> u64 {
        let finalized = self.fork_resolver.lock().finalized_height();
        // Checkpoints are generated locally every ~30 blocks and are always at
        // or below the finalized height in practice; max() keeps the floor
        // correct if that ever stops holding.
        finalized.max(self.latest_checkpoint_height())
    }

    /// Height of the highest ACTIVE local checkpoint, or 0 if none.
    ///
    /// Only activated checkpoints bind — a checkpoint still inside its
    /// activation delay is not yet a commitment, so treating it as a floor
    /// would block resolutions the protocol still permits.
    fn latest_checkpoint_height(&self) -> u64 {
        self.consensus
            .read()
            .checkpoint_manager()
            .highest_active_height()
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

    // ── Healing coordination ──

    /// Ingest a clue from any detection source. No action taken — clues
    /// accumulate until `evaluate_and_execute` runs at the end of the tick.
    pub fn ingest_clue(&mut self, clue: HealingClue) {
        let label = match &clue {
            HealingClue::ForkResolve { target_height, .. } =>
                format!("fork_resolve (target height {target_height})"),
            HealingClue::SyncChainMismatch { rejected_height, .. } =>
                format!("sync_chain_mismatch (rejected height {rejected_height})"),
            HealingClue::ProposedBlockRejected { block_height, .. } =>
                format!("proposed_block_rejected (height {block_height})"),
            HealingClue::CrossChainAdopt { target_chain_id, .. } =>
                format!("cross_chain_adopt (chain {:#010X})", target_chain_id),
            HealingClue::SyncStall { stalled_height, .. } =>
                format!("sync_stall (block {stalled_height})"),
        };
        self.broadcast_event(serde_json::json!({
            "event": "healing_clue",
            "clue": label,
            "phase": format!("{:?}", self.healing_phase),
        }));
        self.clue_collector.ingest(clue);
    }

    /// Current healing phase (for API/GUI visibility).
    pub fn current_healing_phase(&self) -> HealingPhase {
        self.healing_phase
    }

    /// Evaluate all accumulated clues and execute the highest-priority
    /// healing action. Called ONCE per tick, AFTER all detection has run.
    ///
    /// This is the SINGLE decision + execution point for all healing.
    pub fn evaluate_and_execute(&mut self) {
        // Don't drain if we can't act — leave clues for next tick.
        if matches!(self.healing_phase, HealingPhase::Resolving | HealingPhase::Adopting) {
            if self.clue_collector.has_clues() {
                tracing::debug!(
                    task = "healing",
                    "clues pending during active {:?} — deferred to next tick",
                    self.healing_phase,
                );
            }
            return;
        }

        let clues = self.clue_collector.drain();
        if clues.is_empty() { return; }

        let local_height = self.consensus.read().chain_tip().0;
        let action = pick_healing_action(&clues, local_height);

        match action {
            HealingAction::Adopt { target_chain_id, reason } => {
                self.broadcast_event(serde_json::json!({
                    "event": "healing_action",
                    "action": "adopt",
                    "target_chain_id": format!("{:#010X}", target_chain_id),
                    "reason": &reason,
                    "clue_count": clues.len(),
                }));
                self.healing_phase = HealingPhase::Adopting;
                self.execute_adoption(target_chain_id, &reason);
                self.healing_phase = HealingPhase::Syncing;
            }
            HealingAction::Resolve { target_hash, target_height, reason } => {
                self.broadcast_event(serde_json::json!({
                    "event": "healing_action",
                    "action": "resolve",
                    "target_height": target_height,
                    "reason": &reason,
                    "clue_count": clues.len(),
                }));
                self.healing_phase = HealingPhase::Resolving;
                self.execute_resolution(target_hash, target_height, &reason);
                self.healing_phase = HealingPhase::Syncing;
            }
            HealingAction::None => {}
        }
    }

    // ── Accessors ──

    pub fn sync_behind(&self) -> bool { !matches!(self.sync_state, SyncState::Idle) }
    pub fn sync_behind_shared(&self) -> &Arc<AtomicBool> { &self.sync_behind_shared }
    pub fn sync_target_height_shared(&self) -> &Arc<AtomicU64> { &self.sync_target_height_shared }
    pub fn sync_progress_current(&self) -> &Arc<AtomicU64> { &self.sync_progress_current }
    pub fn sync_progress_total(&self) -> &Arc<AtomicU64> { &self.sync_progress_total }
    pub fn alignment(&self) -> &Arc<RwLock<AlignmentSnapshot>> { &self.alignment }

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

    // ── Centralized alignment computation ──

    /// Compute the canonical alignment state. Called once per tick, AFTER
    /// `detect_forks()`. This is THE single source of truth — `getSyncStatus`
    /// reads from the shared snapshot, and the GUI renders it without any
    /// independent logic.
    pub fn compute_alignment(&mut self) {
        // 1. Read consensus state (lock 4 — dropped before storage).
        let (height, local_hash, has_proposals) = {
            let engine = self.consensus.read();
            let (h, hash) = engine.chain_tip();
            let proposals = !engine.candidate_tracker().is_empty();
            (h, hash, proposals)
        };

        // 2. Read peer info (lock 7 — dropped before storage).
        let local_chain_id = self.get_chain_id();
        let local_tip_hex = hex::encode(local_hash.as_bytes());
        let peers_snapshot: Vec<(Option<u64>, Option<String>)> = {
            let info = self.peer_info.read();
            info.values()
                .filter(|e| {
                    // Only same-chain peers.
                    match e.chain_id {
                        Some(cid) if local_chain_id != 0 && cid != local_chain_id => false,
                        _ => true,
                    }
                })
                .map(|e| (e.chain_tip_height, e.chain_tip_hash.clone()))
                .collect()
        };

        // Total connected peers (for Isolated check).
        let connected_peers = peers_snapshot.len();
        // Peers with chain_tip data (for majority check — pre-announce peers excluded).
        let peers_with_tip: usize = peers_snapshot.iter()
            .filter(|(h, hash)| h.is_some() && hash.is_some())
            .count();
        let highest_known = peers_snapshot.iter()
            .filter_map(|(h, _)| *h)
            .max()
            .unwrap_or(height)
            .max(height);

        // 3-5. Decision tree — pure logic lives in `decide_alignment` (unit
        // tested); the two closures keep the fork_resolver and storage locks
        // lazy, invoked only on the branch that needs them (same lock
        // discipline as before the extraction).
        let state = decide_alignment(
            height,
            connected_peers,
            peers_with_tip,
            highest_known,
            has_proposals,
            || self.fork_resolver.lock().dwell_counter() > 0,
            || {
                // Majority chain check. Need storage (lock 2) — safe because
                // consensus(4) and peer_info(7) are already dropped.
                let mut agreeing: usize = 0;
                let mut ahead_same_chain: usize = 0;
                let storage = self.storage.read();
                for (peer_h, peer_hash) in &peers_snapshot {
                    let (Some(ph), Some(phash)) = (peer_h, peer_hash) else { continue };
                    if *phash == local_tip_hex {
                        // Exact tip match — definitely agreeing.
                        agreeing += 1;
                    } else if *ph <= height {
                        // Peer behind or at same height with different tip.
                        // Check if their tip matches our chain at their height.
                        match storage.get_block_hash_by_height(*ph) {
                            Ok(our_hash) => {
                                if hex::encode(our_hash.as_bytes()) == *phash {
                                    agreeing += 1; // Same chain, just behind.
                                }
                            }
                            Err(e) => {
                                tracing::trace!(task = "alignment", "storage miss at height {ph}: {e}");
                            }
                        }
                    } else {
                        // Peer ahead — already filtered to same chain_id (line 580).
                        // Count as agreeing: they're on our chain, just further along.
                        agreeing += 1;
                        ahead_same_chain += 1;
                    }
                }
                (agreeing, ahead_same_chain)
            },
        );

        // 6. Read dwell for cycles_remaining (if Diverged from fork).
        let cycles_remaining = if matches!(state, AlignmentState::Diverged) {
            let resolver = self.fork_resolver.lock();
            let dwell = resolver.dwell_counter();
            if dwell > 0 {
                Some(resolver.min_fork_duration().saturating_sub(dwell))
            } else {
                None
            }
        } else {
            None
        };

        let progress = if highest_known == 0 { 0.0 } else { height as f64 / highest_known as f64 };

        let snapshot = AlignmentSnapshot {
            state,
            height,
            peer_count: connected_peers,
            highest_known,
            progress,
            cycles_remaining,
        };

        // 7. Detect state or height change and emit WS event.
        let prev = self.alignment.read().clone();
        *self.alignment.write() = snapshot;

        if state != prev.state || height != prev.height {
            self.broadcast_event(serde_json::json!({
                "event": "alignment_changed",
                "state": state.label(),
                "severity": state.severity(),
                "height": height,
                "peer_count": connected_peers,
                "highest_known": highest_known,
                "progress": progress,
                "cycles_remaining": cycles_remaining,
                "previous_state": prev.state.label(),
            }));
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
        drop(storage);
        // The chain is gone — every pooled tx was validated against it.
        // Purge; origin wallets re-relay. (Lock order: Storage(2) < Mempool(5).)
        self.mempool.lock().clear();
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
        // Rolled-back UTXOs no longer exist — pooled txs spending them are
        // invalid and would pollute proposals/fee stats until expiry. Purge;
        // still-valid txs are re-relayed by their origin wallets.
        self.mempool.lock().clear();
    }

    fn clear_cycle_history_storage(&self) {
        if let Err(e) = self.storage.read().clear_cycle_history() {
            tracing::warn!(task = "healing", "clear_cycle_history: {e}");
        }
    }

    fn clear_pending_proposals(&self) {
        self.send_network(NetworkCommand::ClearPendingProposals);
    }

    /// Clear gossip dedup caches so stale entries from the old chain
    /// don't block relay of transactions/blocks valid on the new chain.
    fn clear_gossip_caches(&self) {
        self.send_network(NetworkCommand::ClearGossipCaches);
    }

    /// Ask ALL connected peers for their status (`SyncRequest::GetStatus`).
    /// Responses land as `PeerChainTipUpdated`, filling the chain-tip fields
    /// `compute_alignment` needs — call this whenever peer tips are unknown
    /// (fresh connect, post-wipe) so "Verifying" lasts seconds, not minutes.
    pub(crate) fn request_sync(&self) {
        self.send_network(NetworkCommand::RequestSync);
    }

    fn update_tip_height(&self, h: u64) {
        self.send_network(NetworkCommand::UpdateTipHeight(h));
    }

    /// Update chain_id across ALL subsystems: AtomicU32, consensus engine, network.
    /// Single entry point — prevents forgetting one target (which caused B4 merkle
    /// mismatch when only AtomicU32 + network were updated but engine stayed at 0).
    fn update_chain_id(&self, new_cid: u32) {
        self.chain_id.store(new_cid, Ordering::Relaxed);
        self.consensus.write().set_chain_id(new_cid);
        self.send_network(NetworkCommand::UpdateChainId(new_cid));
        // tx_ids commit to the chain_id, so every pooled entry's identity is
        // now stale (blockchain hop, or pre-genesis→real transition). Purge.
        self.mempool.lock().clear();
        tracing::info!(task = "chain_id", "chain_id updated to {:#010X}", new_cid);
    }

    fn clear_last_proposed(&self) {
        *self.last_proposed.lock() = None;
    }

    /// Clear chain-specific fields from all peer_info entries so stale
    /// chain state doesn't poison sync peer selection after a chain reset
    /// or adoption (stale-cache-#3).
    fn clear_peer_chain_state(&self) {
        let mut peers = self.peer_info.write();
        for entry in peers.values_mut() {
            entry.chain_id = None;
            entry.chain_tip_height = None;
            entry.chain_tip_hash = None;
            entry.proposed_height = None;
        }
    }

    /// Remove a committed block's txs from the mempool — INCLUDING any
    /// conflicting mempool tx that spends an outpoint the block just consumed
    /// (removeForBlock + removeConflicts). Sync-imported blocks are the most
    /// conflict-prone (catch-up after being behind/forked), so this must
    /// mirror the consensus commit path exactly; a plain by-id removal would
    /// leave permanently-invalid conflicting txs polluting the pool until
    /// expiry.
    fn evict_from_mempool(&self, block_txs: &[noble_core::Transaction], tx_ids: &[Hash256]) {
        let mut mempool = self.mempool.lock();
        mempool.remove_for_block(block_txs, tx_ids);
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
        // A clean idle reset (typically sync-complete) clears the failure streak.
        self.sync_failure_streak = 0;
        self.sync_atomics_from_state();
        // If we were Syncing, transition back to Idle.
        // Don't change phase if we're Resolving/Adopting (those manage their own transitions).
        if self.healing_phase == HealingPhase::Syncing {
            self.healing_phase = HealingPhase::Idle;
        }
    }

    /// Post-sync range verification: integrity check + peer alignment.
    /// Called after sync completes, BEFORE resetting to Idle.
    fn verify_sync_range(&self, sync_start: u64, sync_end: u64) -> SyncVerifyResult {
        if sync_end <= sync_start {
            return SyncVerifyResult::Ok;
        }
        // 1. Full integrity check on the synced range.
        let chain_id = self.get_chain_id();
        let report = {
            let storage = self.storage.read();
            noble_storage::verify_chain_integrity(
                &*storage, chain_id, sync_start + 1, sync_end,
            )
        };
        if !report.is_clean() {
            let first = report.first_corrupt_height.unwrap_or(sync_start + 1);
            tracing::error!(
                task = "sync_verify",
                "post-sync integrity failure: {} finding(s), first corrupt at height {}",
                report.findings.len(), first,
            );
            return SyncVerifyResult::IntegrityFailure {
                first_corrupt: first,
                findings_count: report.findings.len(),
            };
        }

        // 2. Peer alignment check: does our new tip match at least one peer?
        // Only meaningful if at least one peer has reported a chain tip (via NodeAnnounce).
        // Peers with chain_tip_height=None haven't announced yet — don't count them.
        let our_tip = self.consensus.read().chain_tip();
        let peers = self.peer_info.read();
        let peers_with_tip: usize = peers.values()
            .filter(|p| p.chain_tip_height.is_some())
            .count();
        if peers_with_tip > 0 {
            let our_tip_hex = hex::encode(our_tip.1.as_bytes());
            let agreeing = peers.values()
                .filter(|p| {
                    p.chain_tip_height == Some(our_tip.0)
                        && p.chain_tip_hash.as_deref() == Some(&our_tip_hex)
                })
                .count();
            // Also count peers that are ahead of us (they implicitly passed through
            // our height — alignment will be confirmed when we catch up further).
            let ahead = peers.values()
                .filter(|p| p.chain_tip_height.map_or(false, |h| h > our_tip.0))
                .count();
            if agreeing == 0 && ahead == 0 {
                tracing::warn!(
                    task = "sync_verify",
                    "post-sync misalignment: our tip {} doesn't match any of {} peer(s) with tips",
                    our_tip.0, peers_with_tip,
                );
                return SyncVerifyResult::MisalignedWithPeers {
                    our_height: our_tip.0,
                    peer_count: peers_with_tip,
                };
            }
        }

        tracing::info!(
            task = "sync_verify",
            "post-sync verification passed: range {}..={}, {} block(s) verified",
            sync_start + 1, sync_end, sync_end - sync_start,
        );
        SyncVerifyResult::Ok
    }

    /// Handle post-sync verification result. On failure, escalates recovery
    /// based on `sync_verify_retries` (ancestor depth escalation).
    fn handle_post_sync_failure(&mut self, result: SyncVerifyResult) {
        self.sync_verify_retries = self.sync_verify_retries.saturating_add(1);
        let retries = self.sync_verify_retries;

        match result {
            SyncVerifyResult::Ok => unreachable!(),
            SyncVerifyResult::IntegrityFailure { first_corrupt, findings_count } => {
                // Escalate rollback depth based on retry count (same as misalignment).
                let rollback_height = match retries {
                    1 => first_corrupt.saturating_sub(1),
                    2 => first_corrupt.saturating_sub(1).min(self.sync_start_height),
                    _ => 0, // Third+ failure: full re-sync from genesis.
                };
                tracing::warn!(
                    task = "sync_verify",
                    "integrity failure recovery (attempt {}): rolling back to {} ({} findings, first_corrupt={})",
                    retries, rollback_height, findings_count, first_corrupt,
                );
                self.broadcast_event(serde_json::json!({
                    "event": "sync_verify_failure",
                    "kind": "integrity",
                    "first_corrupt": first_corrupt,
                    "rollback_to": rollback_height,
                    "retry": retries,
                }));
                self.rollback_to(rollback_height);
                self.reset_sync_idle();
                if retries >= 3 {
                    self.sync_verify_retries = 0; // Reset for fresh attempt.
                }
            }
            SyncVerifyResult::MisalignedWithPeers { our_height, peer_count } => {
                // Ancestor depth escalation based on retry count.
                let rollback_height = match retries {
                    1 => {
                        // First failure: re-find common ancestor with peers.
                        // For now, rollback to sync_start (the pre-sync height).
                        tracing::warn!(
                            task = "sync_verify",
                            "misalignment recovery (attempt 1): rolling back to sync start {}",
                            self.sync_start_height,
                        );
                        self.sync_start_height
                    }
                    2 => {
                        // Second failure: halve the trust point.
                        let half = our_height / 2;
                        tracing::warn!(
                            task = "sync_verify",
                            "misalignment recovery (attempt 2): rolling back to height {}",
                            half,
                        );
                        half
                    }
                    _ => {
                        // Third+ failure: full re-sync from genesis.
                        tracing::error!(
                            task = "sync_verify",
                            "misalignment recovery (attempt {}): rolling back to genesis",
                            retries,
                        );
                        0
                    }
                };
                self.broadcast_event(serde_json::json!({
                    "event": "sync_verify_failure",
                    "kind": "misalignment",
                    "our_height": our_height,
                    "peer_count": peer_count,
                    "rollback_to": rollback_height,
                    "retry": retries,
                }));
                self.rollback_to(rollback_height);
                self.reset_sync_idle();
                // If we've retried 3+ times, also ban the current sync peer.
                if retries >= 3 {
                    self.sync_verify_retries = 0; // Reset for fresh peer attempt.
                }
            }
        }
    }

    /// Sync conveyor: advance the manifest-based sync state machine.
    ///
    /// **Isolated from healing decisions.** The conveyor only runs when the
    /// healing phase allows it (Idle or Syncing). During Resolving/Adopting,
    /// the conveyor is paused — the execute_* methods reset sync state and
    /// the conveyor restarts naturally on the next tick.
    pub fn advance_sync(&mut self, now: u64) {
        // Guard: don't advance conveyor during resolution/adoption.
        if matches!(self.healing_phase, HealingPhase::Resolving | HealingPhase::Adopting) {
            return;
        }

        let our_height = self.consensus.read().chain_tip().0;

        // Layer 6 backstop: must never fire if Layers 1-4 work, but guarantees a
        // wedge can never persist silently (the 26-day failure mode).
        self.check_sync_stall(our_height, now);

        match &self.sync_state {
            SyncState::Idle => {
                // Check if any peer is ahead.
                let (best_peer, best_height) = self.find_best_sync_peer(our_height);
                if let Some(peer) = best_peer {
                    let behind = best_height - our_height;
                    // Record sync session metadata for post-sync verification.
                    self.sync_start_height = our_height;
                    self.sync_import_kind = match self.healing_phase {
                        HealingPhase::Resolving => SyncImportKind::ForkResolution,
                        HealingPhase::Adopting => SyncImportKind::CrossChainAdoption,
                        _ if our_height == 0 => SyncImportKind::Bootstrap,
                        _ => SyncImportKind::CatchUp,
                    };
                    // Transition healing phase to Syncing.
                    self.healing_phase = HealingPhase::Syncing;
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
                    // Post-sync verification before declaring complete.
                    let verify = self.verify_sync_range(self.sync_start_height, our_height);
                    match verify {
                        SyncVerifyResult::Ok => {
                            self.sync_verify_retries = 0;
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
                        }
                        failure => {
                            self.handle_post_sync_failure(failure);
                        }
                    }
                    return;
                }
                // Timeout check.
                if now.saturating_sub(*requested_at) >= SYNC_MANIFEST_TIMEOUT_SECS {
                    tracing::warn!(
                        task = "sync",
                        peer = %hex::encode(peer),
                        "manifest request timed out after {}s",
                        SYNC_MANIFEST_TIMEOUT_SECS,
                    );
                    let old_peer = peer.clone();
                    let target = *target;
                    // Layer 4: escalate. Prefer a different peer; if this is the
                    // only one and it keeps failing, force-drop + redial it
                    // rather than retrying the same dead channel forever.
                    self.escalate_sync_failure(old_peer, target, our_height, now);
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
                    // Extract values before matching — avoids holding a borrow on
                    // self.sync_state during ingest_clue/send_network calls.
                    let entry_height = manifest[cursor].height;
                    let entry_hash = manifest[cursor].hash;
                    let entry_status = manifest[cursor].status;
                    match entry_status {
                        EntryStatus::Pending => {
                            self.send_network(NetworkCommand::RequestBlockByHeight {
                                peer_id: peer.clone(),
                                height: entry_height,
                            });
                            // Mark as requested.
                            if let SyncState::Fetching { ref mut manifest, .. } = self.sync_state {
                                manifest[cursor].status = EntryStatus::Requested { at: now };
                            }
                        }
                        EntryStatus::Requested { at } => {
                            let stalled_secs = now.saturating_sub(at);
                            // Retry every SYNC_RETRY_SECS. `retry_count` tracks
                            // total retries since first request (at is never reset).
                            let retry_count = stalled_secs / SYNC_RETRY_SECS;
                            // Only act at each retry boundary (avoid re-firing every tick).
                            let at_boundary = stalled_secs >= SYNC_RETRY_SECS
                                && stalled_secs % SYNC_RETRY_SECS < 5; // 5s window around boundary
                            if at_boundary {

                                if retry_count >= 3 {
                                    // Persistent stall — sync RPC is broken for this peer.
                                    // Ingest a clue so evaluate_and_execute can decide.
                                    tracing::warn!(
                                        task = "sync",
                                        "block {} fetch persistently stalled ({retry_count} retries, {}s) — escalating to healing",
                                        entry_height, stalled_secs,
                                    );
                                    self.ingest_clue(HealingClue::SyncStall {
                                        stalled_height: entry_height,
                                        target_height: target,
                                        reason: format!(
                                            "sync block {} stalled after {} retries ({}s) — sync RPC may be broken",
                                            entry_height, retry_count, stalled_secs,
                                        ),
                                    });
                                    // Mark as failed so the conveyor switches peer.
                                    if let SyncState::Fetching { ref mut manifest, .. } = self.sync_state {
                                        manifest[cursor].status = EntryStatus::Failed { attempts: SYNC_MAX_BLOCK_RETRIES };
                                    }
                                } else {
                                    tracing::warn!(
                                        task = "sync",
                                        "block {} fetch stalled ({}s, retry {}) — retrying via RPC + gossip",
                                        entry_height, stalled_secs, retry_count,
                                    );
                                    // Retry via sync RPC.
                                    self.send_network(NetworkCommand::RequestBlockByHeight {
                                        peer_id: peer.clone(),
                                        height: entry_height,
                                    });
                                    // Fallback: also request via gossip protocol.
                                    {
                                        let hash = entry_hash;
                                        if hash != [0u8; 32] {
                                            self.send_network(NetworkCommand::RequestBlock {
                                                peer_id: peer.clone(),
                                                hash,
                                            });
                                        }
                                    }
                                    self.broadcast_event(serde_json::json!({
                                        "event": "sync_progress",
                                        "height": entry_height,
                                        "target": target,
                                        "progress": 0,
                                        "stalled": true,
                                        "stalled_secs": stalled_secs,
                                        "retry": retry_count,
                                    }));
                                    // NOTE: do NOT reset `at` — keep the original request time
                                    // so stalled_secs accumulates and retry_count increases.
                                    // The next tick will see stalled_secs=20, retry_count=2, etc.
                                }
                            }
                        }
                        EntryStatus::Failed { attempts } if attempts >= SYNC_MAX_BLOCK_RETRIES => {
                            // Too many failures — ingest SyncStall clue so
                            // evaluate_and_execute can trigger fork resolution
                            // instead of endlessly restarting sync.
                            let stalled_h = manifest[cursor].height;
                            tracing::warn!(
                                task = "sync",
                                "block {} failed {} times — ingesting sync stall clue",
                                stalled_h, attempts,
                            );
                            self.ingest_clue(HealingClue::SyncStall {
                                stalled_height: stalled_h,
                                target_height: target,
                                reason: format!(
                                    "block {stalled_h} failed {attempts} times, sync cannot advance"
                                ),
                            });
                            self.reset_sync_idle();
                        }
                        EntryStatus::Failed { .. } => {
                            // Retry — but keep Failed status so the attempt counter
                            // accumulates across retries (don't reset to Requested).
                            self.send_network(NetworkCommand::RequestBlockByHeight {
                                peer_id: peer.clone(),
                                height: entry_height,
                            });
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
                        // Post-sync verification before declaring complete.
                        let verify = self.verify_sync_range(self.sync_start_height, our_height);
                        match verify {
                            SyncVerifyResult::Ok => {
                                self.sync_verify_retries = 0;
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
                            }
                            failure => {
                                self.handle_post_sync_failure(failure);
                            }
                        }
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

    /// Layer 1→4 fast path: an outbound sync request to a peer failed at the
    /// transport level (timeout / connection reset / dial error), surfaced by
    /// the network service. If it's the peer we're actively syncing from, react
    /// **now** — within the ~10s request timeout — instead of waiting out the
    /// 60s manifest timeout. Routes through the same escalation as the timeout
    /// path so a wedged channel is rebuilt in ~20s rather than retried forever.
    pub fn on_sync_request_failed(&mut self, peer_id: &[u8], now: u64) {
        let (active_peer, target) = match &self.sync_state {
            SyncState::AwaitingManifest { peer, target, .. }
            | SyncState::Fetching { peer, target, .. } => (peer.clone(), *target),
            SyncState::Idle => return,
        };
        if active_peer != peer_id {
            // Failure for some other (non-sync) request — not our concern here.
            return;
        }
        let our_height = self.consensus.read().chain_tip().0;
        tracing::warn!(
            task = "sync",
            peer = %hex::encode(&active_peer),
            "sync request to active peer failed — reacting immediately (not waiting for the 60s manifest timeout)",
        );
        self.escalate_sync_failure(active_peer, target, our_height, now);
    }

    /// Shared escalation for a failed sync attempt against `failed_peer` (a fast
    /// request-response failure or a 60s manifest timeout). Increments the
    /// failure streak; once it reaches [`SYNC_PEER_MAX_FAILURES`] the peer's
    /// connection is force-dropped (the node's reconnect loop then redials it
    /// with a fresh yamux session, and the next tick re-requests cleanly) rather
    /// than retrying the same wedged channel forever. Below the threshold it
    /// re-targets a different peer if one exists, else retries the same one.
    fn escalate_sync_failure(&mut self, failed_peer: Vec<u8>, target: u64, our_height: u64, now: u64) {
        self.sync_state = SyncState::Idle;
        self.sync_failure_streak = self.sync_failure_streak.saturating_add(1);
        let streak = self.sync_failure_streak;
        // K3-04: per-peer memory (survives the disconnect below, unlike the
        // global streak). Exponential quarantine of this peer's ADVERTISED
        // tips once failures repeat — timeouts alone are NOT protocol
        // violations, so no ban category is applied here.
        self.record_tip_failure(&failed_peer, now);

        if streak >= SYNC_PEER_MAX_FAILURES {
            // Channel to this peer is wedged (connected but not answering).
            // Drop it; reconnect + the next advance_sync tick rebuild cleanly.
            tracing::warn!(
                task = "sync",
                peer = %hex::encode(&failed_peer),
                streak,
                "sync peer unresponsive after {streak} consecutive attempts — dropping connection to force a fresh one",
            );
            self.send_network(NetworkCommand::DisconnectPeer(failed_peer));
            self.sync_failure_streak = 0;
            self.broadcast_event(serde_json::json!({
                "event": "sync_peer_reset",
                "reason": "unresponsive_sync_channel",
            }));
            self.sync_atomics_from_state();
            return;
        }

        // Below threshold: prefer a different peer, else retry the same one fast.
        let (alt, alt_height) = self.find_best_sync_peer_excluding(our_height, &failed_peer);
        let (peer, peer_height) = match alt {
            Some(p) => (p, alt_height),
            None => (failed_peer, target),
        };
        let start = our_height + 1;
        let count = (peer_height.saturating_sub(our_height)).min(MANIFEST_WINDOW as u64) as u16;
        self.send_network(NetworkCommand::RequestSyncManifest {
            peer_id: peer.clone(),
            start_height: start,
            count,
        });
        self.sync_state = SyncState::AwaitingManifest {
            peer,
            target: peer_height,
            requested_at: now,
        };
        self.sync_atomics_from_state();
    }

    /// Layer 6 stall watchdog (backstop). If we stay behind a known-ahead peer
    /// with NO tip progress for [`SYNC_STALL_ALARM_SECS`], the per-peer recovery
    /// (Layers 1-4) has failed to converge. Fire a CRITICAL alarm (log + GUI
    /// alignment feed) and force a full re-sync. Re-arms once per window while
    /// stuck; any tip progress (or catching up) clears it. This should never
    /// trigger — its job is to make sure a wedge is never *silent*.
    fn check_sync_stall(&mut self, our_height: u64, now: u64) {
        let (_, best_height) = self.find_best_sync_peer(our_height);

        // Not behind any peer → nothing to watch; clear the episode.
        if best_height <= our_height {
            self.stall_watch_height = our_height;
            self.stall_watch_since = now;
            return;
        }

        // First observation of being-behind, or the tip advanced since we
        // started watching → (re)start the timer. Progress is healthy.
        if self.stall_watch_since == 0 || our_height > self.stall_watch_height {
            self.stall_watch_height = our_height;
            self.stall_watch_since = now;
            return;
        }

        let stalled = now.saturating_sub(self.stall_watch_since);
        if stalled >= SYNC_STALL_ALARM_SECS {
            tracing::error!(
                task = "sync",
                our_height,
                target = best_height,
                stalled_secs = stalled,
                "SYNC STALLED: {stalled}s behind peers (at {our_height}, target {best_height}) with no progress — forcing recovery. The per-peer self-healing should have prevented this; please report.",
            );
            self.broadcast_event(serde_json::json!({
                "event": "sync_stall_alarm",
                "severity": "critical",
                "height": our_height,
                "target": best_height,
                "stalled_secs": stalled,
            }));
            // Force recovery: refresh every peer's status and reset the sync FSM
            // so the rest of this tick re-picks a peer and re-requests cleanly.
            self.send_network(NetworkCommand::RequestSync);
            self.reset_sync_idle();
            // Re-arm: rate-limit re-fire to once per window while still stuck.
            self.stall_watch_since = now;
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
        // A manifest arrived → the request/response channel to this peer works.
        // Clear the failure streak so transient blips don't accrue toward a drop.
        self.sync_failure_streak = 0;

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
                        // Bootstrap fork detection: if the rejection is a chain
                        // disagreement (PrevHashMismatch) and we're early in the chain,
                        // we're on a different fork than the sync peer.  Reset to
                        // genesis and re-sync from the dominant chain.
                        let is_fork_reject = reason.contains("PrevHash")
                            || reason.contains("prev_block_hash")
                            || reason.contains("HeightMismatch");
                        if is_fork_reject {
                            let sync_target = target;
                            tracing::warn!(
                                task = "sync",
                                "chain mismatch clue: sync block {} rejected ({reason})",
                                height,
                            );
                            self.ingest_clue(HealingClue::SyncChainMismatch {
                                rejected_height: height,
                                sync_target,
                                reason: format!("sync block {height} rejected: {reason}"),
                            });
                            // Pause conveyor — evaluate_and_execute will decide.
                            return;
                        }
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
        self.select_sync_peer(our_height, None)
    }

    /// K3-04 selection core: prefer the highest VERIFIED height (a peer that
    /// actually served us valid blocks); fall back to the highest ADVERTISED
    /// height from peers not under tip quarantine. `exclude_hex` skips one
    /// peer (retry escalation).
    fn select_sync_peer(
        &self,
        our_height: u64,
        exclude_hex: Option<&str>,
    ) -> (Option<Vec<u8>>, u64) {
        let local_chain_id = self.get_chain_id();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let peers = self.peer_info.read();
        let mut best_verified: Option<(Vec<u8>, u64)> = None;
        let mut best_advertised: Option<(Vec<u8>, u64)> = None;
        for entry in peers.values() {
            if exclude_hex.is_some_and(|x| entry.peer_id == x) {
                continue;
            }
            // Skip peers on a known-different chain.  chain_id=None means
            // "not yet announced" — allow (service.rs mismatch check is authoritative).
            if local_chain_id != 0 {
                if let Some(peer_cid) = entry.chain_id {
                    if peer_cid != local_chain_id { continue; }
                }
            }
            let Ok(pid) = hex::decode(&entry.peer_id) else { continue };
            if let Some(v) = entry.verified_height {
                if v > our_height && best_verified.as_ref().is_none_or(|(_, bh)| v > *bh) {
                    best_verified = Some((pid.clone(), v));
                }
            }
            if let Some(h) = entry.chain_tip_height {
                if h > our_height
                    && !self.is_tip_quarantined(&entry.peer_id, now)
                    && best_advertised.as_ref().is_none_or(|(_, bh)| h > *bh)
                {
                    best_advertised = Some((pid, h));
                }
            }
        }
        // Verified wins even at a lower height than an unverified claim —
        // a proven source beats a promise. (An advertised-only claim still
        // gets its bounded probe when no verified source exists.)
        match best_verified.or(best_advertised) {
            Some((pid, h)) => (Some(pid), h),
            None => (None, our_height),
        }
    }

    /// Find the best sync peer on the same chain, excluding a specific peer.
    fn find_best_sync_peer_excluding(&self, our_height: u64, exclude: &[u8]) -> (Option<Vec<u8>>, u64) {
        let exclude_hex = hex::encode(exclude);
        self.select_sync_peer(our_height, Some(&exclude_hex))
    }

    /// K3-04: record a failed attempt to substantiate `peer`'s claimed tip.
    /// Second-and-later failures start an exponential quarantine of the
    /// peer's ADVERTISED heights (60s x 2^(n-1), capped 3600s).
    fn record_tip_failure(&mut self, peer: &[u8], now: u64) {
        let hex_pid = hex::encode(peer);
        // Bound the map: evict the record with the OLDEST `until` when full
        // and the peer isn't already tracked.
        if !self.tip_quarantine.contains_key(&hex_pid)
            && self.tip_quarantine.len() >= TIP_QUARANTINE_CAP
        {
            if let Some(oldest) = self
                .tip_quarantine
                .iter()
                .min_by_key(|(_, r)| r.until)
                .map(|(k, _)| k.clone())
            {
                self.tip_quarantine.remove(&oldest);
            }
        }
        let rec = self.tip_quarantine.entry(hex_pid.clone()).or_default();
        rec.failures = rec.failures.saturating_add(1);
        let failures = rec.failures;
        if failures >= SYNC_PEER_MAX_FAILURES {
            let exp = failures.saturating_sub(SYNC_PEER_MAX_FAILURES).min(6);
            let dur = (TIP_QUARANTINE_BASE_SECS << exp).min(TIP_QUARANTINE_MAX_SECS);
            rec.until = now.saturating_add(dur);
            tracing::warn!(
                task = "sync",
                peer = %hex_pid,
                failures,
                quarantine_secs = dur,
                "peer repeatedly failed to substantiate its claimed tip — advertised heights quarantined",
            );
            self.broadcast_event(serde_json::json!({
                "event": "tip_quarantine",
                "peer_id": hex_pid,
                "failures": failures,
                "quarantine_secs": dur,
            }));
        }
    }

    /// K3-04: true while `peer_hex`'s ADVERTISED tips must be ignored.
    pub fn is_tip_quarantined(&self, peer_hex: &str, now: u64) -> bool {
        self.tip_quarantine
            .get(peer_hex)
            .is_some_and(|r| r.until > now)
    }

    /// K3-04: a block from this peer validated + committed — its tip claims
    /// are substantiated. Clears failure memory and any active quarantine.
    pub fn clear_tip_failures(&mut self, peer: &[u8]) {
        self.tip_quarantine.remove(&hex::encode(peer));
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

    /// Detect fork status among same-chain peers.
    ///
    /// **Detection only** — ingests clues but never triggers resolution directly.
    /// Resolution is handled by `evaluate_and_execute()` at the end of the tick.
    ///
    /// Returns `ForkEvalResult` for GUI event emission in node.rs.
    pub fn detect_forks(&mut self) -> ForkEvalResult {
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
                self.ingest_clue(HealingClue::ForkResolve {
                    target_hash,
                    target_height,
                    reason,
                });
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

    /// Detect cross-chain fork conditions.
    ///
    /// **Detection only** — ingests clues but never triggers adoption directly.
    pub fn detect_cross_chain(&mut self) {
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
                self.ingest_clue(HealingClue::CrossChainAdopt {
                    target_chain_id,
                    reason,
                });
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
        // Guard: never perform integrity wipe during active resolution/adoption.
        if matches!(self.healing_phase, HealingPhase::Resolving | HealingPhase::Adopting) {
            tracing::debug!(
                task = "healing",
                phase = ?self.healing_phase,
                "skipping peer chain tip update during active healing"
            );
            return;
        }

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

            self.update_chain_id(0);
            if let Err(e) = self.consensus.write().reset_tip(0, Hash256::ZERO, true) {
                tracing::error!(task = "integrity", "reset_tip after integrity wipe failed: {e}");
            }
            self.update_tip_height(0);
            self.clear_pending_proposals();
            self.clear_gossip_caches();

            // Clear stale caches that reference the wiped chain (stale-cache-#4/#5/#7).
            self.announce_cache.lock().clear();
            self.discovered_blockchains.lock().clear();
            self.persist_discovered_blockchains();
            self.fork_common_ancestor = None;

            // Reset sync state + post-sync verification counters
            // (prevent retry bleed from previous healing case).
            self.reset_sync_idle();
            self.sync_verify_retries = 0;
            self.sync_start_height = 0;

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

    /// Execute fork resolution: rollback storage and reset consensus.
    ///
    /// Called ONLY from `evaluate_and_execute`. Phase transitions are handled
    /// by the caller — this method performs the raw rollback and cleanup.
    fn execute_resolution(
        &mut self,
        target_hash: Hash256,
        target_height: u64,
        reason: &str,
    ) {
        tracing::warn!(
            task = "fork_resolution",
            "AUTO-RESOLVING: {reason} (target height {target_height})"
        );

        // H9: the finality floor must be compared against the ROLLBACK POINT,
        // not the competing fork's tip.
        //
        // The tip-based check in `fork_resolver` only asks whether the rival
        // chain is taller than finality — a fork can be far ahead at its tip
        // while diverging *below* the finalized height, and rolling back to
        // that ancestor silently rewrites finalized history. Finality is
        // supposed to be the one thing automation cannot undo.
        //
        // Unknown ancestry is the dangerous case: it used to mean
        // `unwrap_or(0)` → `rollback_to(0)` → a full wipe to genesis, chosen
        // automatically, on the strength of peer-reported heights. Refuse
        // instead and leave the chain intact; a deliberate reset stays
        // available through the TOTP-gated manual RPC.
        let Some((ancestor_height, _)) = self.fork_common_ancestor else {
            tracing::error!(
                task = "fork_resolution",
                "REFUSING automatic resolution: common ancestor unknown — not resetting to genesis. \
                 Operator action required (manual reset is available via authenticated RPC)."
            );
            return;
        };

        let floor = self.rollback_floor();
        if ancestor_height < floor {
            tracing::error!(
                task = "fork_resolution",
                "REFUSING automatic resolution: rollback point {ancestor_height} is below the \
                 finality/checkpoint floor {floor} — finalized history must not be rewritten \
                 automatically. Operator action required."
            );
            return;
        }

        let rollback_height = ancestor_height;

        // Rollback or reset storage.
        self.rollback_to(rollback_height);

        // Clear cycle history.
        self.clear_cycle_history_storage();

        // Reset fork and alignment state.
        self.fork_visible = false;
        self.fork_common_ancestor = None;
        *self.alignment.write() = AlignmentSnapshot::default();

        // Clear stale chain state from peer_info (stale-cache-#3), then
        // immediately re-solicit peer status — the wipe leaves every peer
        // tipless, which would otherwise park alignment in Verifying until
        // the next NodeAnnounce (up to a full cycle away).
        self.clear_peer_chain_state();
        self.request_sync();

        // Clear pending proposals and gossip dedup caches.
        self.clear_pending_proposals();
        self.clear_gossip_caches();

        // Reset fork resolver and stale caches when rolling back to genesis.
        if rollback_height == 0 {
            *self.fork_resolver.lock() = ForkResolver::new(
                self.fork_resolution_strategy,
                self.fork_resolution_delay_cycles,
            );
            // Clear announce cache — stale NodeAnnounce entries could cause
            // false ChainTipRegression equivocation detection after reset.
            self.announce_cache.lock().clear();
            // Clear cross-chain discovery data — stale entries could trigger
            // premature re-adoption after genesis-level resolution.
            self.discovered_blockchains.lock().clear();
            self.persist_discovered_blockchains();
        }

        // Reset sync state — the conveyor will restart on the next tick
        // when evaluate_and_execute transitions to HealingPhase::Syncing.
        self.reset_sync_idle();

        self.broadcast_event(serde_json::json!({
            "event": "fork_auto_resolved",
            "target_height": target_height,
            "target_hash": hex::encode(target_hash.as_bytes()),
            "rollback_height": rollback_height,
            "reason": reason,
        }));
    }

    // ── Chain adoption ──

    /// Execute chain adoption: wipe all data and reset for re-sync.
    ///
    /// Called ONLY from `evaluate_and_execute`. Phase transitions are handled
    /// by the caller.
    fn execute_adoption(&mut self, target_chain_id: u32, reason: &str) {
        tracing::warn!(
            task = "chain_adoption",
            "CROSS-CHAIN ADOPTION: adopting chain {:#010X} — {reason}",
            target_chain_id
        );

        // 1. Wipe ALL chain data.
        self.wipe_and_reset(reason);

        // 2. Reset chain_id to 0 (all subsystems: atomic + consensus engine + network).
        self.update_chain_id(0);
        self.chain_vote_weight.store(0, Ordering::Relaxed);
        self.fork_visible = false;
        self.fork_common_ancestor = None;
        *self.alignment.write() = AlignmentSnapshot::default();

        // 2b. Clear announce cache.
        self.announce_cache.lock().clear();

        // 2c. Clear discovered blockchains.
        self.discovered_blockchains.lock().clear();
        self.persist_discovered_blockchains();

        // 2d. Clear stale chain state from peer_info (stale-cache-#3), then
        // immediately re-solicit peer status so alignment regains evidence in
        // seconds instead of waiting out the announce cadence.
        self.clear_peer_chain_state();
        self.request_sync();

        // 3. Update network tip height.
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

        // 5. Reset sync state + post-sync verification counters
        // (prevent retry bleed from previous healing case).
        // NOTE(stale-cache-#12): reset_sync_idle() → sync_atomics_from_state()
        // sets sync_target_height_shared, sync_progress_current, and
        // sync_progress_total all to 0 when state is Idle. No separate reset needed.
        self.reset_sync_idle();
        self.sync_verify_retries = 0;
        self.sync_start_height = 0;

        // 6. Clear stale proposals and gossip dedup caches.
        self.clear_pending_proposals();
        self.clear_gossip_caches();

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
            //
            // SAFETY(stale-cache-#2): chain_vote_weight is read here at detection
            // time to compute the adoption score. If adoption is triggered, the
            // clue carries the decision and execute_adoption() resets the weight
            // to 0 (line ~1538). The score comparison uses the *current* weight
            // at detection time, which is correct: the clue captures the decision
            // made with the state that existed when the announce arrived. The
            // weight reset happens later during execution, before any new chain's
            // blocks accumulate votes.
            let their_weight = announce.chain_vote_weight.unwrap_or(0);
            let our_weight = self.chain_vote_weight.load(Ordering::Relaxed);
            let their_score = their_height
                .saturating_mul(10_000)
                .saturating_add(their_weight.min(9_999));
            let our_score = our_height
                .saturating_mul(10_000)
                .saturating_add(our_weight.min(9_999));
            let mut should_adopt = their_score > our_score
                || (their_score == our_score && announce.chain_id < our_chain_id);

            // M5: adoption WIPES our chain, so it must not run on numbers a peer
            // simply asserted. `chain_tip_height` and `chain_vote_weight` are
            // self-reported and cost nothing to inflate; a tip HASH is the
            // minimum checkable commitment — it names a specific block we will
            // then have to sync and validate, and a peer that cannot name one
            // has given us nothing to verify against.
            //
            // This is deliberately the *cheap* half of M5. It does not fully
            // satisfy "require validated block material before wiping": the
            // wipe still precedes validating their block 1. The exposure is
            // bounded — adoption only fires while our own chain is at or below
            // EARLY_CHAIN_HEIGHT_LIMIT (5 blocks), inside the same trusted
            // early window that C4 was de-scoped for — but it is a real
            // residual, recorded rather than papered over.
            if should_adopt && announce.chain_tip_hash.is_none() {
                tracing::warn!(
                    task = "chain_adoption",
                    "refusing early-chain adoption of {:#010X} from {}: advertised height {} with no tip hash \
                     (nothing checkable to adopt toward)",
                    announce.chain_id,
                    announce.node_name,
                    their_height,
                );
                should_adopt = false;
            }

            if should_adopt {
                let reason = format!(
                    "early-chain adoption: peer {} on chain {:#010X} (h={}, w={}) vs local {:#010X} (h={}, w={})",
                    announce.node_name, announce.chain_id, their_height, their_weight,
                    our_chain_id, our_height, our_weight,
                );
                self.ingest_clue(HealingClue::CrossChainAdopt {
                    target_chain_id: announce.chain_id,
                    reason,
                });
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
        // Detect under the cache lock, act after dropping it: the evidence
        // actions below acquire storage(2) and consensus(4), and holding the
        // (untracked) announce_cache mutex across those acquisitions is a
        // latent lock-order hazard — one future counter-path (any code that
        // takes announce_cache while holding storage/consensus) would close a
        // deadlock cycle. See lock_order.rs. Detection/action separation per
        // walkabout Discipline 6.
        let mut evidence_to_publish: Option<noble_core::AnnounceEquivocationEvidence> = None;
        {
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

                // ── Evidence construction (owned — actions happen after the
                // cache guard drops) ──
                if let Some(c) = contradiction {
                    evidence_to_publish = Some(noble_core::AnnounceEquivocationEvidence {
                        identity_key: announce.identity_key.clone(),
                        announce_a: prev.clone(),
                        announce_b: announce.clone(),
                        contradiction: c,
                    });
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
        } // announce_cache guard drops here — actions below hold nothing.

        // ── Evidence verification, storage, and publication (lock-free
        // entry: storage(2) and consensus(4) each taken as temporaries) ──
        if let Some(evidence) = evidence_to_publish {
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

    // ── Sync import ──

    /// Import a committed block from a sync peer directly to storage,
    /// bypassing the consensus voting pipeline.
    ///
    /// Reads parent header and validator list from its own subsystem references.
    /// Executes all side-effects directly (storage commit, consensus update,
    /// mempool eviction, network commands, broadcast events).
    pub fn try_sync_import(&self, block: &noble_core::Block, vote_data: Option<&[u8]>) -> SyncImportResult {
        let (tip_height, _) = self.consensus.read().chain_tip();
        let mut chain_id = self.get_chain_id();

        // Block 1 is ALWAYS proposed with chain_id = 0 (the node has no chain
        // identity yet at proposal time). After block 1 commits, the real
        // chain_id is derived from block 1's hash. So:
        //   - Block 1 validation: MUST use chain_id = 0 (matching the proposer)
        //   - Block 2+: use the derived chain_id from storage
        //
        // Getting this wrong causes merkle root mismatches: the proposer
        // computed tx_ids with chain_id=0, but the validator recomputes with
        // the derived chain_id → different preimage → different merkle → B4.
        if block.header.height == 1 {
            // Block 1 was proposed with chain_id = 0, always validate with 0.
            chain_id = 0;
        } else if chain_id == 0 && block.header.height > 1 {
            // For blocks > 1 when we don't have a chain_id yet (post-reset),
            // derive it from the stored block 1 hash.
            let storage = self.storage.read();
            if let Ok(block1_hash) = storage.get_block_hash_by_height(1) {
                chain_id = noble_core::derive_chain_id(&block1_hash);
            } else if let Ok(genesis_hash) = storage.get_block_hash_by_height(0) {
                chain_id = noble_core::derive_chain_id(&genesis_hash);
            }
            if chain_id == 0 {
                tracing::error!(
                    task = "sync_import",
                    height = block.header.height,
                    "could not derive chain_id — rejecting sync import",
                );
                return SyncImportResult::Rejected {
                    reason: "could not derive chain_id from storage".to_string(),
                };
            }
        }

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

        // H8: anchor the imported history to OUR genesis.
        //
        // At tip_height == 0 there is no parent header, so B2 (prev_hash) is
        // skipped and block 1 was accepted on its signature alone — a syncing
        // node could be handed a fabricated origin and would then extend it,
        // which is the long-range / false-history attack fork-prevention
        // Layer 3 names. The anchor is per-deployment and already on disk: our
        // own genesis block. No shipped checkpoint set, no release authority.
        if block.header.height == 1 {
            let genesis_hash = {
                let storage = self.storage.read();
                storage.get_block_hash_by_height(0).ok()
            };
            match genesis_hash {
                Some(expected) => {
                    if block.header.prev_block_hash != expected {
                        tracing::warn!(
                            task = "sync_import",
                            "rejecting block 1: prev_block_hash {} does not descend from our genesis {}",
                            block.header.prev_block_hash,
                            expected
                        );
                        return SyncImportResult::Rejected {
                            reason: "block 1 does not descend from the configured genesis".to_string(),
                        };
                    }
                }
                None => {
                    // No genesis on disk: we have nothing to anchor against, so
                    // there is no safe way to accept someone else's origin.
                    tracing::warn!(
                        task = "sync_import",
                        "rejecting block 1: no local genesis to anchor against"
                    );
                    return SyncImportResult::Rejected {
                        reason: "no local genesis block to anchor block 1 against".to_string(),
                    };
                }
            }
        }

        let validator_list = self.consensus.read().validator_snapshot()
            .map(|snap| snap.pubkey_vec.clone())
            .unwrap_or_default();

        // Historical TimeContext: T4 validates tx timestamps against the block's
        // own timestamp (proves tx was fresh when block was created).  B6 future-guard
        // uses wall clock (no importing future blocks).  B6 past and B13 are skipped
        // (historical blocks are old; recent timestamps are unreliable after rollback).
        // T-EXPIRY is skipped (proposer validated at creation time).
        // B5 (monotonicity) always enforced.
        let wall_clock = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Any validator can propose — include block's own validator_id.
        let mut val_list = validator_list;
        if !val_list.contains(&block.header.validator_id) {
            val_list.push(block.header.validator_id.clone());
        }

        let ctx = noble_core::BlockValidationContext {
            chain_id,
            time_context: noble_core::TimeContext::Historical {
                block_time: block.header.timestamp,
                wall_clock,
            },
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

        // L8: one failed tx_id must REJECT the block, not silently shorten the
        // list. `filter_map` dropped failures, so `tx_ids` could come back
        // shorter than `block.transactions` — and those ids are what the Merkle
        // root and every storage index are built from. A short list means
        // committing a block whose transactions are not all indexed, with a
        // Merkle root that cannot match.
        let tx_ids: Vec<Hash256> = match block
            .transactions
            .iter()
            .map(|tx| tx.compute_tx_id(chain_id))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(task = "sync_import", "tx_id computation failed: {e}");
                return SyncImportResult::Rejected {
                    reason: format!("tx_id computation failed: {e}"),
                };
            }
        };

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

        // Post-commit integrity spot-check (single block).
        {
            let storage = self.storage.read();
            let spot = noble_storage::verify_chain_integrity(
                &*storage, chain_id,
                block.header.height, block.header.height,
            );
            if !spot.is_clean() {
                tracing::error!(
                    task = "integrity",
                    "SYNC-IMPORT INTEGRITY FAILURE at height {}: {}",
                    block.header.height,
                    spot.findings.iter()
                        .map(|f| format!("{:?}: {}", f.kind, f.detail))
                        .collect::<Vec<_>>()
                        .join("; "),
                );
            }
        }

        // Update consensus tip.
        self.consensus.write().update_tip_with_header(block.header.clone());

        // Block 1: clear stale cycle history.
        if block.header.height == 1 {
            self.clear_cycle_history_storage();
        }

        // Update chain_id if needed (all subsystems: atomic + consensus engine + network).
        if let Some(new_cid) = new_chain_id {
            self.update_chain_id(new_cid);
        }

        // Update network tip height.
        self.update_tip_height(block.header.height);

        // Remove committed txs from mempool — plus any conflicting tx that
        // spends an outpoint this block just consumed.
        if !tx_ids.is_empty() {
            self.evict_from_mempool(&block.transactions, &tx_ids);
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

        // Store vote witness from sync peer (if available).
        // Validate CBOR before storing: prevents corrupted/malicious data from propagating.
        if let Some(vd) = vote_data {
            match <noble_consensus::BlockVotes as noble_codec::NobleCbor>::from_cbor(vd) {
                Ok(parsed) => {
                    // H8/M10: a successful CBOR decode proves only that the
                    // bytes are well-formed. Previously the parsed value was
                    // discarded (`Ok(_parsed)`) and the blob stored as-is, so a
                    // peer could hand us any validator names it liked and we
                    // would persist them as this block's "legitimacy proof".
                    //
                    // Verify the signed certificate instead, when present: every
                    // vote must carry a valid signature and be bound to this
                    // block's candidate hash and cycle. A certificate that fails
                    // is DISCARDED rather than stored — the block itself already
                    // passed validation and commit, so refusing the witness data
                    // costs us a legitimacy record, not the chain.
                    //
                    // Scope limit (documented, do not overstate): this proves
                    // signed SUPPORT, not that it was the network majority at
                    // the time. Open consensus records no historical membership.
                    let witness_ok = match &parsed.certificate {
                        Some(cert) => {
                            if cert.candidate_hash != block_hash {
                                tracing::warn!(
                                    task = "sync",
                                    "discarding witness certificate for height {}: certificate names candidate {} but the block is {}",
                                    block.header.height,
                                    cert.candidate_hash,
                                    block_hash
                                );
                                false
                            } else {
                                match cert.verify() {
                                    Ok(witnesses) => {
                                        tracing::debug!(
                                            task = "sync",
                                            "verified {witnesses} witness signature(s) for synced block {}",
                                            block.header.height
                                        );
                                        true
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            task = "sync",
                                            "discarding unverifiable witness certificate for height {}: {e}",
                                            block.header.height
                                        );
                                        false
                                    }
                                }
                            }
                        }
                        // No certificate: tallies alone are unverifiable, so
                        // they are not stored as proof of anything.
                        None => {
                            tracing::debug!(
                                task = "sync",
                                "synced vote witness for height {} carries no certificate — not stored",
                                block.header.height
                            );
                            false
                        }
                    };

                    if !witness_ok {
                        // Fall through without storing.
                    } else {
                    let storage = self.storage.read();
                    if let Err(e) = storage.store_block_votes(block.header.height, vd) {
                        tracing::warn!(
                            task = "sync",
                            "failed to store synced vote witness for height {}: {e}",
                            block.header.height
                        );
                    } else {
                        tracing::debug!(
                            task = "sync",
                            "stored vote witness for synced block {}",
                            block.header.height
                        );
                    }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        task = "sync",
                        "discarding malformed vote witness for height {}: {e}",
                        block.header.height
                    );
                }
            }
        }

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
        .filter_map(|(tip_hash, (height, peer_count))| {
            let decoded = match hex::decode(&tip_hash) {
                Ok(d) if d.len() == 32 => d,
                Ok(_) => {
                    tracing::warn!(task = "fork_groups", "invalid tip_hash length: {}", tip_hash);
                    return None;
                }
                Err(e) => {
                    tracing::warn!(task = "fork_groups", "invalid tip_hash hex: {e}");
                    return None;
                }
            };
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&decoded);
            Some(noble_consensus::ForkInfo {
                tip_hash: Hash256::from_bytes(bytes),
                height,
                peer_count,
                is_local: tip_hash == local_tip_hex,
                has_chain_owner: owner_group.as_ref() == Some(&tip_hash),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Pure alignment decision tree — extracted from `compute_alignment` so the
/// state logic is unit-testable without a full `HealingManager`. The two lazy
/// closures preserve the caller's lock discipline: they are invoked only on
/// the branch that needs them (`dwell_active` → fork_resolver lock,
/// `majority` → storage lock, returning `(agreeing, ahead_same_chain)`).
fn decide_alignment(
    height: u64,
    connected_peers: usize,
    peers_with_tip: usize,
    highest_known: u64,
    has_proposals: bool,
    dwell_active: impl FnOnce() -> bool,
    majority: impl FnOnce() -> (usize, usize),
) -> AlignmentState {
    if height == 0 && connected_peers == 0 {
        AlignmentState::Isolated
    } else if height == 0 && !has_proposals {
        AlignmentState::Bootstrapping
    } else if height == 0 {
        AlignmentState::Creating
    } else if connected_peers == 0 {
        AlignmentState::Isolated
    } else if highest_known.saturating_sub(height) > ALIGNMENT_SYNC_GAP_BLOCKS {
        AlignmentState::Syncing
    } else if peers_with_tip == 0 {
        // Connected peers but none have announced chain tips yet. Evidence-free
        // is NOT aligned — report Verifying until at least one tip arrives.
        // Status is solicited on connect and after peer-state wipes, so this
        // state lasts seconds, not announce-cycles.
        AlignmentState::Verifying
    } else if dwell_active() {
        // Healing fork override: dwell timer running → force Diverged.
        AlignmentState::Diverged
    } else {
        let (agreeing, ahead_same_chain) = majority();
        // agreeing + self vs peers-with-tip + self.
        // Peers without chain_tip (pre-announce) are excluded from both sides.
        let local_side = agreeing + 1;
        let total = peers_with_tip + 1;
        if local_side * 2 > total {
            if ahead_same_chain > 0 {
                AlignmentState::CatchingUp
            } else {
                AlignmentState::Aligned
            }
        } else {
            AlignmentState::Diverged
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noble_api::lock_order::LockOrder;
    use noble_storage::MemoryStorage;

    // ── decide_alignment: the previously-untested state tree ──
    // Closure probes: `dwell(false)` / `maj(a, ahead)` return canned values;
    // `unreachable_dwell`/`unreachable_maj` assert the lazy branches are NOT
    // taken on early exits.

    fn dwell(v: bool) -> impl FnOnce() -> bool {
        move || v
    }
    fn maj(agreeing: usize, ahead: usize) -> impl FnOnce() -> (usize, usize) {
        move || (agreeing, ahead)
    }
    fn unreachable_dwell() -> bool {
        panic!("dwell closure must not run on early-exit branches")
    }
    fn unreachable_maj() -> (usize, usize) {
        panic!("majority closure must not run on early-exit branches")
    }

    #[test]
    fn alignment_isolated_when_no_peers() {
        assert_eq!(
            decide_alignment(0, 0, 0, 0, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Isolated
        );
        assert_eq!(
            decide_alignment(5, 0, 0, 5, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Isolated
        );
    }

    #[test]
    fn alignment_bootstrapping_and_creating_at_height_zero() {
        assert_eq!(
            decide_alignment(0, 2, 0, 0, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Bootstrapping
        );
        assert_eq!(
            decide_alignment(0, 2, 0, 0, true, unreachable_dwell, unreachable_maj),
            AlignmentState::Creating
        );
    }

    #[test]
    fn alignment_verifying_when_peers_have_no_tips() {
        // THE fix: connected but evidence-free must NOT claim Aligned.
        // (Previously returned Aligned — two nodes 22 blocks apart both
        // showed "ALIGNED".)
        assert_eq!(
            decide_alignment(2751, 1, 0, 2751, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Verifying
        );
    }

    #[test]
    fn alignment_gap_threshold_is_two_blocks() {
        // Gap ≤ 2 (one-block tip race territory): not Syncing.
        for gap in 0..=ALIGNMENT_SYNC_GAP_BLOCKS {
            assert_eq!(
                decide_alignment(100, 1, 1, 100 + gap, false, dwell(false), maj(1, 0)),
                AlignmentState::Aligned,
                "gap {gap} must stay Aligned"
            );
        }
        // Gap 3: Syncing — no more hiding hours of lag behind a green badge.
        assert_eq!(
            decide_alignment(100, 1, 1, 100 + ALIGNMENT_SYNC_GAP_BLOCKS + 1, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Syncing
        );
    }

    #[test]
    fn alignment_dwell_forces_diverged() {
        assert_eq!(
            decide_alignment(100, 2, 2, 100, false, dwell(true), unreachable_maj),
            AlignmentState::Diverged
        );
    }

    #[test]
    fn alignment_majority_paths() {
        // Majority agrees, someone ahead within tolerance → CatchingUp.
        assert_eq!(
            decide_alignment(100, 2, 2, 101, false, dwell(false), maj(2, 1)),
            AlignmentState::CatchingUp
        );
        // Majority agrees, nobody ahead → Aligned.
        assert_eq!(
            decide_alignment(100, 2, 2, 100, false, dwell(false), maj(2, 0)),
            AlignmentState::Aligned
        );
        // Minority (0 agreeing of 2 with tips: 1+0=1 vs 3) → Diverged.
        assert_eq!(
            decide_alignment(100, 2, 2, 100, false, dwell(false), maj(0, 0)),
            AlignmentState::Diverged
        );
    }

    fn make_healing_manager() -> HealingManager<MemoryStorage> {
        let storage = Arc::new(TrackedRwLock::new(LockOrder::Storage, MemoryStorage::new()));
        let consensus = Arc::new(TrackedRwLock::new(LockOrder::Consensus, CycleEngine::new(
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
        let mempool = Arc::new(TrackedMutex::new(LockOrder::Mempool, Mempool::new(mempool_config)));
        let peer_info = Arc::new(TrackedRwLock::new(LockOrder::PeerInfo, HashMap::new()));
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

    fn wire_io(h: &mut HealingManager<MemoryStorage>) -> mpsc::Receiver<NetworkCommand> {
        let (net_tx, net_rx) = mpsc::channel::<NetworkCommand>(32);
        let (nb_tx, _nb_rx) = broadcast::channel(32);
        let (cp_tx, _cp_rx) = broadcast::channel(32);
        h.set_io_channels(net_tx, nb_tx, cp_tx, None);
        net_rx
    }

    /// A4: consecutive sync-request failures to the only peer escalate to a
    /// forced disconnect (which the node's reconnect loop turns into a fresh
    /// session) instead of retrying the same wedged channel forever.
    #[test]
    fn sync_failures_escalate_to_disconnect() {
        let mut h = make_healing_manager();
        let mut net_rx = wire_io(&mut h);
        let peer = vec![1u8, 2, 3];
        h.sync_state = SyncState::AwaitingManifest {
            peer: peer.clone(),
            target: 100,
            requested_at: 0,
        };

        // Failure 1: below threshold → retry same peer, streak = 1, no disconnect.
        h.on_sync_request_failed(&peer, 10);
        assert_eq!(h.sync_failure_streak, 1);

        // Failure 2: streak reaches SYNC_PEER_MAX_FAILURES → disconnect + reset.
        h.on_sync_request_failed(&peer, 20);
        assert_eq!(h.sync_failure_streak, 0, "streak resets after forcing a reconnect");

        let mut saw_disconnect = false;
        while let Ok(cmd) = net_rx.try_recv() {
            if let NetworkCommand::DisconnectPeer(p) = cmd {
                if p == peer {
                    saw_disconnect = true;
                }
            }
        }
        assert!(
            saw_disconnect,
            "a wedged sync peer must be disconnected to force a fresh connection"
        );
    }

    /// K3-04: repeated failed tip substantiation quarantines the peer's
    /// ADVERTISED heights with exponential backoff; success clears it.
    #[test]
    fn tip_quarantine_lifecycle() {
        let mut h = make_healing_manager();
        let _net_rx = wire_io(&mut h);
        let peer = vec![7u8, 7, 7];
        let hex_pid = hex::encode(&peer);
        let now = 1_000_000u64;

        // First failure: recorded, but below the quarantine threshold.
        h.record_tip_failure(&peer, now);
        assert!(!h.is_tip_quarantined(&hex_pid, now));

        // Second failure: quarantine starts (base 60s).
        h.record_tip_failure(&peer, now);
        assert!(h.is_tip_quarantined(&hex_pid, now));
        assert!(h.is_tip_quarantined(&hex_pid, now + 59));
        assert!(!h.is_tip_quarantined(&hex_pid, now + 61), "base quarantine is 60s");

        // Third failure: exponential — 120s.
        h.record_tip_failure(&peer, now + 100);
        assert!(h.is_tip_quarantined(&hex_pid, now + 100 + 119));
        assert!(!h.is_tip_quarantined(&hex_pid, now + 100 + 121));

        // A validated block from the peer clears everything.
        h.clear_tip_failures(&peer);
        assert!(!h.is_tip_quarantined(&hex_pid, now));
        h.record_tip_failure(&peer, now);
        assert!(!h.is_tip_quarantined(&hex_pid, now), "history restarts after clear");
    }

    /// K3-04: sync selection prefers VERIFIED heights and ignores advertised
    /// claims from quarantined peers.
    #[test]
    fn sync_selection_prefers_verified_and_skips_quarantined() {
        let mut h = make_healing_manager();
        let _net_rx = wire_io(&mut h);
        let real_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mk = |id: &str, adv: Option<u64>, ver: Option<u64>| PeerInfoEntry {
            peer_id: id.to_string(),
            direction: "outbound".to_string(),
            addr: String::new(),
            connected_at: 0,
            ban_score: 0,
            misbehavior_categories: Vec::new(),
            chain_tip_height: adv,
            chain_tip_hash: None,
            verified_height: ver,
            proposed_height: None,
            identity_key: None,
            node_name: None,
            latency_ms: None,
            last_ban_reason: None,
            chain_id: None,
            min_fee_rate: None,
        };
        let a = hex::encode([0xAAu8; 4]);
        let b = hex::encode([0xBBu8; 4]);
        let c = hex::encode([0xCCu8; 4]);
        {
            let mut info = h.peer_info.write();
            info.insert(a.clone(), mk(&a, Some(100), None)); // loudest claim
            info.insert(b.clone(), mk(&b, Some(50), None));
            info.insert(c.clone(), mk(&c, Some(30), Some(30))); // proven source
        }

        // Verified beats a louder unverified claim.
        let (peer, height) = h.find_best_sync_peer(10);
        assert_eq!(peer, Some(hex::decode(&c).unwrap()), "verified source must win");
        assert_eq!(height, 30);

        // Without any verified source, the loudest NON-quarantined claim wins:
        // quarantine A (2 failures) -> B (50) is selected, not A (100).
        {
            let mut info = h.peer_info.write();
            info.get_mut(&c).unwrap().verified_height = None;
        }
        let a_bytes = hex::decode(&a).unwrap();
        h.record_tip_failure(&a_bytes, real_now);
        h.record_tip_failure(&a_bytes, real_now);
        assert!(h.is_tip_quarantined(&a, real_now));
        let (peer, height) = h.find_best_sync_peer(10);
        assert_eq!(peer, Some(hex::decode(&b).unwrap()), "quarantined claim must be skipped");
        assert_eq!(height, 50);
    }

    /// A4 regression: a failure for a peer we are NOT syncing from is ignored
    /// (no escalation, no disconnect).
    #[test]
    fn sync_failure_for_other_peer_is_ignored() {
        let mut h = make_healing_manager();
        let _net_rx = wire_io(&mut h);
        h.sync_state = SyncState::AwaitingManifest {
            peer: vec![1, 2, 3],
            target: 100,
            requested_at: 0,
        };
        h.on_sync_request_failed(&[9, 9, 9], 10);
        assert_eq!(h.sync_failure_streak, 0, "unrelated peer must not bump the streak");
    }

    /// A6 regression: the stall watchdog must NOT fire (no forced recovery) when
    /// we are not behind any peer — empty peer_info means no peer ahead.
    #[test]
    fn stall_watchdog_silent_when_not_behind() {
        let mut h = make_healing_manager();
        let mut net_rx = wire_io(&mut h);
        h.check_sync_stall(0, 1_000_000);
        h.check_sync_stall(0, 1_000_000 + SYNC_STALL_ALARM_SECS + 10);
        assert!(
            net_rx.try_recv().is_err(),
            "no recovery action when not behind a peer"
        );
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
        let result = hm.detect_forks();
        assert_eq!(result.dwell_before, 0);
        assert_eq!(result.dwell_after, 0);
    }

    #[test]
    fn fork_eval_single_group_no_fork() {
        let mut hm = make_healing_manager();
        let result = hm.detect_forks();
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
                verified_height: None,
                chain_id: Some(0xDEADBEEF), // different chain
                identity_key: None,
                proposed_height: None,
                node_name: None,
                latency_ms: None,
                last_ban_reason: None,
                min_fee_rate: None,
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
    fn chain_adoption_via_clue_resets_state() {
        let mut hm = make_healing_manager();
        hm.sync_state = SyncState::AwaitingManifest {
            peer: vec![1, 2, 3],
            target: 10,
            requested_at: 50,
        };
        hm.fork_visible = true;
        hm.fork_common_ancestor = Some((5, [0xAA; 32]));
        hm.chain_vote_weight.store(100, Ordering::Relaxed);
        // Ingest adoption clue and evaluate.
        hm.ingest_clue(HealingClue::CrossChainAdopt {
            target_chain_id: 0xDEADBEEF,
            reason: "test".into(),
        });
        hm.evaluate_and_execute();
        assert!(matches!(hm.sync_state, SyncState::Idle));
        assert!(!hm.fork_visible);
        assert!(hm.fork_common_ancestor.is_none());
        assert_eq!(hm.chain_vote_weight.load(Ordering::Relaxed), 0);
        // After evaluate_and_execute, phase should be Syncing (post-adoption).
        assert_eq!(hm.healing_phase, HealingPhase::Syncing);
    }

    #[test]
    fn evaluate_no_clues_is_noop() {
        let mut hm = make_healing_manager();
        hm.evaluate_and_execute();
        assert_eq!(hm.healing_phase, HealingPhase::Idle);
    }

    #[test]
    fn evaluate_ignores_clues_during_resolving() {
        let mut hm = make_healing_manager();
        hm.healing_phase = HealingPhase::Resolving;
        hm.ingest_clue(HealingClue::ForkResolve {
            target_hash: Hash256::ZERO,
            target_height: 5,
            reason: "test".into(),
        });
        hm.evaluate_and_execute();
        // Phase unchanged — clues deferred.
        assert_eq!(hm.healing_phase, HealingPhase::Resolving);
    }

    #[test]
    fn advance_sync_blocked_during_resolving() {
        let mut hm = make_healing_manager();
        hm.healing_phase = HealingPhase::Resolving;
        hm.advance_sync(100);
        // Should remain Idle sync state — conveyor blocked.
        assert!(matches!(hm.sync_state, SyncState::Idle));
    }

    // Equivocation detection is tested in integration tests where
    // NodeAnnounce can be properly signed.
}
