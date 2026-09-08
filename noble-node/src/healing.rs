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
use noble_api::state::TipLegitimacy;
use noble_consensus::SegmentLegitimacy;
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
    /// The peer answered and we rejected the block, `attempts` times.
    Failed { attempts: u8 },
    /// The peer never answered after `retries` re-requests. Distinct from
    /// `Failed`: nothing was delivered, so there is nothing to blame the block
    /// for and the operator message must not claim a validation failure.
    Stalled { retries: u64 },
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
/// R2: how long a peer whose chain we refused is skipped as a sync source.
/// Bounded so a peer that later re-founds correctly is not shunned forever.
const REJECTED_SOURCE_TTL: std::time::Duration = std::time::Duration::from_secs(600);
/// D3: ceiling for ancestor-discovery backoff — one cycle. Retries never stop,
/// they only slow down, so the state stays transient without polling hard.
const ANCESTOR_RETRY_MAX_SECS: u64 = 960;

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
    /// Our own segment is self-voted and a peer holds the witnessed prefix we
    /// share: roll back to it and adopt nothing.
    AbandonSelfVoted {
        to_height: u64,
        first_solo: u64,
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
    /// Abandon our self-voted segment back to the witnessed prefix; no adoption.
    AbandonSelfVoted {
        to_height: u64,
        first_solo: u64,
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

    // Priority 2b: Abandon a self-voted local segment (rollback only, no adoption).
    for clue in clues {
        if let HealingClue::AbandonSelfVoted { to_height, first_solo, reason } = clue {
            return HealingAction::AbandonSelfVoted {
                to_height: *to_height,
                first_solo: *first_solo,
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
    /// Blocks handed to us for import, accepted or rejected. See
    /// [`HealingManager::sync_blocks_delivered`].
    sync_blocks_delivered: Arc<AtomicU64>,
    /// R2: peers whose chain we refused, with when we refused it. Skipped as
    /// sync sources until [`REJECTED_SOURCE_TTL`] passes, so a peer that later
    /// re-founds correctly is not shunned forever. This replaced a halt: the
    /// node used to stop entirely rather than just stop pulling from one peer.
    rejected_sync_sources: HashMap<Vec<u8>, std::time::Instant>,
    /// D3: `(unix_secs_of_last_send, attempt_count)` for ancestor discovery,
    /// so it retries with backoff while `fork_common_ancestor` is unknown.
    last_ancestor_request: Option<(u64, u32)>,

    // ── Legitimacy assessment (F3–F6) ──
    /// Rival segments being fetched for assessment, keyed by peer id bytes.
    awaiting_assessment: HashMap<Vec<u8>, AssessmentRun>,
    /// Completed verdicts keyed by the rival's tip hash (hex). A verdict is
    /// about a specific tip, so it needs no invalidation: a peer that moves
    /// its tip simply has no verdict until assessed again.
    assessments: HashMap<String, SegmentLegitimacy>,
    /// F5: the one case in which under-witnessed blocks may be imported —
    /// the resolver decided a self-voted rival is the best chain available
    /// (only solo runs exist and it out-grades ours). `(peer, tip hash hex)`.
    solo_adoption_permit: Option<(Vec<u8>, String)>,
    /// F4: cached verdict on our own segment: `((ancestor, tip), legitimacy, witnessed_prefix_end)`.
    local_legitimacy_cache: Option<((u64, [u8; 32]), SegmentLegitimacy, u64)>,

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
    /// Create a new HealingManager with default (no chain yet) state.
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
            sync_blocks_delivered: Arc::new(AtomicU64::new(0)),
            rejected_sync_sources: HashMap::new(),
            last_ancestor_request: None,
            awaiting_assessment: HashMap::new(),
            assessments: HashMap::new(),
            solo_adoption_permit: None,
            local_legitimacy_cache: None,
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
            HealingClue::AbandonSelfVoted { to_height, first_solo, .. } =>
                format!("abandon_self_voted (solo from {first_solo}, back to {to_height})"),
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
            HealingAction::AbandonSelfVoted { to_height, first_solo, reason } => {
                self.broadcast_event(serde_json::json!({
                    "event": "healing_action",
                    "action": "abandon_self_voted",
                    "to_height": to_height,
                    "first_solo": first_solo,
                    "reason": &reason,
                    "clue_count": clues.len(),
                }));
                self.healing_phase = HealingPhase::Resolving;
                self.execute_abandon(to_height, first_solo, &reason);
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

    /// Shared L11 integrity halt. Exposed so `Node` and tests observe the same
    /// flag that forces [`AlignmentState::Blocked`].

    /// Returns true if we are in the Fetching state and this height is in the manifest.
    pub fn is_sync_block(&self, height: u64) -> bool {
        if let SyncState::Fetching { ref manifest, .. } = self.sync_state {
            manifest.iter().any(|e| e.height == height)
        } else {
            false
        }
    }

    /// Hash the current manifest promised for `height`, if we are in
    /// manifest-driven sync.
    fn manifest_hash_for(&self, height: u64) -> Option<[u8; 32]> {
        if let SyncState::Fetching { ref manifest, .. } = self.sync_state {
            manifest
                .iter()
                .find(|e| e.height == height)
                .map(|e| e.hash)
                .filter(|h| *h != [0u8; 32])
        } else {
            None
        }
    }

    /// First height to request when syncing.
    ///
    /// A node with no chain must start at GENESIS — it needs the foundation
    /// before anything can descend from it. `our_height + 1` is only correct
    /// once we already hold a chain; used unconditionally it silently skips
    /// genesis, and every block after it is then unanchorable.
    fn next_height_to_fetch(&self, our_height: u64) -> u64 {
        if self.consensus.read().has_chain() {
            our_height + 1
        } else {
            noble_core::GENESIS_HEIGHT
        }
    }

    /// Peer we are currently syncing from, if any.
    fn sync_peer(&self) -> Option<&Vec<u8>> {
        match &self.sync_state {
            SyncState::Fetching { peer, .. } | SyncState::AwaitingManifest { peer, .. } => Some(peer),
            SyncState::Idle => None,
        }
    }

    /// R2: stop using the current peer as a sync source and stay on our chain.
    ///
    /// Replaces the old operator halt. A peer whose chain we refuse is a
    /// statement about *that peer*; this node keeps its own chain, keeps
    /// proposing, and simply stops pulling from that source. The peer is
    /// remembered so the same chain is not immediately re-attempted, and the
    /// entry ages out so a peer that re-founds correctly can be used again.
    fn drop_sync_source(&mut self, reason: &str) {
        if let Some(peer) = self.sync_peer().cloned() {
            tracing::warn!(
                task = "sync",
                peer = %hex::encode(&peer),
                "refusing this peer's chain ({reason}) — dropping it as a sync source and \
                 continuing on our own chain"
            );
            self.rejected_sync_sources.insert(peer, std::time::Instant::now());
        } else {
            tracing::warn!(
                task = "sync",
                "refusing an offered chain ({reason}) — continuing on our own chain"
            );
        }
    }

    /// True if this peer's chain was refused recently enough to still skip.
    fn is_rejected_sync_source(&self, peer: &[u8]) -> bool {
        self.rejected_sync_sources
            .get(peer)
            .is_some_and(|at| at.elapsed() < REJECTED_SOURCE_TTL)
    }

    /// R3: ask peers for genesis rather than halting for an operator.
    ///
    /// Genesis is servable over `GetBlocks` like any other block, so a node
    /// without one requests it. With no peers to ask there is nothing to do
    /// here — the engine keeps proposing a genesis candidate under the normal
    /// Dual-Witness rules, which is the founding path, unchanged.
    fn request_genesis_from_peers(&mut self) {
        self.rejected_sync_sources
            .retain(|_, at| at.elapsed() < REJECTED_SOURCE_TTL);
        let (peer, _) = self.select_sync_peer(noble_core::GENESIS_HEIGHT, None);
        match peer {
            Some(p) if !self.is_rejected_sync_source(&p) => {
                tracing::info!(
                    task = "sync",
                    peer = %hex::encode(&p),
                    "no genesis yet — requesting it over the vote-carrying path"
                );
                self.send_network(NetworkCommand::RequestBlockByHeight {
                    peer_id: p,
                    height: noble_core::GENESIS_HEIGHT,
                });
            }
            _ => {
                tracing::info!(
                    task = "sync",
                    "no genesis and no usable peer to ask — continuing to participate in founding"
                );
            }
        }
    }

    /// Returns true if actively syncing (not Idle).
    pub fn is_syncing(&self) -> bool { !matches!(self.sync_state, SyncState::Idle) }

    // ── Legitimacy (F3–F7) ──────────────────────────────────────────────────

    /// Hex tip hash currently advertised by `peer`, if known.
    fn peer_tip_hex(&self, peer: &[u8]) -> Option<String> {
        let hex_pid = hex::encode(peer);
        self.peer_info.read().get(&hex_pid).and_then(|e| e.chain_tip_hash.clone())
    }

    /// F2: clear any sync-source rejection for the peer holding `tip`.
    ///
    /// The `ChainMismatch` that triggered resolution drops the serving peer, so
    /// by the time the resolver decides to adopt that peer's chain it is sitting
    /// in `rejected_sync_sources` and `select_sync_peer` refuses to pick it.
    /// A decided adoption overrides an earlier refusal of the same chain.
    fn readmit_adoption_source(&mut self, tip: Hash256) {
        if let Some(peer) = self.peer_for_tip(tip) {
            if self.rejected_sync_sources.remove(&peer).is_some() {
                tracing::info!(
                    task = "fork_resolution",
                    peer = %hex::encode(&peer),
                    "re-admitting sync source: its chain was refused earlier, and has now been \
                     judged the one to adopt"
                );
            }
        }
    }

    /// A connected same-chain peer advertising `tip` as its chain tip.
    fn peer_for_tip(&self, tip: Hash256) -> Option<Vec<u8>> {
        let tip_hex = hex::encode(tip.as_bytes());
        let peers = self.peer_info.read();
        peers
            .values()
            .find(|e| e.chain_tip_hash.as_deref() == Some(tip_hex.as_str()))
            .and_then(|e| hex::decode(&e.peer_id).ok())
    }

    /// Verdict on a rival tip, from completed assessments only. `Hash256::ZERO`
    /// (the `SyncChainMismatch` path) resolves to the current sync peer's tip.
    fn rival_legitimacy_for(&self, target: Hash256) -> SegmentLegitimacy {
        let tip_hex = if target == Hash256::ZERO {
            match self.sync_peer().and_then(|p| self.peer_tip_hex(p)) {
                Some(t) => t,
                None => return SegmentLegitimacy::Unknown,
            }
        } else {
            hex::encode(target.as_bytes())
        };
        self.assessments.get(&tip_hex).copied().unwrap_or(SegmentLegitimacy::Unknown)
    }

    /// F4: legitimacy of OUR segment above `ancestor`, re-verifying every
    /// stored certificate. Returns the verdict and `witnessed_prefix_end`.
    pub fn local_segment_legitimacy(&self, ancestor: u64) -> (SegmentLegitimacy, u64) {
        let (tip_height, tip_hash) = self.consensus.read().chain_tip();
        let key = (ancestor, tip_hash.0);
        if let Some((k, leg, end)) = &self.local_legitimacy_cache {
            if *k == key {
                return (*leg, *end);
            }
        }
        if tip_height <= ancestor {
            return (SegmentLegitimacy::NotContesting, tip_height);
        }
        let required = self.consensus.read().min_unique_voters();
        let validators = self
            .consensus
            .read()
            .validator_snapshot()
            .map(|s| s.count)
            .unwrap_or(required)
            .max(required);
        let staged: Vec<StagedBlock> = {
            let storage = self.storage.read();
            (ancestor + 1..=tip_height)
                .map(|h| {
                    let hash = storage.get_block_hash_by_height(h).unwrap_or(Hash256::ZERO);
                    let proposer = storage
                        .get_block_header(&hash)
                        .map(|hd| hd.validator_id.to_wire_bytes())
                        .unwrap_or_default();
                    let facts = storage
                        .get_block_votes(h)
                        .ok()
                        .flatten()
                        .and_then(|raw| certificate_facts(Some(&raw), hash));
                    StagedBlock::from_facts(h, hash, proposer, facts)
                })
                .collect()
        };
        let (leg, end) = grade_segment(&staged, ancestor, required, validators);
        (leg, end)
    }

    /// F3: begin fetching `(from, to]` of the rival that advertises `tip`,
    /// with votes, for assessment. Nothing is adopted until it completes.
    fn start_assessment(&mut self, tip: Hash256, from: u64, to: u64) {
        let Some(peer) = self.peer_for_tip(tip) else { return };
        if self.awaiting_assessment.contains_key(&peer) {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut run = AssessmentRun {
            tip_hex: hex::encode(tip.as_bytes()),
            from,
            to,
            staged: std::collections::BTreeMap::new(),
            requested: HashMap::new(),
        };
        for h in from + 1..=to {
            run.requested.insert(h, (now, 1));
            self.send_network(NetworkCommand::RequestBlockByHeight { peer_id: peer.clone(), height: h });
        }
        tracing::info!(
            task = "fork_assessment",
            peer = %hex::encode(&peer),
            from, to,
            "assessing rival segment from its certificates before any decision"
        );
        self.awaiting_assessment.insert(peer, run);
    }

    /// True if a `BlockReceived` from `peer` at `height` belongs to an
    /// assessment and must NOT be routed to sync import.
    pub fn is_assessment_block(&self, peer: &[u8], height: u64) -> bool {
        self.awaiting_assessment
            .get(peer)
            .is_some_and(|r| height > r.from && height <= r.to && !r.staged.contains_key(&height))
    }

    /// F3: record one assessed block. Verifies the proposer signature and the
    /// witness certificate; completes the run when the range is full.
    pub fn assess_block(&mut self, peer: &[u8], block: &noble_core::Block, vote_data: Option<&[u8]>) {
        let Some(run) = self.awaiting_assessment.get_mut(peer) else { return };
        let h = block.header.height;
        if h <= run.from || h > run.to || run.staged.contains_key(&h) {
            return;
        }
        let hash = block.header.compute_block_hash().unwrap_or(Hash256::ZERO);
        // Proposer identity is only as good as the block signature (B8).
        let proposer_ok = block
            .header
            .compute_signing_message()
            .ok()
            .and_then(|m| block.header.validator_id.verify(&m, &block.header.validator_sig).ok())
            .is_some();
        let proposer = if proposer_ok { block.header.validator_id.to_wire_bytes() } else { Vec::new() };
        let facts = certificate_facts(vote_data, hash);
        run.staged.insert(h, StagedBlock::from_facts(h, hash, proposer, facts));
        run.requested.remove(&h);
        if run.staged.len() as u64 == run.to - run.from {
            self.complete_assessment(peer);
        }
    }

    /// F3: bounded lifetime. Re-request stale heights; after the retry budget
    /// an unserved block is scored unprovable (w = 0) and the run completes.
    fn tick_assessments(&mut self, now: u64) {
        let peers: Vec<Vec<u8>> = self.awaiting_assessment.keys().cloned().collect();
        for peer in peers {
            let mut exhausted: Vec<u64> = Vec::new();
            let mut retry: Vec<u64> = Vec::new();
            if let Some(run) = self.awaiting_assessment.get_mut(&peer) {
                for (h, (at, attempts)) in run.requested.iter_mut() {
                    if now.saturating_sub(*at) < SYNC_RETRY_SECS {
                        continue;
                    }
                    if *attempts >= SYNC_MAX_BLOCK_RETRIES {
                        exhausted.push(*h);
                    } else {
                        *attempts += 1;
                        *at = now;
                        retry.push(*h);
                    }
                }
                for h in &exhausted {
                    run.requested.remove(h);
                    run.staged.insert(*h, StagedBlock::from_facts(*h, Hash256::ZERO, Vec::new(), None));
                }
            }
            for h in retry {
                self.send_network(NetworkCommand::RequestBlockByHeight { peer_id: peer.clone(), height: h });
            }
            let done = self
                .awaiting_assessment
                .get(&peer)
                .is_some_and(|r| r.staged.len() as u64 == r.to - r.from);
            if done {
                self.complete_assessment(&peer);
            }
        }
    }

    fn complete_assessment(&mut self, peer: &[u8]) {
        let Some(run) = self.awaiting_assessment.remove(peer) else { return };
        let required = self.consensus.read().min_unique_voters();
        let validators = self
            .consensus
            .read()
            .validator_snapshot()
            .map(|s| s.count)
            .unwrap_or(required)
            .max(required);
        let staged: Vec<StagedBlock> = run.staged.into_values().collect();
        let (leg, _) = grade_segment(&staged, run.from, required, validators);
        tracing::info!(
            task = "fork_assessment",
            peer = %hex::encode(peer),
            tip = %run.tip_hex,
            legitimacy = leg.label(),
            "rival segment assessed"
        );
        // Mirror onto every peer advertising this tip, for RPC/GUI display.
        {
            let mut peers = self.peer_info.write();
            for e in peers.values_mut() {
                if e.chain_tip_hash.as_deref() == Some(run.tip_hex.as_str()) {
                    e.tip_legitimacy = Some(tip_legitimacy_view(&run.tip_hex, &leg));
                }
            }
        }
        self.broadcast_event(serde_json::json!({
            "event": "fork_assessed",
            "tip_hash": run.tip_hex,
            "from_height": run.from,
            "to_height": run.to,
            "rival_legitimacy": leg.label(),
            "detail": format!("{leg:?}"),
        }));
        self.assessments.insert(run.tip_hex, leg);
    }

    /// F7: abandon our self-voted segment back to the witnessed prefix. No
    /// adoption, no operator branch: by F1 the rollback floor only anchors on
    /// witnessed blocks, so `to_height >= floor` holds by construction.
    fn execute_abandon(&mut self, to_height: u64, first_solo: u64, reason: &str) {
        let from = self.consensus.read().chain_tip().0;
        let floor = self.rollback_floor();
        debug_assert!(
            to_height >= floor,
            "witnessed prefix end {to_height} below rollback floor {floor}: a solo block was finalized"
        );
        let target = to_height.max(floor);
        tracing::warn!(
            task = "fork_resolution",
            from, to = target, first_solo,
            "abandoning self-voted segment: {reason}"
        );
        self.rollback_to(target);
        self.clear_cycle_history_storage();
        self.fork_visible = false;
        self.fork_common_ancestor = None;
        self.local_legitimacy_cache = None;
        self.clear_pending_proposals();
        self.reset_sync_idle();
        self.broadcast_event(serde_json::json!({
            "event": "self_voted_abandoned",
            "from": from,
            "to": target,
            "discarded": from.saturating_sub(target),
            "first_solo": first_solo,
            "reason": reason,
        }));
        self.request_sync();
    }

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
            self.consensus.read().has_chain(),
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

        // R1: there is no halted state to override the topology-derived one.
        // Every condition that used to force `Blocked` now resolves itself, so
        // the state computed above is the state reported.
        let snapshot = AlignmentSnapshot {
            state,
            height,
            peer_count: connected_peers,
            highest_known,
            progress,
            cycles_remaining,
            blocked_reason: None,
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
        // Rolling back TO genesis is an ordinary rollback — genesis is a real
        // block at a real height. `height > 0` treated height 0 as "no target",
        // which under the new numbering is genesis itself.
        let genesis_height = storage.genesis().ok().flatten().map(|g| g.height);
        let result = match genesis_height {
            Some(gh) if height > gh => storage.rollback_to_height(height, chain_id),
            Some(_) => storage.force_reset_to_genesis(chain_id),
            None => storage.force_reset_to_genesis(chain_id),
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
        // A chain consisting only of genesis has tip height 0 and a perfectly
        // real tip header. Gating on `height > 0` degraded B2/B3/B5 for it.
        let tip_header = if tip.block_hash != Hash256::ZERO {
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
        // now stale (blockchain hop, or uninitialized→real transition). Purge.
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
        // F5: a solo-adoption permit is scoped to one sync — but "one sync"
        // means the PERMITTED sync, not any reset that happens to pass through.
        // Clearing unconditionally killed a permit granted milliseconds earlier
        // by `execute_resolution` (which resets on its way out), and any
        // `check_sync_stall` alarm firing before the first block imported would
        // do the same — recreating the deadlock with a different trigger. So
        // the permit dies only when the sync it authorised is the one ending.
        let permitted_sync_ending = match (&self.solo_adoption_permit, &self.sync_state) {
            (Some((permit_peer, _)), SyncState::AwaitingManifest { peer, .. })
            | (Some((permit_peer, _)), SyncState::Fetching { peer, .. }) => permit_peer == peer,
            _ => false,
        };
        if permitted_sync_ending {
            self.solo_adoption_permit = None;
        } else if self.solo_adoption_permit.is_some() {
            tracing::debug!(
                task = "sync",
                "solo-adoption permit preserved across a reset of an unrelated sync"
            );
        }
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
                        _ if !self.consensus.read().has_chain() => SyncImportKind::Bootstrap,
                        _ => SyncImportKind::CatchUp,
                    };
                    // Transition healing phase to Syncing.
                    self.healing_phase = HealingPhase::Syncing;
                    tracing::info!(
                        task = "sync",
                        "peer {} at height {}, we're at {} ({} behind) — requesting manifest",
                        hex::encode(&peer), best_height, our_height, behind,
                    );
                    let start = self.next_height_to_fetch(our_height);
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
                                    // Mark as stalled so the conveyor switches
                                    // peer. NOT `Failed { attempts: MAX }` —
                                    // that made a peer which never answered
                                    // report as "failed 5 times", conflating
                                    // "no block ever arrived" with "we rejected
                                    // it five times". Different causes, and
                                    // only one of them is the peer's fault.
                                    if let SyncState::Fetching { ref mut manifest, .. } = self.sync_state {
                                        manifest[cursor].status = EntryStatus::Stalled { retries: retry_count };
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
                        EntryStatus::Stalled { retries } => {
                            // The peer never delivered this block. Say exactly
                            // that — the old code reported it as N validation
                            // failures, sending operators to look at a block
                            // they had never received.
                            let stalled_h = manifest[cursor].height;
                            tracing::warn!(
                                task = "sync",
                                "block {} never delivered after {} retries — ingesting sync stall clue",
                                stalled_h, retries,
                            );
                            self.ingest_clue(HealingClue::SyncStall {
                                stalled_height: stalled_h,
                                target_height: target,
                                reason: format!(
                                    "block {stalled_h} not delivered by peer after {retries} retries"
                                ),
                            });
                            self.reset_sync_idle();
                        }
                        EntryStatus::Failed { attempts } if attempts >= SYNC_MAX_BLOCK_RETRIES => {
                            // Too many rejections — ingest SyncStall clue so
                            // evaluate_and_execute can trigger fork resolution
                            // instead of endlessly restarting sync.
                            let stalled_h = manifest[cursor].height;
                            tracing::warn!(
                                task = "sync",
                                "block {} rejected {} times — ingesting sync stall clue",
                                stalled_h, attempts,
                            );
                            self.ingest_clue(HealingClue::SyncStall {
                                stalled_height: stalled_h,
                                target_height: target,
                                reason: format!(
                                    "block {stalled_h} rejected {attempts} times, sync cannot advance"
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
                        let start = self.next_height_to_fetch(our_height);
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
        let start = self.next_height_to_fetch(our_height);
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

        // A block hash is a SHA-256 digest; all-zeros cannot occur. A peer
        // sending one is either broken or trying to blank the hash we bind
        // genesis against, so the manifest is refused rather than trusted in
        // part.
        if entries.iter().any(|(_, hash)| matches!(hash, Some(h) if *h == [0u8; 32])) {
            tracing::warn!(
                task = "sync",
                "manifest contains an all-zero block hash — refusing it"
            );
            self.reset_sync_idle();
            return;
        }

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
                        // Importing a block is proof the blocking condition is
                        // gone. Cleared here rather than in `reset_sync_idle`,
                        // which the blocking paths themselves call.

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
                    SyncImportResult::Rejected { reason, kind } => match kind {
                        // Chain disagreement: we're on a different fork than the
                        // sync peer. Fork resolution decides, retrying cannot.
                        RejectKind::ChainMismatch => {
                            let sync_target = target;
                            tracing::warn!(
                                task = "sync",
                                "chain mismatch clue: sync block {} rejected ({reason})",
                                height,
                            );
                            // D1: pausing the conveyor is not enough. `detect_forks`
                            // opens with `if self.is_syncing() { return }` and is the
                            // ONLY caller of `start_assessment` and the only trigger of
                            // ancestor discovery. Leaving `sync_state` non-Idle here
                            // deadlocked the node: the step that makes the rival
                            // knowable was skipped because we were syncing, and the
                            // sync could never finish because the fork was unresolved,
                            // so `execute_resolution` refused forever on
                            // `rival == Unknown`. Drop the source (so selection does not
                            // hand back the same doomed peer) and go Idle (so the next
                            // tick may assess it). `start_assessment` resolves its peer
                            // through `peer_for_tip`, not `select_sync_peer`, so the
                            // drop does not block assessing the very chain we refused.
                            self.drop_sync_source(&reason);
                            self.reset_sync_idle();
                            self.ingest_clue(HealingClue::SyncChainMismatch {
                                rejected_height: height,
                                sync_target,
                                reason: format!("sync block {height} rejected: {reason}"),
                            });
                            return;
                        }
                        // F1a: our own storage failed — the peer is blameless.
                        // Ordinary retry accounting, no drop, no fork clue.
                        RejectKind::LocalStorage => {
                            let attempts = match manifest[*cursor].status {
                                EntryStatus::Failed { attempts } => attempts + 1,
                                _ => 1,
                            };
                            tracing::error!(
                                task = "sync",
                                "local storage error importing block {height} \
                                 (attempt {attempts}): {reason}"
                            );
                            if attempts >= SYNC_MAX_BLOCK_RETRIES {
                                self.reset_sync_idle();
                                return;
                            }
                            manifest[*cursor].status = EntryStatus::Failed { attempts };
                        }
                        // No genesis: no peer and no number of retries can fix
                        // this, so don't burn attempts pretending otherwise.
                        // Stop the conveyor and tell the operator what to do.
                        RejectKind::GenesisWitnessMissing => {
                            // Re-request genesis explicitly by height — that
                            // path serves `get_block_votes`, batch sync does
                            // not. Reuse the ordinary retry accounting so this
                            // still escalates if no peer ever supplies one.
                            let attempts = match manifest[*cursor].status {
                                EntryStatus::Failed { attempts } => attempts + 1,
                                _ => 1,
                            };
                            tracing::warn!(
                                task = "sync",
                                "genesis served without its witness record (attempt {attempts}) \
                                 — re-requesting by height: {reason}",
                            );
                            manifest[*cursor].status = EntryStatus::Failed { attempts };
                            if let Some(peer) = self.sync_peer().cloned() {
                                self.send_network(NetworkCommand::RequestBlockByHeight {
                                    peer_id: peer,
                                    height: noble_core::GENESIS_HEIGHT,
                                });
                            }
                        }
                        RejectKind::GenesisUnacceptable => {
                            tracing::error!(
                                task = "sync",
                                "cannot join this chain: {reason}. Its genesis does not meet the \
                                 Dual-Witness Rule, so nothing descending from it can be trusted. \
                                 This is not retryable — the chain itself must be re-founded, or \
                                 this node pointed at a different peer."
                            );
                            // R2: this is a verdict about the PEER's chain, not
                            // about us. Drop it as a sync source and carry on
                            // with our own — a peer offering an unacceptable
                            // foundation must never take this node down.
                            self.drop_sync_source(&reason);
                            // G4: carry the real reason, not a generic verdict.
                            // A chain refused for a record fault must never be
                            // presented as one founded by a single node.
                            self.broadcast_event(serde_json::json!({
                                "event": "sync_source_rejected",
                                "height": height,
                                "reason": reason,
                                "under_witnessed": reason.contains("Dual-Witness Rule"),
                                "message": format!(
                                    "Not adopting this peer's chain ({reason}) — \
                                     continuing on our own chain"
                                ),
                            }));
                            self.reset_sync_idle();
                            return;
                        }
                        RejectKind::NoGenesis => {
                            tracing::error!(
                                task = "sync",
                                "cannot sync: this node has no genesis block, so the chain's first block \
                                 cannot be anchored. Set [chain] genesis_seed in noble.toml \
                                 to the seed used by this chain (`noble-tool genesis --seed \
                                 <SEED>` prints the resulting chain ID), then restart."
                            );
                            // R3: re-enter the founding/fetch path instead of
                            // halting. Genesis is servable over GetBlocks, so a
                            // node without one asks its peers for it; with no
                            // peers it keeps proposing a candidate under the
                            // normal Dual-Witness rules. Never demand a config
                            // edit and a restart.
                            self.request_genesis_from_peers();
                            self.broadcast_event(serde_json::json!({
                                "event": "genesis_requested",
                                "height": height,
                                "reason": "no genesis block yet",
                                "message": "No genesis yet — requesting it from peers and \
                                            continuing to participate in founding",
                            }));
                            self.reset_sync_idle();
                            return;
                        }
                        RejectKind::WitnessMissing => {
                            // Re-request by height — that path serves
                            // `get_block_votes`; batch sync and the by-hash
                            // gossip retry do not. Ordinary retry accounting,
                            // so an unprovable block still escalates.
                            let attempts = match manifest[*cursor].status {
                                EntryStatus::Failed { attempts } => attempts + 1,
                                _ => 1,
                            };
                            if attempts >= SYNC_MAX_BLOCK_RETRIES {
                                tracing::warn!(
                                    task = "sync",
                                    "block {height} still has no witness record after {attempts} \
                                     attempts — unprovable, treating as legitimacy 0"
                                );
                                self.drop_sync_source(&reason);
                                self.broadcast_event(serde_json::json!({
                                    "event": "sync_source_rejected",
                                    "height": height,
                                    "reason": reason,
                                    "under_witnessed": true,
                                    "message": format!(
                                        "Peer never proved block {height}'s witnesses — \
                                         unprovable is legitimacy 0"
                                    ),
                                }));
                                self.reset_sync_idle();
                                return;
                            }
                            tracing::warn!(
                                task = "sync",
                                "block {height} served without its witness record \
                                 (attempt {attempts}) — re-requesting by height: {reason}"
                            );
                            manifest[*cursor].status = EntryStatus::Failed { attempts };
                            if let Some(peer) = self.sync_peer().cloned() {
                                self.send_network(NetworkCommand::RequestBlockByHeight {
                                    peer_id: peer,
                                    height,
                                });
                            }
                        }
                        RejectKind::SelfVoted => {
                            tracing::warn!(
                                task = "sync",
                                "sync block {height} is under-witnessed ({reason}) — this peer's \
                                 chain has legitimacy 0; dropping it as a sync source"
                            );
                            if let Some(peer) = self.sync_peer().cloned() {
                                if let Some(tip) = self.peer_tip_hex(&peer) {
                                    self.assessments.insert(
                                        tip,
                                        SegmentLegitimacy::SelfVoted {
                                            first_solo: height,
                                            grade: noble_consensus::SoloGrade::default(),
                                        },
                                    );
                                }
                            }
                            self.drop_sync_source(&reason);
                            self.broadcast_event(serde_json::json!({
                                "event": "sync_source_rejected",
                                "height": height,
                                "reason": reason,
                                "under_witnessed": true,
                                "message": format!(
                                    "Peer's chain is self-voted from height {height} — legitimacy 0, \
                                     not adopting"
                                ),
                            }));
                            self.reset_sync_idle();
                            return;
                        }
                        RejectKind::Invalid => {
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
                    },
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
            // R2: a peer whose chain we refused is not a candidate source until
            // its rejection ages out. Without this the refusal is inert —
            // `drop_sync_source` would record it and selection would hand back
            // the same peer on the very next tick, retrying a chain we have
            // already judged unacceptable.
            if self.is_rejected_sync_source(&pid) {
                continue;
            }
            // F5: "no node syncs with it" — a tip assessed self-voted is not a
            // source, unless the resolver decided it is the best chain there is.
            if let Some(tip) = entry.chain_tip_hash.as_ref() {
                if matches!(self.assessments.get(tip), Some(SegmentLegitimacy::SelfVoted { .. })) {
                    let permitted = self
                        .solo_adoption_permit
                        .as_ref()
                        .is_some_and(|(p, t)| *p == pid && t == tip);
                    if !permitted {
                        continue;
                    }
                }
            }
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

        // F3: assessments have a bounded lifetime — retry, then score unprovable.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.tick_assessments(now);
        }

        // Read consensus state.
        let engine_read = self.consensus.read();
        let (our_height, our_hash) = engine_read.chain_tip();
        let chain_owner_key = engine_read.chain_owner_key().map(|k| k.to_vec());
        let our_identity_key = engine_read.our_validator_wire_bytes();
        drop(engine_read);

        let local_chain_id = self.get_chain_id();
        let peers = self.peer_info.read().clone();

        let mut fork_groups = compute_fork_groups(
            &peers,
            our_height,
            our_hash,
            chain_owner_key.as_deref(),
            our_identity_key.as_deref(),
            local_chain_id,
        );
        // F4/F3: fill verified legitimacy — ours from storage, rivals from
        // completed assessments; a rival tip that is a block on OUR chain holds
        // only the shared prefix (NotContesting).
        {
            let ancestor = self.fork_common_ancestor.map(|(h, _)| h).unwrap_or(our_height);
            let (local_leg, prefix_end) = self.local_segment_legitimacy(ancestor);
            let storage = self.storage.read();
            for f in fork_groups.iter_mut() {
                if f.is_local {
                    f.legitimacy = local_leg;
                    f.witnessed_prefix_end = prefix_end;
                    continue;
                }
                let tip_hex = hex::encode(f.tip_hash.as_bytes());
                f.legitimacy = if f.height <= our_height
                    && storage.get_block_hash_by_height(f.height).ok() == Some(f.tip_hash)
                {
                    SegmentLegitimacy::NotContesting
                } else {
                    self.assessments.get(&tip_hex).copied().unwrap_or(SegmentLegitimacy::Unknown)
                };
            }
        }
        let total_peers = peers.len();

        // Emit fork_detected / fork_aligned events for GUI visibility.
        let is_forked = fork_groups.len() > 1;
        if is_forked && !self.fork_visible {
            self.fork_visible = true;
            // Clear stale ancestor from any previous fork.
            self.fork_common_ancestor = None;
            self.last_ancestor_request = None;
            let remote: Vec<_> = fork_groups.iter().filter(|g| !g.is_local).collect();
            self.broadcast_event(serde_json::json!({
                "event": "fork_detected",
                "fork_count": fork_groups.len(),
                "local_height": our_height,
                "remote_heights": remote.iter().map(|g| g.height).collect::<Vec<_>>(),
                "remote_peer_counts": remote.iter().map(|g| g.peer_count).collect::<Vec<_>>(),
            }));
        } else if !is_forked && self.fork_visible {
            self.fork_visible = false;
            self.last_ancestor_request = None;
            self.broadcast_event(serde_json::json!({
                "event": "fork_aligned",
                "height": our_height,
            }));
        }

        // D3: ancestor discovery must not be edge-triggered. It used to fire
        // once, on the transition into "forked", in the same branch that clears
        // `fork_common_ancestor`. A dropped response — or simply entering
        // Syncing before it landed — left the ancestor unknown forever, and
        // `execute_resolution` then refused with "Operator action required": a
        // human-in-the-loop dead end for a transient condition. Retry for as
        // long as the ancestor is unknown, backing off so the cost is bounded,
        // and never stop. Every fork group is on OUR chain id (a different
        // genesis is a different chain), so an ancestor always exists.
        if is_forked && self.fork_common_ancestor.is_none() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let (due, attempt) = match self.last_ancestor_request {
                None => (true, 0u32),
                Some((at, n)) => {
                    let backoff = SYNC_RETRY_SECS
                        .saturating_mul(1u64 << n.min(7))
                        .min(ANCESTOR_RETRY_MAX_SECS);
                    (now.saturating_sub(at) >= backoff, n)
                }
            };
            if due {
                if let Some(remote_group) = fork_groups.iter().find(|g| !g.is_local) {
                    let tip_hex = hex::encode(remote_group.tip_hash.as_bytes());
                    let peer_on_fork = peers
                        .values()
                        .find(|e| e.chain_tip_hash.as_deref() == Some(&tip_hex))
                        .map(|e| e.peer_id.clone());
                    if let Some(peer_id) = peer_on_fork {
                        match hex::decode(&peer_id) {
                            Ok(pid_bytes) => {
                                tracing::info!(
                                    task = "healing",
                                    attempt = attempt + 1,
                                    "common ancestor unknown — requesting it from a peer on the rival fork"
                                );
                                self.send_network(NetworkCommand::FindCommonAncestor {
                                    peer_id: pid_bytes,
                                    local_height: our_height,
                                    peer_height: remote_group.height,
                                });
                                self.last_ancestor_request = Some((now, attempt.saturating_add(1)));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    task = "healing",
                                    "failed to decode peer_id for FindCommonAncestor: {e} — retrying next tick",
                                );
                            }
                        }
                    }
                }
            }
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
            noble_consensus::ForkDecision::Assess { target_hash, target_height, from_height } => {
                self.start_assessment(target_hash, from_height, target_height);
            }
            noble_consensus::ForkDecision::AbandonSelfVoted { to_height, first_solo, reason } => {
                self.ingest_clue(HealingClue::AbandonSelfVoted { to_height, first_solo, reason });
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

    /// Scan downward from `from_height` for the highest height whose block is
    /// actually readable, i.e. the deepest point the chain is still intact.
    ///
    /// Returns `None` when nothing below `from_height` is readable, which
    /// means there is no prefix worth keeping and the caller must halt rather
    /// than rewind. Height 0 is included in the scan: genesis is a legitimate
    /// rewind target, and a chain whose genesis is unreadable is exactly the
    /// unrepairable case.
    ///
    /// Bounded by [`MAX_REORG_DEPTH`] — damage deeper than a legal reorg is
    /// not something automation should silently rewind past.
    fn highest_intact_height(&self, from_height: u64) -> Option<u64> {
        let floor = from_height.saturating_sub(noble_core::MAX_REORG_DEPTH);
        let storage = self.storage.read();
        for h in (floor..from_height).rev() {
            let readable = storage
                .get_block_hash_by_height(h)
                .ok()
                .filter(|hash| storage.get_block_header(hash).is_ok())
                .is_some();
            if readable {
                return Some(h);
            }
        }
        None
    }

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
        // "Do we have a chain", not "is the tip above 0" — a genesis-only chain
        // is a chain, and its integrity is exactly as worth probing.
        let have_chain = our_tip_hash != Hash256::ZERO;
        let tip_block_exists = if have_chain {
            self.storage.read().get_block_header(&our_tip_hash).is_ok()
        } else {
            true
        };

        // Chain integrity probe: our tip claims a block that storage doesn't
        // have. Repair by rewinding to the highest intact height; if there is
        // no intact prefix, halt read-only and wait for an operator.
        //
        // This used to call `wipe_and_reset` unconditionally. On 2026-08-11
        // that destroyed a healthy 196-block chain and its chain_id: a failed
        // rollback (see the storage preflights) left the tip dangling, this
        // probe saw the inconsistency one tick later, and answered by deleting
        // everything. Damage localized to the last few blocks does not justify
        // discarding the whole chain, and losing chain_id makes the node
        // unable to rejoin the chain it was already on.
        if have_chain && !tip_block_exists {
            tracing::error!(
                task = "integrity",
                "CHAIN INTEGRITY FAILURE: tip at height {} claims hash {} but block missing from storage",
                our_height,
                hex::encode(our_tip_hash.as_bytes()),
            );

            match self.highest_intact_height(our_height) {
                Some(intact) => {
                    tracing::warn!(
                        task = "integrity",
                        "repairing: rewinding {} damaged block(s) to intact height {}",
                        our_height.saturating_sub(intact),
                        intact,
                    );
                    let chain_id = self.get_chain_id();
                    let rewound = self
                        .storage
                        .read()
                        .rollback_to_height(intact, chain_id);
                    match rewound {
                        Ok(tip) => {
                            if let Err(e) =
                                self.consensus.write().reset_tip(tip.height, tip.block_hash, true)
                            {
                                tracing::error!(
                                    task = "integrity",
                                    "reset_tip after integrity repair failed: {e}"
                                );
                            }
                            self.update_tip_height(tip.height);
                            self.clear_pending_proposals();
                            self.fork_common_ancestor = None;
                            self.reset_sync_idle();
                            self.sync_verify_retries = 0;
                            self.sync_start_height = 0;
                            self.broadcast_event(serde_json::json!({
                                "event": "integrity_repaired",
                                "from_height": our_height,
                                "to_height": tip.height,
                            }));
                            // Chain is consistent again — resume normal sync.
                            self.request_sync();
                            return;
                        }
                        Err(e) => {
                            // The rollback refused (it preflights now), so the
                            // chain is untouched. Fall through to the halt.
                            tracing::error!(
                                task = "integrity",
                                "integrity repair to height {intact} refused: {e}"
                            );
                        }
                    }
                }
                None => {
                    tracing::error!(
                        task = "integrity",
                        "no intact prefix found below height {our_height}"
                    );
                }
            }

            // R4: no intact prefix above genesis. Escalate the rewind instead
            // of halting — genesis is the last anchor that cannot be wrong, so
            // fall back to it and resync from the fork-choice winner.
            //
            // ACQUIRE-VERIFY-SWAP: `rollback_to` preflights, and nothing below
            // genesis is ever discarded. The chain's identity survives, so a
            // failed resync leaves us where we started rather than empty. The
            // old code halted here precisely because an earlier version wiped
            // before validating; rewinding to genesis destroys no foundation
            // and so does not reopen that hole.
            tracing::warn!(
                task = "integrity",
                "no intact prefix below height {our_height} — rewinding to genesis and \
                 resyncing from peers; chain identity is preserved"
            );
            self.rollback_to(noble_core::GENESIS_HEIGHT);
            self.broadcast_event(serde_json::json!({
                "event": "integrity_recovery",
                "height": our_height,
                "rewound_to": noble_core::GENESIS_HEIGHT,
                "message": "Chain integrity failure — rewound to genesis and resyncing \
                            automatically; no operator action needed",
            }));
            self.clear_pending_proposals();
            self.reset_sync_idle();
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
        self.local_legitimacy_cache = None;
        let (local_leg, prefix_end) = self.local_segment_legitimacy(ancestor_height);
        self.broadcast_event(serde_json::json!({
            "event": "fork_divergence",
            "ancestor_height": ancestor_height,
            "ancestor_hash": hex::encode(ancestor_hash),
            "local_height": our_height,
            "divergence_depth": our_height.saturating_sub(ancestor_height),
            "local_legitimacy": local_leg.label(),
            "witnessed_prefix_end": prefix_end,
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
            // The guard itself stays: without an ancestor the only "resolution"
            // available is rollback_to(0) — a full wipe chosen on peer-reported
            // heights. But this is no longer a dead end needing a person: D3
            // retries discovery for as long as the fork is visible, so the
            // condition is transient and the next tick may well clear it.
            tracing::warn!(
                task = "fork_resolution",
                "resolution deferred: common ancestor not yet known — not resetting to genesis; \
                 ancestor discovery is retrying"
            );
            return;
        };

        // F6: acquire-verify-swap, applied at the swap. Every adoption path
        // (ForkResolve, SyncChainMismatch, bootstrap SyncStall) passes here.
        // A witnessed local segment is never traded for an unproven or
        // self-voted one; a self-voted local segment yields to anything
        // witnessed, or to a better-participated solo run (with a permit so
        // its blocks may be imported).
        let (local_leg, _prefix_end) = self.local_segment_legitimacy(ancestor_height);
        let rival_leg = self.rival_legitimacy_for(target_hash);
        match (local_leg, rival_leg) {
            (SegmentLegitimacy::SelfVoted { .. }, SegmentLegitimacy::Witnessed(_)) => {
                // F2: the mismatch that started this almost certainly dropped
                // the peer we have now decided to adopt from. Re-admit it, or
                // `select_sync_peer` skips it and the adoption stalls again.
                self.readmit_adoption_source(target_hash);
            }
            (SegmentLegitimacy::SelfVoted { grade: mine, .. }, SegmentLegitimacy::SelfVoted { grade: theirs, .. })
                if theirs > mine =>
            {
                self.readmit_adoption_source(target_hash);
                if let Some(peer) = self.peer_for_tip(target_hash) {
                    self.solo_adoption_permit =
                        Some((peer, hex::encode(target_hash.as_bytes())));
                }
            }
            (SegmentLegitimacy::Witnessed(mine), SegmentLegitimacy::Witnessed(theirs)) if theirs > mine => {}
            (SegmentLegitimacy::Witnessed(mine), SegmentLegitimacy::Witnessed(theirs)) if theirs == mine => {
                // Equal grade: the resolver's height/owner/peer rules decided. Proceed.
            }
            (local, rival) => {
                tracing::warn!(
                    task = "fork_resolution",
                    local = local.label(),
                    rival = rival.label(),
                    "refusing resolution: local segment is not less legitimate than the target \
                     (legitimacy is decided from verified certificates, never announcements)"
                );
                self.broadcast_event(serde_json::json!({
                    "event": "fork_resolution_refused",
                    "local_legitimacy": local.label(),
                    "rival_legitimacy": rival.label(),
                    "target_height": target_height,
                    "reason": reason,
                }));
                return;
            }
        }

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

        // Re-arm the stall watch against the post-rollback tip: otherwise the
        // 300s alarm still measures the pre-rollback episode and can fire
        // immediately on a sync that has only just begun.
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.stall_watch_height = rollback_height;
            self.stall_watch_since = now;
        }

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
        // Adopting another chain means destroying our genesis — the foundation
        // this node has been validating against. Automation does not get to do
        // that. Per ADR-031 the node halts and an operator decides; switching
        // chains is a deliberate act (wipe the data dir and restart), not a
        // conclusion reached from peer-reported heights.
        //
        // The old automatic path also wiped BEFORE validating the adopted
        // chain (the M5 residual), so a node could destroy a good chain and
        // then fail to obtain the one it destroyed it for.
        // R5: the refusal stands — we do not adopt another chain automatically.
        // But refusing is not a failure of THIS node, and it must not disable
        // it. Previously a peer sitting on a foreign chain took us down with
        // it: we stopped proposing and reported a halt, having done nothing
        // wrong. We simply stay on our own chain, fully operational.
        tracing::warn!(
            task = "chain_adoption",
            "not adopting chain {:#010X} — {reason}. Continuing on our own chain; \
             switching chains remains a deliberate operator act, but this node keeps \
             validating and proposing normally.",
            target_chain_id
        );
        self.broadcast_event(serde_json::json!({
            "event": "adoption_declined",
            "target_chain_id": target_chain_id,
            "reason": reason,
            "message": "Not adopting another chain — continuing on our own",
        }));
        self.reset_sync_idle();
    }

    /// Unused remnant of the automatic adoption path, kept only so the
    /// deliberate operator route (manual reset RPC) still has a wipe to call.
    #[allow(dead_code)]
    fn execute_adoption_unused(&mut self, target_chain_id: u32, reason: &str) {
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
    /// Count of blocks a peer has actually handed us for import, accepted or
    /// not. Distinct from sync *progress*, which only counts accepted blocks.
    ///
    /// The proposal gate needs both: a peer that advertises height 197 and
    /// delivers nothing may be lying, but a peer that delivers blocks we
    /// reject has substantiated that its chain exists. Treating the second
    /// case as "unsubstantiated" is what let a node that could not sync start
    /// minting a rival chain.
    pub fn sync_blocks_delivered(&self) -> &Arc<AtomicU64> {
        &self.sync_blocks_delivered
    }

    pub fn try_sync_import(&self, block: &noble_core::Block, vote_data: Option<&[u8]>) -> SyncImportResult {
        self.sync_blocks_delivered.fetch_add(1, Ordering::Relaxed);
        let (tip_height, have_chain) = {
            let engine = self.consensus.read();
            let (h, _) = engine.chain_tip();
            (h, engine.has_chain())
        };
        let mut chain_id = self.get_chain_id();

        // Genesis is the one block that cannot commit to its own chain id:
        // the id is derived from the genesis hash, and the hash covers the
        // transactions, whose ids would have to embed the id. That circularity
        // is inherent to founding a chain, not an artefact of numbering — so
        // genesis is produced and validated with chain_id = 0, and every block
        // after it uses the id derived from genesis.
        //
        // Getting this wrong causes merkle root mismatches: the proposer
        // computed tx_ids with chain_id=0, but the validator recomputes with
        // the derived chain_id → different preimage → different merkle → B4.
        if block.header.height == noble_core::GENESIS_HEIGHT {
            chain_id = 0;
        } else if chain_id == 0 {
            // Post-reset: recover the id from the genesis block we hold.
            let storage = self.storage.read();
            if let Ok(Some(g)) = storage.genesis() {
                chain_id = noble_core::derive_chain_id(&g.block_hash);
            }
            if chain_id == 0 {
                tracing::error!(
                    task = "sync_import",
                    height = block.header.height,
                    "could not derive chain_id — rejecting sync import",
                );
                return SyncImportResult::reject(
                    RejectKind::Invalid,
                    "could not derive chain_id from storage",
                );
            }
        }

        // Load parent header from storage for B2/B3/B5 validation.
        //
        // The test is "do we have a chain", NOT "is the tip above 0". With
        // genesis at height 0 those stopped being the same question, and a node
        // holding only genesis was handed `None` here — so the block right
        // after genesis was validated with B2/B3/B5 skipped and any parent hash
        // accepted. That is the false-history hole H8 exists to close.
        let parent_header = if have_chain {
            let storage = self.storage.read();
            let chain_tip = match storage.get_chain_tip() {
                Ok(Some(t)) => t,
                Ok(None) => {
                    tracing::error!(task = "sync_import", "chain tip missing at height {tip_height} — aborting");
                    return SyncImportResult::reject(RejectKind::Invalid, "chain tip missing");
                }
                Err(e) => {
                    tracing::error!(task = "sync_import", "failed to load chain tip: {e}");
                    return SyncImportResult::reject(RejectKind::Invalid, format!("chain tip error: {e}"));
                }
            };
            match storage.get_block_header(&chain_tip.block_hash) {
                Ok(header) => Some(header),
                Err(e) => {
                    tracing::error!(task = "sync_import", "failed to load parent header: {e}");
                    // Our disk, not their chain — see RejectKind::LocalStorage.
                    return SyncImportResult::reject(
                        RejectKind::LocalStorage,
                        format!("parent header error: {e}"),
                    );
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
        if block.header.height == noble_core::GENESIS_HEIGHT {
            // Genesis has no parent to chain to — nothing precedes it. So the
            // check is identity, not descent: if we already have a genesis, an
            // incoming one must BE it. Two different foundations are two
            // different chains.
            let ours = {
                let storage = self.storage.read();
                storage.genesis().ok().flatten()
            };
            if let Some(g) = ours {
                let incoming = match block.header.compute_block_hash() {
                    Ok(h) => h,
                    Err(e) => {
                        return SyncImportResult::reject(
                            RejectKind::Invalid,
                            format!("genesis hash computation failed: {e}"),
                        )
                    }
                };
                if incoming != g.block_hash {
                    tracing::warn!(
                        task = "sync_import",
                        "rejecting genesis {incoming}: we are on the chain founded by {}",
                        g.block_hash
                    );
                    return SyncImportResult::reject(
                        RejectKind::ChainMismatch,
                        "genesis differs from ours — this peer is on another chain",
                    );
                }
            }
            // No chain yet: we are being handed someone else's foundation.
            //
            // The consensus engine enforces Dual-Witness when a chain is
            // FOUNDED, but sync import bypasses the engine entirely — so
            // without this check a joining node accepts a genesis that was
            // never witnessed by anyone, which is a chain founded by one node.
            // The witness certificate is the only evidence available to a node
            // that was not present at founding, so it is mandatory here, is
            // verified BEFORE commit, and must clear the same threshold the
            // engine applies.
            else {
                // Bind genesis to the hash the manifest promised.
                //
                // Every other height is bound by its parent link (B2): a
                // substituted block fails because it does not chain to what we
                // already hold. Genesis has no parent, so without this a peer
                // can advertise one chain in its manifest and deliver a
                // different — even properly witnessed — foundation, and the
                // joining node adopts the chain it was not asked to join.
                let Some(promised) = self.manifest_hash_for(noble_core::GENESIS_HEIGHT) else {
                    // No manifest naming a genesis means nothing to bind
                    // against — this block was pushed at us, not requested.
                    // Adopting a foundation opportunistically is how a node
                    // ends up on a chain it never chose; wait for the manifest
                    // that names one. Retryable: the manifest is in flight.
                    return SyncImportResult::reject(
                        RejectKind::GenesisWitnessMissing,
                        "refusing to adopt a genesis that no manifest asked for — \
                         awaiting a manifest to bind against",
                    );
                };
                {
                    let incoming = match block.header.compute_block_hash() {
                        Ok(h) => h,
                        Err(e) => {
                            return SyncImportResult::reject(
                                RejectKind::Invalid,
                                format!("genesis hash computation failed: {e}"),
                            )
                        }
                    };
                    if incoming.as_bytes() != &promised {
                        tracing::warn!(
                            task = "sync_import",
                            "peer delivered genesis {incoming} but its manifest promised {} \
                             — refusing to adopt a foundation we did not ask for",
                            hex::encode(promised),
                        );
                        return SyncImportResult::reject(
                            RejectKind::GenesisUnacceptable,
                            "genesis does not match the hash this peer's own manifest promised",
                        );
                    }
                }

                let required = self.consensus.read().min_unique_voters();
                let cert = match vote_data {
                    Some(vd) => match <noble_consensus::BlockVotes as noble_codec::NobleCbor>::from_cbor(vd) {
                        Ok(parsed) => parsed.certificate,
                        Err(e) => {
                            return SyncImportResult::reject(
                                RejectKind::Invalid,
                                format!("genesis witness data undecodable: {e}"),
                            )
                        }
                    },
                    None => None,
                };
                let Some(cert) = cert else {
                    return SyncImportResult::reject(
                        RejectKind::GenesisWitnessMissing,
                        "genesis arrived without its witness record — re-requesting over the \
                         vote-carrying path",
                    );
                };
                let incoming = match block.header.compute_block_hash() {
                    Ok(h) => h,
                    Err(e) => {
                        return SyncImportResult::reject(
                            RejectKind::Invalid,
                            format!("genesis hash computation failed: {e}"),
                        )
                    }
                };
                if cert.candidate_hash != incoming {
                    return SyncImportResult::reject(
                        RejectKind::GenesisUnacceptable,
                        "genesis witness certificate names a different block",
                    );
                }
                match cert.verify() {
                    Ok(witnesses) if witnesses >= required => {
                        tracing::info!(
                            task = "sync_import",
                            "adopting genesis {incoming} witnessed by {witnesses} distinct \
                             validator(s) (>= {required} required)"
                        );
                    }
                    Ok(witnesses) => {
                        // G4: this is the ONLY path entitled to call a chain
                        // insufficiently witnessed, and it reports the count it
                        // actually measured. Every other rejection reason says
                        // what it really was, so a chain refused over an
                        // encoding fault can never be mistaken — by an
                        // operator or by fork choice — for one founded alone.
                        tracing::warn!(
                            task = "sync_import",
                            measured_witnesses = witnesses,
                            required_witnesses = required,
                            genesis = %incoming,
                            "peer's genesis is genuinely under-witnessed"
                        );
                        return SyncImportResult::reject(
                            RejectKind::GenesisUnacceptable,
                            format!(
                                "genesis witnessed by only {witnesses} distinct validator(s), \
                                 {required} required by the Dual-Witness Rule"
                            ),
                        )
                    }
                    // G3: a verification failure is not automatically a verdict
                    // on the peer's chain. Only a genuine witness shortfall or
                    // a forged/mismatched record condemns a foundation; a cycle
                    // binding fault is a defect in the *record*, and treating
                    // it as illegitimacy permanently refused properly-founded
                    // chains and told the operator they had to be re-founded.
                    Err(noble_consensus::history::WitnessError::WrongCycle {
                        got,
                        expected,
                        ..
                    }) => {
                        return SyncImportResult::reject(
                            RejectKind::GenesisWitnessMissing,
                            format!(
                                "genesis witness certificate has an inconsistent cycle binding \
                                 (vote cycle {got}, certificate cycle {expected}) — re-requesting \
                                 over the vote-carrying path; this is NOT a witness shortfall"
                            ),
                        )
                    }
                    Err(e) => {
                        return SyncImportResult::reject(
                            RejectKind::GenesisUnacceptable,
                            format!("genesis witness certificate does not verify: {e}"),
                        )
                    }
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
            // `is_fork` was already computed correctly right above and used
            // only to pick a log level. A prev-hash/height disagreement is a
            // chain disagreement — fork resolution decides it. Classifying it
            // as Invalid sent it to the retry path, where five attempts are
            // spent on something retrying cannot fix.
            return SyncImportResult::reject(
                if is_fork { RejectKind::ChainMismatch } else { RejectKind::Invalid },
                format!("{e}"),
            );
        }

        let block_hash = match block.header.compute_block_hash() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(task = "sync_import", "block hash computation failed: {e}");
                return SyncImportResult::reject(RejectKind::Invalid, format!("block hash computation failed: {e}"));
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
                return SyncImportResult::reject(RejectKind::Invalid, format!("tx_id computation failed: {e}"));
            }
        };

        // F5 / F8: every non-genesis synced block must PROVE its witnesses.
        // Genesis was handled above with its own Dual-Witness rules.
        let verified = certificate_facts(vote_data, block_hash);
        if block.header.height != noble_core::GENESIS_HEIGHT {
            let required = self.consensus.read().min_unique_voters();
            let w = verified.as_ref().map(|f| f.witnesses).unwrap_or(0);
            if w < required {
                let permitted = match (&self.solo_adoption_permit, self.sync_peer()) {
                    (Some((peer, _)), Some(src)) => peer == src,
                    _ => false,
                };
                if !permitted {
                    // Absent record → transport, retryable. Present record that
                    // verifies but falls short → the chain, terminal.
                    let kind = if verified.is_none() {
                        RejectKind::WitnessMissing
                    } else {
                        RejectKind::SelfVoted
                    };
                    return SyncImportResult::reject(
                        kind,
                        format!(
                            "block {} carries {w} verified witness(es), {required} required — \
                             legitimacy 0 and no solo-adoption permit for this source",
                            block.header.height
                        ),
                    );
                }
                tracing::info!(
                    task = "sync_import",
                    height = block.header.height,
                    witnesses = w,
                    "importing under-witnessed block under solo-adoption permit (best chain available)"
                );
            }
        }
        // F8: credit the chain by the witnesses actually verified, not a flat 1.
        // A synced two-witness chain used to report half the legitimacy of one
        // watched live — indistinguishable from a solo run.
        let credited = verified.as_ref().map(|f| f.witnesses as u64).unwrap_or(1).max(1);
        let old = self.chain_vote_weight.load(Ordering::Relaxed);
        let new = noble_consensus::decay_vote_weight(old, credited);
        self.chain_vote_weight.store(new, Ordering::Relaxed);

        // Chain identity comes from GENESIS, and only from genesis.
        //
        // This used to derive it from `block_hash` — whatever block happened to
        // import first. That was correct only while genesis was guaranteed to
        // be that block. Deriving it from any other block stamps the node with
        // an id no peer shares, and since tx_id commits to chain_id, every
        // index it then writes is keyed wrongly.
        let new_chain_id = if chain_id == 0 && block.header.height == noble_core::GENESIS_HEIGHT {
            let new_cid = noble_core::derive_chain_id(&block_hash);
            tracing::info!(
                task = "sync_import",
                "chain_id set to {:#010X} from imported genesis",
                new_cid,
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
                return SyncImportResult::reject(RejectKind::Invalid, format!("commit failed: {e}"));
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
    // A tip above genesis with no chain id means genesis is unreadable, so the
    // id could not be derived. That is a corruption signal, and per ADR-031 the
    // answer is to halt for an operator — never to wipe. This function used to
    // return `true` here meaning "wipe inconsistent state", which is how a
    // 196-block chain was deleted; it now only reports.
    if chain_id == 0 && tip_height > noble_core::GENESIS_HEIGHT {
        tracing::error!(
            task = "startup",
            "chain tip at height {} but no chain id could be derived — genesis is \
             unreadable. Chain data is preserved; block proposals are suppressed.",
            tip_height,
        );
        return true;
    }
    false
}

// ── Legitimacy gradation (F3/F4) ─────────────────────────────────────────────

/// What a verified certificate proves about one block.
#[derive(Debug, Clone, Default)]
pub struct CertFacts {
    /// Distinct signer keys (wire bytes).
    pub keys: Vec<Vec<u8>>,
    /// `|keys|`.
    pub witnesses: usize,
    /// Distinct signers with at least one round-1 vote.
    pub r1: usize,
}

/// Decode `vote_data`, require the certificate to name `block_hash`, verify it,
/// and report distinct signers and round-1 signers. `None` if anything fails —
/// unprovable is scored as zero by the caller.
pub fn certificate_facts(vote_data: Option<&[u8]>, block_hash: Hash256) -> Option<CertFacts> {
    let vd = vote_data?;
    let bv = <noble_consensus::BlockVotes as noble_codec::NobleCbor>::from_cbor(vd).ok()?;
    let cert = bv.certificate?;
    if cert.candidate_hash != block_hash {
        return None;
    }
    cert.verify().ok()?;
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut r1_keys: Vec<Vec<u8>> = Vec::new();
    for v in &cert.votes {
        let k = v.voter_pubkey.to_wire_bytes();
        if !keys.contains(&k) {
            keys.push(k.clone());
        }
        if v.round == 1 && !r1_keys.contains(&k) {
            r1_keys.push(k);
        }
    }
    Some(CertFacts { witnesses: keys.len(), r1: r1_keys.len(), keys })
}

/// One block of a segment under assessment, as verified facts.
#[derive(Debug, Clone)]
pub struct StagedBlock {
    pub height: u64,
    pub hash: Hash256,
    /// Verified proposer key (empty if the block signature did not verify).
    pub proposer: Vec<u8>,
    pub facts: CertFacts,
}

impl StagedBlock {
    fn from_facts(height: u64, hash: Hash256, proposer: Vec<u8>, facts: Option<CertFacts>) -> Self {
        Self { height, hash, proposer, facts: facts.unwrap_or_default() }
    }
}

/// A rival segment being fetched for assessment.
#[derive(Debug)]
struct AssessmentRun {
    tip_hex: String,
    from: u64,
    to: u64,
    staged: std::collections::BTreeMap<u64, StagedBlock>,
    /// height → (last requested at, attempts)
    requested: HashMap<u64, (u64, u8)>,
}

/// The gradation algorithm (plan Steps 1, 2, 2b), pure and integer-only.
///
/// Returns the verdict and `witnessed_prefix_end` — the highest height such
/// that every block in `(ancestor, h]` is witnessed.
pub fn grade_segment(
    blocks: &[StagedBlock],
    ancestor: u64,
    required: usize,
    validators: usize,
) -> (SegmentLegitimacy, u64) {
    let _ = validators; // reserved: density is reported per block, not per validator set
    if blocks.is_empty() {
        return (SegmentLegitimacy::NotContesting, ancestor);
    }
    let mut sorted: Vec<&StagedBlock> = blocks.iter().collect();
    sorted.sort_by_key(|b| b.height);

    // Step 1 — tier, and the witnessed prefix.
    let mut prefix_end = ancestor;
    let mut first_solo: Option<u64> = None;
    for b in &sorted {
        if b.facts.witnesses >= required {
            if first_solo.is_none() {
                prefix_end = b.height;
            }
        } else if first_solo.is_none() {
            first_solo = Some(b.height);
        }
    }

    match first_solo {
        None => {
            // Step 2 — Tier 1 grade.
            let weakest = sorted.iter().map(|b| b.facts.witnesses as u64).min().unwrap_or(0);
            let weakest_r1 = sorted.iter().map(|b| b.facts.r1 as u64).min().unwrap_or(0);
            let mut coverage: Vec<&Vec<u8>> = Vec::new();
            let mut total = 0u64;
            for b in &sorted {
                total += b.facts.witnesses as u64;
                for k in &b.facts.keys {
                    if !coverage.contains(&k) {
                        coverage.push(k);
                    }
                }
            }
            (
                SegmentLegitimacy::Witnessed(noble_consensus::Grade {
                    weakest,
                    weakest_r1,
                    coverage: coverage.len() as u64,
                    total,
                }),
                prefix_end,
            )
        }
        Some(fs) => {
            // Step 2b — Tier 0 participation grade. P(b) = witnesses ∪ {proposer}.
            let mut participants: Vec<Vec<u8>> = Vec::new();
            let mut per_key: HashMap<Vec<u8>, u64> = HashMap::new();
            let mut total = 0u64;
            let mut witnessed_blocks = 0u64;
            for b in &sorted {
                let mut p: Vec<Vec<u8>> = b.facts.keys.clone();
                if !b.proposer.is_empty() && !p.contains(&b.proposer) {
                    p.push(b.proposer.clone());
                }
                total += p.len() as u64;
                if b.facts.witnesses >= required {
                    witnessed_blocks += 1;
                }
                for k in p {
                    *per_key.entry(k.clone()).or_insert(0) += 1;
                    if !participants.contains(&k) {
                        participants.push(k);
                    }
                }
            }
            let n = sorted.len() as u64;
            let grade = noble_consensus::SoloGrade {
                variety: participants.len() as u64,
                density_x1000: total.saturating_mul(1000) / n.max(1),
                witnessed_blocks,
                balance: per_key.values().copied().min().unwrap_or(0),
                total,
            };
            (SegmentLegitimacy::SelfVoted { first_solo: fs, grade }, prefix_end)
        }
    }
}

/// RPC/GUI view of a completed assessment.
pub fn tip_legitimacy_view(tip_hex: &str, leg: &SegmentLegitimacy) -> TipLegitimacy {
    match leg {
        SegmentLegitimacy::Witnessed(g) => TipLegitimacy {
            tip_hash: tip_hex.to_string(),
            label: leg.label().to_string(),
            weakest_witnesses: Some(g.weakest),
            coverage: Some(g.coverage),
            first_solo_height: None,
        },
        SegmentLegitimacy::SelfVoted { first_solo, grade } => TipLegitimacy {
            tip_hash: tip_hex.to_string(),
            label: leg.label().to_string(),
            weakest_witnesses: None,
            coverage: Some(grade.variety),
            first_solo_height: Some(*first_solo),
        },
        _ => TipLegitimacy {
            tip_hash: tip_hex.to_string(),
            label: leg.label().to_string(),
            weakest_witnesses: None,
            coverage: None,
            first_solo_height: None,
        },
    }
}

// ── Witnessed-floor helpers (F1) ─────────────────────────────────────────────

/// True if the block at `height` has a stored, verifying witness certificate
/// with at least `required` distinct signers naming that block's own hash.
///
/// This is the definition of "witnessed" used everywhere a rollback floor or a
/// legitimacy verdict is computed: it re-verifies the certificate rather than
/// trusting a stored count, so it cannot be satisfied by a record that merely
/// *claims* witnesses.
pub fn block_is_witnessed<S: StorageEngine + ?Sized>(storage: &S, height: u64, required: usize) -> bool {
    let Ok(block_hash) = storage.get_block_hash_by_height(height) else { return false };
    let Ok(Some(raw)) = storage.get_block_votes(height) else { return false };
    let Ok(bv) = <noble_consensus::BlockVotes as noble_codec::NobleCbor>::from_cbor(&raw) else {
        return false;
    };
    let Some(cert) = bv.certificate else { return false };
    if cert.candidate_hash != block_hash {
        return false;
    }
    matches!(cert.verify(), Ok(w) if w >= required)
}

/// Highest height `h ≤ height` whose block is witnessed (see
/// [`block_is_witnessed`]). Genesis qualifies by construction of the
/// Dual-Witness founding rule, so this returns `Some(0)` at worst for any
/// chain with a stored genesis certificate; `None` only if nothing at all
/// below `height` can prove its witnesses.
pub fn highest_witnessed_at_or_below<S: StorageEngine + ?Sized>(
    storage: &S,
    height: u64,
    required: usize,
) -> Option<u64> {
    let mut h = height;
    loop {
        if block_is_witnessed(storage, h, required) {
            return Some(h);
        }
        if h == 0 {
            return None;
        }
        h -= 1;
    }
}

/// Result of a sync import attempt.
#[derive(Debug)]
pub enum SyncImportResult {
    /// Block was accepted and committed.
    Accepted {
        new_chain_id: Option<u32>,
    },
    /// Block was rejected (validation failure).
    Rejected { reason: String, kind: RejectKind },
}

/// Why a synced block was rejected, as a value rather than a message.
///
/// The conveyor used to classify rejections by substring-matching the reason
/// text (`reason.contains("PrevHash")`), so a rejection whose wording didn't
/// happen to contain the expected fragment was misrouted into the retry path
/// and burned all five attempts on something retrying could never fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// The block doesn't chain to what we have — a genuine fork/origin
    /// disagreement that fork resolution must decide, not a retry.
    ChainMismatch,
    /// The genesis this peer offers cannot be accepted — its certificate is
    /// present but invalid, mismatched, or short of the Dual-Witness
    /// threshold. Terminal: that is a statement about the CHAIN, and no
    /// number of retries changes it.
    GenesisUnacceptable,
    /// Genesis arrived with no witness record at all.
    ///
    /// Retryable, and the distinction matters: whether a certificate arrives
    /// depends on which path served the block. `GetBlockByHeight` carries vote
    /// data; batch sync does not (`vote_data: None` — service.rs). Treating
    /// absence as terminal makes an HONEST peer that happened to answer by
    /// batch permanently unjoinable, which blames the chain for a transport
    /// choice. Re-request over the vote-carrying path first.
    GenesisWitnessMissing,
    /// We have no genesis block, so the chain's origin cannot be anchored. Retrying
    /// cannot help; the operator must configure `[chain] genesis_seed`.
    NoGenesis,
    /// Ordinary validation failure — retrying a different peer may succeed.
    Invalid,
    /// F5: a non-genesis block whose certificate is PRESENT, verifies, and
    /// names this block — but carries fewer than `min_unique_voters` distinct
    /// signers. That is a statement about the CHAIN: legitimacy zero, terminal
    /// for that source.
    SelfVoted,
    /// F5: a non-genesis block arrived with no usable witness record.
    ///
    /// Retryable, and the distinction from `SelfVoted` is the same one that
    /// separates `GenesisWitnessMissing` from `GenesisUnacceptable`: whether a
    /// certificate arrives depends on WHICH PATH served the block.
    /// `GetBlockByHeight` carries vote data; batch `GetBlocks` sets
    /// `vote_data: None` (service.rs), and so does the by-hash gossip retry.
    /// Treating absence as a self-voted verdict would reject an honest chain
    /// for a transport choice and drop the peer serving it — breaking ordinary
    /// catch-up. Re-request over the vote-carrying path first; only when the
    /// retry budget is exhausted is the block unprovable, and unprovable is
    /// then legitimacy zero (plan Step 0).
    WitnessMissing,
    /// OUR storage failed while loading OUR own tip header — nothing about the
    /// peer or its chain. Kept distinct from `ChainMismatch` because the
    /// mismatch arm drops the serving peer as a sync source: a local I/O error
    /// would otherwise quarantine an innocent peer for `REJECTED_SOURCE_TTL`
    /// and, worse, raise a fork clue for a fork that does not exist.
    /// Retryable, no drop, no clue.
    LocalStorage,
}

impl SyncImportResult {
    /// Reject with an explicit kind.
    pub fn reject(kind: RejectKind, reason: impl Into<String>) -> Self {
        Self::Rejected { reason: reason.into(), kind }
    }
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
            let is_local = tip_hash == local_tip_hex;
            Some(noble_consensus::ForkInfo {
                tip_hash: Hash256::from_bytes(bytes),
                height,
                peer_count,
                is_local,
                has_chain_owner: owner_group.as_ref() == Some(&tip_hash),
                // Filled by the caller from verified certificates (F3/F4).
                legitimacy: if is_local {
                    SegmentLegitimacy::Witnessed(noble_consensus::Grade::default())
                } else {
                    SegmentLegitimacy::Unknown
                },
                witnessed_prefix_end: if is_local { local_height } else { 0 },
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
    have_chain: bool,
    connected_peers: usize,
    peers_with_tip: usize,
    highest_known: u64,
    has_proposals: bool,
    dwell_active: impl FnOnce() -> bool,
    majority: impl FnOnce() -> (usize, usize),
) -> AlignmentState {
    // Order matters. `Syncing` used to sit *below* the `height == 0` arms, so
    // it was unreachable for a node at height 0 — a blank node facing a peer
    // 197 blocks ahead reported `Creating`, i.e. "forming a new chain", while
    // the sync banner simultaneously said "catching up to 197". Being far
    // behind a known chain is a property of the gap, not of our own height, so
    // it is tested first and the height-0 arms now describe only the case they
    // were meant for: a chain that genuinely has no peer ahead of it.
    if connected_peers == 0 {
        AlignmentState::Isolated
    } else if highest_known.saturating_sub(height) > ALIGNMENT_SYNC_GAP_BLOCKS {
        AlignmentState::Syncing
    } else if !have_chain && !has_proposals {
        AlignmentState::Bootstrapping
    } else if !have_chain {
        AlignmentState::Creating
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
            decide_alignment(0, false, 0, 0, 0, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Isolated
        );
        assert_eq!(
            decide_alignment(5, true, 0, 0, 5, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Isolated
        );
    }

    #[test]
    fn alignment_bootstrapping_and_creating_at_height_zero() {
        assert_eq!(
            decide_alignment(0, false, 2, 0, 0, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Bootstrapping
        );
        assert_eq!(
            decide_alignment(0, false, 2, 0, 0, true, unreachable_dwell, unreachable_maj),
            AlignmentState::Creating
        );
    }

    // ── Bootstrap & sync seams (2026-08-12) ──
    //
    // These exercise the two lifecycles the product depends on and that had no
    // coverage at all: founding a chain, and joining one from empty. Every
    // defect they pin was live in a suite that was otherwise green.

    /// Commit a genesis block directly and point consensus at it, producing the
    /// "genesis only" state — a real chain whose tip height is 0.
    fn found_chain(h: &mut HealingManager<MemoryStorage>) -> (Hash256, u32) {
        // Use the shared test genesis so the chain id the fixtures sign with
        // (`test_chain_id()`) is exactly the one derived from this genesis.
        // Otherwise every later block fails on merkle mismatch before reaching
        // the rule under test — which is how the first version of this test
        // passed while proving nothing.
        let block = noble_test_utils::fixtures::test_genesis_block();
        let hash = noble_test_utils::fixtures::test_genesis_hash();
        assert_eq!(block.header.height, noble_core::GENESIS_HEIGHT);
        h.storage
            .read()
            .commit_block(&block, &hash, &[])
            .expect("genesis commits");
        h.consensus
            .write()
            .reset_tip(noble_core::GENESIS_HEIGHT, hash, true)
            .expect("tip set to genesis");
        let cid = noble_core::derive_chain_id(&hash);
        assert_eq!(cid, noble_test_utils::fixtures::test_chain_id());
        h.update_chain_id(cid);
        (hash, cid)
    }

    /// Put the manager in the state a real joining node is in when genesis
    /// arrives: syncing, with a manifest that names the genesis we asked for.
    /// Genesis is only ever adopted against such a promise.
    fn expect_genesis(h: &mut HealingManager<MemoryStorage>, promised: Hash256) {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(promised.as_bytes());
        h.sync_state = SyncState::Fetching {
            peer: vec![1, 2, 3],
            target: 2,
            manifest: vec![ManifestEntry {
                height: noble_core::GENESIS_HEIGHT,
                hash,
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };
    }

    /// Build a signed witness certificate for `candidate` from `n` distinct
    /// validators, as a CBOR `BlockVotes` blob (what sync carries).
    fn witness_blob(candidate: Hash256, n: usize) -> Vec<u8> {
        witness_blob_at_cycle(candidate, n, 0)
    }

    /// As [`witness_blob`], but for a genesis founded in `cycle`.
    ///
    /// The fixtures used to hard-code cycle 0 on both the votes and the
    /// certificate, so the one shape that actually broke — founding that took
    /// more than a single cycle — was never constructed and never tested.
    fn witness_blob_at_cycle(candidate: Hash256, n: usize, cycle: u64) -> Vec<u8> {
        use noble_codec::NobleCbor;
        let mut votes = Vec::new();
        for _ in 0..n {
            let (sk, pk) = noble_crypto::secp256k1::generate_keypair();
            let priv_key = noble_crypto::NoblePrivateKey::Secp256k1(sk);
            let pub_key = noble_crypto::NoblePublicKey::Secp256k1(pk);
            votes.push(
                noble_consensus::PorVote::sign(cycle, candidate, &priv_key, pub_key)
                    .expect("vote signs"),
            );
        }
        let bv = noble_consensus::BlockVotes {
            cycle_number: cycle,
            voter_count: n,
            strength: "Strong".to_string(),
            r1_voters: vec![],
            r2_voters: vec![],
            unique_witness_count: n,
            dual_witness_required: true,
            dual_witness_met: true,
            certificate: Some(noble_consensus::history::WitnessCertificate {
                cycle,
                candidate_hash: candidate,
                votes,
            }),
        };
        bv.to_cbor().expect("blob encodes")
    }

    #[test]
    fn a_founded_genesis_survives_restart_and_can_be_joined() {
        // I2: startup HALTS a node whose genesis cannot show a valid
        // certificate. So if founding stores one that later fails
        // verification, the founding node bricks itself on its own valid
        // chain — and no peer can join it either. Prove the round trip:
        // store what founding stores, verify it the way startup does, then
        // hand the same pair to a second node's sync import.
        use noble_codec::NobleCbor;

        let h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        let hash = noble_test_utils::fixtures::test_genesis_hash();
        let required = h.consensus.read().min_unique_voters();

        // What the engine persists at commit.
        let blob = witness_blob(hash, required);
        h.storage.read().commit_block(&block, &hash, &[]).expect("genesis commits");
        h.storage
            .read()
            .store_block_votes(noble_core::GENESIS_HEIGHT, &blob)
            .expect("witness record persists");

        // --- what startup does on the next boot ---
        let raw = h
            .storage
            .read()
            .get_block_votes(noble_core::GENESIS_HEIGHT)
            .expect("readable")
            .expect("genesis must have a stored witness record");
        let bv = <noble_consensus::BlockVotes as NobleCbor>::from_cbor(&raw).expect("decodes");
        let cert = bv.certificate.expect("genesis must carry a certificate");
        assert_eq!(cert.candidate_hash, hash, "certificate must name genesis");
        let witnesses = cert.verify().expect("stored certificate must verify after a restart");
        assert!(
            witnesses >= required,
            "stored genesis certificate must still meet the Dual-Witness threshold"
        );

        // --- what a JOINING node does with the same pair ---
        let mut joiner = make_healing_manager();
        expect_genesis(&mut joiner, hash);
        let result = joiner.try_sync_import(&block, Some(&raw));
        assert!(
            matches!(result, SyncImportResult::Accepted { .. }),
            "a genesis good enough to keep must be good enough to join, got {result:?}"
        );
    }

    #[test]
    fn a_missing_genesis_certificate_triggers_a_re_request_by_height() {
        // Classifying a missing certificate as retryable is only useful if the
        // node then actually re-asks over the path that CARRIES certificates.
        // `GetBlocks` (batch, and the by-hash retry) has no slot for vote data;
        // only `GetBlockByHeight` serves `get_block_votes`. Without this the
        // "retryable" classification would just re-request over the same
        // voteless path forever.
        let (net_tx, mut net_rx) = mpsc::channel(32);
        let (blk_tx, _) = broadcast::channel(32);
        let (phase_tx, _) = broadcast::channel(32);
        let mut h = make_healing_manager();
        h.set_io_channels(net_tx, blk_tx, phase_tx, None);

        // Put the conveyor in Fetching with genesis outstanding.
        h.sync_state = SyncState::Fetching {
            peer: vec![9, 9, 9],
            target: 3,
            manifest: vec![ManifestEntry {
                height: noble_core::GENESIS_HEIGHT,
                hash: [0u8; 32],
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };

        // Drive the conveyor with the refusal a voteless genesis produces.
        let block = noble_test_utils::fixtures::test_genesis_block();
        let result = h.try_sync_import(&block, None);
        assert!(
            matches!(result, SyncImportResult::Rejected { kind: RejectKind::GenesisWitnessMissing, .. }),
            "precondition: a voteless genesis is refused as retryable"
        );
        h.advance_after_import(noble_core::GENESIS_HEIGHT, &result, 0);

        let mut asked_for_genesis_by_height = false;
        while let Ok(cmd) = net_rx.try_recv() {
            if let NetworkCommand::RequestBlockByHeight { height, .. } = cmd {
                if height == noble_core::GENESIS_HEIGHT {
                    asked_for_genesis_by_height = true;
                }
            }
        }
        assert!(
            asked_for_genesis_by_height,
            "a genesis served without its certificate must be re-requested by height"
        );
    }

    #[test]
    fn a_manifest_with_an_all_zero_hash_is_refused() {
        // A block hash is a SHA-256 digest — all-zeros cannot occur. Accepting
        // one would have let a peer blank the very field genesis is bound
        // against, silently disabling the binding.
        let mut h = make_healing_manager();
        h.sync_state = SyncState::AwaitingManifest {
            peer: vec![4, 5, 6],
            target: 3,
            requested_at: 0,
        };
        h.on_manifest_received(
            &[4, 5, 6],
            &[
                (noble_core::GENESIS_HEIGHT, Some([0u8; 32])),
                (1, Some([0xAB; 32])),
            ],
            0,
        );
        assert!(
            matches!(h.sync_state, SyncState::Idle),
            "a manifest containing an impossible hash must be refused outright"
        );
    }

    #[test]
    fn genesis_pushed_without_a_manifest_is_not_adopted() {
        // Nothing to bind against means the block was pushed at us, not asked
        // for. Adopting opportunistically is how a node lands on a chain it
        // never chose — retryable, so the manifest can still arrive.
        let h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        let hash = noble_test_utils::fixtures::test_genesis_hash();
        let blob = witness_blob(hash, h.consensus.read().min_unique_voters());
        match h.try_sync_import(&block, Some(&blob)) {
            SyncImportResult::Rejected { ref reason, kind } => {
                assert_eq!(kind, RejectKind::GenesisWitnessMissing, "{reason}");
                assert!(reason.contains("no manifest asked for"), "got: {reason}");
            }
            other => panic!("an unrequested genesis must not be adopted, got {other:?}"),
        }
    }

    #[test]
    fn a_peer_cannot_deliver_a_genesis_its_manifest_did_not_promise() {
        // Every height above genesis is bound by its parent link: a substituted
        // block fails B2 because it does not chain to what we hold. Genesis has
        // no parent, so it needs explicit binding — otherwise a peer advertises
        // one chain and delivers another, properly witnessed, and the joining
        // node adopts a chain it never asked to join.
        let mut h = make_healing_manager();
        let real = noble_test_utils::fixtures::test_genesis_block();
        let real_hash = noble_test_utils::fixtures::test_genesis_hash();

        // The manifest promises a DIFFERENT genesis than the peer will deliver.
        h.sync_state = SyncState::Fetching {
            peer: vec![7, 7, 7],
            target: 2,
            manifest: vec![ManifestEntry {
                height: noble_core::GENESIS_HEIGHT,
                hash: [0xC3; 32],
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };

        // Even WITH a valid two-witness certificate, the swap must be refused.
        let blob = witness_blob(real_hash, h.consensus.read().min_unique_voters());
        match h.try_sync_import(&real, Some(&blob)) {
            SyncImportResult::Rejected { ref reason, kind } => {
                assert_eq!(
                    kind,
                    RejectKind::GenesisUnacceptable,
                    "a substituted genesis must be terminal: {reason}"
                );
                assert!(
                    reason.contains("manifest"),
                    "the reason must name the broken promise, got: {reason}"
                );
            }
            other => panic!("substituted genesis must be refused, got {other:?}"),
        }
    }

    /// R6/G1: a chain founded after several cycles must be joinable.
    ///
    /// Founding routinely takes more than one cycle — live logs show cycle 3
    /// and cycle 13. The certificate used to be stamped cycle 0 regardless, so
    /// such a chain could never prove its witnesses: every joining peer refused
    /// it as under-witnessed and told the operator it had to be re-founded.
    /// This is the exact case the fixtures never built.
    #[test]
    fn a_genesis_founded_after_many_cycles_is_accepted_by_a_joining_peer() {
        let mut h = make_healing_manager();
        let real = noble_test_utils::fixtures::test_genesis_block();
        let real_hash = noble_test_utils::fixtures::test_genesis_hash();
        let mut promised = [0u8; 32];
        promised.copy_from_slice(real_hash.as_bytes());

        h.sync_state = SyncState::Fetching {
            peer: vec![7, 7, 7],
            target: 2,
            manifest: vec![ManifestEntry {
                height: noble_core::GENESIS_HEIGHT,
                hash: promised,
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };

        let required = h.consensus.read().min_unique_voters();
        let blob = witness_blob_at_cycle(real_hash, required, 13);
        match h.try_sync_import(&real, Some(&blob)) {
            SyncImportResult::Rejected { ref reason, kind } => panic!(
                "a properly witnessed genesis founded at cycle 13 must be accepted, \
                 got {kind:?}: {reason}"
            ),
            _ => {}
        }
    }

    /// R6/G3: a cycle-binding fault is retryable, never a verdict on the chain.
    #[test]
    fn a_cycle_binding_fault_is_retryable_not_a_witness_verdict() {
        use noble_codec::NobleCbor;
        let mut h = make_healing_manager();
        let real = noble_test_utils::fixtures::test_genesis_block();
        let real_hash = noble_test_utils::fixtures::test_genesis_hash();
        let mut promised = [0u8; 32];
        promised.copy_from_slice(real_hash.as_bytes());

        h.sync_state = SyncState::Fetching {
            peer: vec![7, 7, 7],
            target: 2,
            manifest: vec![ManifestEntry {
                height: noble_core::GENESIS_HEIGHT,
                hash: promised,
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };

        // Two genuine witnesses, but the certificate's cycle is far from the
        // votes' — the legacy on-disk shape, and a record fault, not a fraud.
        let required = h.consensus.read().min_unique_voters();
        let mut bv = <noble_consensus::BlockVotes as NobleCbor>::from_cbor(
            &witness_blob_at_cycle(real_hash, required, 13),
        )
        .expect("decodes");
        if let Some(cert) = bv.certificate.as_mut() {
            cert.cycle = 0;
        }
        let blob = bv.to_cbor().expect("encodes");

        match h.try_sync_import(&real, Some(&blob)) {
            SyncImportResult::Rejected { ref reason, kind } => {
                assert_eq!(
                    kind,
                    RejectKind::GenesisWitnessMissing,
                    "a record fault must be retryable, not a terminal verdict: {reason}"
                );
                assert!(
                    !reason.contains("Dual-Witness Rule"),
                    "must not be reported as a witness shortfall, got: {reason}"
                );
            }
            other => panic!("expected a retryable rejection, got {other:?}"),
        }
    }

    /// R2: refusing a peer's chain must drop that peer as a source, not the node.
    #[test]
    fn a_refused_peer_is_skipped_as_a_sync_source_but_the_node_keeps_running() {
        let mut h = make_healing_manager();
        h.sync_state = SyncState::Fetching {
            peer: vec![1, 2, 3],
            target: 5,
            manifest: vec![],
            cursor: 0,
        };
        h.drop_sync_source("genesis witnessed by only 1 distinct validator(s)");

        assert!(
            h.is_rejected_sync_source(&[1, 2, 3]),
            "the refusal must actually be recorded, or selection re-picks the peer"
        );
        h.compute_alignment();
        assert_ne!(
            h.alignment().read().state.label(),
            "Blocked",
            "refusing a peer's chain must never halt this node"
        );
    }

    // ── Legitimacy gradation (F3–F8) ──

    fn facts(keys: &[u8], r1: usize) -> CertFacts {
        let keys: Vec<Vec<u8>> = keys.iter().map(|k| vec![*k]).collect();
        CertFacts { witnesses: keys.len(), r1, keys }
    }
    fn staged(h: u64, proposer: u8, keys: &[u8]) -> StagedBlock {
        StagedBlock::from_facts(h, Hash256::from_bytes([h as u8; 32]), vec![proposer], Some(facts(keys, keys.len())))
    }

    #[test]
    fn witnessed_prefix_end_stops_at_the_first_solo_block() {
        // ancestor 26; 27,28 witnessed; 29 solo; 30 witnessed (built on solo).
        let seg = vec![staged(27, 1, &[1, 2]), staged(28, 2, &[1, 2]), staged(29, 1, &[1]), staged(30, 2, &[1, 2])];
        let (leg, end) = grade_segment(&seg, 26, 2, 2);
        assert_eq!(end, 28, "the witnessed prefix ends just below the first solo block");
        match leg {
            SegmentLegitimacy::SelfVoted { first_solo, .. } => assert_eq!(first_solo, 29),
            other => panic!("a segment with one solo block is Tier 0, got {other:?}"),
        }
    }

    #[test]
    fn a_fully_witnessed_segment_is_graded_weakest_first() {
        let seg = vec![staged(1, 1, &[1, 2, 3]), staged(2, 2, &[1, 2]), staged(3, 3, &[2, 3])];
        match grade_segment(&seg, 0, 2, 3).0 {
            SegmentLegitimacy::Witnessed(g) => {
                assert_eq!(g.weakest, 2);
                assert_eq!(g.coverage, 3);
                assert_eq!(g.total, 7);
            }
            other => panic!("expected Witnessed, got {other:?}"),
        }
    }

    #[test]
    fn solo_grade_measures_participation_from_varied_peers() {
        // All by key 1, self-witnessed: variety 1, density 1000, balance 3.
        let mono = vec![staged(1, 1, &[1]), staged(2, 1, &[1]), staged(3, 1, &[1])];
        // Proposed by 1, witnessed only by 2 (one witness, but two participants).
        let duo = vec![staged(1, 1, &[2]), staged(2, 2, &[1]), staged(3, 1, &[2])];
        let g1 = match grade_segment(&mono, 0, 2, 2).0 { SegmentLegitimacy::SelfVoted { grade, .. } => grade, o => panic!("{o:?}") };
        let g2 = match grade_segment(&duo, 0, 2, 2).0 { SegmentLegitimacy::SelfVoted { grade, .. } => grade, o => panic!("{o:?}") };
        assert_eq!(g1.variety, 1);
        assert_eq!(g2.variety, 2);
        assert_eq!(g2.density_x1000, 2000);
        assert!(g2 > g1, "two participating peers out-grade one, regardless of witness count");
    }

    #[test]
    fn an_empty_segment_is_not_contesting() {
        assert_eq!(grade_segment(&[], 10, 2, 2), (SegmentLegitimacy::NotContesting, 10));
    }

    #[test]
    fn certificate_facts_require_the_certificate_to_name_the_block() {
        let hash = Hash256::from_bytes([0x5A; 32]);
        let blob = witness_blob(hash, 2);
        let f = certificate_facts(Some(&blob), hash).expect("valid certificate");
        assert_eq!(f.witnesses, 2);
        assert_eq!(f.r1, 2);
        assert!(certificate_facts(Some(&blob), Hash256::from_bytes([0x5B; 32])).is_none());
        assert!(certificate_facts(None, hash).is_none());
    }

    /// F1: a persisted finality anchor on an under-witnessed block is not a
    /// floor — the algorithm lowers it to the highest witnessed block.
    #[test]
    fn a_persisted_solo_anchor_is_not_a_floor() {
        let mut h = make_healing_manager();
        let (hash, _) = found_chain(&mut h);
        let required = h.consensus.read().min_unique_voters();
        h.storage
            .read()
            .store_block_votes(noble_core::GENESIS_HEIGHT, &witness_blob(hash, required))
            .unwrap();
        let st = h.storage.read();
        assert!(block_is_witnessed(&*st, 0, required));
        assert!(!block_is_witnessed(&*st, 1, required), "nothing provable at height 1");
        // A record claiming finality at height 1 must be lowered to genesis.
        assert_eq!(highest_witnessed_at_or_below(&*st, 1, required), Some(0));
        assert_eq!(highest_witnessed_at_or_below(&*st, 0, required), Some(0));
    }

    /// F5 regression guard: batch sync (`SyncResponse::Blocks`) and the
    /// by-hash gossip retry both set `vote_data: None` (service.rs:1670). If
    /// absence were treated as a self-voted verdict, ordinary catch-up would
    /// reject honest chains and drop the peers serving them — the same
    /// "gate correct, delivery path not enumerated" failure as the GetBlocks
    /// genesis regression. Absence must be RETRYABLE over the vote-carrying
    /// path; only a certificate that verifies and falls short is a verdict.
    #[test]
    fn a_block_served_without_votes_is_retryable_not_a_self_voted_verdict() {
        let mut h = make_healing_manager();
        let (genesis_hash, _) = found_chain(&mut h);
        let required = h.consensus.read().min_unique_voters();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let validator = noble_test_utils::fixtures::TestKeypair::generate();
        let (block, block_hash, _) = noble_test_utils::fixtures::make_block_with_coinbase(
            vec![], 1, genesis_hash, now, &validator, &[],
        );

        // Served by a voteless path.
        match h.try_sync_import(&block, None) {
            SyncImportResult::Rejected { kind, ref reason } => assert_eq!(
                kind,
                RejectKind::WitnessMissing,
                "absence is a transport fact, not a chain verdict: {reason}"
            ),
            other => panic!("expected a retryable refusal, got {other:?}"),
        }

        // Served WITH a certificate that verifies but falls short: a verdict.
        let short = witness_blob(block_hash, required - 1);
        match h.try_sync_import(&block, Some(&short)) {
            SyncImportResult::Rejected { kind, ref reason } => assert_eq!(
                kind,
                RejectKind::SelfVoted,
                "a proven shortfall is a chain verdict: {reason}"
            ),
            other => panic!("expected a terminal refusal, got {other:?}"),
        }
    }

    /// D1: a chain mismatch must RELEASE the sync guard, not merely pause the
    /// conveyor. `detect_forks` is the only caller of `start_assessment` and
    /// the only trigger of ancestor discovery, and it returns early while
    /// `is_syncing()`. Leaving sync_state non-Idle here deadlocked the node:
    /// the rival could never be assessed, so `execute_resolution` refused
    /// forever on `rival == Unknown`.
    #[test]
    fn chain_mismatch_releases_the_sync_guard() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        h.sync_state = SyncState::Fetching {
            peer: peer.clone(),
            target: 1289,
            manifest: vec![ManifestEntry {
                height: 1285,
                hash: [0xAB; 32],
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };
        assert!(h.is_syncing());

        h.advance_after_import(
            1285,
            &SyncImportResult::reject(RejectKind::ChainMismatch, "prev_hash mismatch"),
            0,
        );

        assert!(!h.is_syncing(), "the guard must be released so detect_forks can run");
        assert!(
            h.is_rejected_sync_source(&peer),
            "the peer whose chain we refused must not be re-picked immediately"
        );
    }

    /// F1a: a failure to read OUR OWN tip header is our disk, not their chain.
    /// It must not drop the peer, and must not raise a fork clue for a fork
    /// that does not exist.
    #[test]
    fn local_storage_error_does_not_drop_the_peer() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        h.sync_state = SyncState::Fetching {
            peer: peer.clone(),
            target: 30,
            manifest: vec![ManifestEntry {
                height: 10,
                hash: [0xAB; 32],
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };

        h.advance_after_import(
            10,
            &SyncImportResult::reject(RejectKind::LocalStorage, "parent header error: disk"),
            0,
        );

        assert!(
            !h.is_rejected_sync_source(&peer),
            "our own storage failing must never quarantine an innocent peer"
        );
        assert!(
            !h.clue_collector.has_clues(),
            "a local I/O error is not evidence of a fork"
        );
    }

    /// F2: `execute_resolution` resets sync on its way out. Under the old
    /// unconditional clear that destroyed the permit it had just granted, so
    /// the adopted chain's unwitnessed blocks were rejected as `SelfVoted` and
    /// the whole solo-adoption branch was dead code in production.
    #[test]
    fn solo_adoption_permit_survives_an_unrelated_reset() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        let tip_hex = hex::encode([0xC1u8; 32]);
        h.solo_adoption_permit = Some((peer.clone(), tip_hex));

        // A reset of a DIFFERENT peer's sync must leave the permit alone.
        h.sync_state = SyncState::Fetching {
            peer: vec![9, 9, 9],
            target: 30,
            manifest: Vec::new(),
            cursor: 0,
        };
        h.reset_sync_idle();
        assert!(h.solo_adoption_permit.is_some(), "an unrelated sync ending must not revoke it");

        // And a reset from Idle — which is exactly what execute_resolution does
        // immediately after granting — must also leave it alone.
        h.reset_sync_idle();
        assert!(h.solo_adoption_permit.is_some(), "an Idle reset must not revoke it");
    }

    /// F2: the stall alarm calls `reset_sync_idle` too. If it fired between the
    /// grant and the first imported block it would revoke the permit and
    /// recreate the deadlock through a different door.
    #[test]
    fn stall_alarm_does_not_kill_a_fresh_permit() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        let tip_hex = hex::encode([0xC1u8; 32]);
        h.peer_info
            .write()
            .insert(hex::encode(&peer), peer_entry(&peer, &tip_hex, 1289));
        h.solo_adoption_permit = Some((peer.clone(), tip_hex));

        let now = 10_000u64;
        h.stall_watch_height = 0;
        h.stall_watch_since = 1;
        h.check_sync_stall(0, now);

        assert!(
            h.solo_adoption_permit.is_some(),
            "a stall alarm must not revoke a permit for a sync that has not started"
        );
    }

    /// F2: the mismatch that triggers resolution drops the serving peer. By the
    /// time the resolver decides to adopt that peer's chain it is quarantined,
    /// and `select_sync_peer` would skip it — stalling the adoption a second
    /// time. A decided adoption overrides the earlier refusal.
    #[test]
    fn adopted_peer_is_readmitted_as_a_sync_source() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        let tip = Hash256::from_bytes([0xC1; 32]);
        let tip_hex = hex::encode(tip.as_bytes());
        h.peer_info
            .write()
            .insert(hex::encode(&peer), peer_entry(&peer, &tip_hex, 1289));
        h.rejected_sync_sources.insert(peer.clone(), std::time::Instant::now());
        assert!(h.is_rejected_sync_source(&peer));

        h.readmit_adoption_source(tip);

        assert!(
            !h.is_rejected_sync_source(&peer),
            "the peer whose chain we decided to adopt must be selectable again"
        );
    }

    /// D3: ancestor discovery used to be edge-triggered — one send, in the same
    /// branch that clears `fork_common_ancestor`. A lost response (or entering
    /// Syncing before it landed) left the ancestor unknown forever, and
    /// `execute_resolution` then refused with "Operator action required": a
    /// human-in-the-loop dead end for a transient condition.
    #[test]
    fn ancestor_discovery_retries_while_unknown() {
        let (tx, mut rx) = mpsc::channel(64);
        let mut h = make_healing_manager();
        h.network_cmd = Some(tx);
        let (_genesis, cid) = found_chain(&mut h);

        // A peer on a rival tip at a greater height → two fork groups.
        // `compute_fork_groups` skips peers whose chain_id is unannounced, so
        // it must be set for this peer to form a group at all.
        let peer = vec![7u8, 7, 7];
        let rival_tip = hex::encode([0xC1u8; 32]);
        let mut entry = peer_entry(&peer, &rival_tip, 1289);
        entry.chain_id = Some(cid);
        h.peer_info.write().insert(hex::encode(&peer), entry);

        let count_ancestor_requests = |rx: &mut mpsc::Receiver<NetworkCommand>| {
            let mut n = 0;
            while let Ok(cmd) = rx.try_recv() {
                if matches!(cmd, NetworkCommand::FindCommonAncestor { .. }) {
                    n += 1;
                }
            }
            n
        };

        h.detect_forks();
        assert!(h.fork_common_ancestor.is_none(), "still unknown");
        assert_eq!(count_ancestor_requests(&mut rx), 1, "first attempt goes out");

        // Immediately again: the backoff must suppress it.
        h.detect_forks();
        assert_eq!(count_ancestor_requests(&mut rx), 0, "backoff suppresses a same-tick retry");

        // Past the backoff window: it must try again rather than give up.
        h.last_ancestor_request = Some((0, 0));
        h.detect_forks();
        assert_eq!(count_ancestor_requests(&mut rx), 1, "discovery retries — it never stops");

        // Once known, it stops asking.
        h.fork_common_ancestor = Some((1279, [0xAA; 32]));
        h.last_ancestor_request = Some((0, 0));
        h.detect_forks();
        assert_eq!(count_ancestor_requests(&mut rx), 0, "a known ancestor ends the retries");
    }

    fn peer_entry(peer: &[u8], tip_hex: &str, height: u64) -> PeerInfoEntry {
        PeerInfoEntry {
            peer_id: hex::encode(peer),
            direction: "outbound".to_string(),
            addr: String::new(),
            connected_at: 0,
            ban_score: 0,
            misbehavior_categories: Vec::new(),
            chain_tip_height: Some(height),
            chain_tip_hash: Some(tip_hex.to_string()),
            verified_height: None,
            proposed_height: None,
            identity_key: None,
            node_name: None,
            latency_ms: None,
            last_ban_reason: None,
            chain_id: None,
            min_fee_rate: None,
            tip_legitimacy: None,
        }
    }

    /// F3: blocks fetched for assessment are evidence, not imports — the
    /// routing predicate node.rs consults must claim them.
    #[test]
    fn assessment_blocks_are_claimed_before_sync_import() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        let tip = Hash256::from_bytes([0xC1; 32]);
        h.peer_info.write().insert(hex::encode(&peer), peer_entry(&peer, &hex::encode(tip.as_bytes()), 30));
        h.start_assessment(tip, 26, 30);
        assert!(h.is_assessment_block(&peer, 27));
        assert!(h.is_assessment_block(&peer, 30));
        assert!(!h.is_assessment_block(&peer, 26), "the ancestor itself is not fetched");
        assert!(!h.is_assessment_block(&peer, 31));
        assert!(!h.is_assessment_block(&[9, 9, 9], 27), "other peers' blocks are not claimed");
    }

    /// F3: assessment always terminates. A peer that never serves votes is
    /// scored unprovable — Tier 0 — after the retry budget, not waited on.
    #[test]
    fn assessment_terminates_when_a_peer_never_serves_votes() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        let tip = Hash256::from_bytes([0xC2; 32]);
        let tip_hex = hex::encode(tip.as_bytes());
        h.peer_info.write().insert(hex::encode(&peer), peer_entry(&peer, &tip_hex, 28));
        h.start_assessment(tip, 26, 28);
        assert!(h.assessments.get(&tip_hex).is_none());
        // Advance well past the retry budget; each tick either retries or
        // exhausts. Base on the real clock: `start_assessment` stamps requests
        // with wall time, so a synthetic epoch never appears to elapse.
        let mut now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for _ in 0..(SYNC_MAX_BLOCK_RETRIES as u64 + 2) {
            now += SYNC_RETRY_SECS + 1;
            h.tick_assessments(now);
        }
        match h.assessments.get(&tip_hex) {
            Some(SegmentLegitimacy::SelfVoted { first_solo, .. }) => assert_eq!(*first_solo, 27),
            other => panic!("unprovable must resolve to Tier 0, got {other:?}"),
        }
        assert!(!h.is_assessment_block(&peer, 27), "completed runs release their heights");
        let view = h.peer_info.read().get(&hex::encode(&peer)).unwrap().tip_legitimacy.clone();
        assert_eq!(view.map(|v| v.label), Some("self_voted".to_string()));
    }

    /// F5: "no node syncs with it" — unless the resolver issued a permit.
    #[test]
    fn select_sync_peer_skips_a_self_voted_tip_unless_permitted() {
        let mut h = make_healing_manager();
        let peer = vec![7u8, 7, 7];
        let tip_hex = "cc".repeat(32);
        h.peer_info.write().insert(hex::encode(&peer), peer_entry(&peer, &tip_hex, 40));
        h.assessments.insert(
            tip_hex.clone(),
            SegmentLegitimacy::SelfVoted { first_solo: 21, grade: noble_consensus::SoloGrade::default() },
        );
        assert_eq!(h.select_sync_peer(20, None).0, None, "a self-voted tip is not a source");
        h.solo_adoption_permit = Some((peer.clone(), tip_hex.clone()));
        assert_eq!(h.select_sync_peer(20, None).0, Some(peer.clone()), "the permitted peer is");
        // F2: "scoped to one sync" means the PERMITTED sync. The fixture used
        // to reset from Idle, which is the case that must now SURVIVE — under
        // the old unconditional clear, `execute_resolution`'s own trailing
        // reset destroyed every permit it had just granted. Put the permitted
        // sync in flight, then end it.
        h.sync_state = SyncState::Fetching {
            peer: peer.clone(),
            target: 30,
            manifest: Vec::new(),
            cursor: 0,
        };
        h.reset_sync_idle();
        assert!(h.solo_adoption_permit.is_none(), "a permit is scoped to one sync");
    }

    /// F6: the swap point refuses to trade a witnessed chain for an unproven one.
    #[test]
    fn execute_resolution_refuses_when_local_is_witnessed_and_rival_unassessed() {
        let mut h = make_healing_manager();
        let (hash, _) = found_chain(&mut h);
        h.fork_common_ancestor = Some((0, *hash.as_bytes()));
        let before = h.consensus.read().chain_tip();
        h.execute_resolution(Hash256::from_bytes([0xEE; 32]), 40, "test");
        assert_eq!(h.consensus.read().chain_tip(), before, "no rollback may happen");
        assert!(h.fork_common_ancestor.is_some(), "a refused resolution leaves fork state intact");
    }

    #[test]
    fn the_promised_genesis_is_still_accepted() {
        // The binding must not reject the genesis we actually asked for.
        let mut h = make_healing_manager();
        let real = noble_test_utils::fixtures::test_genesis_block();
        let real_hash = noble_test_utils::fixtures::test_genesis_hash();
        let mut promised = [0u8; 32];
        promised.copy_from_slice(real_hash.as_bytes());

        h.sync_state = SyncState::Fetching {
            peer: vec![7, 7, 7],
            target: 2,
            manifest: vec![ManifestEntry {
                height: noble_core::GENESIS_HEIGHT,
                hash: promised,
                status: EntryStatus::Requested { at: 0 },
            }],
            cursor: 0,
        };

        let blob = witness_blob(real_hash, h.consensus.read().min_unique_voters());
        let result = h.try_sync_import(&real, Some(&blob));
        assert!(
            matches!(result, SyncImportResult::Accepted { .. }),
            "the genesis the manifest promised must be adoptable, got {result:?}"
        );
    }

    #[test]
    fn synced_genesis_without_witnesses_is_refused() {
        // The engine enforces Dual-Witness when FOUNDING, but sync import
        // bypasses the engine. Without this check a joining node adopts a
        // foundation nobody witnessed — a chain founded by one node.
        let mut h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        expect_genesis(&mut h, noble_test_utils::fixtures::test_genesis_hash());

        // No witness data at all: refused, but RETRYABLE — absence depends on
        // which path served the block, not on the chain. `GetBlockByHeight`
        // carries vote data; batch sync does not. Making absence terminal would
        // let an honest peer that answered by batch render the chain
        // permanently unjoinable.
        match h.try_sync_import(&block, None) {
            SyncImportResult::Rejected { ref reason, kind } => {
                assert_eq!(
                    kind,
                    RejectKind::GenesisWitnessMissing,
                    "a missing witness record must be retryable, not terminal: {reason}"
                );
            }
            other => panic!("unwitnessed genesis must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_bad_genesis_certificate_is_terminal_but_a_missing_one_is_not() {
        // The two must not be conflated. "Present but insufficient" is a
        // statement about the CHAIN and no retry changes it. "Absent" is a
        // statement about the TRANSPORT and must be retried over the path that
        // carries votes.
        let mut h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        let hash = noble_test_utils::fixtures::test_genesis_hash();
        expect_genesis(&mut h, hash);

        match h.try_sync_import(&block, None) {
            SyncImportResult::Rejected { kind, .. } => {
                assert_eq!(kind, RejectKind::GenesisWitnessMissing, "absent must be retryable")
            }
            other => panic!("expected refusal, got {other:?}"),
        }

        let blob = witness_blob(hash, 1);
        match h.try_sync_import(&block, Some(&blob)) {
            SyncImportResult::Rejected { kind, .. } => {
                assert_eq!(
                    kind,
                    RejectKind::GenesisUnacceptable,
                    "an under-witnessed chain must be terminal"
                )
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn synced_genesis_with_one_witness_is_refused() {
        // One witness is exactly the solo-founding case the Dual-Witness Rule
        // exists to prevent. The threshold must match the engine's.
        let mut h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        let hash = noble_test_utils::fixtures::test_genesis_hash();
        expect_genesis(&mut h, hash);
        let required = h.consensus.read().min_unique_voters();
        assert!(required >= 2, "Dual-Witness threshold must be at least 2");

        let blob = witness_blob(hash, 1);
        match h.try_sync_import(&block, Some(&blob)) {
            SyncImportResult::Rejected { ref reason, .. } => {
                assert!(
                    reason.contains("only 1 distinct"),
                    "must name the witness shortfall, got: {reason}"
                );
            }
            other => panic!("single-witness genesis must be refused, got {other:?}"),
        }
    }

    #[test]
    fn synced_genesis_certificate_must_name_this_block() {
        // A certificate for some other block proves nothing about this one;
        // without the binding, one valid certificate would launder any genesis.
        let mut h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        expect_genesis(&mut h, noble_test_utils::fixtures::test_genesis_hash());
        let blob = witness_blob(Hash256::from_bytes([0x77; 32]), 2);
        match h.try_sync_import(&block, Some(&blob)) {
            SyncImportResult::Rejected { ref reason, .. } => {
                assert!(
                    reason.contains("different block"),
                    "must reject a certificate bound elsewhere, got: {reason}"
                );
            }
            other => panic!("mismatched certificate must be refused, got {other:?}"),
        }
    }

    #[test]
    fn synced_genesis_with_two_witnesses_is_accepted() {
        // The rule must not reject everything — a properly witnessed genesis
        // has to be adoptable or no node can ever join.
        let mut h = make_healing_manager();
        let block = noble_test_utils::fixtures::test_genesis_block();
        let hash = noble_test_utils::fixtures::test_genesis_hash();
        expect_genesis(&mut h, hash);
        let blob = witness_blob(hash, 2);
        let result = h.try_sync_import(&block, Some(&blob));
        assert!(
            matches!(result, SyncImportResult::Accepted { .. }),
            "a genesis with two distinct witnesses must be adoptable, got {result:?}"
        );
    }

    #[test]
    fn block_after_genesis_is_validated_against_its_parent() {
        // B4: a node holding only genesis has tip_height == 0, which the sync
        // path read as "no chain, therefore no parent header" — so the block
        // right after genesis was validated with B2/B3/B5 SKIPPED. That is the
        // false-history hole H8 exists to close, reopened by the renumbering.
        let mut h = make_healing_manager();
        let (genesis_hash, _) = found_chain(&mut h);

        let validator = noble_test_utils::fixtures::TestKeypair::generate();
        // Correct height, deliberately wrong parent.
        let (bad, _hash, _ids) = noble_test_utils::fixtures::make_block_with_coinbase(
            vec![],
            noble_core::GENESIS_HEIGHT + 1,
            Hash256::from_bytes([0xAB; 32]),
            noble_core::GENESIS_TIMESTAMP + 960,
            &validator,
            &[],
        );
        assert_ne!(bad.header.prev_block_hash, genesis_hash);

        let result = h.try_sync_import(&bad, None);
        // The REASON matters. A rejection for some unrelated rule (reward
        // arithmetic, timestamp) would leave the parent check still skipped
        // while the test looked green.
        match result {
            SyncImportResult::Rejected { ref reason, kind } => {
                eprintln!("REJECT kind={kind:?} reason={reason}");
                assert_eq!(
                    kind,
                    RejectKind::ChainMismatch,
                    "must be rejected for not descending from genesis, got: {reason}"
                );
            }
            other => panic!("must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn chain_id_comes_from_genesis_not_from_the_first_block_imported() {
        // B2: chain_id was derived from whatever block arrived first. That was
        // only ever correct while genesis WAS the first block.
        let mut h = make_healing_manager();
        let (genesis_hash, _) = found_chain(&mut h);
        let expected = noble_core::derive_chain_id(&genesis_hash);
        assert_eq!(h.get_chain_id(), expected);

        // Import the next block; the chain id must not be re-derived from it.
        let validator = noble_test_utils::fixtures::TestKeypair::generate();
        let (next, _hash, _ids) = noble_test_utils::fixtures::make_block_with_coinbase(
            vec![],
            noble_core::GENESIS_HEIGHT + 1,
            genesis_hash,
            noble_core::GENESIS_TIMESTAMP + 960,
            &validator,
            &[],
        );
        let _ = h.try_sync_import(&next, None);
        assert_eq!(
            h.get_chain_id(),
            expected,
            "chain id must stay derived from genesis"
        );
    }

    #[test]
    fn a_node_with_no_chain_syncs_from_genesis() {
        // B1: `our_height + 1` yields 1 when there is no chain, so genesis at
        // height 0 was never requested and a joining node could never obtain
        // the block everything else descends from.
        let h = make_healing_manager();
        assert_eq!(
            h.next_height_to_fetch(0),
            noble_core::GENESIS_HEIGHT,
            "a node with no chain must request genesis first"
        );
    }

    #[test]
    fn a_node_holding_only_genesis_continues_from_genesis() {
        // The "genesis only" state is real and normal, and must not be
        // mistaken for "no chain": the next block to fetch is genesis + 1.
        let mut h = make_healing_manager();
        let _ = found_chain(&mut h);
        assert_eq!(
            h.next_height_to_fetch(noble_core::GENESIS_HEIGHT),
            noble_core::GENESIS_HEIGHT + 1,
            "a node holding genesis must continue after it, not refetch it"
        );
    }

    /// R6: the inverse of the test this replaces.
    ///
    /// Alignment used to be overridden by a halt flag that outranked every
    /// topology-derived state. There is no such flag and no such state now: a
    /// chain failure is resolved by protocol, so alignment always reports what
    /// the node is actually doing.
    #[test]
    fn alignment_never_reports_a_halted_operator_gated_state() {
        let mut h = make_healing_manager();

        h.compute_alignment();
        let snap = h.alignment().read().clone();
        assert_ne!(snap.state.label(), "Blocked");
        assert!(
            snap.blocked_reason.is_none(),
            "no path may produce an operator-facing halt reason"
        );
        assert!(
            matches!(snap.state.severity(), "zero" | "syncing" | "medium" | "high"),
            "state must still classify for display"
        );
    }

    #[test]
    fn highest_intact_height_finds_the_rewind_target_and_reports_none_when_unrepairable() {
        let h = make_healing_manager();

        // Empty storage: nothing readable below the claimed tip, so there is
        // no prefix to keep and the caller must halt rather than rewind.
        assert_eq!(
            h.highest_intact_height(10),
            None,
            "no readable block below the tip must report unrepairable, not height 0"
        );

        // Commit a short chain, then claim a tip beyond it: the scan must land
        // on the highest block that actually exists rather than give up and
        // let the caller wipe.
        let validator = noble_test_utils::fixtures::TestKeypair::generate();
        let mut last = Hash256::ZERO;
        for height in 0..=3u64 {
            let (block, hash, ids) = noble_test_utils::fixtures::make_block_with_coinbase(
                vec![],
                height,
                last,
                noble_core::GENESIS_TIMESTAMP + height * 960,
                &validator,
                &[],
            );
            h.storage
                .read()
                .commit_block(&block, &hash, &ids)
                .expect("fixture block should commit");
            last = hash;
        }
        assert_eq!(
            h.highest_intact_height(7),
            Some(3),
            "must rewind to the deepest intact block, not wipe the chain"
        );
    }

    #[test]
    fn alignment_blank_node_behind_a_peer_is_syncing_not_creating() {
        // Regression, 2026-08-11: `Syncing` sat below the `height == 0` arms
        // and was therefore unreachable at height 0. A blank node facing a
        // peer 197 blocks ahead reported `Creating` — "forming a new chain" —
        // while the sync banner said "catching up to 197". Both were rendered
        // at once, and the node really was trying to do both.
        assert_eq!(
            decide_alignment(0, false, 1, 1, 197, true, unreachable_dwell, unreachable_maj),
            AlignmentState::Syncing
        );
        // Also with no proposals seen: still joining, not bootstrapping.
        assert_eq!(
            decide_alignment(0, false, 1, 1, 197, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Syncing
        );
    }

    #[test]
    fn a_genesis_only_chain_is_not_reported_as_having_no_chain() {
        // A chain consisting of genesis alone sits at height 0. Before
        // `have_chain` was explicit, that was read as "forming a chain" — the
        // node claimed to be bootstrapping a chain it had already founded.
        assert_eq!(
            decide_alignment(0, true, 2, 2, 0, true, dwell(false), maj(1, 0)),
            AlignmentState::Aligned,
            "a founded chain must not report as still forming"
        );
    }

    #[test]
    fn alignment_height_zero_still_forms_a_chain_when_no_peer_is_ahead() {
        // The Syncing reorder must not swallow genuine chain formation: peers
        // present, nobody ahead, so this really is a chain being created.
        assert_eq!(
            decide_alignment(0, false, 2, 2, 0, true, unreachable_dwell, unreachable_maj),
            AlignmentState::Creating
        );
        assert_eq!(
            decide_alignment(0, false, 2, 2, 0, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Bootstrapping
        );
    }

    #[test]
    fn alignment_verifying_when_peers_have_no_tips() {
        // THE fix: connected but evidence-free must NOT claim Aligned.
        // (Previously returned Aligned — two nodes 22 blocks apart both
        // showed "ALIGNED".)
        assert_eq!(
            decide_alignment(2751, true, 1, 0, 2751, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Verifying
        );
    }

    #[test]
    fn alignment_gap_threshold_is_two_blocks() {
        // Gap ≤ 2 (one-block tip race territory): not Syncing.
        for gap in 0..=ALIGNMENT_SYNC_GAP_BLOCKS {
            assert_eq!(
                decide_alignment(100, true, 1, 1, 100 + gap, false, dwell(false), maj(1, 0)),
                AlignmentState::Aligned,
                "gap {gap} must stay Aligned"
            );
        }
        // Gap 3: Syncing — no more hiding hours of lag behind a green badge.
        assert_eq!(
            decide_alignment(100, true, 1, 1, 100 + ALIGNMENT_SYNC_GAP_BLOCKS + 1, false, unreachable_dwell, unreachable_maj),
            AlignmentState::Syncing
        );
    }

    #[test]
    fn alignment_dwell_forces_diverged() {
        assert_eq!(
            decide_alignment(100, true, 2, 2, 100, false, dwell(true), unreachable_maj),
            AlignmentState::Diverged
        );
    }

    #[test]
    fn alignment_majority_paths() {
        // Majority agrees, someone ahead within tolerance → CatchingUp.
        assert_eq!(
            decide_alignment(100, true, 2, 2, 101, false, dwell(false), maj(2, 1)),
            AlignmentState::CatchingUp
        );
        // Majority agrees, nobody ahead → Aligned.
        assert_eq!(
            decide_alignment(100, true, 2, 2, 100, false, dwell(false), maj(2, 0)),
            AlignmentState::Aligned
        );
        // Minority (0 agreeing of 2 with tips: 1+0=1 vs 3) → Diverged.
        assert_eq!(
            decide_alignment(100, true, 2, 2, 100, false, dwell(false), maj(0, 0)),
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
            tip_legitimacy: None,
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
                tip_legitimacy: None,
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
    fn chain_adoption_is_refused_and_preserves_the_chain() {
        // Adopting another chain destroys this chain's genesis. Automation does
        // not get to make that call: the node halts and preserves its data.
        // This test previously asserted the opposite (that adoption wiped and
        // reset), which is the behaviour that cost a 196-block chain.
        let mut hm = make_healing_manager();
        hm.sync_state = SyncState::AwaitingManifest {
            peer: vec![1, 2, 3],
            target: 10,
            requested_at: 50,
        };
        hm.fork_common_ancestor = Some((5, [0xAA; 32]));
        hm.chain_vote_weight.store(100, Ordering::Relaxed);

        hm.ingest_clue(HealingClue::CrossChainAdopt {
            target_chain_id: 0xDEADBEEF,
            reason: "test".into(),
        });
        hm.evaluate_and_execute();

        // R5: the refusal stands, but it is not a failure of THIS node. We stay
        // on our own chain and keep operating — a peer on a foreign chain must
        // not be able to disable us by existing.
        assert!(
            hm.alignment().read().blocked_reason.is_none(),
            "refusing adoption must not halt this node"
        );
        assert_ne!(
            hm.alignment().read().state.label(),
            "Blocked",
            "declining a foreign chain is not an operator-gated failure"
        );
        // And nothing was destroyed: the chain's own weight is untouched.
        assert_eq!(
            hm.chain_vote_weight.load(Ordering::Relaxed),
            100,
            "refused adoption must not reset chain state"
        );
        assert!(matches!(hm.sync_state, SyncState::Idle));
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
