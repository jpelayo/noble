// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Central consensus state machine implementing `ConsensusStateMachine`.
//!
//! Orchestrates cycle management, block proposals, vote collection,
//! and chain tip advancement using deterministic event-driven processing.

use noble_core::{
    validate_block, validate_transaction, Block, BlockHeader, BlockValidationContext,
    TxValidationContext,
};
use noble_crypto::{Hash256, NoblePrivateKey, NoblePublicKey};
use tracing::{debug, info, warn};

use crate::badge::{self, BadgeProposalType, BadgeStore, VoteBadge};
use crate::candidate::{CandidateTracker, DeliveredBlockLog};
use crate::config::ConsensusConfig;
use crate::error::ConsensusError;
use crate::finality::FinalityTracker;
use crate::cycle::{CycleManager, CyclePhase};
use crate::event::{CycleEvent, CycleIo};
use crate::history::{CycleHistoryEntry, CycleProposal, CycleVoteTally};
use crate::reputation::ReputationEngine;
use crate::vote::{MigrationResult, PorVote, VoteManager};

/// Accept votes from peers whose clocks are up to this many seconds ahead.
/// Prevents dropping valid votes when a peer enters the Voting phase before
/// our local clock recognises the phase transition.
const VOTE_ACCEPT_TOLERANCE: u64 = 30;

/// Trait for the consensus state machine.
pub trait ConsensusStateMachine {
    /// Process an input event and return output actions.
    fn step(&mut self, event: CycleEvent) -> Vec<CycleIo>;
    /// Return the current consensus phase.
    fn current_phase(&self) -> CyclePhase;
    /// Return the current cycle number.
    fn current_cycle(&self) -> u64;
    /// Return the chain tip (height, block_hash).
    fn chain_tip(&self) -> (u64, Hash256);
    /// Return phase timing: (phase_index, phase_remaining_secs, cycle_remaining_secs).
    /// phase_index: 0 = Proposal, 1 = Voting, 2 = Reflection, 3 = Propagation.
    fn phase_timing(&self) -> (u8, u64, u64);
    /// Return the genesis timestamp (block 1's timestamp), or `None` if not set.
    fn genesis_timestamp(&self) -> Option<u64>;
    /// Return the cycle number for a given block timestamp.
    fn cycle_for_timestamp(&self, ts: u64) -> Option<u64>;
}

/// The NOBLE PoR consensus engine.
pub struct CycleEngine {
    config: ConsensusConfig,
    cycle_mgr: CycleManager,
    vote_mgr: VoteManager,
    candidate_tracker: CandidateTracker,
    /// Chain tip: (height, block_hash, timestamp).
    tip_height: u64,
    tip_hash: Hash256,
    /// AUD2-C2: Track tip block timestamp so we can validate B5 (timestamp ordering).
    tip_timestamp: u64,
    /// AUD3-D6: Full tip block header for proper B2/B3/B5 validation.
    /// Set on startup (from storage) and updated on each CommitBlock.
    tip_header: Option<BlockHeader>,
    /// Current tracked cycle and phase.
    tracked_cycle: u64,
    tracked_phase: CyclePhase,
    /// Chain ID for block validation.
    chain_id: u32,
    /// This node's validator credentials (None = observation mode).
    our_validator_key: Option<(NoblePrivateKey, NoblePublicKey)>,
    /// Number of connected peers (set externally by the node event loop).
    total_peers: usize,
    /// AUD-M7: Monotonic clock anchor (Instant, unix_timestamp) captured at creation.
    /// Used by phase_timing() to avoid NTP jumps affecting phase reporting.
    clock_anchor: (std::time::Instant, u64),
    /// Cycle number where the epoch was reset (block 1 commit). Used as a
    /// one-shot guard to prevent the generic cleanup at the end of
    /// handle_cycle_boundary from undoing vote suppression. Set once,
    /// consumed once.
    epoch_reset_cycle: Option<u64>,
    /// H-002: Last completed cycle's history entry, ready for persistence.
    last_cycle_history: Option<CycleHistoryEntry>,
    /// P1.3: Manual vote target for the Manual voting strategy (set via castVote RPC).
    manual_vote: Option<Hash256>,
    /// Whether an R1 vote has been cast this cycle.
    r1_vote_cast: bool,
    /// Suppresses repeated "no candidate for R1 vote" log after first emission per cycle.
    r1_retry_logged: bool,
    /// P1.2: Whether an R2 confirmation vote has been cast this cycle.
    r2_vote_cast: bool,
    /// Suppresses repeated "no candidate for R2 vote" log after first emission per cycle.
    r2_retry_logged: bool,
    /// S15-A: Per-validator reputation scoring engine.
    reputation: ReputationEngine,
    /// First tick: triggers proposal request if starting mid-Proposal phase.
    first_tick: bool,
    /// Whether this node should propose blocks (true for validators, false for
    /// vote-only peers / voting gateways).  When false the key is still used to
    /// sign votes but `RequestMempoolTransactions` is never emitted.
    proposals_enabled: bool,
    /// Whether this node should cast R1/R2 votes (true for voters and full
    /// validators, false for block-producer-only nodes).
    voting_enabled: bool,
    /// Badge store for governance (grant/revoke) tracking.
    badge_store: BadgeStore,
    /// Active badge proposals (keyed by proposal hash hex).
    badge_proposals: std::collections::HashMap<String, badge::BadgeProposal>,
    /// Phase 1: Finality tracker — counts consecutive clean cycles for finality.
    finality_tracker: FinalityTracker,
    /// Block 1's validator public key (the chain owner).
    /// Cached on block 1 commit/import; used by fork resolver for chain owner edge.
    chain_owner_key: Option<Vec<u8>>,
    /// Long-lived block hash memory — prevents false DuplicateProposal bans
    /// when stale blocks from prior cycles re-arrive after `previous_hashes`
    /// has been cleared.  Checked before `add_candidate()` in `handle_block_proposed`.
    delivered_block_log: DeliveredBlockLog,
    /// Phase 3: Periodic checkpoint manager.
    checkpoint_mgr: crate::checkpoint::CheckpointManager,
    /// Optional UTXO value lookup for accurate fee computation in proposals.
    /// When None, fees default to 0 (coinbase gets subsidy only).
    utxo_value_lookup: Option<Box<dyn crate::proposal::UtxoValueLookup + Send + Sync>>,
    /// Immutable validator snapshot injected per tick from ValidatorRegistry.
    /// When set, consensus operations use this instead of the internal validator_list.
    validator_snapshot: Option<std::sync::Arc<crate::registry::ValidatorSnapshot>>,
}

impl CycleEngine {
    /// Create a new consensus engine.
    ///
    /// If `validator_key` is `None`, the engine runs in observation mode
    /// (never broadcasts blocks or votes, still commits winning blocks).
    /// `genesis_timestamp` should be `Some(ts)` where `ts` is the first block's
    /// timestamp (from storage). Pass `None` when the chain has no blocks yet —
    /// the engine will enter genesis-proposal mode until the first block is committed.
    pub fn new(
        config: ConsensusConfig,
        tip_height: u64,
        tip_hash: Hash256,
        chain_id: u32,
        validator_key: Option<(NoblePrivateKey, NoblePublicKey)>,
        genesis_timestamp: Option<u64>,
    ) -> Self {
        let cycle_mgr = CycleManager::new(noble_core::CYCLE_DURATION_SECS, genesis_timestamp);
        let confirmation_threshold = config.confirmation_threshold;
        let checkpoint_interval = config.checkpoint_interval;
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            config,
            cycle_mgr,
            vote_mgr: VoteManager::new(),
            candidate_tracker: CandidateTracker::new(),
            tip_height,
            tip_hash,
            tip_timestamp: 0,
            tip_header: None,
            tracked_cycle: u64::MAX, // sentinel: first tick initializes without boundary event
            tracked_phase: CyclePhase::Propagation,
            chain_id,
            our_validator_key: validator_key,
            total_peers: 0,
            clock_anchor: (std::time::Instant::now(), now_unix),
            epoch_reset_cycle: None,
            last_cycle_history: None,
            manual_vote: None,
            r1_vote_cast: false,
            r1_retry_logged: false,
            r2_vote_cast: false,
            r2_retry_logged: false,
            reputation: ReputationEngine::new(),
            first_tick: true,
            proposals_enabled: true, // default; call set_proposals_enabled(false) for vote-only
            voting_enabled: true,   // default; call set_voting_enabled(false) for propose-only
            badge_store: BadgeStore::new(),
            badge_proposals: std::collections::HashMap::new(),
            finality_tracker: FinalityTracker::new(confirmation_threshold),
            chain_owner_key: None,
            delivered_block_log: DeliveredBlockLog::new(2048),
            checkpoint_mgr: crate::checkpoint::CheckpointManager::new(
                checkpoint_interval,
                confirmation_threshold,
            ),
            utxo_value_lookup: None,
            validator_snapshot: None,
        }
    }

    /// Inject a validator snapshot for this tick cycle.
    ///
    /// When set, consensus operations (voting strategies, block validation,
    /// name resolution) use the snapshot instead of the internal validator_list.
    pub fn set_validator_snapshot(&mut self, snap: std::sync::Arc<crate::registry::ValidatorSnapshot>) {
        self.validator_snapshot = Some(snap);
    }

    /// Get the current validator snapshot, if set.
    pub fn validator_snapshot(&self) -> Option<&std::sync::Arc<crate::registry::ValidatorSnapshot>> {
        self.validator_snapshot.as_ref()
    }

    /// Set the UTXO value lookup for accurate fee computation in block proposals.
    ///
    /// When set, `propose_block` uses this to resolve input UTXO values and
    /// compute correct fee totals for the coinbase transaction.
    pub fn set_utxo_value_lookup(&mut self, lookup: Box<dyn crate::proposal::UtxoValueLookup + Send + Sync>) {
        self.utxo_value_lookup = Some(lookup);
    }

    /// Update the connected peer count (called by node event loop).
    pub fn set_peer_count(&mut self, count: usize) {
        self.total_peers = count;
    }

    /// Enable or disable block proposals.
    ///
    /// When disabled the engine still casts R1/R2 votes using the validator key
    /// but never requests mempool transactions or proposes blocks.  Used for
    /// vote-only peers (VotingGateway role).
    pub fn set_proposals_enabled(&mut self, enabled: bool) {
        self.proposals_enabled = enabled;
    }

    /// Enable or disable R1/R2 voting.
    ///
    /// When disabled the engine still proposes blocks using the validator key
    /// but never casts votes.  Used for block-producer-only nodes.
    pub fn set_voting_enabled(&mut self, enabled: bool) {
        self.voting_enabled = enabled;
    }

    /// Human-readable cycle label for log messages.
    ///
    /// Before genesis (`tip_height == 0`) the cycle number is wall-clock-aligned
    /// (typically 0) but the chain has no blocks yet, so we display
    /// `"pre-genesis"` instead.
    fn cycle_label(&self) -> String {
        if self.tip_height == 0 {
            "pre-genesis".to_string()
        } else {
            self.tracked_cycle.to_string()
        }
    }

    /// Resolve a candidate block hash to its proposer's friendly name.
    ///
    /// Returns the validator name from the validator list if the candidate is
    /// tracked and the proposer is known; otherwise returns the truncated hash.
    fn candidate_label(&self, hash: &noble_crypto::Hash256) -> String {
        if let Some(entry) = self.candidate_tracker.get(hash) {
            let wire = entry.block.header.validator_id.to_wire_bytes();
            let name = self.snapshot_find_name(&wire);
            if !name.is_empty() {
                return name;
            }
        }
        // Fallback: truncated hash wrapped in {} to denote raw identifier.
        let hex = hex::encode(hash.as_bytes());
        format!("{{{}...{}}}", &hex[..6], &hex[hex.len() - 6..])
    }

    /// Get finality tracker (read-only) for RPC queries.
    pub fn finality_tracker(&self) -> &FinalityTracker {
        &self.finality_tracker
    }

    /// Restore finality state from storage on startup.
    pub fn restore_finality(&mut self, height: u64, hash: Hash256, cycle: u64) {
        self.finality_tracker.restore(height, hash, cycle);
    }

    /// Get the chain owner key (block 1 validator's wire bytes).
    pub fn chain_owner_key(&self) -> Option<&[u8]> {
        self.chain_owner_key.as_deref()
    }

    /// Get checkpoint manager (read-only) for RPC queries.
    pub fn checkpoint_manager(&self) -> &crate::checkpoint::CheckpointManager {
        &self.checkpoint_mgr
    }

    /// Restore checkpoints from storage on startup.
    pub fn restore_checkpoints(&mut self, cps: Vec<crate::checkpoint::Checkpoint>) {
        self.checkpoint_mgr.restore(cps);
    }

    /// Update the chain_id after block 1 commits.
    ///
    /// The engine starts with chain_id=0 (pre-genesis). After block 1 commits
    /// and the real chain_id is derived from block 1's hash, this must be called
    /// so that blocks 2+ are proposed/validated with the correct chain_id.
    /// Without this, the engine uses chain_id=0 for all blocks in the session,
    /// causing tx_id mismatches at storage commit time.
    pub fn set_chain_id(&mut self, id: u32) {
        self.chain_id = id;
    }

    /// Whether a validator key is configured.
    pub fn has_validator_key(&self) -> bool {
        self.our_validator_key.is_some()
    }

    /// Our validator public key as wire bytes (for identity comparison).
    pub fn our_validator_wire_bytes(&self) -> Option<Vec<u8>> {
        self.our_validator_key
            .as_ref()
            .map(|(_, pk)| pk.to_wire_bytes())
    }

    /// Whether block proposals are enabled.
    pub fn proposals_enabled(&self) -> bool {
        self.proposals_enabled
    }

    /// Current tracked phase.
    pub fn current_tracked_phase(&self) -> CyclePhase {
        self.tracked_phase
    }

    /// Resolve a validator name from the snapshot.
    fn snapshot_find_name(&self, wire: &[u8]) -> String {
        self.validator_snapshot
            .as_ref()
            .and_then(|snap| snap.find_by_wire(wire))
            .map(|e| e.name.clone())
            .unwrap_or_default()
    }

    /// Get validator count from the snapshot.
    fn snapshot_len(&self) -> usize {
        self.validator_snapshot.as_ref().map(|s| s.len()).unwrap_or(0)
    }

    /// Get pubkey vec from snapshot.
    fn snapshot_pubkey_vec(&self) -> Vec<NoblePublicKey> {
        self.validator_snapshot
            .as_ref()
            .map(|s| s.pubkey_vec.clone())
            .unwrap_or_default()
    }

    /// Get a reference to the candidate tracker (for API queries).
    pub fn candidate_tracker(&self) -> &CandidateTracker {
        &self.candidate_tracker
    }

    /// Get a reference to the badge store.
    pub fn badge_store(&self) -> &BadgeStore {
        &self.badge_store
    }

    /// Get a mutable reference to the badge store.
    pub fn badge_store_mut(&mut self) -> &mut BadgeStore {
        &mut self.badge_store
    }

    /// Get a reference to the active badge proposals.
    pub fn badge_proposals(&self) -> &std::collections::HashMap<String, badge::BadgeProposal> {
        &self.badge_proposals
    }

    /// Get a mutable reference to the active badge proposals.
    pub fn badge_proposals_mut(&mut self) -> &mut std::collections::HashMap<String, badge::BadgeProposal> {
        &mut self.badge_proposals
    }

    /// Update the chain tip (height + block hash).
    ///
    /// Used by the node when a rollback or external chain-state change occurs
    /// (e.g., storage integrity repair).
    pub fn update_tip(&mut self, height: u64, block_hash: Hash256) {
        self.tip_height = height;
        self.tip_hash = block_hash;
    }

    /// Reset the chain tip to a new height/hash and clear all in-flight state.
    ///
    /// Used after `force_reset_to_genesis()` for fork recovery (blockchain hop).
    /// Clears the vote manager, candidate tracker, cycle history, and — when
    /// resetting to height 0 — the cycle epoch so the engine re-enters pre-genesis
    /// mode and waits for the new chain's block 1 to set the epoch.
    pub fn reset_tip(&mut self, height: u64, block_hash: Hash256, force: bool) -> Result<(), ConsensusError> {
        if !force && height != 0 {
            if height <= self.finality_tracker.finalized_height {
                return Err(ConsensusError::ReorgPastFinality {
                    finalized: self.finality_tracker.finalized_height,
                    requested: height,
                });
            }
            let cp_floor = self.checkpoint_mgr.highest_active_height();
            if cp_floor > 0 && height <= cp_floor {
                return Err(ConsensusError::ReorgPastCheckpoint {
                    checkpoint: cp_floor,
                    requested: height,
                });
            }
        }
        self.tip_height = height;
        self.tip_hash = block_hash;
        self.tip_timestamp = 0;
        self.tip_header = None;
        self.vote_mgr = VoteManager::new();
        self.candidate_tracker = CandidateTracker::new();
        self.delivered_block_log.clear();
        self.last_cycle_history = None;
        self.manual_vote = None;
        self.r1_vote_cast = false;
        self.r1_retry_logged = false;
        self.r2_vote_cast = false;
        self.r2_retry_logged = false;
        self.epoch_reset_cycle = None;
        // When hopping to a new chain (height 0), clear the cycle epoch.
        // Next tick sets a wall-clock-aligned epoch; the new chain's block 1
        // resets it to the real timestamp when committed.
        // NOTE(stale-cache-#6): genesis_timestamp is reset to u64::MAX here,
        // which marks it as uninitialized. first_tick re-aligns it on the next
        // engine tick. During sync import, cycle phase timing is not used, so
        // the stale window is harmless. No additional fix needed.
        if height == 0 {
            self.cycle_mgr.set_genesis_timestamp(u64::MAX);
            self.vote_mgr.set_bootstrap_tolerance(true);
            self.tracked_cycle = u64::MAX;
            self.tracked_phase = CyclePhase::Propagation;
            self.first_tick = true;
            // NOTE(stale-cache-#8): chain_owner_key is cleared here on full
            // reset (height 0). The only risk of staleness would be block 1
            // reorg without a full reset — but finality prevents reorg past
            // finalized height, and block 1 finalizes after 3 cycles. Safe.
            self.chain_owner_key = None;
            self.badge_store = BadgeStore::new();
            self.badge_proposals.clear();
            self.finality_tracker.reset_full();
            self.checkpoint_mgr.reset();
        } else {
            self.finality_tracker.reset();
        }
        tracing::warn!("consensus engine reset to height {height}");
        Ok(())
    }

    /// Update the chain tip with timestamp for full parent validation (AUD2-C2).
    pub fn update_tip_with_timestamp(&mut self, height: u64, block_hash: Hash256, timestamp: u64) {
        self.tip_height = height;
        self.tip_hash = block_hash;
        self.tip_timestamp = timestamp;
    }

    /// Get the current voting strategy (Round 1).
    pub fn voting_strategy(&self) -> &crate::strategy::VotingStrategy {
        &self.config.voting_strategy
    }

    /// Get the current confirmation strategy (Round 2).
    pub fn confirmation_strategy(&self) -> &crate::strategy::VotingStrategy {
        &self.config.confirmation_strategy
    }

    /// Set the voting strategy (Round 1).
    pub fn set_voting_strategy(&mut self, strategy: crate::strategy::VotingStrategy) {
        self.config.voting_strategy = strategy;
    }

    /// Set the confirmation strategy (Round 2).
    pub fn set_confirmation_strategy(&mut self, strategy: crate::strategy::VotingStrategy) {
        self.config.confirmation_strategy = strategy;
    }

    /// Get current R1 vote tallies (candidate_hash → vote count).
    pub fn vote_tallies(&self) -> std::collections::HashMap<Hash256, usize> {
        self.vote_mgr.current_tallies()
    }

    /// Look up the proposer of a candidate block.
    ///
    /// Checks candidate_tracker first (full block data), then vote_mgr proposer
    /// hints (survives candidate pruning within the cycle).
    pub fn proposer_of(&self, block_hash: &Hash256) -> Option<Vec<u8>> {
        self.candidate_tracker
            .validator_of(block_hash)
            .or_else(|| self.vote_mgr.proposer_of(block_hash).cloned())
    }

    /// Get current R2 (confirmation) vote tallies (candidate_hash → vote count).
    pub fn r2_tallies(&self) -> std::collections::HashMap<Hash256, usize> {
        self.vote_mgr.r2_tallies()
    }

    /// Take the last completed cycle's history entry (H-002).
    /// Returns `Some` once after each cycle boundary, then `None` until the next.
    pub fn take_cycle_history(&mut self) -> Option<CycleHistoryEntry> {
        self.last_cycle_history.take()
    }

    /// Update the chain tip with the full block header for proper B2/B3/B5 validation (AUD3-D6).
    ///
    /// When block 1 is imported (via sync or consensus), the cycle epoch is set
    /// to the block's timestamp so all nodes converge on the same cycle boundaries.
    pub fn update_tip_with_header(&mut self, header: BlockHeader) {
        let height = header.height;
        let timestamp = header.timestamp;
        self.tip_height = height;
        self.tip_timestamp = timestamp;
        match header.compute_block_hash() {
            Ok(h) => self.tip_hash = h,
            Err(e) => warn!("failed to compute block hash for tip at height {height}: {e}"),
        }
        self.tip_header = Some(header);

        // Block 1 sets (or resets) the cycle epoch regardless of the import path
        // (consensus commit, sync import). Clears stale vote commitments,
        // re-initializes cycle tracking, and suppresses voting to prevent
        // equivocation with peers that still hold pre-reset votes.
        if height == 1 {
            info!("block 1 tip update — cycle epoch set to {}", timestamp);
            self.cycle_mgr.set_genesis_timestamp(timestamp);
            self.vote_mgr.set_bootstrap_tolerance(false);

            // Clear stale vote commitments from the pre-genesis epoch.
            // Without this, votes from the old epoch's cycle numbers
            // persist in vote_commitments. When the new epoch produces
            // the same cycle number, legitimate new votes are flagged
            // as equivocation against the stale commitments.
            self.vote_mgr.clear();

            // Re-initialize cycle tracking from the new epoch.
            // Do NOT use first_tick=true — that defers initialization
            // to the next tick, during which stale cycle/phase values
            // can cause spurious phase transitions and vote casting.
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let new_cycle = self.cycle_mgr.current_cycle(now_ts);
            let new_phase = self.cycle_mgr.current_phase(now_ts);
            self.tracked_cycle = new_cycle;
            self.tracked_phase = new_phase;
            self.vote_mgr.set_current_cycle(new_cycle);

            // Suppress voting for the remainder of this cycle.
            // Peers may still hold votes from the old epoch's cycle
            // with the same number — re-voting would trigger equivocation.
            self.r1_vote_cast = true;
            self.r2_vote_cast = true;
            self.r1_retry_logged = true;
            self.r2_retry_logged = true;
            // One-shot guard for the next handle_cycle_boundary cleanup.
            self.epoch_reset_cycle = Some(new_cycle);

            info!(
                "epoch reset (tip update): cycle {} phase {:?} (votes suppressed)",
                new_cycle, new_phase
            );

            // Cache the chain owner (block 1 validator) for fork resolution.
            self.chain_owner_key = Some(
                self.tip_header.as_ref().unwrap().validator_id.to_wire_bytes()
            );
        }
    }

    fn handle_tick(&mut self, now: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

        // Bootstrap epoch alignment: set the epoch ONCE on first tick so all
        // nodes in the same wall-clock window compute the same cycle 0 start.
        // After that, do NOT re-align — the epoch must stay fixed so the cycle
        // number naturally increments from 0 → 1 at the boundary, triggering
        // handle_cycle_boundary() which commits the winning block.
        //
        // Re-aligning on every tick kept `current_cycle()` permanently at 0,
        // preventing the cycle boundary from ever firing (bootstrap deadlock).
        if self.tip_height == 0 && self.first_tick {
            let cd = self.cycle_mgr.cycle_duration();
            let aligned = (now / cd) * cd;
            self.cycle_mgr.set_genesis_timestamp(aligned);
            self.vote_mgr.set_bootstrap_tolerance(true);
            debug!("cycle engine: bootstrap epoch set to wall-clock-aligned {aligned} (cycle 0)");
        }

        let mut new_cycle = self.cycle_mgr.current_cycle(now);
        let mut new_phase = self.cycle_mgr.current_phase(now);

        // First tick (or late genesis — sentinel still set): initialize tracked
        // state without firing a spurious boundary.
        if self.first_tick || self.tracked_cycle == u64::MAX {
            self.first_tick = false;
            self.tracked_cycle = new_cycle;
            self.tracked_phase = new_phase;
            self.vote_mgr.set_current_cycle(new_cycle);
            info!(
                "cycle engine: initialized at cycle {}, phase {:?}",
                new_cycle, new_phase
            );
            // If starting mid-Proposal and we're a validator, request mempool
            // txs so we can propose in the current cycle.
            if new_phase == CyclePhase::Proposal
                && self.our_validator_key.is_some()
                && self.proposals_enabled
            {
                outputs.push(CycleIo::RequestMempoolTransactions { max_count: 500 });
            }
        } else {
            // Detect cycle boundary
            if new_cycle > self.tracked_cycle {
                let completed = self.tracked_cycle;
                info!(
                    "cycle engine: state transition cycle {} -> {}",
                    completed, new_cycle
                );
                self.tracked_cycle = new_cycle;
                self.vote_mgr.set_current_cycle(new_cycle);
                outputs.extend(self.handle_cycle_boundary(completed));

                // If block 1 committed, handle_cycle_boundary reset the epoch.
                // The local `new_cycle` and `new_phase` are stale (computed from
                // the old epoch). Re-read from the updated cycle manager to
                // prevent stale phase transitions, stale vote casting, and
                // stale proposal deadlines in the remainder of this tick.
                if self.tip_height == 1 {
                    new_cycle = self.cycle_mgr.current_cycle(now);
                    new_phase = self.cycle_mgr.current_phase(now);
                    // tracked_cycle/tracked_phase were already set by the
                    // epoch reset code inside handle_cycle_boundary.
                }

                // Tick checkpoint activation after cycle boundary.
                let activated = self.checkpoint_mgr.tick_activation(new_cycle);
                if !activated.is_empty() {
                    outputs.push(CycleIo::CheckpointsActivated { heights: activated });
                }
            }

            // Detect phase transition
            if new_phase != self.tracked_phase {
                self.tracked_phase = new_phase;
                outputs.extend(self.handle_phase_transition(new_cycle, new_phase));
            }
        }

        // Deadline safety net: seconds before a phase ends to force-retry
        // any action that should have happened but didn't (proposal, R1, R2).
        const DEADLINE_SECS: u64 = 30;
        const VOTE_CAST_DELAY: u64 = 30;

        // Deadline safety net: if an action (proposal, R1, R2) hasn't fired
        // and the phase is about to end (<30s left), force-retry.  The first
        // attempt happens on first tick / phase transition; this catches
        // mid-cycle boots, delayed peer connections, empty gossipsub mesh, etc.
        // handle_mempool_transactions / cast_r1_vote / cast_r2_vote have their
        // own guards so duplicates are impossible.

        // Proposal deadline: <30s left in Proposal phase and haven't proposed.
        if new_phase == CyclePhase::Proposal
            && self.our_validator_key.is_some()
            && self.proposals_enabled
        {
            let our_wire = self.our_validator_key.as_ref().unwrap().1.to_wire_bytes();
            let remaining = self.cycle_mgr.seconds_until_phase_change(now);
            if !self.candidate_tracker.has_proposed(&our_wire) && remaining <= DEADLINE_SECS {
                debug!("cycle engine: deadline proposal — {remaining}s left in Proposal phase");
                outputs.push(CycleIo::RequestMempoolTransactions { max_count: 500 });
            }
        }

        // Cast R1 vote after VOTE_CAST_DELAY seconds into the Voting phase.
        // Blocks had the full Proposal phase + delay to propagate before voters act.
        if new_phase == CyclePhase::Voting && !self.r1_vote_cast {
            let phase_offset = self.cycle_mgr.phase_offset(now);
            let remaining = self.cycle_mgr.seconds_until_phase_change(now);
            if phase_offset >= VOTE_CAST_DELAY {
                outputs.extend(self.cast_r1_vote(new_cycle));
            } else if remaining <= DEADLINE_SECS {
                // R1 deadline: <30s left in Voting phase and haven't voted.
                debug!("cycle engine: deadline R1 vote — {remaining}s left in Voting phase");
                outputs.extend(self.cast_r1_vote(new_cycle));
            }
        }

        // Cast R2 confirmation vote after VOTE_CAST_DELAY seconds into Reflection.
        // R1 votes had the rest of the Voting phase + delay to propagate.
        if new_phase == CyclePhase::Reflection && !self.r2_vote_cast {
            let phase_offset = self.cycle_mgr.phase_offset(now);
            let remaining = self.cycle_mgr.seconds_until_phase_change(now);
            if phase_offset >= VOTE_CAST_DELAY {
                outputs.extend(self.cast_r2_vote(new_cycle));
            } else if remaining <= DEADLINE_SECS {
                // R2 deadline: <30s left in Reflection phase and haven't voted.
                debug!("cycle engine: deadline R2 vote — {remaining}s left in Reflection phase");
                outputs.extend(self.cast_r2_vote(new_cycle));
            }
        }

        // Schedule next timer.  If an action is pending (proposal not sent,
        // vote not cast), use a short retry interval.
        let proposal_pending = new_phase == CyclePhase::Proposal
            && self.our_validator_key.is_some()
            && self.proposals_enabled
            && !self.candidate_tracker.has_proposed(
                &self.our_validator_key.as_ref().unwrap().1.to_wire_bytes(),
            );
        let vote_pending = (new_phase == CyclePhase::Voting && !self.r1_vote_cast)
            || (new_phase == CyclePhase::Reflection && !self.r2_vote_cast)
            || proposal_pending;
        let next_timer = if vote_pending {
            5 // retry every 5s until candidate appears
        } else {
            self.cycle_mgr
                .seconds_until_phase_change(now)
                .min(self.cycle_mgr.seconds_until_cycle_boundary(now))
        };
        outputs.push(CycleIo::SetTimer {
            duration_secs: next_timer.max(1),
        });

        outputs
    }

    fn handle_phase_transition(&mut self, cycle: u64, phase: CyclePhase) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        let old_phase = self.tracked_phase;
        info!(
            "cycle engine: state transition {:?} -> {:?}",
            old_phase, phase
        );

        outputs.push(CycleIo::PhaseChanged { cycle, phase });

        let cl = self.cycle_label();
        match phase {
            CyclePhase::Proposal => {
                // New proposal phase: clear previous state
                self.vote_mgr.clear();
                self.vote_mgr.set_current_cycle(cycle);
                self.candidate_tracker.clear();
                self.r1_vote_cast = false;
                self.r1_retry_logged = false;
                self.r2_vote_cast = false;
                self.r2_retry_logged = false;
                outputs.push(CycleIo::Log(format!(
                    "cycle {cl}: entering Proposal phase"
                )));
                // P0.3: If we are a block-proposing validator, request mempool txs.
                // Vote-only peers (proposals_enabled=false) skip proposal.
                if self.our_validator_key.is_some() && self.proposals_enabled {
                    outputs.push(CycleIo::RequestMempoolTransactions { max_count: 500 });
                }
            }
            CyclePhase::Voting => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {cl}: entering Voting phase"
                )));
                // R1 vote casting happens in handle_tick after VOTE_CAST_DELAY
            }
            CyclePhase::Reflection => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {cl}: entering Reflection phase"
                )));
                // R2 vote casting happens in handle_tick after VOTE_CAST_DELAY
            }
            CyclePhase::Propagation => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {cl}: entering Propagation phase"
                )));
            }
        }

        outputs
    }

    fn handle_cycle_boundary(&mut self, completed_cycle: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        let cl = self.cycle_label();

        // H-002: Build proposals snapshot before clearing.
        let proposals: Vec<CycleProposal> = self
            .candidate_tracker
            .all_candidates()
            .iter()
            .map(|entry| CycleProposal {
                validator: hex::encode(entry.block.header.validator_id.to_wire_bytes()),
                block_hash: entry.block_hash,
                tx_count: entry.block.header.tx_count,
            })
            .collect();

        // H-002: Build vote tallies snapshot before clearing.
        let tallies = self.vote_mgr.current_tallies();
        let r2_tallies = self.vote_mgr.r2_tallies();
        let vote_entries: Vec<CycleVoteTally> = tallies
            .iter()
            .map(|(hash, count)| {
                let validator = self
                    .candidate_tracker
                    .get(hash)
                    .map(|e| hex::encode(e.block.header.validator_id.to_wire_bytes()))
                    .unwrap_or_default();
                CycleVoteTally {
                    block_hash: *hash,
                    validator,
                    vote_count: *count,
                    r2_vote_count: r2_tallies.get(hash).copied().unwrap_or(0),
                }
            })
            .collect();

        // Genesis isolation guard: before block 1 is committed (tip_height == 0),
        // require at least one connected peer.  The Dual-Witness Rule already
        // mandates ≥2 unique voters for block 1, but with zero peers the only
        // vote is the self-vote — which trivially wins plurality.  This guard
        // ensures block 1 always has live witnesses.
        //
        // After genesis (tip_height > 0), a solo validator CAN commit blocks
        // using its self-vote.  If a peer disconnects after block 1, the chain
        // must keep growing — a stuck chain is worse than a potential fork.
        // Fork resolution (manual or automatic) handles divergence on reconnect.
        if self.tip_height == 0 && self.total_peers == 0 {
            debug!(
                "cycle {cl}: genesis isolation guard — no connected peers, skipping consensus"
            );
            // Re-admit all candidate txs
            let all_txs: Vec<_> = self
                .candidate_tracker
                .collect_orphaned_txs(&Hash256::ZERO, self.chain_id);
            if !all_txs.is_empty() {
                outputs.push(CycleIo::ReadmitTransactions(all_txs));
            }
            // Record cycle history with actual proposals/votes (not empty).
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            self.last_cycle_history = Some(CycleHistoryEntry {
                cycle_number: completed_cycle,
                status: "isolated".to_string(),
                proposals,
                votes: vote_entries,
                winner: None,
                winning_hash: None,
                disambiguation: false,
                finalized_at: now_ts,
            });
            self.vote_mgr.clear();
            self.candidate_tracker.clear();
            self.r1_vote_cast = false;
            self.r1_retry_logged = false;
            self.r2_vote_cast = false;
            self.r2_retry_logged = false;
            outputs.push(CycleIo::Log(format!(
                "cycle {cl}: no connected peers — genesis requires live witnesses"
            )));
            return outputs;
        }

        // C-004: Use the actual number of unique voters who cast votes in this
        // cycle as the denominator, NOT the raw peer count.  total_peers includes
        // observers, light clients, and any other non-voting connections — using it
        // inflates the denominator and can make valid unanimous votes look like
        // minority consensus.  Fall back to validator_list size as the minimum
        // denominator so that a single self-voter doesn't trivially win on an
        // otherwise idle network.
        let unique_voters = self.vote_mgr.unique_voter_count();
        let validator_set_size = self.snapshot_len();
        let voter_count = unique_voters.max(validator_set_size).max(1);
        // Post-genesis: allow solo operation. The min_peers_for_consensus
        // check in compute_majority is redundant after block 1 — the
        // Dual-Witness Rule (R1-only) already enforces multi-party genesis.
        // After genesis, a solo validator must be able to keep the chain
        // growing when peers disconnect. A stuck chain is worse than a
        // potential fork (resolved by healing on reconnect).
        let effective_config = if self.tip_height >= 1 {
            let mut cfg = self.config.clone();
            cfg.min_peers_for_consensus = 1;
            cfg
        } else {
            self.config.clone()
        };
        let result = self.vote_mgr.compute_majority(voter_count, &effective_config);

        match result {
            MigrationResult::Adopt {
                candidate_hash,
                strength,
            } => {
                // Dual-Witness Rule: only the genesis block (block 1) requires ≥ min_unique_voters
                // distinct keys voting for the winning candidate. After block 1 is committed,
                // normal plurality consensus applies.
                // Genesis (block 1): require R1-only witnesses. R2 FollowMajority
                // echoes don't count — they're automatic, not independent validation.
                let witness_ok = self.tip_height >= 1
                    || self.vote_mgr.unique_r1_voter_count_for_candidate(&candidate_hash) >= self.config.min_unique_voters;

                if witness_ok {
                    info!(
                        "vote tally complete: winner = {}, strength = {:?}",
                        candidate_hash, strength
                    );
                    if let Some(entry) = self.candidate_tracker.get(&candidate_hash) {
                        let block = entry.block.clone();
                        let new_height = block.header.height;
                        let new_hash = candidate_hash;

                        // Guard: sync may have advanced the tip while the cycle
                        // was running — don't commit a stale candidate.
                        if new_height != self.tip_height + 1 {
                            debug!(
                                "cycle {cl}: skipping stale candidate at height {} (tip is {})",
                                new_height, self.tip_height
                            );
                        } else {
                            // Collect orphaned txs from losing candidates
                            let orphans = self
                                .candidate_tracker
                                .collect_orphaned_txs(&candidate_hash, self.chain_id);
                            if !orphans.is_empty() {
                                outputs.push(CycleIo::ReadmitTransactions(orphans));
                            }

                            // Commit the winning block
                            self.tip_height = new_height;
                            self.tip_hash = new_hash;
                            self.tip_timestamp = block.header.timestamp;
                            self.tip_header = Some(block.header.clone());
                            // Block 1 committed — (re)set cycle epoch to the block's
                            // real timestamp.  Bootstrap used wall-clock-aligned epoch;
                            // this converges all nodes on the same real epoch.
                            if new_height == 1 {
                                info!(
                                    "block 1 committed — cycle epoch set to {}",
                                    block.header.timestamp
                                );
                                self.cycle_mgr
                                    .set_genesis_timestamp(block.header.timestamp);
                                self.vote_mgr.set_bootstrap_tolerance(false);

                                // Re-initialize cycle tracking to the new epoch.
                                // CRITICAL: do NOT use first_tick=true here. That
                                // would set tracked_cycle on the next tick, which
                                // could produce the SAME cycle number as the one
                                // that just committed block 1. The node would then
                                // re-propose and re-vote in that cycle — peers still
                                // have the old vote, detect equivocation, and ban.
                                //
                                // Instead: compute the new cycle directly and mark
                                // votes as already cast so the node stays silent
                                // until the next cycle boundary.
                                let now_ts = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                let new_cycle = self.cycle_mgr.current_cycle(now_ts);
                                let new_phase = self.cycle_mgr.current_phase(now_ts);
                                self.tracked_cycle = new_cycle;
                                self.tracked_phase = new_phase;
                                self.vote_mgr.set_current_cycle(new_cycle);
                                // Suppress voting in the remainder of this cycle —
                                // peers may still have votes from the old epoch's
                                // cycle with the same number.
                                self.r1_vote_cast = true;
                                self.r2_vote_cast = true;
                                self.r1_retry_logged = true;
                                self.r2_retry_logged = true;
                                // One-shot flag: prevents the generic cleanup at the
                                // end of this handle_cycle_boundary from undoing the
                                // suppression. Consumed after one use.
                                self.epoch_reset_cycle = Some(completed_cycle);

                                info!(
                                    "epoch reset: entering cycle {} phase {:?} (votes suppressed until next boundary)",
                                    new_cycle, new_phase
                                );

                                // Cache chain owner for fork resolution.
                                self.chain_owner_key = Some(
                                    block.header.validator_id.to_wire_bytes()
                                );
                                // Purge stale cycle history from the bootstrap epoch.
                                // The cycle numbers from the old epoch are meaningless
                                // after the epoch change.
                                outputs.push(CycleIo::ClearCycleHistory);
                            }
                            // Collect per-block vote witness before CommitBlock.
                            let r1_voters: Vec<crate::history::BlockVoter> = self
                                .vote_mgr
                                .r1_voters_for(&candidate_hash)
                                .iter()
                                .map(|key| crate::history::BlockVoter {
                                    validator_key: hex::encode(key),
                                    name: self.snapshot_find_name(key),
                                })
                                .collect();
                            let r2_voters: Vec<crate::history::BlockVoter> = self
                                .vote_mgr
                                .r2_voters_for(&candidate_hash)
                                .iter()
                                .map(|key| crate::history::BlockVoter {
                                    validator_key: hex::encode(key),
                                    name: self.snapshot_find_name(key),
                                })
                                .collect();
                            let unique_witness =
                                self.vote_mgr.unique_voter_count_for_candidate(&candidate_hash);
                            let dual_required = new_height == 1;
                            // For block 1, the bootstrap-era cycle number is meaningless
                            // (it resets when the epoch changes). Store cycle 0 instead.
                            let vote_cycle = if new_height == 1 { 0 } else { completed_cycle };
                            outputs.push(CycleIo::StoreBlockVotes {
                                height: new_height,
                                votes: Box::new(crate::history::BlockVotes {
                                    cycle_number: vote_cycle,
                                    voter_count,
                                    strength: format!("{:?}", strength),
                                    r1_voters,
                                    r2_voters,
                                    unique_witness_count: unique_witness,
                                    dual_witness_required: dual_required,
                                    dual_witness_met: witness_ok,
                                }),
                            });

                            // Process badge txs from the committed block.
                            self.process_badge_transactions(&block, completed_cycle);
                            outputs.push(CycleIo::CommitBlock(block));
                            outputs.push(CycleIo::EmitMetric {
                                name: "block_committed".to_string(),
                                value: new_height as f64,
                            });
                            outputs.push(CycleIo::Log(format!(
                                "cycle {cl}: committed block {} at height {} ({:?})",
                                new_hash, new_height, strength
                            )));
                            // Track finality: record this commit for finality counting.
                            self.finality_tracker.on_block_committed(new_height, new_hash, completed_cycle);
                            let fh = self.finality_tracker.finalized_height;
                            if fh > 0 {
                                outputs.push(CycleIo::PersistFinalityState {
                                    height: self.finality_tracker.finalized_height,
                                    hash: self.finality_tracker.finalized_hash,
                                    cycle: self.finality_tracker.finalized_at_cycle,
                                });
                                outputs.push(CycleIo::EmitMetric {
                                    name: "finalized_height".to_string(),
                                    value: fh as f64,
                                });
                            }
                            // Sync fork resolver's finality floor.
                            // Checkpoint: if height qualifies, create one.
                            if let Some(cp) = self.checkpoint_mgr.on_block_committed(
                                new_height,
                                new_hash,
                                completed_cycle,
                            ) {
                                outputs.push(CycleIo::PersistCheckpoint(Box::new(cp)));
                            }
                        }
                    } else {
                        outputs.push(CycleIo::Log(format!(
                            "cycle {cl}: majority voted for {} but candidate not found",
                            candidate_hash
                        )));
                    }
                } else {
                    debug!(
                        "cycle {cl}: Dual-Witness not met for genesis block ({} R1 voter(s) for winner {}, need {})",
                        self.vote_mgr.unique_r1_voter_count_for_candidate(&candidate_hash),
                        candidate_hash, self.config.min_unique_voters
                    );
                    // Treat as indeterminate — don't commit, readmit txs
                    let all_txs: Vec<_> = self
                        .candidate_tracker
                        .collect_orphaned_txs(&Hash256::ZERO, self.chain_id);
                    if !all_txs.is_empty() {
                        outputs.push(CycleIo::ReadmitTransactions(all_txs));
                    }
                }
            }
            MigrationResult::Indeterminate => {
                debug!(
                    "cycle {cl}: vote tally indeterminate, no block committed"
                );
                // Re-admit all candidate txs back to mempool
                let all_txs: Vec<_> = self
                    .candidate_tracker
                    .preferred_candidate()
                    .map(|_| {
                        // Return all txs from all candidates
                        self.candidate_tracker
                            .collect_orphaned_txs(&Hash256::ZERO, self.chain_id)
                        // ZERO won't match any candidate
                    })
                    .unwrap_or_default();

                if !all_txs.is_empty() {
                    outputs.push(CycleIo::ReadmitTransactions(all_txs));
                }

                outputs.push(CycleIo::Log(format!(
                    "cycle {cl}: indeterminate — no block committed"
                )));
            }
        }

        // H-002: Record cycle history before clearing state.
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let (status, winner, winning_hash, disambiguation) = match &result {
            MigrationResult::Adopt {
                candidate_hash,
                strength,
            } => {
                let winner_name = self
                    .candidate_tracker
                    .get(candidate_hash)
                    .map(|e| hex::encode(e.block.header.validator_id.to_wire_bytes()));
                // disambiguation is always false: ties return
                // Indeterminate before reaching this Adopt arm.
                (
                    format!("finalized_{:?}", strength).to_lowercase(),
                    winner_name,
                    Some(*candidate_hash),
                    false,
                )
            }
            MigrationResult::Indeterminate => ("indeterminate".to_string(), None, None, false),
        };

        // Only persist cycles that had real activity (proposals, votes, or a winner).
        // Empty indeterminate cycles are noise — don't waste storage on them.
        // Skip the genesis cycle entirely: when block 1 commits, first_tick is set
        // and ClearCycleHistory purges bootstrap entries.  Recording this cycle would
        // use a bootstrap-epoch number (e.g. 224) that is meaningless after the epoch
        // change.  The block commit itself is the permanent record; the first REAL
        // post-genesis cycle (cycle 0 under the new epoch) will be the first entry.
        if self.first_tick {
            // Genesis cycle — block 1 commit resets the epoch; skip history.
        } else if !proposals.is_empty() || !vote_entries.is_empty() || winner.is_some() {
            self.last_cycle_history = Some(CycleHistoryEntry {
                cycle_number: completed_cycle,
                status,
                proposals,
                votes: vote_entries,
                winner,
                winning_hash,
                disambiguation,
                finalized_at: now_ts,
            });
        }

        // S15-A: Update reputation scores at cycle boundary.
        {
            let all_validators: Vec<Vec<u8>> = self.validator_snapshot
                .as_ref()
                .map(|snap| snap.entries.iter().map(|(wire, _)| wire.clone()).collect())
                .unwrap_or_default();

            // Determine the winning proposer and losing proposers.
            let winner_wire: Option<Vec<u8>> = match &result {
                MigrationResult::Adopt { candidate_hash, .. } => self
                    .candidate_tracker
                    .get(candidate_hash)
                    .map(|e| e.block.header.validator_id.to_wire_bytes()),
                MigrationResult::Indeterminate => None,
            };
            let loser_wires: Vec<Vec<u8>> = self
                .candidate_tracker
                .all_candidates()
                .iter()
                .filter_map(|entry| {
                    let wire = entry.block.header.validator_id.to_wire_bytes();
                    if winner_wire.as_deref() == Some(&wire) {
                        None
                    } else {
                        Some(wire)
                    }
                })
                .collect();

            // Collect wire bytes of validators who cast at least one vote.
            let voters: Vec<Vec<u8>> = self.vote_mgr.voter_wire_keys();

            // Active validators = those who proposed or voted (observed online).
            let mut active: Vec<Vec<u8>> = voters.clone();
            for entry in self.candidate_tracker.all_candidates() {
                let wire = entry.block.header.validator_id.to_wire_bytes();
                if !active.contains(&wire) {
                    active.push(wire);
                }
            }

            // Diagnostic tracing for reputation accounting.
            info!(
                "cycle {cl} reputation: validators={}, voters={}, candidates={}, result={:?}",
                all_validators.len(),
                voters.len(),
                self.candidate_tracker.all_candidates().len(),
                std::mem::discriminant(&result)
            );
            for v in &all_validators {
                let in_voters = voters.contains(v);
                debug!(
                    "  validator {}: in_voters={}",
                    hex::encode(&v[..v.len().min(8)]),
                    in_voters
                );
            }

            self.reputation.process_cycle_boundary(
                completed_cycle,
                winner_wire.as_deref(),
                &loser_wires,
                &voters,
                &all_validators,
                &active,
            );
        }

        // Check badge proposal expirations at cycle boundary.
        self.expire_badge_proposals(completed_cycle);

        // Persist badge state to storage if there are any badges or proposals.
        if !self.badge_store.is_empty() || !self.badge_proposals.is_empty() {
            let badges: Vec<(Vec<u8>, Vec<u8>)> = self
                .badge_store
                .list_all()
                .into_iter()
                .filter_map(|(k, v)| {
                    match noble_codec::cbor_ser::to_cbor(v) {
                        Ok(cbor) => Some((k.clone(), cbor)),
                        Err(e) => {
                            warn!("badge CBOR encode failed for key {}: {e}", hex::encode(&k));
                            None
                        }
                    }
                })
                .collect();
            let proposals: Vec<(String, Vec<u8>)> = self
                .badge_proposals
                .iter()
                .filter_map(|(k, v)| {
                    match noble_codec::cbor_ser::to_cbor(v) {
                        Ok(cbor) => Some((k.clone(), cbor)),
                        Err(e) => {
                            warn!("badge proposal CBOR encode failed for {k}: {e}");
                            None
                        }
                    }
                })
                .collect();
            if !badges.is_empty() || !proposals.is_empty() {
                outputs.push(CycleIo::PersistBadgeState { badges, proposals });
            }
        }

        // Clear state for next cycle.
        self.vote_mgr.clear();
        self.vote_mgr.set_current_cycle(self.tracked_cycle);
        self.candidate_tracker.clear();

        // After block 1 commit, the epoch was reset and vote flags were
        // set to `true` to suppress re-voting. The one-shot
        // `epoch_reset_cycle` flag prevents THIS cleanup from undoing
        // the suppression. It fires exactly once (the boundary that
        // committed block 1), then is consumed. Subsequent boundaries
        // at tip_height==1 reset vote flags normally, allowing the node
        // to vote for block 2.
        if self.epoch_reset_cycle == Some(completed_cycle) {
            self.epoch_reset_cycle = None; // consumed — one-shot
        } else {
            self.r1_vote_cast = false;
            self.r1_retry_logged = false;
            self.r2_vote_cast = false;
            self.r2_retry_logged = false;
        }

        outputs
    }

    /// Process badge-related transactions from a committed block.
    ///
    /// Scans for Badge Proposal (0x03) and Badge Vote (0x04) via tx_types registry,
    /// updates the badge store and proposal tracking accordingly.
    fn process_badge_transactions(&mut self, block: &Block, current_cycle: u64) {
        for tx in &block.transactions {
            match tx.tx_type {
                noble_core::TX_TYPE_BADGE_PROPOSAL => {
                    // Decode metadata from the transaction's metadata entries.
                    let target = tx.metadata.iter().find(|m| m.key == "target_pubkey");
                    let ptype = tx.metadata.iter().find(|m| m.key == "proposal_type");
                    let reason = tx.metadata.iter().find(|m| m.key == "reason");

                    let (Some(target_entry), Some(ptype_entry)) = (target, ptype) else {
                        warn!("badge proposal tx missing required metadata fields");
                        continue;
                    };

                    let proposal_type = match ptype_entry.value.first() {
                        Some(&badge::PROPOSAL_TYPE_GRANT) => BadgeProposalType::Grant,
                        Some(&badge::PROPOSAL_TYPE_REVOKE) => BadgeProposalType::Revoke,
                        _ => {
                            warn!("badge proposal tx has invalid proposal_type byte");
                            continue;
                        }
                    };

                    // Validate: grant target must not already have active badge.
                    if proposal_type == BadgeProposalType::Grant
                        && self.badge_store.is_active(&target_entry.value)
                    {
                        debug!("badge grant proposal for already-active peer, skipping");
                        continue;
                    }
                    // Validate: revoke target must hold an active badge.
                    if proposal_type == BadgeProposalType::Revoke
                        && !self.badge_store.is_active(&target_entry.value)
                    {
                        debug!("badge revoke proposal for non-active peer, skipping");
                        continue;
                    }

                    let revocation_reason = if proposal_type == BadgeProposalType::Revoke {
                        reason.and_then(|r| match r.value.first() {
                            Some(0) => Some(badge::RevocationReason::DuplicateProposal),
                            Some(1) => Some(badge::RevocationReason::ProtocolAbuse),
                            Some(2) => Some(badge::RevocationReason::ExtendedAbsence),
                            Some(3) => Some(badge::RevocationReason::Misrepresentation),
                            _ => Some(badge::RevocationReason::Other),
                        })
                    } else {
                        None
                    };

                    let mut proposer_wire = vec![tx.publisher_sig.scheme_id];
                    proposer_wire.extend_from_slice(&tx.publisher_sig.public_key);
                    let proposal = badge::BadgeProposal::new(
                        proposal_type,
                        target_entry.value.clone(),
                        proposer_wire,
                        revocation_reason,
                        current_cycle,
                    );

                    let cbor_bytes = match noble_codec::cbor_ser::to_cbor(tx) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("badge proposal CBOR encoding failed: {e}");
                            continue;
                        }
                    };
                    let tx_hash = hex::encode(noble_crypto::sha256(&cbor_bytes));
                    info!(
                        "badge proposal recorded: type={:?}, target={}..., hash={}",
                        proposal_type,
                        hex::encode(&target_entry.value[..4.min(target_entry.value.len())]),
                        &tx_hash[..8]
                    );
                    self.badge_proposals.insert(tx_hash, proposal);
                }
                noble_core::TX_TYPE_BADGE_VOTE => {
                    let phash = tx.metadata.iter().find(|m| m.key == "proposal_hash");
                    let vote = tx.metadata.iter().find(|m| m.key == "vote");

                    let (Some(phash_entry), Some(vote_entry)) = (phash, vote) else {
                        warn!("badge vote tx missing required metadata fields");
                        continue;
                    };

                    let proposal_hash = hex::encode(&phash_entry.value);
                    let approve = vote_entry.value.first() == Some(&1);
                    let mut voter_wire = vec![tx.publisher_sig.scheme_id];
                    voter_wire.extend_from_slice(&tx.publisher_sig.public_key);

                    // Voter must hold an active badge.
                    if !self.badge_store.is_active(&voter_wire) {
                        debug!("badge vote from non-badge-holder, skipping");
                        continue;
                    }

                    if let Some(proposal) = self.badge_proposals.get_mut(&proposal_hash) {
                        if proposal.status != "active" {
                            debug!("badge vote for non-active proposal {}", &proposal_hash[..8]);
                            continue;
                        }
                        if proposal.record_vote(voter_wire, approve) {
                            debug!(
                                "badge vote recorded for proposal {}: approve={}",
                                &proposal_hash[..8],
                                approve
                            );
                        } else {
                            debug!("duplicate badge vote for proposal {}", &proposal_hash[..8]);
                        }
                    } else {
                        debug!("badge vote references unknown proposal {}", &proposal_hash[..8]);
                    }
                }
                _ => {} // Not a badge tx
            }
        }
    }

    /// Check all open badge proposals for expiration; execute those that pass.
    fn expire_badge_proposals(&mut self, current_cycle: u64) {
        let total_eligible = self.badge_store.count_active();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Collect proposals that need resolution.
        let expired_keys: Vec<String> = self
            .badge_proposals
            .iter()
            .filter(|(_, p)| p.status == "active" && current_cycle >= p.expires_at_cycle)
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired_keys {
            let Some(proposal) = self.badge_proposals.get_mut(&key) else {
                continue;
            };

            if proposal.passes(total_eligible) {
                match proposal.proposal_type {
                    BadgeProposalType::Grant => {
                        let badge = VoteBadge::new(
                            self.tip_height,
                            current_cycle,
                            proposal.proposer_pubkey.clone(),
                            now,
                        );
                        self.badge_store
                            .set_badge(proposal.target_pubkey.clone(), badge);
                        info!(
                            "badge GRANTED to {}... (proposal {})",
                            hex::encode(&proposal.target_pubkey[..4.min(proposal.target_pubkey.len())]),
                            &key[..8]
                        );
                        proposal.status = "passed".to_string();
                    }
                    BadgeProposalType::Revoke => {
                        if let Some(b) = self
                            .badge_store
                            .get_badge_mut(&proposal.target_pubkey)
                        {
                            b.revoke();
                            info!(
                                "badge REVOKED from {}... (proposal {})",
                                hex::encode(&proposal.target_pubkey[..4.min(proposal.target_pubkey.len())]),
                                &key[..8]
                            );
                        }
                        proposal.status = "passed".to_string();
                    }
                }
            } else {
                proposal.status = "expired".to_string();
                debug!(
                    "badge proposal {} expired without majority ({} for / {} against / {} eligible)",
                    &key[..8],
                    proposal.votes_for.len(),
                    proposal.votes_against.len(),
                    total_eligible
                );
            }
        }
    }

    fn handle_block_proposed(&mut self, block: Box<Block>, from_peer: Vec<u8>) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        debug!(
            "consensus: received block proposal at height {}",
            block.header.height
        );

        // Ignore blocks at or below the current tip — they're already committed
        // (e.g., a delayed sync response arriving after the cycle boundary).
        if block.header.height <= self.tip_height {
            return outputs;
        }

        // Safety: tip_height=0 has no parent header for B2/B3 validation.
        // Only accept block 1 (the expected next block).
        if self.tip_height == 0 && block.header.height != 1 {
            outputs.push(CycleIo::Log(format!(
                "ignoring block at height {} when tip=0 (expected 1)",
                block.header.height,
            )));
            return outputs;
        }

        // Blocks are accepted during all 4 phases (Proposal, Voting, Reflection, Propagation).
        // During Voting/Reflection, a block may arrive via vote-triggered RequestBlock
        // (the node missed the original BlockAnnounce during Proposal).  The
        // block is still fully validated — allowing it into the tracker lets
        // the node cast an informed vote for a candidate it would otherwise
        // never see.

        // AUD3-D6: Construct parent header stub from tip state for B2/B3/B5 validation.
        // The validate_block B2 check verifies candidate.prev_block_hash against the
        // parent's computed hash, so we use the stored tip_hash directly. B5 uses
        // parent.timestamp for ordering checks.
        let parent_header = self.tip_header.clone();

        // stale-cache-#9: warn when tip_header is missing at non-genesis height.
        // B2 (prev_hash) and B5 (timestamp ordering) checks are skipped when
        // parent is None, degrading validation to signature-only.
        if parent_header.is_none() && self.tip_height > 0 {
            tracing::warn!(
                "tip_header is None at tip_height {} — B2/B3/B5 parent validation degraded (parent header not loaded after rollback or restart)",
                self.tip_height,
            );
        }

        // Validate the block
        // AUD3-H1: Use wall-clock time for B6 future/past skew checks,
        // not the block's own timestamp (which would bypass the check).
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Build the validator list for B9 validation.  Any peer with a valid
        // signature is allowed to propose — the local validator_list only controls
        // who this node votes for, not who can propose.  We include the block's
        // own validator_id so B9 always passes for the proposer.
        let mut val_list = self.snapshot_pubkey_vec();
        if !val_list.contains(&block.header.validator_id) {
            val_list.push(block.header.validator_id.clone());
        }
        let ctx = BlockValidationContext {
            chain_id: self.chain_id,
            current_time,
            parent: parent_header.as_ref(),
            validator_list: &val_list,
        };

        if let Err(e) = validate_block(&block, &ctx) {
            // Chain-disagreement errors (B2 prev_hash, B3 height, B5 timestamp ordering)
            // mean the peer is on a different fork — not misbehaving.  Log and reject
            // without banning so fork resolution remains possible.
            let is_fork_disagreement = matches!(
                e,
                noble_core::ValidationError::PrevHashMismatch
                    | noble_core::ValidationError::HeightMismatch { .. }
                    | noble_core::ValidationError::TimestampNotAfterParent { .. }
            );
            if is_fork_disagreement {
                outputs.push(CycleIo::Log(format!(
                    "rejected block from fork peer (different chain): {e}"
                )));
                outputs.push(CycleIo::ForkDisagreement {
                    peer_id: from_peer.clone(),
                    block_height: block.header.height,
                    reason: format!("{e}"),
                });
            } else {
                outputs.push(CycleIo::Log(format!(
                    "rejected invalid block from peer: {e}"
                )));
                // Determine if the failure is evidence-capable (universal check).
                let evidence_code = match &e {
                    noble_core::ValidationError::BlockTooLarge { size, max } =>
                        Some(noble_core::InvalidBlockCode::BlockTooLarge { size: *size, max: *max }),
                    noble_core::ValidationError::MerkleRootMismatch =>
                        Some(noble_core::InvalidBlockCode::MerkleRootMismatch),
                    noble_core::ValidationError::ValidatorSigInvalid(_) =>
                        Some(noble_core::InvalidBlockCode::ValidatorSigInvalid),
                    noble_core::ValidationError::TxCountMismatch { claimed, actual } =>
                        Some(noble_core::InvalidBlockCode::TxCountMismatch { claimed: *claimed, actual: *actual }),
                    noble_core::ValidationError::DuplicateTxInBlock { first, second } =>
                        Some(noble_core::InvalidBlockCode::DuplicateTxInBlock { first: *first, second: *second }),
                    noble_core::ValidationError::ValidatorSchemeUnrecognized(s) =>
                        Some(noble_core::InvalidBlockCode::ValidatorSchemeUnrecognized(*s)),
                    noble_core::ValidationError::InvalidTransaction { index, source } =>
                        Some(noble_core::InvalidBlockCode::InvalidTransaction { index: *index, reason: source.to_string() }),
                    _ => None, // B2/B3/B5/B6/B9/B10/B13 — local checks, no universal evidence
                };
                if let Some(code) = evidence_code {
                    let evidence = noble_core::InvalidBlockEvidence {
                        block: (*block).clone(),
                        failure_code: code,
                    };
                    if evidence.verify(self.chain_id).is_ok() {
                        outputs.push(CycleIo::PublishEvidence(Box::new(
                            noble_core::MisbehaviorEvidence::InvalidBlock(evidence),
                        )));
                        outputs.push(CycleIo::BanPeer {
                            peer_id: from_peer,
                            category: noble_core::BanCategoryCode::InvalidBlock,
                            reason: format!("invalid block (evidence verified): {e}"),
                        });
                    } else {
                        // Evidence construction succeeded but verify() failed — unusual
                        outputs.push(CycleIo::BanPeer {
                            peer_id: from_peer,
                            category: noble_core::BanCategoryCode::InvalidBlock,
                            reason: format!("invalid block: {e}"),
                        });
                    }
                } else {
                    // Local-only check failure — ban without evidence
                    outputs.push(CycleIo::BanPeer {
                        peer_id: from_peer,
                        category: noble_core::BanCategoryCode::InvalidBlock,
                        reason: format!("invalid block: {e}"),
                    });
                }
            }
            return outputs;
        }

        // Clone header before add_candidate (which takes ownership of block).
        let new_header = block.header.clone();

        // Compute block hash
        let block_hash = match block.header.compute_block_hash() {
            Ok(h) => h,
            Err(e) => {
                outputs.push(CycleIo::Log(format!("failed to compute block hash: {e}")));
                return outputs;
            }
        };

        // DeliveredBlockLog: long-lived hash memory.  If this block was EVER
        // processed by handle_block_proposed (even many cycles ago), skip it
        // silently.  This is the primary defense against false DuplicateProposal
        // bans from stale re-deliveries.
        if self.delivered_block_log.contains(block_hash.as_bytes()) {
            debug!("delivered_block_log: duplicate block {} — ignoring", block_hash);
            return outputs;
        }

        // Record proposer hint for name resolution (survives candidate pruning).
        self.vote_mgr.record_proposer(block_hash, new_header.validator_id.to_wire_bytes());

        // Add to candidate tracker
        match self.candidate_tracker.add_candidate(block, block_hash, 0) {
            Ok(()) => {
                self.delivered_block_log.insert(*block_hash.as_bytes());
                outputs.push(CycleIo::Log(format!(
                    "accepted candidate block {{{}}} from validator {}",
                    block_hash,
                    self.candidate_tracker
                        .get(&block_hash)
                        .map(|e| format!("{:?}", e.block.header.validator_id))
                        .unwrap_or_default()
                )));
            }
            Err(existing_hash) if existing_hash == block_hash => {
                // Duplicate delivery of the same block (e.g., vote-triggered
                // RequestBlock racing with BlockAnnounce fetch).  Not a double
                // proposal — just ignore.
                outputs.push(CycleIo::Log(format!(
                    "duplicate block delivery {{{}}} (already tracked)",
                    block_hash
                )));
            }
            Err(existing_hash) => {
                // Potential double proposal: same validator, different block hash.
                // Only ban if we have cryptographically verified evidence — both
                // block headers with valid signatures from the same validator key.
                // This prevents trigger-happy bans from edge cases not caught by
                // the stale-delivery guard (e.g., clock skew, relay races).
                let new_ts = new_header.timestamp;
                let new_validator = hex::encode(new_header.validator_id.to_wire_bytes());
                let mut evidence_verified = false;
                let mut existing_ts = 0u64;

                if let Some(existing_entry) = self.candidate_tracker.get(&existing_hash) {
                    existing_ts = existing_entry.block.header.timestamp;

                    // Cross-cycle guard: compute the cycle number for each block's
                    // timestamp.  If they fall in different cycles, this is NOT a
                    // double proposal — it happens when a block arrives between tick
                    // fires and the candidate_tracker hasn't been cleared yet.
                    let existing_cycle = self.cycle_mgr.current_cycle(existing_ts);
                    let new_cycle = self.cycle_mgr.current_cycle(new_ts);
                    if existing_cycle != new_cycle {
                        debug!(
                            "cross-cycle proposal from same validator — NOT a double proposal \
                             (existing ts {} cycle {}, new ts {} cycle {})",
                            existing_ts, existing_cycle, new_ts, new_cycle
                        );
                    } else {
                        let evidence = noble_core::DoubleProposalEvidence::new(
                            existing_entry.block.header.clone(),
                            new_header,
                        );
                        if evidence.verify().is_ok() {
                            outputs.push(CycleIo::PublishEvidence(Box::new(
                                noble_core::MisbehaviorEvidence::DoubleProposal(evidence),
                            )));
                            evidence_verified = true;
                        }
                    }
                }

                if evidence_verified {
                    outputs.push(CycleIo::BanPeer {
                        peer_id: from_peer,
                        category: noble_core::BanCategoryCode::DuplicateProposal,
                        reason: format!(
                            "double proposal (evidence verified): existing {} (ts {}), \
                             new {} (ts {}), validator {}",
                            existing_hash, existing_ts, block_hash, new_ts, new_validator,
                        ),
                    });
                    outputs.push(CycleIo::Log(format!(
                        "banned peer for verified double proposal \
                         (existing: {}, new: {}, validator: {})",
                        existing_hash, block_hash, new_validator,
                    )));
                } else {
                    // Insufficient evidence — could be a stale delivery edge case,
                    // relay race, cross-cycle proposal, or tracker state inconsistency.
                    // Reject the block but do NOT ban the peer.  Log with full forensic
                    // detail so operators can investigate.
                    outputs.push(CycleIo::Log(format!(
                        "rejected potential double proposal without ban \
                         (existing: {} ts {}, new: {} ts {}, validator: {})",
                        existing_hash, existing_ts, block_hash, new_ts, new_validator,
                    )));
                }
            }
        }

        outputs
    }

    fn handle_vote_received(&mut self, vote: PorVote, from_peer: Vec<u8>) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        debug!(
            "consensus: received vote for candidate {}",
            vote.candidate_hash
        );

        // Reject votes during early Proposal phase — voting hasn't started yet.
        // Accept votes during Voting, Reflection, Propagation, and the final
        // 30 seconds of Proposal phase.  The tolerance window prevents dropping
        // valid votes from peers whose clocks are slightly ahead and have already
        // entered the Voting phase while we're still in late Proposal.
        if self.tracked_phase == CyclePhase::Proposal {
            let phase_remaining = self.cycle_mgr.seconds_until_phase_change(
                self.clock_anchor.1
                    + self.clock_anchor.0.elapsed().as_secs(),
            );
            if phase_remaining > VOTE_ACCEPT_TOLERANCE {
                outputs.push(CycleIo::Log(
                    "rejected vote during Proposal phase (voting not yet open)".to_string(),
                ));
                return outputs;
            }
            // Late Proposal: accept the vote (peer likely entered Voting already)
            debug!(
                "accepting vote during late Proposal phase ({phase_remaining}s until Voting)"
            );
        }

        // Votes are accepted from any connected peer with a valid signature.
        // The local validator_list only controls who THIS node votes for,
        // not whose votes it accepts.  The only hard requirements are:
        //   - valid cryptographic signature (GAP-C7, checked in record_vote)
        //   - correct cycle number (AUD2-M4, checked in record_vote)
        //   - not a duplicate (P0.2, checked in record_vote)
        //   - peer not banned (handled at the network layer)

        // If we receive a vote for a candidate we haven't seen yet, request
        // the block from ALL connected peers.  The voter (from_peer) likely
        // didn't propose the block and may not have it cached.  Only the
        // proposer has the block in pending_proposals; other peers may have
        // committed it or received it via gossip.  Broadcasting the request
        // maximises the chance of actually obtaining the block body before
        // the cycle boundary.
        if self.candidate_tracker.get(&vote.candidate_hash).is_none() {
            outputs.push(CycleIo::RequestBlockFromAll {
                block_hash: vote.candidate_hash,
            });
        }

        // Record the vote (includes signature verification via GAP-C7)
        match self.vote_mgr.record_vote(&from_peer, &vote) {
            Ok(true) => {
                outputs.push(CycleIo::Log(format!(
                    "recorded vote from peer for candidate {}",
                    self.candidate_label(&vote.candidate_hash)
                )));
            }
            Ok(false) => {
                outputs.push(CycleIo::Log(
                    "duplicate vote from peer (ignored)".to_string(),
                ));
            }
            Err(crate::vote::VoteError::Equivocation {
                round,
                first_candidate,
                second_candidate,
                first_vote,
                ..
            }) => {
                // Construct evidence from both votes — only ban if evidence verifies.
                if let Some(first) = first_vote {
                    let evidence = noble_core::VoteEquivocationEvidence {
                        cycle: vote.cycle,
                        round,
                        candidate_a: first_candidate,
                        candidate_b: second_candidate,
                        voter_pubkey: vote.voter_pubkey.clone(),
                        signature_a: first.signature.clone(),
                        signature_b: vote.signature.clone(),
                    };
                    if evidence.verify().is_ok() {
                        outputs.push(CycleIo::PublishEvidence(Box::new(
                            noble_core::MisbehaviorEvidence::VoteEquivocation(evidence),
                        )));
                        outputs.push(CycleIo::BanPeer {
                            peer_id: from_peer,
                            category: noble_core::BanCategoryCode::InvalidVote,
                            reason: format!("vote equivocation (evidence verified) in round {round}"),
                        });
                    } else {
                        outputs.push(CycleIo::Log(
                            "WARNING: vote equivocation evidence failed verification — NOT banning".to_string(),
                        ));
                    }
                } else {
                    outputs.push(CycleIo::Log(
                        "WARNING: vote equivocation detected but first vote unavailable — NOT banning".to_string(),
                    ));
                }
            }
            Err(crate::vote::VoteError::WrongCycle { .. }) => {
                outputs.push(CycleIo::Log(format!(
                    "ignored vote from fork peer (cycle mismatch)"
                )));
            }
            Err(e) => {
                // Log invalid votes without banning — the relay peer may not
                // be the author, and transient issues (timing, round mismatch)
                // are not clear misbehavior.  Cumulative scoring happens at the
                // network layer for repeated offenses.
                outputs.push(CycleIo::Log(format!(
                    "rejected invalid vote from peer: {e}"
                )));
            }
        }

        outputs
    }

    /// P0.3: Handle mempool transactions response — build and broadcast a block proposal.
    fn handle_mempool_transactions(&mut self, txs: Vec<noble_core::Transaction>) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

        // Only propose during Proposal phase, and only if proposals are enabled.
        if self.tracked_phase != CyclePhase::Proposal {
            return outputs;
        }
        if !self.proposals_enabled {
            return outputs;
        }

        let (ref priv_key, ref pub_key) = match &self.our_validator_key {
            Some(kp) => kp,
            None => return outputs,
        };

        // Guard: skip if we already proposed a block this cycle (prevents
        // duplicate proposals from bootstrap retry or re-triggered events).
        let our_wire = pub_key.to_wire_bytes();
        if self.candidate_tracker.has_proposed(&our_wire) {
            return outputs;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Use injected UTXO lookup if available, otherwise fall back to no-op (0 fees).
        struct NoopUtxoLookup;
        impl crate::proposal::UtxoValueLookup for NoopUtxoLookup {
            fn utxo_value(&self, _: &noble_core::OutPoint) -> Option<u64> { None }
        }
        let noop = NoopUtxoLookup;
        let lookup: &dyn crate::proposal::UtxoValueLookup = match &self.utxo_value_lookup {
            Some(l) => l.as_ref(),
            None => &noop,
        };

        match crate::proposal::propose_block(
            &txs,
            self.tip_hash,
            self.tip_height + 1,
            now,
            self.chain_id,
            priv_key,
            pub_key,
            self.config.max_block_size,
            lookup,
        ) {
            Ok(block) => {
                // P0-3: Validate self-proposed block before broadcast (same checks as remote proposals).
                let current_time = now;
                let val_list = self.snapshot_pubkey_vec();
                let ctx = BlockValidationContext {
                    chain_id: self.chain_id,
                    current_time,
                    parent: self.tip_header.as_ref(),
                    validator_list: &val_list,
                };
                if let Err(e) = validate_block(&block, &ctx) {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {}: self-proposed block failed validation: {e}",
                        self.cycle_label()
                    )));
                    // Identify which tx(s) failed validation and evict them
                    let mut bad_tx_ids = Vec::new();
                    for tx in &block.transactions {
                        let tx_ctx = TxValidationContext {
                            chain_id: self.chain_id,
                            current_time,
                            chain_height: self.tip_height + 1,
                        };
                        match tx.compute_tx_id(self.chain_id) {
                            Ok(tx_id) => {
                                if validate_transaction(tx, &tx_id, &tx_ctx).is_err() {
                                    bad_tx_ids.push(tx_id);
                                }
                            }
                            Err(e) => {
                                warn!("failed to compute tx_id for eviction check: {e}");
                            }
                        }
                    }
                    if !bad_tx_ids.is_empty() {
                        outputs.push(CycleIo::EvictTransactions(bad_tx_ids));
                    }
                    return outputs;
                }

                let block_hash = match block.header.compute_block_hash() {
                    Ok(h) => h,
                    Err(e) => {
                        outputs.push(CycleIo::Log(format!(
                            "failed to compute proposed block hash: {e}"
                        )));
                        return outputs;
                    }
                };
                // Record proposer hint for self-proposed block.
                self.vote_mgr.record_proposer(block_hash, block.header.validator_id.to_wire_bytes());
                // Add to our own candidate tracker
                let block_box = Box::new(block);
                if let Err(e) =
                    self.candidate_tracker
                        .add_candidate(block_box.clone(), block_hash, 0)
                {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {}: failed to add self-proposed candidate: {e}",
                        self.cycle_label()
                    )));
                    return outputs;
                }
                outputs.push(CycleIo::BroadcastBlock(block_box));
                let hash_hex = format!("{}", block_hash);
                let hash_short = if hash_hex.len() > 13 {
                    format!("{{{}...{}}}", &hash_hex[..5], &hash_hex[hash_hex.len()-8..])
                } else {
                    format!("{{{hash_hex}}}")
                };
                outputs.push(CycleIo::Log(format!(
                    "cycle {}: proposed block {} ({} txs) at height {}",
                    self.cycle_label(),
                    hash_short,
                    txs.len(),
                    self.tip_height + 1
                )));
            }
            Err(e) => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {}: failed to propose block: {e}",
                    self.cycle_label()
                )));
            }
        }

        outputs
    }

    /// Cast an R1 vote for our preferred candidate.
    fn cast_r1_vote(&mut self, cycle: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        let cl = self.cycle_label();

        // Propose-only nodes (voting_enabled=false) don't cast votes.
        if !self.voting_enabled {
            self.r1_vote_cast = true;
            return outputs;
        }

        let (ref priv_key, ref pub_key) = match &self.our_validator_key {
            Some(kp) => kp,
            None => {
                self.r1_vote_cast = true;
                return outputs;
            }
        };

        let tallies = self.vote_mgr.current_tallies();
        // P1.3: Pass manual_vote to strategy selector
        let manual = self.manual_vote.take();
        let empty_snap = crate::registry::ValidatorSnapshot {
            entries: vec![], ordered_keys: vec![], pubkey_vec: vec![], count: 0,
        };
        let snap_ref = self.validator_snapshot.as_deref().unwrap_or(&empty_snap);
        let selected = crate::strategy::select_candidate(
            &self.config.voting_strategy,
            &self.candidate_tracker,
            snap_ref,
            cycle,
            manual,
            Some(&tallies),
        );
        if let Some(candidate_hash) = selected {
            self.r1_vote_cast = true;
            match PorVote::sign(cycle, candidate_hash, priv_key, pub_key.clone()) {
                Ok(vote) => {
                    // Record our own R1 vote locally — gossipsub does not
                    // deliver published messages back to the sender, so
                    // without this the validator's vote is lost from its
                    // own tally and compute_majority always returns
                    // Indeterminate on small networks.
                    if let Err(e) = self.vote_mgr.record_vote(b"self", &vote) {
                        warn!("cycle {cl}: self R1 vote rejected: {e}");
                    }
                    outputs.push(CycleIo::BroadcastVote(vote));
                    outputs.push(CycleIo::Log(format!(
                        "cycle {cl}: broadcast R1 vote for candidate {} (strategy: {})",
                        self.candidate_label(&candidate_hash),
                        self.config.voting_strategy.name()
                    )));
                }
                Err(e) => {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {cl}: failed to sign vote: {e}"
                    )));
                }
            }
        } else if !self.r1_retry_logged {
            // No candidate available yet — DON'T set r1_vote_cast so
            // handle_tick will retry on the next tick when a candidate
            // may have arrived via gossip.  Log only once per cycle.
            self.r1_retry_logged = true;
            let n = self.candidate_tracker.all_candidates().len();
            outputs.push(CycleIo::Log(format!(
                "cycle {cl}: no candidate selected for R1 vote ({n} proposal(s) available), will retry"
            )));
        }

        outputs
    }

    /// P1.2: Cast an R2 confirmation vote based on R1 tallies.
    fn cast_r2_vote(&mut self, cycle: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        let cl = self.cycle_label();

        // Propose-only nodes (voting_enabled=false) don't cast votes.
        if !self.voting_enabled {
            self.r2_vote_cast = true;
            return outputs;
        }

        let (ref priv_key, ref pub_key) = match &self.our_validator_key {
            Some(kp) => kp,
            None => {
                self.r2_vote_cast = true;
                return outputs;
            }
        };

        // Use confirmation_strategy applied to current R1 tallies.
        let tallies = self.vote_mgr.current_tallies();
        let empty_snap = crate::registry::ValidatorSnapshot {
            entries: vec![], ordered_keys: vec![], pubkey_vec: vec![], count: 0,
        };
        let snap_ref = self.validator_snapshot.as_deref().unwrap_or(&empty_snap);
        let selected = crate::strategy::select_candidate(
            &self.config.confirmation_strategy,
            &self.candidate_tracker,
            snap_ref,
            cycle,
            None,
            Some(&tallies),
        );

        if let Some(candidate_hash) = selected {
            self.r2_vote_cast = true;
            match PorVote::sign_round(cycle, candidate_hash, 2, priv_key, pub_key.clone()) {
                Ok(vote) => {
                    // Record our own R2 vote
                    if let Err(e) = self.vote_mgr.record_vote(b"self", &vote) {
                        warn!("cycle {cl}: self R2 vote rejected: {e}");
                    }
                    outputs.push(CycleIo::BroadcastVote(vote));
                    outputs.push(CycleIo::Log(format!(
                        "cycle {cl}: broadcast R2 confirmation vote for {} (strategy: {})",
                        self.candidate_label(&candidate_hash),
                        self.config.confirmation_strategy.name()
                    )));
                }
                Err(e) => {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {cl}: failed to sign R2 vote: {e}"
                    )));
                }
            }
        } else if !self.r2_retry_logged {
            // No candidate available — log once, then retry silently on subsequent ticks.
            self.r2_retry_logged = true;
            let r1_count = self.vote_mgr.current_tallies().len();
            outputs.push(CycleIo::Log(format!(
                "cycle {cl}: no candidate selected for R2 vote ({r1_count} R1 candidate(s)), will retry"
            )));
        }

        outputs
    }

    /// Set a manual vote target for the Manual voting strategy (P1.3).
    pub fn set_manual_vote(&mut self, hash: Hash256) {
        self.manual_vote = Some(hash);
    }

    /// Get a reference to the reputation engine (S15-A).
    pub fn reputation(&self) -> &ReputationEngine {
        &self.reputation
    }

    /// Get a mutable reference to the reputation engine (S15-A).
    pub fn reputation_mut(&mut self) -> &mut ReputationEngine {
        &mut self.reputation
    }

    /// Replace the reputation engine (used at startup to restore persisted data).
    pub fn set_reputation(&mut self, engine: ReputationEngine) {
        self.reputation = engine;
    }

}

impl ConsensusStateMachine for CycleEngine {
    #[tracing::instrument(skip(self, event), fields(task = "consensus_step", cycle = self.tracked_cycle))]
    fn step(&mut self, event: CycleEvent) -> Vec<CycleIo> {
        debug!(
            "consensus: processing event {:?}",
            std::mem::discriminant(&event)
        );
        match event {
            CycleEvent::Tick { now } => self.handle_tick(now),
            CycleEvent::PhaseTransition { cycle, new_phase } => {
                self.tracked_phase = new_phase;
                self.handle_phase_transition(cycle, new_phase)
            }
            CycleEvent::CycleBoundary { completed_cycle } => {
                self.handle_cycle_boundary(completed_cycle)
            }
            CycleEvent::BlockProposed { block, from_peer } => {
                self.handle_block_proposed(block, from_peer)
            }
            CycleEvent::VoteReceived { vote, from_peer } => {
                self.handle_vote_received(vote, from_peer)
            }
            CycleEvent::MempoolTransactions(txs) => self.handle_mempool_transactions(txs),
        }
    }

    fn current_phase(&self) -> CyclePhase {
        self.tracked_phase
    }

    fn current_cycle(&self) -> u64 {
        self.tracked_cycle
    }

    fn chain_tip(&self) -> (u64, Hash256) {
        (self.tip_height, self.tip_hash)
    }

    fn phase_timing(&self) -> (u8, u64, u64) {
        // AUD-M7: Use monotonic Instant offset from anchor to avoid NTP jumps
        let elapsed = std::time::Instant::now()
            .duration_since(self.clock_anchor.0)
            .as_secs();
        let now = self.clock_anchor.1 + elapsed;
        // Compute phase from cycle_mgr in real-time (not from tracked_phase)
        // to avoid stale data during the 1-tick window after epoch changes.
        let phase_idx = match self.cycle_mgr.current_phase(now) {
            CyclePhase::Proposal => 0,
            CyclePhase::Voting => 1,
            CyclePhase::Reflection => 2,
            CyclePhase::Propagation => 3,
        };
        let phase_remaining = self.cycle_mgr.seconds_until_phase_change(now);
        let cycle_remaining = self.cycle_mgr.seconds_until_cycle_boundary(now);
        (phase_idx, phase_remaining, cycle_remaining)
    }

    fn genesis_timestamp(&self) -> Option<u64> {
        if self.cycle_mgr.has_genesis() {
            Some(self.cycle_mgr.genesis_ts())
        } else {
            None
        }
    }

    fn cycle_for_timestamp(&self, ts: u64) -> Option<u64> {
        if self.cycle_mgr.has_genesis() {
            Some(self.cycle_mgr.current_cycle(ts))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::VotingStrategy;
    use noble_core::{
        BlockHeader, NobleAddress, OutPoint, Transaction, TxIn, TxOut,
        TX_TYPE_COINBASE, PROTOCOL_VERSION, subsidy_at_height,
    };
    use noble_test_utils::fixtures::test_chain_id;
    use noble_crypto::{ed25519, NobleSigner, SignatureEnvelope, SCHEME_ED25519};

    fn make_validator() -> (NoblePrivateKey, NoblePublicKey) {
        let (sk, _) = ed25519::generate_keypair();
        let priv_key = NoblePrivateKey::Ed25519(sk);
        let pub_key = priv_key.public_key();
        (priv_key, pub_key)
    }

    fn make_engine(
        validator_key: Option<(NoblePrivateKey, NoblePublicKey)>,
        validators: &[NoblePublicKey],
        peers: usize,
    ) -> CycleEngine {
        let mut reg = crate::registry::ValidatorRegistry::empty();
        for v in validators {
            reg.add_validator(v.clone(), 100, 0);
        }
        let snap = reg.create_snapshot();
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            0,
            Hash256::ZERO,
            test_chain_id(),
            validator_key,
            Some(noble_core::GENESIS_TIMESTAMP),
        );
        engine.set_validator_snapshot(snap);
        engine.set_peer_count(peers);
        engine
    }

    fn make_valid_block(
        val_priv: &NoblePrivateKey,
        val_pub: &NoblePublicKey,
        height: u64,
        prev_hash: Hash256,
    ) -> (Box<Block>, Hash256) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Build a coinbase transaction (U9: every block must have exactly one)
        let subsidy = subsidy_at_height(height);
        let validator_addr = NobleAddress::Noble(val_pub.clone());
        let coinbase_tx = Transaction {
            version: PROTOCOL_VERSION,
            tx_type: TX_TYPE_COINBASE,
            inputs: vec![TxIn { prev_output: OutPoint::COINBASE_PREVOUT }],
            outputs: vec![TxOut { value: subsidy, address: validator_addr }],
            checksum: Hash256::ZERO,
            timestamp: now,
            publisher_sig: SignatureEnvelope {
                scheme_id: val_pub.scheme_id(),
                public_key: val_pub.key_bytes().to_vec(),
                signature: vec![],
            },
            additional_sigs: vec![],
            metadata: vec![],
            encrypted_locator: None,
            external_attestations: vec![],
            gateway_address: None,
            contract_data: None,
        };
        // Sign the coinbase
        let chain_id = test_chain_id();
        let cb_msg = coinbase_tx.compute_signing_message_for_chain(chain_id).unwrap();
        let cb_sig = val_priv.sign(&cb_msg).unwrap();
        let mut coinbase_signed = coinbase_tx;
        coinbase_signed.publisher_sig = cb_sig;

        let tx_id = coinbase_signed.compute_tx_id(chain_id).unwrap();
        let merkle_root = noble_core::compute_merkle_root(&[tx_id]);

        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: now,
            height,
            tx_count: 1,
            validator_id: val_pub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: val_pub.key_bytes().to_vec(),
                signature: vec![],
            },
        };
        let msg = header.compute_signing_message().unwrap();
        header.validator_sig = val_priv.sign(&msg).unwrap();
        let hash = header.compute_block_hash().unwrap();
        (
            Box::new(Block {
                header,
                transactions: vec![coinbase_signed],
            }),
            hash,
        )
    }

    // --- Phase acceptance/rejection ---

    #[test]
    fn block_proposal_accepted_during_proposal() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        // Use height=1 (next block after tip=0)
        let (block, _hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let outputs = engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"peer1".to_vec(),
        });

        assert!(!has_ban(&outputs), "valid block should not be banned");
        assert_eq!(engine.candidate_tracker.len(), 1);
    }

    #[test]
    fn block_proposal_accepted_during_voting() {
        // Blocks are accepted during all phases so that vote-triggered
        // RequestBlock fetches can populate the candidate tracker.
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Voting;

        // Use height=1 (next block after tip=0)
        let (block, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let outputs = engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"peer1".to_vec(),
        });

        assert!(!has_ban(&outputs), "valid block should not be banned");
        assert_eq!(
            engine.candidate_tracker.len(),
            1,
            "block should be accepted in Voting"
        );
    }

    #[test]
    fn vote_accepted_during_voting() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Voting;

        let candidate = Hash256::from_bytes([0x42; 32]);
        let vote = PorVote::sign(0, candidate, &vp, vpub.clone()).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"peer1".to_vec(),
        });

        assert!(!has_ban(&outputs));
        assert_eq!(engine.vote_mgr.total_votes(), 1);
    }

    #[test]
    fn vote_rejected_during_early_proposal() {
        // Votes should be rejected during early Proposal phase (>30s until Voting).
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;
        // Pin the clock to the very START of a Proposal phase so
        // seconds_until_phase_change() returns ~300 (well above tolerance).
        let g = noble_core::GENESIS_TIMESTAMP;
        engine.clock_anchor = (std::time::Instant::now(), g);

        let candidate = Hash256::from_bytes([0x42; 32]);
        let vote = PorVote::sign(0, candidate, &vp, vpub.clone()).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"peer1".to_vec(),
        });

        assert_eq!(
            engine.vote_mgr.total_votes(),
            0,
            "vote should be rejected in early Proposal phase"
        );
        assert!(has_log_containing(&outputs, "rejected"));
    }

    #[test]
    fn vote_accepted_during_late_proposal() {
        // Votes should be accepted during late Proposal phase (≤30s until Voting).
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;
        // Pin clock to 280s into the Proposal phase → 20s until Voting (< tolerance).
        let g = noble_core::GENESIS_TIMESTAMP;
        engine.clock_anchor = (std::time::Instant::now(), g + 280);

        let candidate = Hash256::from_bytes([0x42; 32]);
        let vote = PorVote::sign(0, candidate, &vp, vpub.clone()).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"peer1".to_vec(),
        });

        assert_eq!(
            engine.vote_mgr.total_votes(),
            1,
            "vote should be accepted in late Proposal phase (clock skew tolerance)"
        );
        assert!(!has_log_containing(&outputs, "rejected"));
    }

    // --- Majority tiers ---

    #[test]
    fn cycle_boundary_commits_strong_majority() {
        let (vp, vpub) = make_validator();
        // Create 3 voting validators (must be in the validator list for AUD2-C3)
        let voters: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let mut all_validators: Vec<NoblePublicKey> = vec![vpub.clone()];
        all_validators.extend(voters.iter().map(|(_, pk)| pk.clone()));
        let mut engine = make_engine(None, &all_validators, 5);

        // Add a candidate
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.tracked_phase = CyclePhase::Proposal;
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Add votes (3/5 = 60% > 50% → Strong)
        engine.tracked_phase = CyclePhase::Voting;
        for (i, (vk, vpk)) in voters.iter().enumerate() {
            let vote = PorVote::sign(0, hash, vk, vpk.clone()).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i as u8 + 10],
            });
        }

        // Cycle boundary
        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(has_commit(&outputs), "strong majority should commit");
        assert_eq!(engine.tip_height, 1);
        assert_eq!(engine.tip_hash, hash);
    }

    #[test]
    fn cycle_boundary_insufficient_peers_indeterminate() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 1); // < 2 min_peers

        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.tracked_phase = CyclePhase::Proposal;
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        engine.tracked_phase = CyclePhase::Voting;
        let (vk, vp2) = make_validator();
        let vote = PorVote::sign(0, hash, &vk, vp2).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"p2".to_vec(),
        });

        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(!has_commit(&outputs), "insufficient peers → no commit");
        assert!(has_log_containing(&outputs, "indeterminate"));
    }

    // --- Double proposal ban ---

    #[test]
    fn double_proposal_bans_peer() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let (block1, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        // Second block must have a DIFFERENT hash to trigger the double-proposal
        // ban.  Use a different timestamp so the signing message differs.
        let (mut block2, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        block2.header.timestamp += 1;
        let msg = block2.header.compute_signing_message().unwrap();
        block2.header.validator_sig = vp.sign(&msg).unwrap();

        engine.step(CycleEvent::BlockProposed {
            block: block1,
            from_peer: b"peer1".to_vec(),
        });

        let outputs = engine.step(CycleEvent::BlockProposed {
            block: block2,
            from_peer: b"peer1".to_vec(),
        });

        assert!(has_ban(&outputs), "double proposal should ban peer");
        assert_eq!(engine.candidate_tracker.len(), 1);
    }

    #[test]
    fn duplicate_block_delivery_does_not_ban() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let (block, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let block_clone = Box::new(Block {
            header: block.header.clone(),
            transactions: block.transactions.clone(),
        });

        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"peer1".to_vec(),
        });
        assert_eq!(engine.candidate_tracker.len(), 1);

        // Same block arriving again (e.g., vote-triggered fetch racing with
        // BlockAnnounce fetch) should NOT ban.
        let outputs = engine.step(CycleEvent::BlockProposed {
            block: block_clone,
            from_peer: b"peer1".to_vec(),
        });

        assert!(!has_ban(&outputs), "duplicate delivery must not ban");
        assert_eq!(engine.candidate_tracker.len(), 1);
    }

    // --- Invalid vote sig ban ---

    #[test]
    fn invalid_vote_sig_rejected_not_banned() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Voting;

        let candidate = Hash256::from_bytes([0x42; 32]);
        let mut vote = PorVote::sign(0, candidate, &vp, vpub.clone()).unwrap();
        vote.signature.signature = vec![0u8; 64]; // corrupt

        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"badpeer".to_vec(),
        });

        // Invalid signatures are rejected but NOT banned — the relay peer may
        // not be the vote author.  Cumulative scoring at the network layer
        // handles repeated offenses.
        assert!(!has_ban(&outputs), "invalid vote sig should not ban relay peer");
        assert!(
            outputs.iter().any(|o| matches!(o, CycleIo::Log(msg) if msg.contains("rejected invalid vote"))),
            "should log rejection"
        );
    }

    // --- Observation mode ---

    #[test]
    fn observation_mode_no_broadcast() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5); // no validator key

        // Add a candidate
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, _hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Phase transition to Voting — observer should NOT broadcast vote
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 0,
            new_phase: CyclePhase::Voting,
        });

        assert!(
            !has_broadcast_vote(&outputs),
            "observation mode should not broadcast votes"
        );
    }

    #[test]
    fn observation_mode_still_commits() {
        let (vp, vpub) = make_validator();
        // Voters must be in the validator list (AUD2-C3)
        let voters: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let mut all_validators: Vec<NoblePublicKey> = vec![vpub.clone()];
        all_validators.extend(voters.iter().map(|(_, pk)| pk.clone()));
        let mut engine = make_engine(None, &all_validators, 5);

        // Proposal
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Votes from others
        engine.tracked_phase = CyclePhase::Voting;
        for (i, (vk, vpk)) in voters.iter().enumerate() {
            let vote = PorVote::sign(0, hash, vk, vpk.clone()).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i as u8 + 20],
            });
        }

        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(
            has_commit(&outputs),
            "observer should still commit winning blocks"
        );
    }

    // --- Tick-driven state transitions ---

    #[test]
    fn tick_detects_phase_and_cycle_changes() {
        let (_vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        let g = noble_core::GENESIS_TIMESTAMP;

        // Tick at genesis: cycle 0, Proposal
        let outputs = engine.step(CycleEvent::Tick { now: g });
        assert!(has_set_timer(&outputs));
        assert_eq!(engine.current_phase(), CyclePhase::Proposal);
        assert_eq!(engine.current_cycle(), 0);

        // Tick at g+300: should transition to Voting
        let _outputs = engine.step(CycleEvent::Tick { now: g + 300 });
        assert_eq!(engine.current_phase(), CyclePhase::Voting);

        // Tick at g+600: should transition to Reflection
        let _outputs = engine.step(CycleEvent::Tick { now: g + 600 });
        assert_eq!(engine.current_phase(), CyclePhase::Reflection);

        // Tick at g+900: should transition to Propagation
        let _outputs = engine.step(CycleEvent::Tick { now: g + 900 });
        assert_eq!(engine.current_phase(), CyclePhase::Propagation);

        // Tick at g+1200: should transition to new cycle
        let _outputs = engine.step(CycleEvent::Tick { now: g + 1200 });
        assert_eq!(engine.current_cycle(), 1);
        assert_eq!(engine.current_phase(), CyclePhase::Proposal);
    }

    #[test]
    fn deterministic_same_events_same_result() {
        // Run the same event sequence and verify chain tip advances
        let (vp, vpub) = make_validator();
        // Voters must be in the validator list (AUD2-C3)
        let voters: Vec<_> = (0..3).map(|_| make_validator()).collect();
        let mut all_validators: Vec<NoblePublicKey> = vec![vpub.clone()];
        all_validators.extend(voters.iter().map(|(_, pk)| pk.clone()));
        let mut engine = make_engine(None, &all_validators, 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        engine.tracked_phase = CyclePhase::Voting;
        for (i, (vk, vpk)) in voters.iter().enumerate() {
            let vote = PorVote::sign(0, hash, vk, vpk.clone()).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i as u8 + 30],
            });
        }

        engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        let (h, _) = engine.chain_tip();
        assert_eq!(h, 1, "chain tip should advance to height 1");
    }

    // --- Helper functions ---

    fn has_commit(outputs: &[CycleIo]) -> bool {
        outputs.iter().any(|o| matches!(o, CycleIo::CommitBlock(_)))
    }

    fn has_ban(outputs: &[CycleIo]) -> bool {
        outputs.iter().any(|o| matches!(o, CycleIo::BanPeer { .. }))
    }

    fn has_broadcast_vote(outputs: &[CycleIo]) -> bool {
        outputs
            .iter()
            .any(|o| matches!(o, CycleIo::BroadcastVote(_)))
    }

    fn has_set_timer(outputs: &[CycleIo]) -> bool {
        outputs
            .iter()
            .any(|o| matches!(o, CycleIo::SetTimer { .. }))
    }

    fn has_log_containing(outputs: &[CycleIo], needle: &str) -> bool {
        outputs.iter().any(|o| {
            if let CycleIo::Log(msg) = o {
                msg.contains(needle)
            } else {
                false
            }
        })
    }

    // --- Dual-Witness / bootstrap ---

    #[test]
    fn dual_witness_blocks_single_voter_at_genesis() {
        // tip_height=0, 1 voter for candidate → Dual-Witness blocks commit
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 2);
        // tip_height=0 from make_engine
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });
        engine.tracked_phase = CyclePhase::Voting;
        let vote = PorVote::sign(0, hash, &vp, vpub).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"p1".to_vec(),
        });
        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(!has_commit(&outputs), "single voter must not commit block 1");
    }

    #[test]
    fn dual_witness_allows_two_voters_at_genesis() {
        // tip_height=0, 2 distinct voters → Dual-Witness passes → commit
        let (vp, vpub) = make_validator();
        let (vp2, vpub2) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone(), vpub2.clone()], 2);
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });
        engine.tracked_phase = CyclePhase::Voting;
        let v1 = PorVote::sign(0, hash, &vp, vpub).unwrap();
        let v2 = PorVote::sign(0, hash, &vp2, vpub2).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote: v1,
            from_peer: b"p1".to_vec(),
        });
        engine.step(CycleEvent::VoteReceived {
            vote: v2,
            from_peer: b"p2".to_vec(),
        });
        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(has_commit(&outputs), "2 voters should commit block 1");
        assert_eq!(engine.tip_height, 1);
    }

    #[test]
    fn dual_witness_not_required_after_block_1() {
        // tip_height=1, 1 voter → normal plurality, no Dual-Witness → commits.
        // Use min_peers_for_consensus=1 to isolate the Dual-Witness check
        // (this test is not about the minimum voter threshold).
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 2);
        engine.config.min_peers_for_consensus = 1;
        engine.tip_height = 1;
        let parent_hash = Hash256::from_bytes([0x99; 32]);
        engine.tip_hash = parent_hash;
        // Set a tip_header so B2/B3 validation can work
        let merkle_root = noble_core::compute_merkle_root(&[]);
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut parent_hdr = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: Hash256::from_bytes([0x88; 32]),
            merkle_root,
            timestamp: now_ts - 10,
            height: 1,
            tx_count: 0,
            validator_id: vpub.clone(),
            validator_sig: SignatureEnvelope {
                scheme_id: SCHEME_ED25519,
                public_key: vpub.key_bytes().to_vec(),
                signature: vec![],
            },
        };
        let msg = parent_hdr.compute_signing_message().unwrap();
        parent_hdr.validator_sig = vp.sign(&msg).unwrap();
        engine.tip_header = Some(parent_hdr.clone());
        // Recompute tip_hash from the actual parent header
        engine.tip_hash = parent_hdr.compute_block_hash().unwrap();

        // Create block 2 with correct prev_hash
        let (block, hash) = make_valid_block(&vp, &vpub, 2, engine.tip_hash);
        engine.tracked_phase = CyclePhase::Proposal;
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });
        engine.tracked_phase = CyclePhase::Voting;
        let vote = PorVote::sign(0, hash, &vp, vpub).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"p1".to_vec(),
        });
        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(
            has_commit(&outputs),
            "after block 1, single voter can commit"
        );
    }

    #[test]
    fn bootstrap_epoch_initializes_cycle_machinery() {
        // Engine with genesis_timestamp=None → first tick sets a wall-clock-aligned epoch.
        // `aligned = floor(now / 1200) * 1200`, so `current_cycle(now)` is 0 or 1.
        let (vp, vpub) = make_validator();
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            0,
            Hash256::ZERO,
            test_chain_id(),
            Some((vp, vpub)),
            None,
        );
        engine.set_peer_count(1);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let outputs = engine.step(CycleEvent::Tick { now });
        assert!(
            has_set_timer(&outputs),
            "bootstrap should enable normal timer"
        );
        // Wall-clock-aligned epoch: cycle should be 0 (within the same window)
        assert!(
            engine.tracked_cycle <= 1,
            "bootstrap cycle should be 0 or 1 (wall-clock-aligned), got {}",
            engine.tracked_cycle,
        );
        // Verify the genesis timestamp is wall-clock aligned
        let expected_epoch = (now / 1200) * 1200;
        assert_eq!(
            engine.cycle_mgr.genesis_ts(),
            expected_epoch,
            "bootstrap epoch should be floor(now/1200)*1200"
        );
    }

    #[test]
    fn wall_clock_aligned_epoch_produces_cycle_zero() {
        // Regardless of when the node starts, bootstrap always produces cycle 0.
        let (vp, vpub) = make_validator();
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            0,
            Hash256::ZERO,
            test_chain_id(),
            Some((vp, vpub)),
            None,
        );
        engine.set_peer_count(1);
        // Use a timestamp far in the future — should still get cycle 0
        let far_future = 2_000_000_000u64; // ~2033
        let outputs = engine.step(CycleEvent::Tick { now: far_future });
        assert!(has_set_timer(&outputs));
        assert_eq!(
            engine.tracked_cycle, 0,
            "wall-clock-aligned epoch must produce cycle 0 at the alignment point"
        );
        let expected_epoch = (far_future / 1200) * 1200;
        assert_eq!(engine.cycle_mgr.genesis_ts(), expected_epoch);
    }

    #[test]
    fn bootstrap_tolerance_disabled_after_block_1_commit() {
        // After block 1 commits, bootstrap tolerance should be off.
        let (vp, vpub) = make_validator();
        let (vp2, vpub2) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone(), vpub2.clone()], 2);
        // Simulate bootstrap: clear genesis so first tick sets wall-clock epoch
        engine.cycle_mgr.set_genesis_timestamp(u64::MAX);
        engine.first_tick = true;
        engine.tip_height = 0;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        engine.step(CycleEvent::Tick { now });
        assert!(
            engine.vote_mgr.bootstrap_tolerance,
            "bootstrap tolerance should be enabled after bootstrap init"
        );

        // Propose and commit block 1
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed { block, from_peer: b"p1".to_vec() });
        engine.tracked_phase = CyclePhase::Voting;
        let v1 = PorVote::sign(0, hash, &vp, vpub).unwrap();
        let v2 = PorVote::sign(0, hash, &vp2, vpub2).unwrap();
        engine.step(CycleEvent::VoteReceived { vote: v1, from_peer: b"p1".to_vec() });
        engine.step(CycleEvent::VoteReceived { vote: v2, from_peer: b"p2".to_vec() });
        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(has_commit(&outputs), "block 1 should commit");
        assert!(
            !engine.vote_mgr.bootstrap_tolerance,
            "bootstrap tolerance must be disabled after block 1 commit"
        );
    }

    #[test]
    fn block_1_votes_stored_as_cycle_zero() {
        // StoreBlockVotes for block 1 should use cycle_number=0
        let (vp, vpub) = make_validator();
        let (vp2, vpub2) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone(), vpub2.clone()], 2);
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed { block, from_peer: b"p1".to_vec() });
        engine.tracked_phase = CyclePhase::Voting;
        let v1 = PorVote::sign(0, hash, &vp, vpub).unwrap();
        let v2 = PorVote::sign(0, hash, &vp2, vpub2).unwrap();
        engine.step(CycleEvent::VoteReceived { vote: v1, from_peer: b"p1".to_vec() });
        engine.step(CycleEvent::VoteReceived { vote: v2, from_peer: b"p2".to_vec() });
        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        let stored = outputs.iter().find_map(|o| {
            if let CycleIo::StoreBlockVotes { votes, .. } = o {
                Some(votes)
            } else {
                None
            }
        });
        assert!(stored.is_some(), "StoreBlockVotes should be emitted");
        assert_eq!(
            stored.unwrap().cycle_number, 0,
            "block 1 votes must be stored with cycle_number=0"
        );
    }

    // --- P0.3: Block proposal emission ---

    #[test]
    fn validator_requests_mempool_on_proposal_entry() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 1,
            new_phase: CyclePhase::Proposal,
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, CycleIo::RequestMempoolTransactions { .. })),
            "validator should request mempool txs on Proposal entry"
        );
    }

    #[test]
    fn observer_does_not_request_mempool() {
        let (_vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub], 5);
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 1,
            new_phase: CyclePhase::Proposal,
        });
        assert!(
            !outputs
                .iter()
                .any(|o| matches!(o, CycleIo::RequestMempoolTransactions { .. })),
            "observer should NOT request mempool txs"
        );
    }

    #[test]
    fn mempool_transactions_produces_block_proposal() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let outputs = engine.step(CycleEvent::MempoolTransactions(vec![]));
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, CycleIo::BroadcastBlock(_))),
            "should broadcast proposed block"
        );
        assert_eq!(
            engine.candidate_tracker.len(),
            1,
            "should add to own candidates"
        );
    }

    // --- P1.3: Manual vote injection ---

    #[test]
    fn manual_vote_injection() {
        let (vp, vpub) = make_validator();
        let (vp2, vpub2) = make_validator();
        let target_hash = Hash256::from_bytes([0xAA; 32]);
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub, vpub2.clone()], 5);
        engine.set_voting_strategy(VotingStrategy::Manual);
        engine.set_manual_vote(target_hash);

        // Add a candidate so the tracker isn't empty
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, _hash) = make_valid_block(&vp2, &vpub2, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Tick into Voting phase with VOTE_CAST_DELAY to trigger R1 vote
        let g = noble_core::GENESIS_TIMESTAMP;
        engine.tracked_cycle = 0;
        engine.tracked_phase = CyclePhase::Voting;
        engine.r1_vote_cast = false;
        let outputs = engine.step(CycleEvent::Tick { now: g + 300 + 30 }); // Voting + 30s delay

        let vote_broadcast = outputs
            .iter()
            .find(|o| matches!(o, CycleIo::BroadcastVote(_)));
        assert!(vote_broadcast.is_some(), "manual vote should broadcast");
        if let Some(CycleIo::BroadcastVote(vote)) = vote_broadcast {
            assert_eq!(
                vote.candidate_hash, target_hash,
                "should vote for manual target"
            );
        }
    }

    // --- P1.2: Two-round voting ---

    #[test]
    fn r1_vote_cast_during_voting_phase() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        let g = noble_core::GENESIS_TIMESTAMP;

        // Initialize engine with a tick at genesis
        engine.step(CycleEvent::Tick { now: g });
        assert_eq!(engine.current_phase(), CyclePhase::Proposal);

        // Tick into Voting phase past VOTE_CAST_DELAY (30s)
        // Voting starts at g+300, delay fires at g+330
        let _outputs = engine.step(CycleEvent::Tick { now: g + 330 });

        // With no candidates available, r1_vote_cast stays false so the
        // engine can retry when a candidate arrives via gossip.
        assert!(
            !engine.r1_vote_cast,
            "r1_vote_cast should stay false when no candidates available (allows retry)"
        );
    }

    #[test]
    fn r2_vote_cast_during_reflection_phase() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        let g = noble_core::GENESIS_TIMESTAMP;

        // Move to Reflection phase
        engine.tracked_phase = CyclePhase::Reflection;
        engine.tracked_cycle = 1;
        engine.r1_vote_cast = true;
        engine.r2_vote_cast = false;

        // Tick at 30s into Reflection phase of cycle 1
        // Reflection starts at 600s in cycle, so offset 630s from cycle start
        let now = g + 1200 + 600 + 30; // cycle 1 start + Reflection + 30s delay
        let _outputs = engine.step(CycleEvent::Tick { now });

        // With no candidates available, r2_vote_cast stays false so the
        // engine can retry when a candidate arrives.
        assert!(
            !engine.r2_vote_cast,
            "r2_vote_cast should stay false when no candidates available (allows retry)"
        );
    }

    #[test]
    fn r2_vote_override_at_cycle_boundary() {
        let (vp, vpub) = make_validator();
        let voters: Vec<_> = (0..5).map(|_| make_validator()).collect();
        let mut all_validators: Vec<NoblePublicKey> = vec![vpub.clone()];
        all_validators.extend(voters.iter().map(|(_, pk)| pk.clone()));
        let mut engine = make_engine(None, &all_validators, 7);

        // Propose a candidate
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // R1 votes: 2 out of 6 validators → not Strong
        engine.tracked_phase = CyclePhase::Voting;
        for (i, (vk, vpk)) in voters[..2].iter().enumerate() {
            let vote = PorVote::sign(0, hash, vk, vpk.clone()).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i as u8 + 10],
            });
        }

        // R2 votes: 4 out of 6 → Strong majority → should override
        for (i, (vk, vpk)) in voters[..4].iter().enumerate() {
            let vote = PorVote::sign_round(0, hash, 2, vk, vpk.clone()).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i as u8 + 20],
            });
        }

        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(
            has_commit(&outputs),
            "R2 Strong majority should commit block"
        );
        assert_eq!(engine.tip_height, 1);
    }

    // --- AUD-M7: Monotonic phase_timing ---

    #[test]
    fn phase_timing_returns_consistent_values() {
        let (_vp, vpub) = make_validator();
        let engine = make_engine(None, &[vpub], 5);
        let (phase_idx, _phase_remaining, _cycle_remaining) = engine.phase_timing();
        // Phase index should be 0..3 (Proposal, Voting, Reflection, Propagation)
        assert!(phase_idx <= 3);
    }

    // --- AUD2-C2: Block with wrong prev_hash rejected ---

    #[test]
    fn block_with_wrong_prev_hash_rejected() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        // Create a parent block at height 1 so tip_header is set
        let (parent_block, _parent_hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.update_tip_with_header(parent_block.header.clone());

        // Create a block that claims prev_hash is ZERO (wrong — tip is parent_hash)
        let (block, _) = make_valid_block(&vp, &vpub, 2, Hash256::ZERO);
        let outputs = engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"peer1".to_vec(),
        });

        // Block should be rejected (prev_hash doesn't match parent)
        assert!(
            has_ban(&outputs) || has_log_containing(&outputs, "rejected"),
            "block with wrong prev_hash should be rejected"
        );
    }

    // --- Open consensus: votes accepted from any peer with valid sig ---

    #[test]
    fn vote_from_unknown_validator_accepted() {
        let (_vp, vpub) = make_validator();
        let (unknown_priv, unknown_pub) = make_validator();
        // Engine only knows vpub, not unknown_pub — but open consensus
        // accepts votes from any peer with a valid signature.
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Voting;

        let candidate = Hash256::from_bytes([0x42; 32]);
        let vote = PorVote::sign(0, candidate, &unknown_priv, unknown_pub).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"unknownpeer".to_vec(),
        });

        assert!(!has_ban(&outputs), "vote from unknown validator should not ban");
        assert_eq!(engine.vote_mgr.total_votes(), 1);
    }

    #[test]
    fn vote_from_valid_validator_accepted() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Voting;

        let candidate = Hash256::from_bytes([0x42; 32]);
        let vote = PorVote::sign(0, candidate, &vp, vpub).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"peer1".to_vec(),
        });

        assert!(
            !has_ban(&outputs),
            "valid validator's vote should be accepted"
        );
        assert_eq!(engine.vote_mgr.total_votes(), 1);
    }

    // --- S45-A2: Network-level voter count ---

    #[test]
    fn network_voter_count_validator_plus_one_peer_commits() {
        // With 1 connected peer and self as validator, voter_count = 1 + 1 = 2,
        // which meets min_peers_for_consensus = 2.  Dual-Witness requires ≥2
        // distinct keys — the engine's self-vote + peer vote satisfies this.
        let (our_priv, our_pub) = make_validator();
        let (peer_priv, peer_pub) = make_validator();
        let mut engine = make_engine(
            Some((our_priv, our_pub.clone())),
            &[our_pub, peer_pub.clone()],
            1, // 1 connected peer
        );

        // Propose a block from the peer
        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&peer_priv, &peer_pub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Trigger R1 vote via cast_r1_vote directly (replaces old Reflection phase transition)
        engine.tracked_phase = CyclePhase::Voting;
        engine.vote_mgr.set_current_cycle(0);
        let _outputs = engine.cast_r1_vote(0);

        // Vote from the peer → 2 distinct keys (self + peer)
        let vote = PorVote::sign(0, hash, &peer_priv, peer_pub).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"p1".to_vec(),
        });

        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(
            has_commit(&outputs),
            "validator + 1 peer should reach consensus (voter_count=2, 2 unique keys)"
        );
        assert_eq!(engine.tip_height, 1);
    }

    #[test]
    fn network_voter_count_observer_not_counted() {
        // Observer (no validator key) with 1 peer: voter_count = 1 + 0 = 1,
        // which is below min_peers_for_consensus = 2 → Indeterminate.
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 1);

        engine.tracked_phase = CyclePhase::Proposal;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        engine.tracked_phase = CyclePhase::Voting;
        let vote = PorVote::sign(0, hash, &vp, vpub).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"p1".to_vec(),
        });

        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(
            !has_commit(&outputs),
            "observer + 1 peer = voter_count 1 → insufficient"
        );
    }

    // --- P0-3: Self-proposed block validation ---

    #[test]
    fn self_proposed_block_is_validated() {
        // A validator engine should validate its own block before broadcasting it.
        // When the validator is in the validator list, the block passes validation
        // and is broadcast.
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let outputs = engine.step(CycleEvent::MempoolTransactions(vec![]));
        let has_broadcast = outputs
            .iter()
            .any(|o| matches!(o, CycleIo::BroadcastBlock(_)));
        assert!(
            has_broadcast,
            "self-proposed block should pass validation and be broadcast"
        );
        assert_eq!(
            engine.candidate_tracker.len(),
            1,
            "validated block should be added to candidate tracker"
        );
    }

    #[test]
    fn self_proposed_block_rejected_if_not_in_validator_list() {
        // A validator whose key is NOT in the validator list should fail B9 check
        // and not broadcast.
        let (vp, vpub) = make_validator();
        let (_other_priv, other_pub) = make_validator();
        // Engine has vp as validator key, but only other_pub is in the list
        let mut engine = make_engine(Some((vp, vpub)), &[other_pub], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let outputs = engine.step(CycleEvent::MempoolTransactions(vec![]));
        let has_broadcast = outputs
            .iter()
            .any(|o| matches!(o, CycleIo::BroadcastBlock(_)));
        assert!(
            !has_broadcast,
            "block from non-trusted validator should not be broadcast"
        );
        assert!(
            has_log_containing(&outputs, "failed validation"),
            "should log validation failure"
        );
        assert_eq!(
            engine.candidate_tracker.len(),
            0,
            "rejected block should not be in candidate tracker"
        );
    }

    // --- DeliveredBlockLog integration tests ---

    #[test]
    fn delivered_log_prevents_cross_cycle_false_ban() {
        // Block from cycle N re-arrives in cycle N+2 (after an empty cycle).
        // The delivered_block_log should catch it and prevent any ban.
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        // Cycle N: propose block
        let (block1, _hash1) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let block1_clone = Box::new(Block {
            header: block1.header.clone(),
            transactions: block1.transactions.clone(),
        });

        engine.step(CycleEvent::BlockProposed {
            block: block1,
            from_peer: b"peer1".to_vec(),
        });
        assert_eq!(engine.candidate_tracker.len(), 1);

        // Cycle boundary → N+1
        engine.candidate_tracker.clear();
        // Cycle boundary → N+2 (empty cycle, previous_hashes from N+1 is empty)
        engine.candidate_tracker.clear();

        // Block from cycle N re-arrives in cycle N+2
        let outputs = engine.step(CycleEvent::BlockProposed {
            block: block1_clone,
            from_peer: b"peer1".to_vec(),
        });

        assert!(
            !has_ban(&outputs),
            "stale block from cycle N must not trigger ban in cycle N+2"
        );
        assert_eq!(
            engine.candidate_tracker.len(),
            0,
            "stale block should not be added to candidate tracker"
        );
    }

    #[test]
    fn reset_tip_clears_delivered_log() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let (block, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"peer1".to_vec(),
        });
        assert!(!engine.delivered_block_log.is_empty());

        // Blockchain hop: reset to genesis
        engine
            .reset_tip(0, Hash256::ZERO, true)
            .expect("force reset should succeed");
        assert!(
            engine.delivered_block_log.is_empty(),
            "reset_tip should clear delivered_block_log"
        );
    }

    #[test]
    fn true_double_proposal_still_bans_with_delivered_log() {
        // Same cycle, same validator, two different blocks → still bans.
        // The delivered_block_log should NOT interfere.
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Proposal;

        let (block1, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let (mut block2, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        block2.header.timestamp += 1;
        let msg = block2.header.compute_signing_message().unwrap();
        block2.header.validator_sig = vp.sign(&msg).unwrap();

        engine.step(CycleEvent::BlockProposed {
            block: block1,
            from_peer: b"peer1".to_vec(),
        });

        let outputs = engine.step(CycleEvent::BlockProposed {
            block: block2,
            from_peer: b"peer1".to_vec(),
        });

        assert!(
            has_ban(&outputs),
            "true double proposal should still ban even with delivered_block_log"
        );
    }
}
