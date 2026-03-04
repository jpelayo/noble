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
use tracing::{debug, info};

use crate::candidate::CandidateTracker;
use crate::config::ConsensusConfig;
use crate::cycle::{CycleManager, CyclePhase};
use crate::event::{CycleEvent, CycleIo};
use crate::history::{CycleHistoryEntry, CycleProposal, CycleVoteTally};
use crate::reputation::ReputationEngine;
use crate::validator::ValidatorList;
use crate::vote::{MigrationResult, PorVote, VoteManager};

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
    /// phase_index: 0 = Validation, 1 = Reflection.
    fn phase_timing(&self) -> (u8, u64, u64);
}

/// The NOBLE PoR consensus engine.
pub struct CycleEngine {
    config: ConsensusConfig,
    cycle_mgr: CycleManager,
    vote_mgr: VoteManager,
    candidate_tracker: CandidateTracker,
    validator_list: ValidatorList,
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
    /// H-002: Last completed cycle's history entry, ready for persistence.
    last_cycle_history: Option<CycleHistoryEntry>,
    /// P1.3: Manual vote target for the Manual voting strategy (set via castVote RPC).
    manual_vote: Option<Hash256>,
    /// P1.2: Whether an R2 confirmation vote has been cast this cycle.
    r2_vote_cast: bool,
    /// S15-A: Per-validator reputation scoring engine.
    reputation: ReputationEngine,
    /// First tick: triggers proposal request if starting mid-Validation phase.
    first_tick: bool,
    /// Whether this node should propose blocks (true for validators, false for
    /// vote-only peers / voting gateways).  When false the key is still used to
    /// sign votes but `RequestMempoolTransactions` is never emitted.
    proposals_enabled: bool,
    /// Whether this node should cast R1/R2 votes (true for voters and full
    /// validators, false for block-producer-only nodes).
    voting_enabled: bool,
    /// True once we've received at least one peer chain-tip status.
    /// Pre-genesis commit waits for this to avoid racing against sync.
    peer_status_known: bool,
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
        validator_list: ValidatorList,
        tip_height: u64,
        tip_hash: Hash256,
        chain_id: u32,
        validator_key: Option<(NoblePrivateKey, NoblePublicKey)>,
        genesis_timestamp: Option<u64>,
    ) -> Self {
        let cycle_mgr = CycleManager::new(config.cycle_duration_secs, genesis_timestamp);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            config,
            cycle_mgr,
            vote_mgr: VoteManager::new(),
            candidate_tracker: CandidateTracker::new(),
            validator_list,
            tip_height,
            tip_hash,
            tip_timestamp: 0,
            tip_header: None,
            tracked_cycle: u64::MAX, // sentinel: first tick initializes without boundary event
            tracked_phase: CyclePhase::Reflection,
            chain_id,
            our_validator_key: validator_key,
            total_peers: 0,
            clock_anchor: (std::time::Instant::now(), now_unix),
            last_cycle_history: None,
            manual_vote: None,
            r2_vote_cast: false,
            reputation: ReputationEngine::new(),
            first_tick: true,
            proposals_enabled: true, // default; call set_proposals_enabled(false) for vote-only
            voting_enabled: true,   // default; call set_voting_enabled(false) for propose-only
            peer_status_known: false,
        }
    }

    /// Update the connected peer count (called by node event loop).
    pub fn set_peer_count(&mut self, count: usize) {
        self.total_peers = count;
    }

    /// Mark that we've received at least one peer status (chain tip height).
    /// Pre-genesis commit waits for this so sync has a chance to deliver
    /// the real block 1 before we commit our own proposal.
    pub fn set_peer_status_known(&mut self) {
        self.peer_status_known = true;
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

    /// Get a reference to the validator list.
    pub fn validator_list(&self) -> &ValidatorList {
        &self.validator_list
    }

    /// Get a mutable reference to the validator list.
    pub fn validator_list_mut(&mut self) -> &mut ValidatorList {
        &mut self.validator_list
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
    pub fn reset_tip(&mut self, height: u64, block_hash: Hash256) {
        self.tip_height = height;
        self.tip_hash = block_hash;
        self.tip_timestamp = 0;
        self.tip_header = None;
        self.vote_mgr = VoteManager::new();
        self.candidate_tracker = CandidateTracker::new();
        self.last_cycle_history = None;
        self.manual_vote = None;
        self.r2_vote_cast = false;
        // When hopping to a new chain (height 0), clear the cycle epoch so
        // the engine re-enters pre-genesis mode.  The new chain's block 1
        // will set the epoch when committed.
        if height == 0 {
            self.cycle_mgr.set_genesis_timestamp(u64::MAX);
            self.tracked_cycle = u64::MAX;
            self.tracked_phase = CyclePhase::Reflection;
            self.first_tick = true;
        }
        tracing::warn!("consensus engine reset to height {height}");
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

    /// Get current vote tallies (candidate_hash → vote count).
    pub fn vote_tallies(&self) -> std::collections::HashMap<Hash256, usize> {
        self.vote_mgr.current_tallies()
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
        if let Ok(h) = header.compute_block_hash() {
            self.tip_hash = h;
        }
        self.tip_header = Some(header);

        // Block 1 sets (or resets) the cycle epoch regardless of the import path
        // (consensus commit, sync import, pre-genesis commit).
        if height == 1 {
            if !self.cycle_mgr.has_genesis() || self.tracked_cycle == u64::MAX {
                info!(
                    "block 1 tip update — cycle epoch set to {}",
                    timestamp
                );
                self.cycle_mgr.set_genesis_timestamp(timestamp);
                self.first_tick = true;
            }
        }
    }

    fn handle_tick(&mut self, now: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

        // No genesis block yet — can't count cycles.
        // Validator proposes on a simple timer; observers just wait.
        // Once a candidate block exists in the tracker, commit it immediately
        // (pre-genesis blocks don't go through the voting cycle).
        if !self.cycle_mgr.has_genesis() {
            if self.first_tick {
                self.first_tick = false;
                info!("cycle engine: awaiting genesis block (block 1)");
                if self.our_validator_key.is_some() && self.proposals_enabled {
                    outputs.push(CycleIo::RequestMempoolTransactions { max_count: 500 });
                }
            }

            // Pre-genesis commit: wait for peers AND at least one peer status
            // response so we know whether the network already has blocks.
            // If a peer is ahead, sync will deliver block 1 — our own proposal
            // stays in the tracker but won't be committed (sync-imported block 1
            // will set has_genesis before the next tick).
            let ready = self.total_peers > 0 && self.peer_status_known;
            let candidates = self.candidate_tracker.all_candidates();
            let best = if ready && !candidates.is_empty() {
                // Deterministic tiebreaker: lowest block hash wins.
                candidates.iter().min_by_key(|e| e.block_hash).copied()
            } else {
                None
            };
            if let Some(entry) = best {
                let block = entry.block.clone();
                let block_hash = entry.block_hash;
                let new_height = block.header.height;
                info!(
                    "pre-genesis: committing block {} at height {} (first valid proposal)",
                    block_hash, new_height
                );
                self.tip_height = new_height;
                self.tip_hash = block_hash;
                self.tip_timestamp = block.header.timestamp;
                self.tip_header = Some(block.header.clone());
                // Set cycle epoch to block 1's timestamp — all nodes converge here.
                self.cycle_mgr.set_genesis_timestamp(block.header.timestamp);
                self.first_tick = true; // next tick initializes cycle/phase
                self.candidate_tracker.clear();
                outputs.push(CycleIo::CommitBlock(block));
                outputs.push(CycleIo::Log(format!(
                    "pre-genesis: block 1 committed — cycle epoch set to {}",
                    self.tip_timestamp
                )));
            }

            outputs.push(CycleIo::SetTimer { duration_secs: 10 });
            return outputs;
        }

        let new_cycle = self.cycle_mgr.current_cycle(now);
        let new_phase = self.cycle_mgr.current_phase(now);

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
            // If starting mid-Validation and we're a validator, request mempool
            // txs so we can propose in the current cycle.
            if new_phase == CyclePhase::Validation
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
                outputs.extend(self.handle_cycle_boundary(completed));
            }

            // Detect phase transition
            if new_phase != self.tracked_phase {
                self.tracked_phase = new_phase;
                outputs.extend(self.handle_phase_transition(new_cycle, new_phase));
            }
        }

        // P1.2: Cast R2 confirmation vote at Reflection midpoint.
        if new_phase == CyclePhase::Reflection && !self.r2_vote_cast {
            let phase_duration = self.config.cycle_duration_secs / 2;
            let phase_remaining = self.cycle_mgr.seconds_until_phase_change(now);
            let elapsed_in_phase = phase_duration.saturating_sub(phase_remaining);
            // Cast R2 at or past the midpoint of the Reflection phase.
            if elapsed_in_phase >= phase_duration / 2 {
                outputs.extend(self.cast_r2_vote(new_cycle));
            }
        }

        // Schedule next timer
        let next_timer = self
            .cycle_mgr
            .seconds_until_phase_change(now)
            .min(self.cycle_mgr.seconds_until_cycle_boundary(now));
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

        match phase {
            CyclePhase::Validation => {
                // New validation phase: clear previous state
                self.vote_mgr.clear();
                self.vote_mgr.set_current_cycle(cycle);
                self.candidate_tracker.clear();
                outputs.push(CycleIo::Log(format!(
                    "cycle {cycle}: entering Validation phase"
                )));
                // P0.3: If we are a block-proposing validator, request mempool txs.
                // Vote-only peers (proposals_enabled=false) skip proposal.
                if self.our_validator_key.is_some() && self.proposals_enabled {
                    outputs.push(CycleIo::RequestMempoolTransactions { max_count: 500 });
                }
            }
            CyclePhase::Reflection => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {cycle}: entering Reflection phase"
                )));
                // If we are a voting validator, cast R1 vote for our preferred candidate.
                // Propose-only nodes (voting_enabled=false) skip voting.
                if self.voting_enabled {
                if let Some((ref priv_key, ref pub_key)) = self.our_validator_key {
                    let tallies = self.vote_mgr.current_tallies();
                    // P1.3: Pass manual_vote to strategy selector
                    let manual = self.manual_vote.take();
                    let selected = crate::strategy::select_candidate(
                        &self.config.voting_strategy,
                        &self.candidate_tracker,
                        &self.validator_list,
                        cycle,
                        manual,
                        Some(&tallies),
                    );
                    if let Some(candidate_hash) = selected {
                        match PorVote::sign(cycle, candidate_hash, priv_key, pub_key.clone()) {
                            Ok(vote) => {
                                // Record our own R1 vote locally — gossipsub does not
                                // deliver published messages back to the sender, so
                                // without this the validator's vote is lost from its
                                // own tally and compute_majority always returns
                                // Indeterminate on small networks.
                                let _ = self.vote_mgr.record_vote(b"self", &vote);
                                outputs.push(CycleIo::BroadcastVote(vote));
                                outputs.push(CycleIo::Log(format!(
                                    "cycle {cycle}: broadcast R1 vote for candidate {} (strategy: {})",
                                    candidate_hash,
                                    self.config.voting_strategy.name()
                                )));
                            }
                            Err(e) => {
                                outputs.push(CycleIo::Log(format!(
                                    "cycle {cycle}: failed to sign vote: {e}"
                                )));
                            }
                        }
                    }
                }
                } // voting_enabled
            }
        }

        outputs
    }

    fn handle_cycle_boundary(&mut self, completed_cycle: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

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
                }
            })
            .collect();

        // Network-level voter count: connected peers + self (if we are a voting validator).
        // Propose-only nodes (voting_enabled=false) don't count themselves — they
        // never cast votes, so including them would inflate the denominator.
        let self_vote = if self.our_validator_key.is_some() && self.voting_enabled {
            1
        } else {
            0
        };
        let voter_count = self.total_peers + self_vote;
        let result = self.vote_mgr.compute_majority(voter_count, &self.config);

        match result {
            MigrationResult::Adopt {
                candidate_hash,
                strength,
            } => {
                info!(
                    "vote tally complete: winner = {}, strength = {:?}",
                    candidate_hash, strength
                );
                if let Some(entry) = self.candidate_tracker.get(&candidate_hash) {
                    let block = entry.block.clone();
                    let new_height = block.header.height;
                    let new_hash = candidate_hash;

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
                    // Block 1 committed — (re)set cycle epoch to the block's timestamp.
                    // This ensures all nodes converge on the same epoch after the
                    // first real block, regardless of when they started (bootstrap
                    // mode uses `now` which differs per node).
                    if new_height == 1 {
                        info!(
                            "block 1 committed — cycle epoch set to {}",
                            block.header.timestamp
                        );
                        self.cycle_mgr.set_genesis_timestamp(block.header.timestamp);
                        self.first_tick = true; // next tick will re-initialize cycle/phase
                    }
                    outputs.push(CycleIo::CommitBlock(block));
                    outputs.push(CycleIo::EmitMetric {
                        name: "block_committed".to_string(),
                        value: new_height as f64,
                    });
                    outputs.push(CycleIo::Log(format!(
                        "cycle {completed_cycle}: committed block {} at height {} ({:?})",
                        new_hash, new_height, strength
                    )));
                } else {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {completed_cycle}: majority voted for {} but candidate not found",
                        candidate_hash
                    )));
                }
            }
            MigrationResult::Indeterminate => {
                debug!(
                    "cycle {}: vote tally indeterminate, no block committed",
                    completed_cycle
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
                    "cycle {completed_cycle}: indeterminate — no block committed"
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
                let disamb = tallies
                    .values()
                    .filter(|&&c| c == tallies.values().copied().max().unwrap_or(0))
                    .count()
                    > 1;
                (
                    format!("finalized_{:?}", strength).to_lowercase(),
                    winner_name,
                    Some(*candidate_hash),
                    disamb,
                )
            }
            MigrationResult::Indeterminate => ("indeterminate".to_string(), None, None, false),
        };

        // Only persist cycles that had real activity (proposals, votes, or a winner).
        // Empty indeterminate cycles are noise — don't waste storage on them.
        if !proposals.is_empty() || !vote_entries.is_empty() || winner.is_some() {
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
            let all_validators: Vec<Vec<u8>> = self
                .validator_list
                .list_validators()
                .iter()
                .map(|(pk, _)| pk.to_wire_bytes())
                .collect();

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

            self.reputation.process_cycle_boundary(
                completed_cycle,
                winner_wire.as_deref(),
                &loser_wires,
                &voters,
                &all_validators,
                &active,
            );
        }

        // Clear state for next cycle
        self.vote_mgr.clear();
        self.vote_mgr.set_current_cycle(self.tracked_cycle);
        self.candidate_tracker.clear();
        self.r2_vote_cast = false;

        outputs
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

        // Only accept block proposals during Validation phase (or pre-genesis).
        let pre_genesis = !self.cycle_mgr.has_genesis();
        if !pre_genesis && self.tracked_phase != CyclePhase::Validation {
            outputs.push(CycleIo::Log(format!(
                "rejected block proposal from peer during {:?} phase",
                self.tracked_phase
            )));
            return outputs;
        }

        // AUD3-D6: Construct parent header stub from tip state for B2/B3/B5 validation.
        // The validate_block B2 check verifies candidate.prev_block_hash against the
        // parent's computed hash, so we use the stored tip_hash directly. B5 uses
        // parent.timestamp for ordering checks.
        let parent_header = self.tip_header.clone();

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
        let mut val_list = self.validator_list.as_pubkey_vec();
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
            } else {
                outputs.push(CycleIo::Log(format!(
                    "rejected invalid block from peer: {e}"
                )));
                outputs.push(CycleIo::BanPeer {
                    peer_id: from_peer,
                    reason: format!("invalid block: {e}"),
                });
            }
            return outputs;
        }

        // Compute block hash
        let block_hash = match block.header.compute_block_hash() {
            Ok(h) => h,
            Err(e) => {
                outputs.push(CycleIo::Log(format!("failed to compute block hash: {e}")));
                return outputs;
            }
        };

        // Add to candidate tracker
        match self.candidate_tracker.add_candidate(block, block_hash, 0) {
            Ok(()) => {
                outputs.push(CycleIo::Log(format!(
                    "accepted candidate block {} from validator {}",
                    block_hash,
                    self.candidate_tracker
                        .get(&block_hash)
                        .map(|e| format!("{:?}", e.block.header.validator_id))
                        .unwrap_or_default()
                )));
            }
            Err(existing_hash) => {
                // Double proposal — ban the peer
                outputs.push(CycleIo::BanPeer {
                    peer_id: from_peer,
                    reason: format!(
                        "double proposal: validator already proposed {}",
                        existing_hash
                    ),
                });
                outputs.push(CycleIo::Log(format!(
                    "banned peer for double proposal (existing: {}, new: {})",
                    existing_hash, block_hash
                )));
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

        // Only accept votes during Reflection phase
        if self.tracked_phase != CyclePhase::Reflection {
            outputs.push(CycleIo::Log(format!(
                "rejected vote from peer during {:?} phase",
                self.tracked_phase
            )));
            return outputs;
        }

        // Votes are accepted from any connected peer with a valid signature.
        // The local validator_list only controls who THIS node votes for,
        // not whose votes it accepts.  The only hard requirements are:
        //   - valid cryptographic signature (GAP-C7, checked in record_vote)
        //   - correct cycle number (AUD2-M4, checked in record_vote)
        //   - not a duplicate (P0.2, checked in record_vote)
        //   - peer not banned (handled at the network layer)

        // If we receive a vote for a candidate we haven't seen yet, request
        // the block from the voting peer so we can add it to our tracker.
        // This handles late-joining peers who missed the BlockAnnounce gossip.
        if self.candidate_tracker.get(&vote.candidate_hash).is_none() {
            outputs.push(CycleIo::RequestBlock {
                peer_id: from_peer.clone(),
                block_hash: vote.candidate_hash,
            });
        }

        // Record the vote (includes signature verification via GAP-C7)
        match self.vote_mgr.record_vote(&from_peer, &vote) {
            Ok(true) => {
                outputs.push(CycleIo::Log(format!(
                    "recorded vote from peer for candidate {}",
                    vote.candidate_hash
                )));
            }
            Ok(false) => {
                outputs.push(CycleIo::Log(
                    "duplicate vote from peer (ignored)".to_string(),
                ));
            }
            Err(e) => {
                // WrongCycle is a chain-disagreement error (fork peer has a
                // different epoch), not misbehavior.  Don't ban.
                // Crypto errors (bad signature) ARE misbehavior → ban.
                let is_wrong_cycle = matches!(e, crate::vote::VoteError::WrongCycle { .. });
                if is_wrong_cycle {
                    outputs.push(CycleIo::Log(format!(
                        "ignored vote from fork peer (cycle mismatch): {e}"
                    )));
                } else {
                    outputs.push(CycleIo::BanPeer {
                        peer_id: from_peer,
                        reason: format!("invalid vote: {e}"),
                    });
                }
            }
        }

        outputs
    }

    /// P0.3: Handle mempool transactions response — build and broadcast a block proposal.
    fn handle_mempool_transactions(&mut self, txs: Vec<noble_core::Transaction>) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

        // Only propose during Validation phase (or pre-genesis), and only if
        // proposals are enabled.
        let pre_genesis = !self.cycle_mgr.has_genesis();
        if !pre_genesis && self.tracked_phase != CyclePhase::Validation {
            return outputs;
        }
        if !self.proposals_enabled {
            return outputs;
        }

        let (ref priv_key, ref pub_key) = match &self.our_validator_key {
            Some(kp) => kp,
            None => return outputs,
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match crate::proposal::propose_block(
            &txs,
            self.tip_hash,
            self.tip_height + 1,
            now,
            self.chain_id,
            priv_key,
            pub_key,
            self.config.max_block_size,
        ) {
            Ok(block) => {
                // P0-3: Validate self-proposed block before broadcast (same checks as remote proposals).
                let current_time = now;
                let val_list = self.validator_list.as_pubkey_vec();
                let ctx = BlockValidationContext {
                    chain_id: self.chain_id,
                    current_time,
                    parent: self.tip_header.as_ref(),
                    validator_list: &val_list,
                };
                if let Err(e) = validate_block(&block, &ctx) {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {}: self-proposed block failed validation: {e}",
                        self.tracked_cycle
                    )));
                    // Identify which tx(s) failed validation and evict them
                    let mut bad_tx_ids = Vec::new();
                    for tx in &block.transactions {
                        let tx_ctx = TxValidationContext {
                            chain_id: self.chain_id,
                            current_time,
                            chain_height: self.tip_height + 1,
                        };
                        if let Ok(tx_id) = tx.compute_tx_id(self.chain_id) {
                            if validate_transaction(tx, &tx_id, &tx_ctx).is_err() {
                                bad_tx_ids.push(tx_id);
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
                // Add to our own candidate tracker
                let block_box = Box::new(block);
                if let Err(e) =
                    self.candidate_tracker
                        .add_candidate(block_box.clone(), block_hash, 0)
                {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {}: failed to add self-proposed candidate: {e}",
                        self.tracked_cycle
                    )));
                    return outputs;
                }
                outputs.push(CycleIo::BroadcastBlock(block_box));
                outputs.push(CycleIo::Log(format!(
                    "cycle {}: proposed block {} ({} txs) at height {}",
                    self.tracked_cycle,
                    block_hash,
                    txs.len(),
                    self.tip_height + 1
                )));
            }
            Err(e) => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {}: failed to propose block: {e}",
                    self.tracked_cycle
                )));
            }
        }

        outputs
    }

    /// P1.2: Cast an R2 confirmation vote based on R1 tallies.
    fn cast_r2_vote(&mut self, cycle: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        self.r2_vote_cast = true;

        // Propose-only nodes (voting_enabled=false) don't cast votes.
        if !self.voting_enabled {
            return outputs;
        }

        let (ref priv_key, ref pub_key) = match &self.our_validator_key {
            Some(kp) => kp,
            None => return outputs,
        };

        // Use confirmation_strategy applied to current R1 tallies.
        let tallies = self.vote_mgr.current_tallies();
        let selected = crate::strategy::select_candidate(
            &self.config.confirmation_strategy,
            &self.candidate_tracker,
            &self.validator_list,
            cycle,
            None,
            Some(&tallies),
        );

        if let Some(candidate_hash) = selected {
            match PorVote::sign_round(cycle, candidate_hash, 2, priv_key, pub_key.clone()) {
                Ok(vote) => {
                    // Record our own R2 vote
                    let _ = self.vote_mgr.record_vote(b"self", &vote);
                    outputs.push(CycleIo::BroadcastVote(vote));
                    outputs.push(CycleIo::Log(format!(
                        "cycle {cycle}: broadcast R2 confirmation vote for {} (strategy: {})",
                        candidate_hash,
                        self.config.confirmation_strategy.name()
                    )));
                }
                Err(e) => {
                    outputs.push(CycleIo::Log(format!(
                        "cycle {cycle}: failed to sign R2 vote: {e}"
                    )));
                }
            }
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
        let phase_idx = match self.tracked_phase {
            CyclePhase::Validation => 0,
            CyclePhase::Reflection => 1,
        };
        let phase_remaining = self.cycle_mgr.seconds_until_phase_change(now);
        let cycle_remaining = self.cycle_mgr.seconds_until_cycle_boundary(now);
        (phase_idx, phase_remaining, cycle_remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::VotingStrategy;
    use noble_core::{BlockHeader, MAINNET_CHAIN_ID, PROTOCOL_VERSION};
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
        let mut val_list = ValidatorList::new();
        for v in validators {
            val_list.add_validator(v.clone(), 100, 0);
        }
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            val_list,
            0,
            Hash256::ZERO,
            MAINNET_CHAIN_ID,
            validator_key,
            Some(noble_core::GENESIS_TIMESTAMP),
        );
        engine.set_peer_count(peers);
        engine
    }

    fn make_valid_block(
        val_priv: &NoblePrivateKey,
        val_pub: &NoblePublicKey,
        height: u64,
        prev_hash: Hash256,
    ) -> (Box<Block>, Hash256) {
        let merkle_root = noble_core::compute_merkle_root(&[]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: now,
            height,
            tx_count: 0,
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
                transactions: vec![],
            }),
            hash,
        )
    }

    // --- Phase acceptance/rejection ---

    #[test]
    fn block_proposal_accepted_during_validation() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Validation;

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
    fn block_proposal_rejected_during_reflection() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Reflection;

        // Use height=1 (next block after tip=0)
        let (block, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let outputs = engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"peer1".to_vec(),
        });

        assert_eq!(
            engine.candidate_tracker.len(),
            0,
            "block should be rejected in Reflection"
        );
        assert!(has_log_containing(&outputs, "rejected"));
    }

    #[test]
    fn vote_accepted_during_reflection() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Reflection;

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
    fn vote_rejected_during_validation() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Validation;

        let candidate = Hash256::from_bytes([0x42; 32]);
        let vote = PorVote::sign(0, candidate, &vp, vpub.clone()).unwrap();
        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"peer1".to_vec(),
        });

        assert_eq!(
            engine.vote_mgr.total_votes(),
            0,
            "vote should be rejected in Validation"
        );
        assert!(has_log_containing(&outputs, "rejected"));
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
        engine.tracked_phase = CyclePhase::Validation;
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Add votes (3/5 = 60% > 50% → Strong)
        engine.tracked_phase = CyclePhase::Reflection;
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
        engine.tracked_phase = CyclePhase::Validation;
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        engine.tracked_phase = CyclePhase::Reflection;
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
        engine.tracked_phase = CyclePhase::Validation;

        let (block1, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        let (block2, _) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);

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

    // --- Invalid vote sig ban ---

    #[test]
    fn invalid_vote_sig_bans_peer() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Reflection;

        let candidate = Hash256::from_bytes([0x42; 32]);
        let mut vote = PorVote::sign(0, candidate, &vp, vpub.clone()).unwrap();
        vote.signature.signature = vec![0u8; 64]; // corrupt

        let outputs = engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"badpeer".to_vec(),
        });

        assert!(has_ban(&outputs), "invalid vote sig should ban peer");
    }

    // --- Observation mode ---

    #[test]
    fn observation_mode_no_broadcast() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5); // no validator key

        // Add a candidate
        engine.tracked_phase = CyclePhase::Validation;
        let (block, _hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Phase transition to Reflection — observer should NOT broadcast vote
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 0,
            new_phase: CyclePhase::Reflection,
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
        engine.tracked_phase = CyclePhase::Validation;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Votes from others
        engine.tracked_phase = CyclePhase::Reflection;
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

        // Tick at genesis: cycle 0, Validation
        let outputs = engine.step(CycleEvent::Tick { now: g });
        assert!(has_set_timer(&outputs));
        assert_eq!(engine.current_phase(), CyclePhase::Validation);
        assert_eq!(engine.current_cycle(), 0);

        // Tick at g+900: should transition to Reflection
        let _outputs = engine.step(CycleEvent::Tick { now: g + 900 });
        assert_eq!(engine.current_phase(), CyclePhase::Reflection);

        // Tick at g+1800: should transition to new cycle
        let _outputs = engine.step(CycleEvent::Tick { now: g + 1800 });
        assert_eq!(engine.current_cycle(), 1);
        assert_eq!(engine.current_phase(), CyclePhase::Validation);
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
        engine.tracked_phase = CyclePhase::Validation;

        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        engine.tracked_phase = CyclePhase::Reflection;
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

    // --- P0.3: Block proposal emission ---

    #[test]
    fn validator_requests_mempool_on_validation_entry() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 1,
            new_phase: CyclePhase::Validation,
        });
        assert!(
            outputs
                .iter()
                .any(|o| matches!(o, CycleIo::RequestMempoolTransactions { .. })),
            "validator should request mempool txs on Validation entry"
        );
    }

    #[test]
    fn observer_does_not_request_mempool() {
        let (_vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub], 5);
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 1,
            new_phase: CyclePhase::Validation,
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
        engine.tracked_phase = CyclePhase::Validation;

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
        engine.tracked_phase = CyclePhase::Validation;
        let (block, _hash) = make_valid_block(&vp2, &vpub2, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Transition to Reflection — should use the manual vote hash
        let outputs = engine.step(CycleEvent::PhaseTransition {
            cycle: 0,
            new_phase: CyclePhase::Reflection,
        });

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
    fn r2_vote_cast_at_reflection_midpoint() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(Some((vp, vpub.clone())), &[vpub], 5);
        let g = noble_core::GENESIS_TIMESTAMP;

        // Move to Reflection phase
        engine.tracked_phase = CyclePhase::Reflection;
        engine.tracked_cycle = 1;
        engine.r2_vote_cast = false;

        // Simulate tick at Reflection midpoint
        // cycle_duration=1800, phase_duration=900, midpoint=450s into Reflection
        // Reflection starts at 900s in cycle, midpoint at 1350s
        let now = g + 1800 + 900 + 450; // cycle 1 start + validation + midpoint
        let _outputs = engine.step(CycleEvent::Tick { now });

        // R2 should have been broadcast (even though no candidates exist,
        // the strategy returns None and no vote is emitted in that case).
        // The r2_vote_cast flag should be set.
        assert!(
            engine.r2_vote_cast,
            "r2_vote_cast should be set after midpoint tick"
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
        engine.tracked_phase = CyclePhase::Validation;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // R1 votes: 2 out of 6 validators → not Strong
        engine.tracked_phase = CyclePhase::Reflection;
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
        // Phase index should be 0 (Validation) or 1 (Reflection)
        assert!(phase_idx <= 1);
    }

    // --- AUD2-C2: Block with wrong prev_hash rejected ---

    #[test]
    fn block_with_wrong_prev_hash_rejected() {
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 5);
        engine.tracked_phase = CyclePhase::Validation;

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
        engine.tracked_phase = CyclePhase::Reflection;

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
        engine.tracked_phase = CyclePhase::Reflection;

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
        // which meets min_peers_for_consensus = 2.
        // We need separate keys for the engine (validator) and the proposer (peer).
        let (our_priv, our_pub) = make_validator();
        let (peer_priv, peer_pub) = make_validator();
        let mut engine = make_engine(
            Some((our_priv, our_pub.clone())),
            &[our_pub, peer_pub.clone()],
            1, // 1 connected peer
        );

        // Propose a block from the peer
        engine.tracked_phase = CyclePhase::Validation;
        let (block, hash) = make_valid_block(&peer_priv, &peer_pub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Vote from the peer (1 out of voter_count=2 → 50% → Strong majority)
        engine.tracked_phase = CyclePhase::Reflection;
        let vote = PorVote::sign(0, hash, &peer_priv, peer_pub).unwrap();
        engine.step(CycleEvent::VoteReceived {
            vote,
            from_peer: b"p1".to_vec(),
        });

        let outputs = engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
        assert!(
            has_commit(&outputs),
            "validator + 1 peer should reach consensus (voter_count=2)"
        );
        assert_eq!(engine.tip_height, 1);
    }

    #[test]
    fn network_voter_count_observer_not_counted() {
        // Observer (no validator key) with 1 peer: voter_count = 1 + 0 = 1,
        // which is below min_peers_for_consensus = 2 → Indeterminate.
        let (vp, vpub) = make_validator();
        let mut engine = make_engine(None, &[vpub.clone()], 1);

        engine.tracked_phase = CyclePhase::Validation;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        engine.tracked_phase = CyclePhase::Reflection;
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
        engine.tracked_phase = CyclePhase::Validation;

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
        engine.tracked_phase = CyclePhase::Validation;

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
}
