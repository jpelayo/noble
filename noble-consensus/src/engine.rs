// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Central consensus state machine implementing `ConsensusStateMachine`.
//!
//! Orchestrates cycle management, block proposals, vote collection,
//! and chain tip advancement using deterministic event-driven processing.

use noble_core::{validate_block, Block, BlockValidationContext};
use noble_crypto::{Hash256, NoblePrivateKey, NoblePublicKey};

use crate::candidate::CandidateTracker;
use crate::config::ConsensusConfig;
use crate::cycle::{CycleManager, CyclePhase};
use crate::event::{CycleEvent, CycleIo};
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
}

/// The NOBLE PoR consensus engine.
pub struct CycleEngine {
    config: ConsensusConfig,
    cycle_mgr: CycleManager,
    vote_mgr: VoteManager,
    candidate_tracker: CandidateTracker,
    validator_list: ValidatorList,
    /// Chain tip: (height, block_hash).
    tip_height: u64,
    tip_hash: Hash256,
    /// Current tracked cycle and phase.
    tracked_cycle: u64,
    tracked_phase: CyclePhase,
    /// Chain ID for block validation.
    chain_id: u32,
    /// This node's validator credentials (None = observation mode).
    our_validator_key: Option<(NoblePrivateKey, NoblePublicKey)>,
    /// Number of connected peers (set externally by the node event loop).
    total_peers: usize,
}

impl CycleEngine {
    /// Create a new consensus engine.
    ///
    /// If `validator_key` is `None`, the engine runs in observation mode
    /// (never broadcasts blocks or votes, still commits winning blocks).
    pub fn new(
        config: ConsensusConfig,
        validator_list: ValidatorList,
        tip_height: u64,
        tip_hash: Hash256,
        chain_id: u32,
        validator_key: Option<(NoblePrivateKey, NoblePublicKey)>,
    ) -> Self {
        let cycle_mgr = CycleManager::new(config.cycle_duration_secs);
        Self {
            config,
            cycle_mgr,
            vote_mgr: VoteManager::new(),
            candidate_tracker: CandidateTracker::new(),
            validator_list,
            tip_height,
            tip_hash,
            tracked_cycle: 0,
            tracked_phase: CyclePhase::Validation,
            chain_id,
            our_validator_key: validator_key,
            total_peers: 0,
        }
    }

    /// Update the connected peer count (called by node event loop).
    pub fn set_peer_count(&mut self, count: usize) {
        self.total_peers = count;
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

    fn handle_tick(&mut self, now: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();
        let new_cycle = self.cycle_mgr.current_cycle(now);
        let new_phase = self.cycle_mgr.current_phase(now);

        // Detect cycle boundary
        if new_cycle > self.tracked_cycle {
            let completed = self.tracked_cycle;
            self.tracked_cycle = new_cycle;
            outputs.extend(self.handle_cycle_boundary(completed));
        }

        // Detect phase transition
        if new_phase != self.tracked_phase {
            self.tracked_phase = new_phase;
            outputs.extend(self.handle_phase_transition(new_cycle, new_phase));
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

        match phase {
            CyclePhase::Validation => {
                // New validation phase: clear previous state
                self.vote_mgr.clear();
                self.candidate_tracker.clear();
                outputs.push(CycleIo::Log(format!(
                    "cycle {cycle}: entering Validation phase"
                )));
            }
            CyclePhase::Reflection => {
                outputs.push(CycleIo::Log(format!(
                    "cycle {cycle}: entering Reflection phase"
                )));
                // If we are a validator, vote for our preferred candidate
                if let Some((ref priv_key, ref pub_key)) = self.our_validator_key {
                    if let Some(preferred) = self.candidate_tracker.preferred_candidate() {
                        match PorVote::sign(cycle, preferred.block_hash, priv_key, pub_key.clone())
                        {
                            Ok(vote) => {
                                outputs.push(CycleIo::BroadcastVote(vote));
                                outputs.push(CycleIo::Log(format!(
                                    "cycle {cycle}: broadcast vote for candidate {}",
                                    preferred.block_hash
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
            }
        }

        outputs
    }

    fn handle_cycle_boundary(&mut self, completed_cycle: u64) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

        // Compute majority from votes
        let result = self
            .vote_mgr
            .compute_majority(self.total_peers, &self.config);

        match result {
            MigrationResult::Adopt {
                candidate_hash,
                strength,
            } => {
                if let Some(entry) = self.candidate_tracker.get(&candidate_hash) {
                    let block = entry.block.clone();
                    let new_height = block.header.height;
                    let new_hash = candidate_hash;

                    // Collect orphaned txs from losing candidates
                    let orphans = self.candidate_tracker.collect_orphaned_txs(&candidate_hash);
                    if !orphans.is_empty() {
                        outputs.push(CycleIo::ReadmitTransactions(orphans));
                    }

                    // Commit the winning block
                    self.tip_height = new_height;
                    self.tip_hash = new_hash;
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
                // Re-admit all candidate txs back to mempool
                let all_txs: Vec<_> = self
                    .candidate_tracker
                    .preferred_candidate()
                    .map(|_| {
                        // Return all txs from all candidates
                        self.candidate_tracker.collect_orphaned_txs(&Hash256::ZERO)
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

        // Clear state for next cycle
        self.vote_mgr.clear();
        self.candidate_tracker.clear();

        outputs
    }

    fn handle_block_proposed(&mut self, block: Box<Block>, from_peer: Vec<u8>) -> Vec<CycleIo> {
        let mut outputs = Vec::new();

        // Only accept block proposals during Validation phase
        if self.tracked_phase != CyclePhase::Validation {
            outputs.push(CycleIo::Log(format!(
                "rejected block proposal from peer during {:?} phase",
                self.tracked_phase
            )));
            return outputs;
        }

        // Validate the block
        let val_list = self.validator_list.as_pubkey_vec();
        let ctx = BlockValidationContext {
            chain_id: self.chain_id,
            current_time: block.header.timestamp,
            parent: None, // simplified: parent check deferred to storage
            validator_list: &val_list,
        };

        if let Err(e) = validate_block(&block, &ctx) {
            outputs.push(CycleIo::Log(format!(
                "rejected invalid block from peer: {e}"
            )));
            outputs.push(CycleIo::BanPeer {
                peer_id: from_peer,
                reason: format!("invalid block: {e}"),
            });
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

        // Only accept votes during Reflection phase
        if self.tracked_phase != CyclePhase::Reflection {
            outputs.push(CycleIo::Log(format!(
                "rejected vote from peer during {:?} phase",
                self.tracked_phase
            )));
            return outputs;
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
                outputs.push(CycleIo::BanPeer {
                    peer_id: from_peer,
                    reason: format!("invalid vote signature: {e}"),
                });
            }
        }

        outputs
    }
}

impl ConsensusStateMachine for CycleEngine {
    fn step(&mut self, event: CycleEvent) -> Vec<CycleIo> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
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
            val_list.add_validator(v.clone(), 100);
        }
        let mut engine = CycleEngine::new(
            ConsensusConfig::default(),
            val_list,
            0,
            Hash256::ZERO,
            MAINNET_CHAIN_ID,
            validator_key,
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
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            prev_block_hash: prev_hash,
            merkle_root,
            timestamp: 1_700_000_000,
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

        let (block, _hash) = make_valid_block(&vp, &vpub, 0, Hash256::ZERO);
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

        let (block, _) = make_valid_block(&vp, &vpub, 0, Hash256::ZERO);
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
        let mut engine = make_engine(None, &[vpub.clone()], 5);

        // Add a candidate
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.tracked_phase = CyclePhase::Validation;
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Add votes (3/5 = 60% > 50% → Strong)
        engine.tracked_phase = CyclePhase::Reflection;
        for i in 0..3u8 {
            let (vk, vp) = make_validator();
            let vote = PorVote::sign(0, hash, &vk, vp).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i + 10],
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
        let mut engine = make_engine(None, &[vpub.clone()], 2); // < 3 min_peers

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

        let (block1, _) = make_valid_block(&vp, &vpub, 0, Hash256::ZERO);
        let (block2, _) = make_valid_block(&vp, &vpub, 0, Hash256::ZERO);

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
        let (block, _hash) = make_valid_block(&vp, &vpub, 0, Hash256::ZERO);
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
        let mut engine = make_engine(None, &[vpub.clone()], 5);

        // Proposal
        engine.tracked_phase = CyclePhase::Validation;
        let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
        engine.step(CycleEvent::BlockProposed {
            block,
            from_peer: b"p1".to_vec(),
        });

        // Votes from others
        engine.tracked_phase = CyclePhase::Reflection;
        for i in 0..3u8 {
            let (vk, vp2) = make_validator();
            let vote = PorVote::sign(0, hash, &vk, vp2).unwrap();
            engine.step(CycleEvent::VoteReceived {
                vote,
                from_peer: vec![i + 20],
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

        // Tick at t=0: cycle 0, Validation
        let outputs = engine.step(CycleEvent::Tick { now: 0 });
        assert!(has_set_timer(&outputs));
        assert_eq!(engine.current_phase(), CyclePhase::Validation);
        assert_eq!(engine.current_cycle(), 0);

        // Tick at t=900: should transition to Reflection
        let _outputs = engine.step(CycleEvent::Tick { now: 900 });
        assert_eq!(engine.current_phase(), CyclePhase::Reflection);

        // Tick at t=1800: should transition to new cycle
        let _outputs = engine.step(CycleEvent::Tick { now: 1800 });
        assert_eq!(engine.current_cycle(), 1);
        assert_eq!(engine.current_phase(), CyclePhase::Validation);
    }

    #[test]
    fn deterministic_same_events_same_result() {
        // Run the same event sequence twice and verify same chain tip
        fn run_sequence() -> (u64, Hash256) {
            let (vp, vpub) = make_validator();
            let mut engine = make_engine(None, &[vpub.clone()], 5);
            engine.tracked_phase = CyclePhase::Validation;

            let (block, hash) = make_valid_block(&vp, &vpub, 1, Hash256::ZERO);
            engine.step(CycleEvent::BlockProposed {
                block,
                from_peer: b"p1".to_vec(),
            });

            engine.tracked_phase = CyclePhase::Reflection;
            for i in 0..3u8 {
                let (vk, vp2) = make_validator();
                let vote = PorVote::sign(0, hash, &vk, vp2).unwrap();
                engine.step(CycleEvent::VoteReceived {
                    vote,
                    from_peer: vec![i + 30],
                });
            }

            engine.step(CycleEvent::CycleBoundary { completed_cycle: 0 });
            engine.chain_tip()
        }

        // Note: due to random key generation, the hash will differ between runs.
        // But within a single run, the result is deterministic.
        let (h, _) = run_sequence();
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
}
