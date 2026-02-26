// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Consensus-related RPC methods: getValidatorList, getReputationScore,
//! getCycleStatus, addValidator, removeValidator.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_consensus::{ConsensusStateMachine, VotingStrategy};
use noble_crypto::NoblePublicKey;
use noble_storage::StorageEngine;

/// Convert a `VotingStrategy` to a (name, params) pair for RPC responses.
fn strategy_to_response(strategy: &VotingStrategy) -> (String, serde_json::Value) {
    let name = strategy.name().to_string();
    let params = match strategy {
        VotingStrategy::FixedValidator { validator_key } => {
            serde_json::json!({ "validator_key": validator_key })
        }
        VotingStrategy::SubsetRotation { validators } => {
            serde_json::json!({ "validators": validators })
        }
        _ => serde_json::Value::Null,
    };
    (name, params)
}

/// Parse a strategy name + optional params into a `VotingStrategy`.
fn parse_strategy(
    name: &str,
    params: Option<&serde_json::Value>,
) -> Result<VotingStrategy, ApiError> {
    match name {
        "first_valid" => Ok(VotingStrategy::FirstValid),
        "round_robin" => Ok(VotingStrategy::RoundRobin),
        "random" => Ok(VotingStrategy::Random),
        "weighted_reputation" => Ok(VotingStrategy::WeightedReputation),
        "follow_majority" => Ok(VotingStrategy::FollowMajority),
        "manual" => Ok(VotingStrategy::Manual),
        "fixed_validator" => {
            let key = params
                .and_then(|p| p.get("validator_key"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ApiError::InvalidParam("fixed_validator requires params.validator_key".into())
                })?;
            Ok(VotingStrategy::FixedValidator {
                validator_key: key.to_string(),
            })
        }
        "subset_rotation" => {
            let vals = params
                .and_then(|p| p.get("validators"))
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    ApiError::InvalidParam(
                        "subset_rotation requires params.validators array".into(),
                    )
                })?;
            let validators: Vec<String> = vals
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if validators.is_empty() {
                return Err(ApiError::InvalidParam(
                    "subset_rotation requires at least one validator".into(),
                ));
            }
            Ok(VotingStrategy::SubsetRotation { validators })
        }
        other => Err(ApiError::InvalidParam(format!(
            "unknown strategy: {other}. Valid: first_valid, fixed_validator, round_robin, \
             subset_rotation, random, weighted_reputation, follow_majority, manual"
        ))),
    }
}

use noble_codec::NobleCbor;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

/// Helper to persist the validator list to disk (C-003).
fn persist_validator_list<S: StorageEngine + Send + Sync + 'static>(
    state: &ApiState<S>,
    consensus: &parking_lot::RwLockWriteGuard<'_, noble_consensus::CycleEngine>,
) -> Result<(), ErrorObjectOwned> {
    if let Some(ref path) = state.validator_list_path {
        let bytes = consensus
            .validator_list()
            .to_cbor()
            .map_err(|e| ApiError::Internal(format!("serialize validator list: {e}")))?;
        std::fs::write(path, &bytes)
            .map_err(|e| ApiError::Internal(format!("persist validator list: {e}")))?;
    }
    Ok(())
}

#[rpc(server, namespace = "noble")]
pub trait ConsensusApi {
    /// List all validators and their weights.
    #[method(name = "getValidatorList")]
    async fn get_validator_list(&self) -> Result<ValidatorListResponse, ErrorObjectOwned>;

    /// Get the reputation score for a validator (placeholder).
    #[method(name = "getReputationScore")]
    async fn get_reputation_score(
        &self,
        pubkey: String,
    ) -> Result<ReputationScoreResponse, ErrorObjectOwned>;

    /// Get the current consensus cycle and phase.
    #[method(name = "getCycleStatus")]
    async fn get_cycle_status(&self) -> Result<CycleStatusResponse, ErrorObjectOwned>;

    /// Add a validator to the trusted set.
    #[method(name = "addValidator")]
    async fn add_validator(
        &self,
        public_key: String,
        name: Option<String>,
        weight: Option<u64>,
    ) -> Result<bool, ErrorObjectOwned>;

    /// Remove a validator from the trusted set.
    #[method(name = "removeValidator")]
    async fn remove_validator(&self, public_key: String) -> Result<bool, ErrorObjectOwned>;

    /// Get the current voting strategy for both rounds.
    #[method(name = "getVotingStrategy")]
    async fn get_voting_strategy(&self) -> Result<VotingStrategyResponse, ErrorObjectOwned>;

    /// Set the voting strategy for a specific round (1 or 2).
    #[method(name = "setVotingStrategy")]
    async fn set_voting_strategy(
        &self,
        round: u8,
        strategy: String,
        params: Option<serde_json::Value>,
    ) -> Result<VotingStrategyResponse, ErrorObjectOwned>;

    /// Get current cycle vote tallies.
    #[method(name = "getVoteTallies")]
    async fn get_vote_tallies(&self) -> Result<VoteTalliesResponse, ErrorObjectOwned>;

    /// Cast a manual vote for Round 1 (Manual strategy only).
    #[method(name = "castVote")]
    async fn cast_vote(&self, block_hash: String) -> Result<bool, ErrorObjectOwned>;

    /// Get recent cycle history entries (H-002).
    #[method(name = "getCycleHistory")]
    async fn get_cycle_history(
        &self,
        count: Option<usize>,
    ) -> Result<CycleHistoryResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> ConsensusApiServer for Arc<ApiState<S>> {
    async fn get_validator_list(&self) -> Result<ValidatorListResponse, ErrorObjectOwned> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Cross-reference validators with peer memory for last_seen
        let storage = self.storage.read();
        let peer_records = storage.list_peer_records().unwrap_or_default();
        drop(storage);

        let mut consensus = self.consensus.write();
        // Update last_seen from peer records
        for rec in &peer_records {
            if let Ok(pk) = NoblePublicKey::from_wire_bytes(&rec.identity_key) {
                if consensus.validator_list().is_validator(&pk) {
                    consensus
                        .validator_list_mut()
                        .update_last_seen(&pk, rec.last_seen);
                }
            }
        }

        let validators = consensus
            .validator_list()
            .list_validators_with_liveness(now);
        let count = validators.len();

        let reputation = consensus.reputation();
        let entries: Vec<ValidatorEntry> = validators
            .into_iter()
            .map(|(pk, weight, liveness, added_at, friendly_name)| {
                let wire = pk.to_wire_bytes();
                let rep_data = reputation.get(&wire);
                let score = rep_data.map(|d| d.score()).unwrap_or(0.0);

                let (
                    blocks_accepted,
                    blocks_rejected,
                    votes_cast,
                    votes_missed,
                    uptime_cycles,
                    total_cycles,
                ) = rep_data
                    .map(|d| {
                        (
                            d.blocks_accepted,
                            d.blocks_rejected,
                            d.votes_cast,
                            d.votes_missed,
                            d.uptime_cycles,
                            d.total_cycles,
                        )
                    })
                    .unwrap_or_default();

                let blocks_produced = blocks_accepted + blocks_rejected;

                let block_acceptance_rate = if blocks_produced > 0 {
                    blocks_accepted as f64 / blocks_produced as f64
                } else {
                    0.5
                };
                let uptime_ratio = if total_cycles > 0 {
                    uptime_cycles as f64 / total_cycles as f64
                } else {
                    0.0
                };

                ValidatorEntry {
                    public_key: hex::encode(&wire),
                    name: friendly_name,
                    status: liveness.as_str().to_string(),
                    weight,
                    reputation_score: score,
                    reputation_breakdown: ReputationBreakdown {
                        block_acceptance_rate,
                        uptime: uptime_ratio,
                        trust_score: 0.0, // Trust score requires peer-listing data (future)
                    },
                    blocks_produced,
                    blocks_accepted,
                    cycles_active: votes_cast + votes_missed, // cycles where validator was in set
                    cycles_reachable: uptime_cycles,
                    total_cycles,
                    last_active: None, // populated from peer records when available
                    joined_cycle: added_at,
                }
            })
            .collect();

        Ok(ValidatorListResponse {
            selection_policy: "weighted_random".to_string(),
            validators: entries,
            count,
        })
    }

    async fn get_reputation_score(
        &self,
        pubkey: String,
    ) -> Result<ReputationScoreResponse, ErrorObjectOwned> {
        let wire_bytes =
            hex::decode(&pubkey).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let pk = NoblePublicKey::from_wire_bytes(&wire_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;

        let consensus = self.consensus.read();
        if !consensus.validator_list().is_validator(&pk) {
            return Err(ApiError::ValidatorNotFound(pubkey).into());
        }

        let rep_data = consensus.reputation().get(&wire_bytes);
        let score = rep_data.map(|d| d.score()).unwrap_or(0.0);
        let (
            blocks_accepted,
            blocks_rejected,
            votes_cast,
            votes_missed,
            uptime_cycles,
            total_cycles,
        ) = rep_data
            .map(|d| {
                (
                    d.blocks_accepted,
                    d.blocks_rejected,
                    d.votes_cast,
                    d.votes_missed,
                    d.uptime_cycles,
                    d.total_cycles,
                )
            })
            .unwrap_or_default();

        let blocks_produced = blocks_accepted + blocks_rejected;
        let block_acceptance_rate = if blocks_produced > 0 {
            blocks_accepted as f64 / blocks_produced as f64
        } else {
            0.5
        };
        let uptime_ratio = if total_cycles > 0 {
            uptime_cycles as f64 / total_cycles as f64
        } else {
            0.0
        };

        Ok(ReputationScoreResponse {
            pubkey,
            score,
            breakdown: ReputationBreakdown {
                block_acceptance_rate,
                uptime: uptime_ratio,
                trust_score: 0.0,
            },
            blocks_accepted,
            blocks_rejected,
            votes_cast,
            votes_missed,
            uptime_cycles,
            total_cycles,
        })
    }

    async fn get_cycle_status(&self) -> Result<CycleStatusResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let cycle = consensus.current_cycle();
        let (_engine_phase_idx, engine_phase_remaining, cycle_remaining) = consensus.phase_timing();
        let engine_phase = consensus.current_phase();

        // H-005: Project 2 engine phases → 4 API phases.
        // Engine phase duration = cycle_duration / 2 = 900s.
        // Sub-phase = engine_phase_duration / 2 = 450s.
        // Validation → [Proposal, Voting], Reflection → [Confirmation, Finalization].
        // engine_phase_remaining counts down from 900 to 0 within each engine phase.
        let half_phase = noble_core::CYCLE_DURATION_SECS / 4;
        let engine_phase_duration = noble_core::CYCLE_DURATION_SECS / 2;
        let elapsed_in_phase = engine_phase_duration.saturating_sub(engine_phase_remaining);

        let (projected_phase, projected_index, phase_remaining) = match engine_phase {
            noble_consensus::CyclePhase::Validation => {
                if elapsed_in_phase < half_phase {
                    ("Proposal", 0u8, half_phase - elapsed_in_phase)
                } else {
                    ("Voting", 1, engine_phase_duration - elapsed_in_phase)
                }
            }
            noble_consensus::CyclePhase::Reflection => {
                if elapsed_in_phase < half_phase {
                    ("Confirmation", 2, half_phase - elapsed_in_phase)
                } else {
                    ("Finalization", 3, engine_phase_duration - elapsed_in_phase)
                }
            }
        };

        Ok(CycleStatusResponse {
            cycle_number: cycle,
            phase: projected_phase.to_string(),
            phase_index: projected_index,
            phase_remaining_secs: phase_remaining,
            cycle_remaining_secs: cycle_remaining,
        })
    }

    async fn add_validator(
        &self,
        public_key: String,
        name: Option<String>,
        weight: Option<u64>,
    ) -> Result<bool, ErrorObjectOwned> {
        let wire_bytes =
            hex::decode(&public_key).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let pk = NoblePublicKey::from_wire_bytes(&wire_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;

        let effective_weight = weight.unwrap_or(100);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut consensus = self.consensus.write();
        consensus
            .validator_list_mut()
            .add_validator(pk.clone(), effective_weight, now);
        if let Some(n) = name {
            consensus.validator_list_mut().set_friendly_name(&pk, n);
        }

        // C-003: Persist validator list to disk.
        persist_validator_list(self, &consensus)?;

        Ok(true)
    }

    async fn remove_validator(&self, public_key: String) -> Result<bool, ErrorObjectOwned> {
        let wire_bytes =
            hex::decode(&public_key).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let pk = NoblePublicKey::from_wire_bytes(&wire_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;

        let mut consensus = self.consensus.write();
        let removed = consensus.validator_list_mut().remove_validator(&pk);
        if !removed {
            return Err(ApiError::ValidatorNotFound(public_key).into());
        }

        // C-003: Persist validator list to disk.
        persist_validator_list(self, &consensus)?;

        Ok(true)
    }

    async fn get_voting_strategy(&self) -> Result<VotingStrategyResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let (r1_name, r1_params) = strategy_to_response(consensus.voting_strategy());
        let (r2_name, r2_params) = strategy_to_response(consensus.confirmation_strategy());
        Ok(VotingStrategyResponse {
            round1_strategy: r1_name,
            round1_params: r1_params,
            round2_strategy: r2_name,
            round2_params: r2_params,
        })
    }

    async fn set_voting_strategy(
        &self,
        round: u8,
        strategy: String,
        params: Option<serde_json::Value>,
    ) -> Result<VotingStrategyResponse, ErrorObjectOwned> {
        if round != 1 && round != 2 {
            return Err(ApiError::InvalidParam("round must be 1 or 2".into()).into());
        }
        let parsed = parse_strategy(&strategy, params.as_ref()).map_err(ErrorObjectOwned::from)?;

        let mut consensus = self.consensus.write();
        if round == 1 {
            consensus.set_voting_strategy(parsed);
        } else {
            consensus.set_confirmation_strategy(parsed);
        }

        let (r1_name, r1_params) = strategy_to_response(consensus.voting_strategy());
        let (r2_name, r2_params) = strategy_to_response(consensus.confirmation_strategy());
        Ok(VotingStrategyResponse {
            round1_strategy: r1_name,
            round1_params: r1_params,
            round2_strategy: r2_name,
            round2_params: r2_params,
        })
    }

    async fn get_vote_tallies(&self) -> Result<VoteTalliesResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let cycle = consensus.current_cycle();
        let phase = consensus.current_phase();
        let tallies = consensus.vote_tallies();

        let mut entries: Vec<VoteTallyEntry> = tallies
            .into_iter()
            .map(|(h, c)| VoteTallyEntry {
                block_hash: hash_to_hex(&h),
                vote_count: c,
            })
            .collect();
        entries.sort_by(|a, b| b.vote_count.cmp(&a.vote_count));

        Ok(VoteTalliesResponse {
            cycle,
            phase: format!("{:?}", phase),
            tallies: entries,
        })
    }

    async fn cast_vote(&self, block_hash: String) -> Result<bool, ErrorObjectOwned> {
        let hash = parse_hash(&block_hash)?;

        let mut consensus = self.consensus.write();
        let strategy = consensus.voting_strategy().clone();
        if !matches!(strategy, VotingStrategy::Manual) {
            return Err(ApiError::InvalidParam(
                "castVote is only available when voting_strategy is 'manual'".into(),
            )
            .into());
        }
        // P1.3: Inject the manual vote target into the consensus engine.
        consensus.set_manual_vote(hash);
        Ok(true)
    }

    async fn get_cycle_history(
        &self,
        count: Option<usize>,
    ) -> Result<CycleHistoryResponse, ErrorObjectOwned> {
        let limit = count.unwrap_or(10).min(100);
        let storage = self.storage.read();
        let raw_entries = storage
            .get_recent_cycle_history(limit)
            .map_err(|e| ApiError::Internal(format!("read cycle history: {e}")))?;

        let entries: Vec<CycleHistoryEntryResponse> = raw_entries
            .into_iter()
            .filter_map(|bytes| noble_consensus::CycleHistoryEntry::from_cbor(&bytes).ok())
            .map(|entry| CycleHistoryEntryResponse {
                cycle_number: entry.cycle_number,
                status: entry.status,
                proposals: entry
                    .proposals
                    .into_iter()
                    .map(|p| CycleHistoryProposal {
                        validator: p.validator,
                        block_hash: hash_to_hex(&p.block_hash),
                        tx_count: p.tx_count,
                    })
                    .collect(),
                votes: entry
                    .votes
                    .into_iter()
                    .map(|v| CycleHistoryVote {
                        block_hash: hash_to_hex(&v.block_hash),
                        validator: v.validator,
                        vote_count: v.vote_count,
                    })
                    .collect(),
                winner: entry.winner,
                winning_hash: entry.winning_hash.map(|h| hash_to_hex(&h)),
                disambiguation: entry.disambiguation,
                finalized_at: entry.finalized_at,
            })
            .collect();

        let count = entries.len();
        Ok(CycleHistoryResponse { entries, count })
    }
}
