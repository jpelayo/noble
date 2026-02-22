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

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

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
    async fn add_validator(&self, pubkey: String, weight: u64) -> Result<bool, ErrorObjectOwned>;

    /// Remove a validator from the trusted set.
    #[method(name = "removeValidator")]
    async fn remove_validator(&self, pubkey: String) -> Result<bool, ErrorObjectOwned>;

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
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> ConsensusApiServer for Arc<ApiState<S>> {
    async fn get_validator_list(&self) -> Result<ValidatorListResponse, ErrorObjectOwned> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Cross-reference validators with peer memory for last_seen
        let storage = self.storage.read().unwrap();
        let peer_records = storage.list_peer_records().unwrap_or_default();
        drop(storage);

        let mut consensus = self.consensus.write().unwrap();
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

        let entries: Vec<ValidatorEntry> = validators
            .into_iter()
            .map(
                |(pk, weight, liveness, added_at, friendly_name)| ValidatorEntry {
                    public_key: hex::encode(pk.to_wire_bytes()),
                    name: friendly_name,
                    status: liveness.as_str().to_string(),
                    weight,
                    reputation_score: -1.0, // -1 = not yet implemented
                    blocks_produced: 0,     // not yet tracked
                    cycles_active: 0,       // not yet tracked
                    last_active: None,      // populated from peer records when available
                    joined_cycle: added_at,
                },
            )
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

        let consensus = self.consensus.read().unwrap();
        if !consensus.validator_list().is_validator(&pk) {
            return Err(ApiError::ValidatorNotFound(pubkey).into());
        }

        // Reputation scoring is not yet implemented — return 0 as sentinel.
        Ok(ReputationScoreResponse { pubkey, score: 0 })
    }

    async fn get_cycle_status(&self) -> Result<CycleStatusResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read().unwrap();
        let cycle = consensus.current_cycle();
        let phase = consensus.current_phase();
        let (phase_idx, phase_remaining, cycle_remaining) = consensus.phase_timing();

        Ok(CycleStatusResponse {
            cycle_number: cycle,
            phase: format!("{:?}", phase),
            phase_index: phase_idx,
            phase_remaining_secs: phase_remaining,
            cycle_remaining_secs: cycle_remaining,
        })
    }

    async fn add_validator(&self, pubkey: String, weight: u64) -> Result<bool, ErrorObjectOwned> {
        let wire_bytes =
            hex::decode(&pubkey).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let pk = NoblePublicKey::from_wire_bytes(&wire_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut consensus = self.consensus.write().unwrap();
        consensus
            .validator_list_mut()
            .add_validator(pk, weight, now);
        Ok(true)
    }

    async fn remove_validator(&self, pubkey: String) -> Result<bool, ErrorObjectOwned> {
        let wire_bytes =
            hex::decode(&pubkey).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let pk = NoblePublicKey::from_wire_bytes(&wire_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;

        let mut consensus = self.consensus.write().unwrap();
        let removed = consensus.validator_list_mut().remove_validator(&pk);
        if !removed {
            return Err(ApiError::ValidatorNotFound(pubkey).into());
        }
        Ok(true)
    }

    async fn get_voting_strategy(&self) -> Result<VotingStrategyResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read().unwrap();
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

        let mut consensus = self.consensus.write().unwrap();
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
        let consensus = self.consensus.read().unwrap();
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
        let _hash = parse_hash(&block_hash)?;

        let consensus = self.consensus.read().unwrap();
        let strategy = consensus.voting_strategy();
        if !matches!(strategy, VotingStrategy::Manual) {
            return Err(ApiError::InvalidParam(
                "castVote is only available when voting_strategy is 'manual'".into(),
            )
            .into());
        }
        // Manual vote is stored in-engine — for now, acknowledge the request.
        // Full implementation requires engine to accept manual vote injection,
        // which will be wired when the engine processes ManualVote events.
        Ok(true)
    }
}
