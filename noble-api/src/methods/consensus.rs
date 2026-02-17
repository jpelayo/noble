// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Consensus-related RPC methods: getValidatorList, getReputationScore,
//! getCycleStatus, addValidator, removeValidator.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_consensus::ConsensusStateMachine;
use noble_crypto::NoblePublicKey;
use noble_storage::StorageEngine;

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
                    reputation_score: 0.0, // placeholder until reputation system is complete
                    blocks_produced: 0,    // placeholder
                    cycles_active: 0,      // placeholder
                    last_active: None,     // populated from peer records when available
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

        // Reputation scoring is a placeholder — return a fixed score.
        Ok(ReputationScoreResponse { pubkey, score: 100 })
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
}
