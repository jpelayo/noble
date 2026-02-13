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
        let consensus = self.consensus.read().unwrap();
        let validators = consensus.validator_list().list_validators();
        let count = validators.len();

        let entries: Vec<ValidatorEntry> = validators
            .into_iter()
            .map(|(pk, weight)| ValidatorEntry {
                pubkey: hex::encode(pk.to_wire_bytes()),
                weight,
            })
            .collect();

        Ok(ValidatorListResponse {
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

        Ok(CycleStatusResponse {
            current_cycle: cycle,
            current_phase: format!("{:?}", phase),
        })
    }

    async fn add_validator(&self, pubkey: String, weight: u64) -> Result<bool, ErrorObjectOwned> {
        let wire_bytes =
            hex::decode(&pubkey).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let pk = NoblePublicKey::from_wire_bytes(&wire_bytes)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()))?;

        let mut consensus = self.consensus.write().unwrap();
        consensus.validator_list_mut().add_validator(pk, weight);
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
