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

/// Parse a public key that may be either hex wire bytes or a `nbl1…` bech32 address.
fn parse_pubkey_input(input: &str) -> Result<NoblePublicKey, ErrorObjectOwned> {
    let trimmed = input.trim();
    // Try nbl1… bech32 address first
    if noble_crypto::noble_addr::is_noble_address(trimmed) {
        return noble_crypto::noble_addr::decode(trimmed)
            .map_err(|e| ApiError::InvalidAddress(e.to_string()).into());
    }
    // Fall back to hex wire bytes
    let wire_bytes =
        hex::decode(trimmed).map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
    NoblePublicKey::from_wire_bytes(&wire_bytes)
        .map_err(|e| ApiError::InvalidAddress(e.to_string()).into())
}

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
        "weighted_probability" => Ok(VotingStrategy::WeightedProbability),
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
             subset_rotation, random, weighted_reputation, weighted_probability, follow_majority, manual"
        ))),
    }
}

use noble_codec::NobleCbor;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

/// Helper to persist the validator registry to disk (C-003).
fn persist_validator_registry<S: StorageEngine + Send + Sync + 'static>(
    registry: &mut noble_consensus::ValidatorRegistry,
) -> Result<(), ErrorObjectOwned> {
    registry
        .persist_if_dirty()
        .map_err(|e| -> ErrorObjectOwned { ApiError::Internal(e).into() })?;
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

    /// Get per-block vote witness data proving which validators approved a block.
    #[method(name = "getBlockVotes")]
    async fn get_block_votes(
        &self,
        height: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Set the validator priority order (drag handles in GUI).
    #[method(name = "setValidatorOrder")]
    async fn set_validator_order(
        &self,
        order: Vec<String>,
    ) -> Result<bool, ErrorObjectOwned>;
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
        let mut peer_records = storage.list_peer_records().unwrap_or_default();

        // Build set of identity_keys for currently-connected peers.
        // Links PeerId (live connection) → identity_key (validator key) directly,
        // bypassing PeerRecord entirely.  Solves: no PeerRecord yet, stale PeerRecord,
        // and gossip-forwarder PeerId mismatch.
        let connected_identity_keys: std::collections::HashSet<Vec<u8>> = {
            let info = self.peer_info.read();
            info.values()
                .filter_map(|entry| entry.identity_key.clone())
                .collect()
        };

        // Backfill: if peer_records is empty but we have live connected peers with
        // identity_keys, synthesize PeerRecords from the live state and persist them.
        // Covers post-reset scenarios where peer_records were wiped but connections exist.
        if peer_records.is_empty() && !connected_identity_keys.is_empty() {
            let info = self.peer_info.read();
            for entry in info.values() {
                if let Some(ref ik) = entry.identity_key {
                    let mut rec = noble_core::PeerRecord::new(
                        ik.clone(),
                        hex::decode(&entry.peer_id).unwrap_or_default(),
                        now,
                    );
                    rec.last_addr = Some(entry.addr.clone());
                    if let Err(e) = storage.store_peer_record(&rec) {
                        tracing::warn!("backfill peer_record failed: {e}");
                    }
                    peer_records.push(rec);
                }
            }
            drop(info);
        }

        drop(storage);

        // Build lookups from peer_records: announce data + last_seen timestamps.
        let mut announce_map: std::collections::HashMap<Vec<u8>, (Option<String>, Option<String>)> =
            std::collections::HashMap::new();
        let mut last_seen_map: std::collections::HashMap<Vec<u8>, u64> =
            std::collections::HashMap::new();
        for rec in &peer_records {
            if let Some(ref ann) = rec.last_announce {
                announce_map.insert(
                    rec.identity_key.clone(),
                    (ann.host_address.clone(), ann.country_code.clone()),
                );
            }
            if rec.last_seen > 0 {
                last_seen_map.insert(rec.identity_key.clone(), rec.last_seen);
            }
        }

        // Lock order: ValidatorRegistry(3) before Consensus(4).
        // Update last_seen in the registry (write lock, then drop).
        {
            let mut registry = self.validator_registry.write();

            // 1. Update last_seen from peer records (historical data).
            for rec in &peer_records {
                if let Ok(pk) = NoblePublicKey::from_wire_bytes(&rec.identity_key) {
                    if registry.is_validator(&pk) {
                        registry.update_last_seen(&pk, rec.last_seen);
                    }
                }
            }

            // 2. Override: any validator whose identity_key matches a connected peer → alive NOW.
            for wire_key in &connected_identity_keys {
                if let Ok(pk) = NoblePublicKey::from_wire_bytes(wire_key) {
                    if registry.is_validator(&pk) {
                        registry.update_last_seen(&pk, now);
                    }
                }
            }

            // 3. SELF is never in its own peer_records — inject current timestamp
            //    so the local validator doesn't show as "unreachable".
            if let Some(ref self_pk_hex) = self.validator_pubkey {
                if let Ok(self_pk) = NoblePublicKey::from_wire_bytes(
                    &hex::decode(self_pk_hex).unwrap_or_default(),
                ) {
                    if registry.is_validator(&self_pk) {
                        registry.update_last_seen(&self_pk, now);
                    }
                }
            }
        }

        // Read validator data from registry (read lock).
        let registry = self.validator_registry.read();
        let validators = registry.list_validators_with_liveness(now);
        // Compute alive count for listers_count (trust metric).
        let alive_count = validators
            .iter()
            .filter(|(_, _, liveness, _, _, _, _)| {
                *liveness == noble_consensus::ValidatorLiveness::Alive
            })
            .count();

        let consensus = self.consensus.read();
        let reputation = consensus.reputation();
        let candidate_tracker = consensus.candidate_tracker();
        let entries: Vec<ValidatorEntry> = validators
            .into_iter()
            .map(|(pk, weight, liveness, added_at, friendly_name, val_host, val_cc)| {
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

                // Priority: announce_map (freshest from peer_records) → validator entry (CBOR) → self identity.
                let (ann_host, ann_cc) = announce_map
                    .get(&wire.to_vec())
                    .cloned()
                    .unwrap_or((None, None));
                let mut host_addr = ann_host.or(val_host);
                let mut country = ann_cc.or(val_cc);

                // Fallback: for our own validator, use the node's identity data.
                let key_display = noble_crypto::noble_addr::encode_wire_bytes(&wire)
                    .unwrap_or_else(|| hex::encode(&wire));
                let key_hex = hex::encode(&wire);
                if host_addr.is_none() && country.is_none() {
                    if let Some(ref self_pk) = self.validator_pubkey {
                        if key_hex == *self_pk {
                            let id = self.node_identity.read();
                            if !id.host_address.is_empty() {
                                host_addr = Some(id.host_address.clone());
                            }
                            if !id.country_code.is_empty() {
                                country = Some(id.country_code.clone());
                            }
                        }
                    }
                }

                // Determine wants_to_validate from known_peers or peer_records.
                // known_peers map is keyed by hex wire bytes (internal format).
                let is_self = self
                    .validator_pubkey
                    .as_deref()
                    .map_or(false, |s| key_hex == *s);
                let wants_validate = if is_self {
                    // Self always wants to validate (we're in the list).
                    true
                } else if let Some(kp) = registry.known_peers().get(&key_hex) {
                    kp.wants_to_validate
                } else {
                    // No announce data — benefit of doubt.
                    true
                };

                ValidatorEntry {
                    public_key: key_display.clone(),
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
                    last_active: {
                        // Connected peers → now; SELF → now; else peer_record.last_seen.
                        let w = wire.to_vec();
                        if connected_identity_keys.contains(&w) {
                            Some(now)
                        } else if is_self {
                            Some(now)
                        } else {
                            last_seen_map.get(&w).copied()
                        }
                    },
                    joined_cycle: added_at,
                    host_address: host_addr,
                    country_code: country,
                    listers_count: alive_count,
                    proposed_this_cycle: candidate_tracker.has_proposed(&wire),
                    wants_to_validate: wants_validate,
                }
            })
            .collect();

        // Auto-kick: remove validators that explicitly announced wants_to_validate=false.
        // Skip self — our own node is never auto-removed.
        // Collect as wire bytes (not display strings) so hex::decode succeeds downstream.
        let mut auto_removed: Vec<Vec<u8>> = Vec::new();
        for entry in &entries {
            if !entry.wants_to_validate {
                // Decode display key (bech32 or hex) back to wire bytes for comparison.
                let wire_bytes = match noble_crypto::noble_addr::decode(&entry.public_key)
                    .map(|pk| pk.to_wire_bytes())
                    .or_else(|_| hex::decode(&entry.public_key))
                {
                    Ok(wb) => Some(wb),
                    Err(e) => {
                        tracing::warn!(key = %entry.public_key, "auto-kick: cannot decode validator key: {e}");
                        None
                    }
                };
                let is_self = wire_bytes.as_ref().map_or(false, |wb| {
                    self.validator_pubkey.as_deref().map_or(false, |s| hex::encode(wb) == *s)
                });
                if !is_self {
                    if let Some(wb) = wire_bytes {
                        auto_removed.push(wb);
                    }
                }
            }
        }
        // Drop read locks before acquiring registry write lock for auto-removal.
        drop(consensus);
        drop(registry);
        if !auto_removed.is_empty() {
            let mut registry = self.validator_registry.write();
            for wire in &auto_removed {
                let wire_hex = hex::encode(wire);
                match NoblePublicKey::from_wire_bytes(wire) {
                    Ok(pk) => {
                        registry.remove_validator(&pk);
                        tracing::info!(
                            key = %wire_hex,
                            "Auto-removed non-proposer from validator list (wants_to_validate=false)"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(key = %wire_hex, err = %e, "Auto-kick: failed to parse pubkey");
                    }
                }
            }
            persist_validator_registry::<S>(&mut registry)?;
        }

        // Filter auto-removed entries from the response.
        // auto_removed holds wire bytes; entry.public_key is bech32 display.
        // Decode each entry's display key to wire bytes for comparison.
        let filtered_entries: Vec<ValidatorEntry> = if auto_removed.is_empty() {
            entries
        } else {
            let removed_set: std::collections::HashSet<Vec<u8>> =
                auto_removed.into_iter().collect();
            entries
                .into_iter()
                .filter(|e| {
                    let wire = noble_crypto::noble_addr::decode(&e.public_key)
                        .map(|pk| pk.to_wire_bytes())
                        .or_else(|_| hex::decode(&e.public_key))
                        .unwrap_or_else(|e_err| {
                            tracing::warn!(key = %e.public_key, "filter: cannot decode key: {e_err}");
                            Vec::new()
                        });
                    !removed_set.contains(&wire)
                })
                .collect()
        };
        let filtered_count = filtered_entries.len();

        let priority_order: Vec<String> = {
            let registry = self.validator_registry.read();
            registry
                .priority_order()
                .iter()
                .map(|wire| {
                    noble_crypto::noble_addr::encode_wire_bytes(wire)
                        .unwrap_or_else(|| hex::encode(wire))
                })
                .collect()
        };

        Ok(ValidatorListResponse {
            selection_policy: "weighted_random".to_string(),
            validators: filtered_entries,
            count: filtered_count,
            priority_order,
        })
    }

    async fn get_reputation_score(
        &self,
        pubkey: String,
    ) -> Result<ReputationScoreResponse, ErrorObjectOwned> {
        let pk = parse_pubkey_input(&pubkey)?;

        // Lock order: ValidatorRegistry(3) before Consensus(4).
        {
            let registry = self.validator_registry.read();
            if !registry.is_validator(&pk) {
                return Err(ApiError::ValidatorNotFound(pubkey).into());
            }
        }

        let consensus = self.consensus.read();
        let rep_data = consensus.reputation().get(&pk.to_wire_bytes());
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
        let tip_height = consensus.chain_tip().0;
        // phase_timing() computes phase/timing from real-time (cycle_mgr),
        // avoiding stale tracked_phase during the 1-tick window after epoch changes.
        let (phase_index, engine_phase_remaining, cycle_remaining) = consensus.phase_timing();

        // 4 phases: derive name from real-time phase index (not tick-tracked).
        let phase_name = match phase_index {
            0 => "Block Proposal",
            1 => "Voting",
            2 => "Reflection",
            _ => "Propagation",
        };

        // No genesis block → hide cycle number but still report real phase info.
        // The engine IS running full consensus during bootstrap (proposals, votes,
        // phase transitions) — the GUI needs the real phase_index to show the
        // pipeline progression and log phase change events.
        let genesis_ts = consensus.genesis_timestamp();

        if tip_height == 0 {
            return Ok(CycleStatusResponse {
                cycle_number: None,
                phase: phase_name.to_string(),
                phase_index,
                phase_remaining_secs: engine_phase_remaining,
                cycle_remaining_secs: cycle_remaining,
                genesis_timestamp: genesis_ts,
            });
        }

        let cycle = consensus.current_cycle();

        Ok(CycleStatusResponse {
            cycle_number: Some(cycle),
            phase: phase_name.to_string(),
            phase_index,
            phase_remaining_secs: engine_phase_remaining,
            cycle_remaining_secs: cycle_remaining,
            genesis_timestamp: genesis_ts,
        })
    }

    async fn add_validator(
        &self,
        public_key: String,
        name: Option<String>,
        weight: Option<u64>,
    ) -> Result<bool, ErrorObjectOwned> {
        let pk = parse_pubkey_input(&public_key)?;

        let effective_weight = weight.unwrap_or(100);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Lock order: ValidatorRegistry(3) before Consensus(4).
        let mut registry = self.validator_registry.write();
        registry.add_validator(pk.clone(), effective_weight, now);
        if let Some(n) = name {
            registry.set_friendly_name(&pk, n);
        }
        persist_validator_registry::<S>(&mut registry)?;

        Ok(true)
    }

    async fn remove_validator(&self, public_key: String) -> Result<bool, ErrorObjectOwned> {
        let pk = parse_pubkey_input(&public_key)?;

        // Lock order: ValidatorRegistry(3) before Consensus(4).
        let mut registry = self.validator_registry.write();
        let removed = registry.remove_validator(&pk);
        if !removed {
            return Err(ApiError::ValidatorNotFound(public_key).into());
        }

        persist_validator_registry::<S>(&mut registry)?;

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
        if round == 1 && strategy == "follow_majority" {
            return Err(ApiError::InvalidParam(
                "follow_majority is only valid for round 2 (confirmation)".into(),
            )
            .into());
        }
        let parsed = parse_strategy(&strategy, params.as_ref()).map_err(ErrorObjectOwned::from)?;

        let mut consensus = self.consensus.write();
        if round == 1 {
            consensus.set_voting_strategy(parsed);
        } else {
            consensus.set_confirmation_strategy(parsed);
        }

        // Persist strategy to noble.toml so it survives restarts.
        if let Some(ref set_fn) = self.set_config_value {
            let key = if round == 1 { "voting_strategy" } else { "confirmation_strategy" };
            if let Err(e) = set_fn("consensus", key, &strategy) {
                tracing::warn!("failed to persist {key}={strategy}: {e}");
            }
            // Also persist params if applicable.
            if strategy == "fixed_validator" {
                if let Some(ref p) = params {
                    if let Some(vk) = p.get("validator_key").and_then(|v| v.as_str()) {
                        if let Err(e) = set_fn("consensus", "voting_preferred_validator", vk) {
                            tracing::warn!("failed to persist voting_preferred_validator: {e}");
                        }
                    }
                }
            } else if strategy == "subset_rotation" {
                if let Some(ref p) = params {
                    if let Some(arr) = p.get("validators").and_then(|v| v.as_array()) {
                        let csv: String = arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(",");
                        if let Err(e) = set_fn("consensus", "voting_subset", &csv) {
                            tracing::warn!("failed to persist voting_subset: {e}");
                        }
                    }
                }
            }
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
        // Lock order: ValidatorRegistry(3) before Consensus(4).
        let registry = self.validator_registry.read();
        let consensus = self.consensus.read();
        let cycle = consensus.current_cycle();
        let phase = consensus.current_phase();
        let tallies = consensus.vote_tallies();
        let candidate_tracker = consensus.candidate_tracker();

        // Build peer announce name lookup as fallback for validators not in local list
        let peer_name_map: std::collections::HashMap<Vec<u8>, String> = {
            let storage = self.storage.read();
            storage
                .list_peer_records()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|rec| {
                    let name = rec
                        .last_announce
                        .as_ref()
                        .map(|ann| ann.node_name.clone())
                        .unwrap_or_default();
                    if name.is_empty() {
                        None
                    } else {
                        Some((rec.identity_key.clone(), name))
                    }
                })
                .collect()
        };

        // Self-node identity: the local node's own validator key may not be
        // in its own validator_list — use node_identity.node_name as fallback.
        let self_validator_name: Option<(String, String)> = self.validator_pubkey.as_ref().map(|pk| {
            let id = self.node_identity.read();
            (pk.clone(), id.node_name.clone())
        });

        let mut entries: Vec<VoteTallyEntry> = tallies
            .into_iter()
            .map(|(h, c)| {
                // Look up proposer wire bytes once (used for both name and key).
                let proposer_wire = candidate_tracker.validator_of(&h);
                let validator_key = proposer_wire.as_ref()
                    .map(|wire| hex::encode(wire));
                let validator = proposer_wire.map(|wire| {
                    let display_key = noble_crypto::noble_addr::encode_wire_bytes(&wire)
                        .unwrap_or_else(|| hex::encode(&wire));
                    registry
                        .find_by_wire(&wire)
                        .map(|v| v.name())
                        .filter(|n| !n.is_empty())
                        .or_else(|| peer_name_map.get(&wire).cloned())
                        .or_else(|| {
                            self_validator_name.as_ref().and_then(|(pk_hex, name)| {
                                let wire_hex = hex::encode(&wire);
                                if *pk_hex == wire_hex && !name.is_empty() {
                                    Some(name.clone())
                                } else {
                                    None
                                }
                            })
                        })
                        .unwrap_or(display_key)
                });
                VoteTallyEntry {
                    block_hash: hash_to_hex(&h),
                    vote_count: c,
                    validator,
                    validator_key,
                }
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
                        r2_vote_count: v.r2_vote_count,
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

    async fn get_block_votes(
        &self,
        height: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let storage = self.storage.read();
        let raw = storage
            .get_block_votes(height)
            .map_err(|e| ApiError::Internal(format!("read block votes: {e}")))?;
        match raw {
            Some(bytes) => {
                let votes: noble_consensus::BlockVotes =
                    noble_codec::NobleCbor::from_cbor(&bytes).map_err(|e| {
                        ApiError::Internal(format!("decode block votes: {e}"))
                    })?;
                let resp = crate::types::BlockVotesResponse {
                    height,
                    cycle_number: votes.cycle_number,
                    voter_count: votes.voter_count,
                    strength: votes.strength,
                    r1_voters: votes
                        .r1_voters
                        .into_iter()
                        .map(|v| crate::types::BlockVoterResponse {
                            validator_key: v.validator_key,
                            name: v.name,
                        })
                        .collect(),
                    r2_voters: votes
                        .r2_voters
                        .into_iter()
                        .map(|v| crate::types::BlockVoterResponse {
                            validator_key: v.validator_key,
                            name: v.name,
                        })
                        .collect(),
                    unique_witness_count: votes.unique_witness_count,
                    dual_witness_required: votes.dual_witness_required,
                    dual_witness_met: votes.dual_witness_met,
                };
                serde_json::to_value(resp)
                    .map_err(|e| ApiError::Internal(format!("serialize block votes: {e}")).into())
            }
            None => Ok(serde_json::json!(null)),
        }
    }

    async fn set_validator_order(
        &self,
        order: Vec<String>,
    ) -> Result<bool, ErrorObjectOwned> {
        // Convert hex or nbl1 strings to wire bytes
        let wire_order: Vec<Vec<u8>> = order
            .iter()
            .map(|key_str| {
                let pk = parse_pubkey_input(key_str)?;
                Ok(pk.to_wire_bytes())
            })
            .collect::<Result<Vec<_>, ErrorObjectOwned>>()?;

        // Lock order: ValidatorRegistry(3) before Consensus(4).
        let mut registry = self.validator_registry.write();
        registry
            .set_priority_order(wire_order)
            .map_err(|e| ApiError::InvalidParam(e))?;
        persist_validator_registry::<S>(&mut registry)?;

        Ok(true)
    }
}
