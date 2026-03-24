// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! DAO governance poll RPC methods: getActivePolls, getPollHistory, createPoll, votePoll.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::DaoPollResponse;

#[rpc(server, namespace = "noble")]
pub trait DaoApi {
    /// List all active DAO polls.
    #[method(name = "getActivePolls")]
    async fn get_active_polls(&self) -> Result<Vec<DaoPollResponse>, ErrorObjectOwned>;

    /// List closed (historical) DAO polls.
    #[method(name = "getPollHistory")]
    async fn get_poll_history(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<DaoPollResponse>, ErrorObjectOwned>;

    /// Create a new DAO governance poll.
    #[method(name = "createPoll")]
    async fn create_poll(
        &self,
        question: String,
        expires_cycles: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Vote on an active DAO poll.
    #[method(name = "votePoll")]
    async fn vote_poll(
        &self,
        poll_id: String,
        vote: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> DaoApiServer for Arc<ApiState<S>> {
    async fn get_active_polls(&self) -> Result<Vec<DaoPollResponse>, ErrorObjectOwned> {
        let engine = self.consensus.read();
        let badge_count = engine.badge_store().count_active();
        let active = engine.dao_store().list_active();

        let polls: Vec<DaoPollResponse> = active
            .into_iter()
            .map(|p| {
                let proposer_addr = crate::types::wire_to_address(&p.proposer);
                let proposer_name = self.resolve_friendly_name(&p.proposer);
                DaoPollResponse {
                    poll_id: p.poll_id.clone(),
                    question: p.question.clone(),
                    proposer: proposer_addr,
                    proposer_name,
                    created_at_cycle: p.created_at_cycle,
                    expires_at_cycle: p.expires_at_cycle,
                    votes_yes: p.votes_yes.len() as u32,
                    votes_no: p.votes_no.len() as u32,
                    votes_abstain: p.votes_abstain.len() as u32,
                    total_eligible: badge_count as u32,
                    status: p.status.clone(),
                }
            })
            .collect();

        Ok(polls)
    }

    async fn get_poll_history(
        &self,
        limit: Option<usize>,
    ) -> Result<Vec<DaoPollResponse>, ErrorObjectOwned> {
        let engine = self.consensus.read();
        let badge_count = engine.badge_store().count_active();
        let history = engine.dao_store().list_history(limit.unwrap_or(50));

        let polls: Vec<DaoPollResponse> = history
            .into_iter()
            .map(|p| {
                let proposer_addr = crate::types::wire_to_address(&p.proposer);
                let proposer_name = self.resolve_friendly_name(&p.proposer);
                DaoPollResponse {
                    poll_id: p.poll_id.clone(),
                    question: p.question.clone(),
                    proposer: proposer_addr,
                    proposer_name,
                    created_at_cycle: p.created_at_cycle,
                    expires_at_cycle: p.expires_at_cycle,
                    votes_yes: p.votes_yes.len() as u32,
                    votes_no: p.votes_no.len() as u32,
                    votes_abstain: p.votes_abstain.len() as u32,
                    total_eligible: badge_count as u32,
                    status: p.status.clone(),
                }
            })
            .collect();

        Ok(polls)
    }

    async fn create_poll(
        &self,
        question: String,
        expires_cycles: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let q = question.trim().to_string();
        if q.is_empty() || q.len() > 500 {
            return Err(ApiError::InvalidParam("question must be 1-500 characters".into()).into());
        }
        let window = expires_cycles.unwrap_or(72).min(720); // default 24h, max 10d

        let metadata = vec![
            noble_core::MetadataEntry {
                key: "dao:action".to_string(),
                value: b"create".to_vec(),
            },
            noble_core::MetadataEntry {
                key: "dao:question".to_string(),
                value: q.into_bytes(),
            },
            noble_core::MetadataEntry {
                key: "dao:expires_cycles".to_string(),
                value: window.to_string().into_bytes(),
            },
        ];

        let tx_hash = crate::methods::badge::build_badge_tx(self, noble_core::TX_TYPE_DAO, metadata)?;
        Ok(serde_json::json!({
            "ok": true,
            "tx_hash": tx_hash,
        }))
    }

    async fn vote_poll(
        &self,
        poll_id: String,
        vote: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Validate vote value.
        if !["yes", "no", "abstain"].contains(&vote.as_str()) {
            return Err(ApiError::InvalidParam("vote must be 'yes', 'no', or 'abstain'".into()).into());
        }

        // Verify poll exists and is active.
        {
            let engine = self.consensus.read();
            match engine.dao_store().get(&poll_id) {
                Some(p) if p.status == "active" => {}
                Some(_) => {
                    return Err(ApiError::InvalidParam("poll is not active".into()).into());
                }
                None => {
                    return Err(ApiError::InvalidParam("poll not found".into()).into());
                }
            }
        }

        let metadata = vec![
            noble_core::MetadataEntry {
                key: "dao:action".to_string(),
                value: b"vote".to_vec(),
            },
            noble_core::MetadataEntry {
                key: "dao:poll_id".to_string(),
                value: poll_id.into_bytes(),
            },
            noble_core::MetadataEntry {
                key: "dao:vote".to_string(),
                value: vote.into_bytes(),
            },
        ];

        let tx_hash = crate::methods::badge::build_badge_tx(self, noble_core::TX_TYPE_DAO, metadata)?;
        Ok(serde_json::json!({
            "ok": true,
            "tx_hash": tx_hash,
        }))
    }
}
