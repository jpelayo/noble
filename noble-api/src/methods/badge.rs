// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Badge governance RPC methods: getBadgeHolders, getActiveProposals,
//! getProposalHistory, getMyBadgeStatus, proposeBadge, voteBadgeProposal.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::{BadgeHolderResponse, BadgeProposalResponse};

#[rpc(server, namespace = "noble")]
pub trait BadgeApi {
    /// List all badge holders and their status.
    #[method(name = "getBadgeHolders")]
    async fn get_badge_holders(&self) -> Result<Vec<BadgeHolderResponse>, ErrorObjectOwned>;

    /// List active (open) badge proposals.
    #[method(name = "getActiveProposals")]
    async fn get_active_proposals(&self) -> Result<Vec<BadgeProposalResponse>, ErrorObjectOwned>;

    /// List historical badge proposals (passed, rejected, expired).
    #[method(name = "getProposalHistory")]
    async fn get_proposal_history(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<BadgeProposalResponse>, ErrorObjectOwned>;

    /// Get this node's own badge status.
    #[method(name = "getMyBadgeStatus")]
    async fn get_my_badge_status(&self) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Submit a badge proposal (grant or revoke).
    #[method(name = "proposeBadge")]
    async fn propose_badge(
        &self,
        target_pubkey: String,
        proposal_type: String,
        reason: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Cast a vote on an active badge proposal.
    #[method(name = "voteBadgeProposal")]
    async fn vote_badge_proposal(
        &self,
        proposal_hash: String,
        vote: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> BadgeApiServer for Arc<ApiState<S>> {
    async fn get_badge_holders(&self) -> Result<Vec<BadgeHolderResponse>, ErrorObjectOwned> {
        let engine = self.consensus.read();
        let store = engine.badge_store();
        let peer_info = self.peer_info.read();

        let mut holders: Vec<BadgeHolderResponse> = store
            .list_all()
            .into_iter()
            .map(|(pubkey_wire, badge)| {
                let pubkey_hex = noble_crypto::noble_addr::encode_wire_bytes(pubkey_wire)
                    .unwrap_or_else(|| hex::encode(pubkey_wire));
                // Try to find the node name from connected peers.
                let node_name = peer_info.values().find_map(|p| {
                    if p.identity_key.as_deref() == Some(pubkey_wire) {
                        Some(p.peer_id.clone())
                    } else {
                        None
                    }
                });
                BadgeHolderResponse {
                    pubkey: pubkey_hex,
                    node_name,
                    status: format!("{:?}", badge.status).to_lowercase(),
                    granted_at_height: badge.granted_at_height,
                    last_seen: badge.last_seen,
                }
            })
            .collect();

        holders.sort_by(|a, b| a.granted_at_height.cmp(&b.granted_at_height));
        Ok(holders)
    }

    async fn get_active_proposals(&self) -> Result<Vec<BadgeProposalResponse>, ErrorObjectOwned> {
        let raw: Vec<(String, noble_consensus::BadgeProposal, u32)> = {
            let engine = self.consensus.read();
            let proposals = engine.badge_proposals();
            let total_eligible = engine.badge_store().count_active() as u32;
            proposals.iter()
                .filter(|(_, p)| p.status == "active")
                .map(|(hash, p)| (hash.clone(), p.clone(), total_eligible))
                .collect()
        };

        let mut result: Vec<BadgeProposalResponse> = raw.iter().map(|(hash, p, te)| {
            let tn = self.resolve_friendly_name(&p.target_pubkey);
            let pn = self.resolve_friendly_name(&p.proposer_pubkey);
            proposal_to_response(hash, p, *te, tn, pn)
        }).collect();

        result.sort_by(|a, b| a.created_at_cycle.cmp(&b.created_at_cycle));
        Ok(result)
    }

    async fn get_proposal_history(
        &self,
        limit: Option<u32>,
    ) -> Result<Vec<BadgeProposalResponse>, ErrorObjectOwned> {
        let max = limit.unwrap_or(50) as usize;
        let raw: Vec<(String, noble_consensus::BadgeProposal, u32)> = {
            let engine = self.consensus.read();
            let proposals = engine.badge_proposals();
            let total_eligible = engine.badge_store().count_active() as u32;
            proposals.iter()
                .filter(|(_, p)| p.status != "active")
                .map(|(hash, p)| (hash.clone(), p.clone(), total_eligible))
                .collect()
        };

        let mut result: Vec<BadgeProposalResponse> = raw.iter().map(|(hash, p, te)| {
            let tn = self.resolve_friendly_name(&p.target_pubkey);
            let pn = self.resolve_friendly_name(&p.proposer_pubkey);
            proposal_to_response(hash, p, *te, tn, pn)
        })
            .collect();

        result.sort_by(|a, b| b.created_at_cycle.cmp(&a.created_at_cycle));
        result.truncate(max);
        Ok(result)
    }

    async fn get_my_badge_status(&self) -> Result<serde_json::Value, ErrorObjectOwned> {
        let engine = self.consensus.read();
        let store = engine.badge_store();

        if let Some(ref pubkey_hex) = *self.validator_pubkey.read() {
            let wire =
                hex::decode(pubkey_hex).map_err(|_| ApiError::Internal("bad pubkey".into()))?;
            if let Some(badge) = store.get_badge(&wire) {
                Ok(serde_json::json!({
                    "has_badge": true,
                    "status": format!("{:?}", badge.status).to_lowercase(),
                    "granted_at_height": badge.granted_at_height,
                    "granted_at_cycle": badge.granted_at_cycle,
                    "last_seen": badge.last_seen,
                }))
            } else {
                Ok(serde_json::json!({
                    "has_badge": false,
                    "status": "none",
                }))
            }
        } else {
            Ok(serde_json::json!({
                "has_badge": false,
                "status": "no_validator_key",
            }))
        }
    }

    async fn propose_badge(
        &self,
        target_pubkey: String,
        proposal_type: String,
        reason: Option<String>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Validate target pubkey.
        // Accept both nbl1… bech32 and hex wire bytes for target_pubkey.
        let target_wire = if noble_crypto::noble_addr::is_noble_address(target_pubkey.trim()) {
            let pk = noble_crypto::noble_addr::decode(target_pubkey.trim())
                .map_err(|e| ApiError::InvalidParam(format!("invalid target_pubkey: {e}")))?;
            pk.to_wire_bytes()
        } else {
            let bytes = hex::decode(&target_pubkey)
                .map_err(|_| ApiError::InvalidParam("invalid hex target_pubkey".into()))?;
            if bytes.len() < 2 {
                return Err(ApiError::InvalidParam("target_pubkey too short".into()).into());
            }
            bytes
        };

        // Determine proposal type byte.
        let ptype_byte = match proposal_type.as_str() {
            "grant" => noble_core::TX_TYPE_BADGE_PROPOSAL,
            "revoke" => noble_core::TX_TYPE_BADGE_PROPOSAL,
            _ => {
                return Err(
                    ApiError::InvalidParam("proposal_type must be 'grant' or 'revoke'".into())
                        .into(),
                )
            }
        };

        let ptype_value = match proposal_type.as_str() {
            "grant" => 0x01u8,
            "revoke" => 0x02u8,
            _ => unreachable!(),
        };

        // Build badge proposal transaction metadata.
        let mut metadata = vec![
            noble_core::MetadataEntry {
                key: "target_pubkey".to_string(),
                value: target_wire,
            },
            noble_core::MetadataEntry {
                key: "proposal_type".to_string(),
                value: vec![ptype_value],
            },
        ];

        if let Some(ref r) = reason {
            let reason_byte = match r.as_str() {
                "DuplicateProposal" => 0u8,
                "ProtocolAbuse" => 1u8,
                "ExtendedAbsence" => 2u8,
                "Misrepresentation" => 3u8,
                _ => 4u8, // Other
            };
            metadata.push(noble_core::MetadataEntry {
                key: "reason".to_string(),
                value: vec![reason_byte],
            });
        }

        // Build and submit the transaction via the wallet/mempool pipeline.
        let tx = build_badge_tx(self, ptype_byte, metadata)?;
        Ok(serde_json::json!({
            "ok": true,
            "tx_hash": tx,
        }))
    }

    async fn vote_badge_proposal(
        &self,
        proposal_hash: String,
        vote: bool,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let phash_bytes = hex::decode(&proposal_hash)
            .map_err(|_| ApiError::InvalidParam("invalid hex proposal_hash".into()))?;

        // Verify the proposal exists and is active.
        {
            let engine = self.consensus.read();
            let proposals = engine.badge_proposals();
            match proposals.get(&proposal_hash) {
                Some(p) if p.status == "active" => {}
                Some(_) => {
                    return Err(
                        ApiError::InvalidParam("proposal is not active".into()).into()
                    );
                }
                None => {
                    return Err(
                        ApiError::InvalidParam("proposal not found".into()).into()
                    );
                }
            }
        }

        let metadata = vec![
            noble_core::MetadataEntry {
                key: "proposal_hash".to_string(),
                value: phash_bytes,
            },
            noble_core::MetadataEntry {
                key: "vote".to_string(),
                value: vec![if vote { 1u8 } else { 0u8 }],
            },
        ];

        let tx = build_badge_tx(self, noble_core::TX_TYPE_BADGE_VOTE, metadata)?;
        Ok(serde_json::json!({
            "ok": true,
            "tx_hash": tx,
        }))
    }
}

// ---------------------------------------------------------------------------
// Adapter structs for mempool admission (same as transaction.rs)
// ---------------------------------------------------------------------------

struct BadgeChainLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> noble_mempool::ChainLookup for BadgeChainLookup<'_, S> {
    fn is_confirmed(&self, tx_id: &noble_crypto::Hash256) -> bool {
        self.storage.has_transaction(tx_id).unwrap_or(false)
    }
}

struct BadgeUtxoLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> noble_mempool::UtxoLookup for BadgeUtxoLookup<'_, S> {
    fn get_utxo(&self, outpoint: &noble_core::OutPoint) -> Option<(u64, bool, u64)> {
        match self.storage.get_utxo(outpoint) {
            Ok(Some(entry)) => Some((entry.value, entry.is_coinbase, entry.height)),
            _ => None,
        }
    }
}

/// Build a badge transaction, sign it, admit to mempool, and broadcast.
fn build_badge_tx<S: StorageEngine + Send + Sync + 'static>(
    state: &Arc<ApiState<S>>,
    tx_type: u8,
    metadata: Vec<noble_core::MetadataEntry>,
) -> Result<String, ErrorObjectOwned> {
    use noble_crypto::Hash256;

    // Require wallet unlocked.
    let wallet_state = state.wallet_state.lock();
    if !wallet_state.is_unlocked() {
        return Err(ApiError::WalletLocked.into());
    }
    drop(wallet_state);

    // Get the first public key from the keystore.
    let keystore = state.wallet_keystore.lock();
    let keys = keystore
        .list_keys()
        .map_err(|e| ApiError::Internal(format!("keystore error: {e}")))?;
    let pk = keys.first().ok_or_else(|| {
        Into::<ErrorObjectOwned>::into(ApiError::Internal(
            "no signing key in keystore".into(),
        ))
    })?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the unsigned transaction.
    let tx = noble_core::Transaction {
        version: noble_core::PROTOCOL_VERSION,
        tx_type,
        inputs: vec![], // Badge txs have no UTXO inputs (zero-fee governance)
        outputs: vec![],
        checksum: Hash256::ZERO,
        timestamp: now,
        publisher_sig: noble_crypto::SignatureEnvelope {
            scheme_id: pk.scheme_id(),
            public_key: pk.key_bytes().to_vec(),
            signature: Vec::new(),
        },
        additional_sigs: Vec::new(),
        metadata,
        encrypted_locator: None,
        external_attestations: Vec::new(),
        gateway_address: None,
        contract_data: None,
    };

    // Sign the transaction.
    let signing_msg = tx
        .compute_signing_message_for_chain(state.chain_id.load(std::sync::atomic::Ordering::Relaxed))
        .map_err(|e| ApiError::Internal(format!("signing message error: {e}")))?;
    let sig_envelope = keystore
        .sign(pk, &signing_msg)
        .map_err(|e| ApiError::Internal(format!("signing error: {e}")))?;
    drop(keystore);

    let mut signed_tx = tx;
    signed_tx.publisher_sig = sig_envelope;

    // Admit to mempool with storage-backed lookups.
    let tx_id = {
        let storage = state.storage.read();
        let chain_height = storage
            .get_chain_tip()
            .ok()
            .flatten()
            .map(|t| t.height)
            .unwrap_or(0);
        let chain_lookup = BadgeChainLookup { storage: &*storage };
        let utxo_lookup = BadgeUtxoLookup { storage: &*storage };

        let mut mempool = state.mempool.lock();
        mempool
            .admit(&signed_tx, now, &chain_lookup, &utxo_lookup, chain_height)
            .map_err(|e| ApiError::TxRejected(e.to_string()))?
    };

    let tx_hash = hex::encode(tx_id);

    // Broadcast to network (best-effort).
    if let Err(e) = state
        .network_cmd
        .try_send(noble_network::NetworkCommand::PublishTransaction(signed_tx))
    {
        tracing::warn!(task = "badge_tx", "network broadcast dropped: {e}");
    }

    Ok(tx_hash)
}

/// Convert a badge proposal to an RPC response.
fn proposal_to_response(
    hash: &str,
    p: &noble_consensus::BadgeProposal,
    total_eligible: u32,
    target_name: Option<String>,
    proposer_name: Option<String>,
) -> BadgeProposalResponse {
    BadgeProposalResponse {
        proposal_hash: hash.to_string(),
        proposal_type: format!("{:?}", p.proposal_type).to_lowercase(),
        target_pubkey: noble_crypto::noble_addr::encode_wire_bytes(&p.target_pubkey)
            .unwrap_or_else(|| hex::encode(&p.target_pubkey)),
        target_name,
        proposer_pubkey: noble_crypto::noble_addr::encode_wire_bytes(&p.proposer_pubkey)
            .unwrap_or_else(|| hex::encode(&p.proposer_pubkey)),
        proposer_name,
        reason: p.reason.as_ref().map(|r| format!("{:?}", r)),
        created_at_cycle: p.created_at_cycle,
        expires_at_cycle: p.expires_at_cycle,
        votes_for: p.votes_for.len() as u32,
        votes_against: p.votes_against.len() as u32,
        total_eligible_voters: total_eligible,
        status: p.status.clone(),
    }
}
