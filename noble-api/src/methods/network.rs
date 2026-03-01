// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network-related RPC methods: getPeerInfo, getNetworkInfo, getSyncStatus, peer memory,
//! dialPeer, seed management.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_consensus::ConsensusStateMachine;
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait NetworkApi {
    /// Get information about connected peers.
    #[method(name = "getPeerInfo")]
    async fn get_peer_info(&self) -> Result<Vec<PeerInfoResponse>, ErrorObjectOwned>;

    /// Get network summary statistics.
    #[method(name = "getNetworkInfo")]
    async fn get_network_info(&self) -> Result<NetworkInfoResponse, ErrorObjectOwned>;

    /// Get current sync status.
    #[method(name = "getSyncStatus")]
    async fn get_sync_status(&self) -> Result<SyncStatusResponse, ErrorObjectOwned>;

    /// Get persistent peer memory records.
    #[method(name = "getPeerMemory")]
    async fn get_peer_memory(&self) -> Result<Vec<PeerRecordResponse>, ErrorObjectOwned>;

    /// Remove a specific peer record by identity key (hex-encoded).
    #[method(name = "removePeerRecord")]
    async fn remove_peer_record(
        &self,
        identity_key: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Prune stale peer records older than `max_age_secs` seconds.
    #[method(name = "pruneStalePeers")]
    async fn prune_stale_peers(
        &self,
        max_age_secs: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Dial a peer by multiaddr (e.g. "/ip4/192.168.5.20/tcp/8780").
    #[method(name = "dialPeer")]
    async fn dial_peer(&self, multiaddr: String) -> Result<DialPeerResponse, ErrorObjectOwned>;

    /// Get the current configured seed node list.
    #[method(name = "getSeeds")]
    async fn get_seeds(&self) -> Result<SeedsResponse, ErrorObjectOwned>;

    /// Add a seed node, dial it immediately, and persist to noble.toml.
    #[method(name = "addSeed")]
    async fn add_seed(&self, multiaddr: String) -> Result<SeedsResponse, ErrorObjectOwned>;

    /// Remove a seed node from the list and persist to noble.toml.
    #[method(name = "removeSeed")]
    async fn remove_seed(&self, multiaddr: String) -> Result<SeedsResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> NetworkApiServer for Arc<ApiState<S>> {
    async fn get_peer_info(&self) -> Result<Vec<PeerInfoResponse>, ErrorObjectOwned> {
        let info = self.peer_info.read();
        let peers: Vec<PeerInfoResponse> = info
            .values()
            .map(|entry| PeerInfoResponse {
                peer_id: entry.peer_id.clone(),
                direction: entry.direction.clone(),
                connected_at: entry.connected_at,
                ban_score: entry.ban_score,
                last_ban_reason: None,
            })
            .collect();
        Ok(peers)
    }

    async fn get_network_info(&self) -> Result<NetworkInfoResponse, ErrorObjectOwned> {
        let stats = self.network_stats.read();
        Ok(NetworkInfoResponse {
            peer_count: stats.peer_count,
            inbound: stats.inbound_count,
            outbound: stats.outbound_count,
        })
    }

    async fn get_sync_status(&self) -> Result<SyncStatusResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let (height, _hash) = consensus.chain_tip();
        // Until sync manager tracks highest known, report current as highest
        let highest_known = height;
        let progress = if highest_known == 0 {
            1.0
        } else {
            height as f64 / highest_known as f64
        };
        let synced = height >= highest_known;
        let state = if synced { "Complete" } else { "Syncing" };

        Ok(SyncStatusResponse {
            synced,
            current_height: height,
            highest_known,
            progress,
            state: state.to_string(),
        })
    }

    async fn get_peer_memory(&self) -> Result<Vec<PeerRecordResponse>, ErrorObjectOwned> {
        let storage = self.storage.read();
        let records = storage
            .list_peer_records()
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(records
            .into_iter()
            .map(|rec| {
                let announce = rec.last_announce.as_ref();
                PeerRecordResponse {
                    identity_key: hex::encode(&rec.identity_key),
                    first_seen: rec.first_seen,
                    last_seen: rec.last_seen,
                    connection_count: rec.connection_count,
                    peer_id: hex::encode(&rec.peer_id_bytes),
                    last_addr: rec.last_addr.clone(),
                    node_name: announce.map(|a| a.node_name.clone()),
                    org_type: announce.map(|a| format!("{:?}", a.org_type)),
                    node_role: announce.map(|a| format!("{:?}", a.node_role)),
                    wants_to_validate: announce.is_some_and(|a| a.wants_to_validate),
                    wants_to_vote: announce.is_some_and(|a| a.wants_to_vote),
                }
            })
            .collect())
    }

    async fn remove_peer_record(
        &self,
        identity_key: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let key_bytes = hex::decode(&identity_key)
            .map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        let storage = self.storage.read();
        storage
            .remove_peer_record(&key_bytes)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(serde_json::json!({ "success": true }))
    }

    async fn prune_stale_peers(
        &self,
        max_age_secs: u64,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let storage = self.storage.read();
        let pruned = storage
            .prune_peer_records(now, max_age_secs)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(serde_json::json!({ "pruned": pruned }))
    }

    async fn dial_peer(&self, multiaddr: String) -> Result<DialPeerResponse, ErrorObjectOwned> {
        let addr: libp2p::Multiaddr = multiaddr
            .parse()
            .map_err(|e| ApiError::InvalidAddress(format!("invalid multiaddr: {e}")))?;
        self.network_cmd
            .send(NetworkCommand::DialPeer(addr))
            .await
            .map_err(|e| ApiError::Internal(format!("failed to send dial command: {e}")))?;
        Ok(DialPeerResponse {
            success: true,
            message: format!("Dialing {multiaddr}"),
        })
    }

    async fn get_seeds(&self) -> Result<SeedsResponse, ErrorObjectOwned> {
        let seeds = self.seeds.read().clone();
        Ok(SeedsResponse { seeds })
    }

    async fn add_seed(&self, multiaddr: String) -> Result<SeedsResponse, ErrorObjectOwned> {
        // Validate multiaddr syntax.
        let addr: libp2p::Multiaddr = multiaddr
            .parse()
            .map_err(|e| ApiError::InvalidAddress(format!("invalid multiaddr: {e}")))?;

        // Add to live list (skip duplicates).
        {
            let mut seeds = self.seeds.write();
            if !seeds.contains(&multiaddr) {
                seeds.push(multiaddr.clone());
            }
        }

        // Dial immediately.
        let _ = self
            .network_cmd
            .send(NetworkCommand::DialPeer(addr))
            .await;

        // Persist to noble.toml via set_config_value callback.
        self.persist_seeds();

        let seeds = self.seeds.read().clone();
        Ok(SeedsResponse { seeds })
    }

    async fn remove_seed(&self, multiaddr: String) -> Result<SeedsResponse, ErrorObjectOwned> {
        {
            let mut seeds = self.seeds.write();
            seeds.retain(|s| s != &multiaddr);
        }

        // Persist to noble.toml.
        self.persist_seeds();

        let seeds = self.seeds.read().clone();
        Ok(SeedsResponse { seeds })
    }
}

/// Helper for seed persistence.
impl<S: StorageEngine + Send + Sync + 'static> ApiState<S> {
    /// Write the current seed list to noble.toml via set_config_value.
    fn persist_seeds(&self) {
        if let Some(ref set_config) = self.set_config_value {
            let seeds = self.seeds.read();
            // Serialize as comma-separated multiaddr list.
            let value = seeds.join(",");
            if let Err(e) = set_config("network", "seeds", &value) {
                tracing::warn!(task = "rpc", %e, "Failed to persist seeds to noble.toml");
            }
        }
    }
}
