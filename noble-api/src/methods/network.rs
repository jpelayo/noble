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

/// Auto-convert bare IP (e.g. "192.168.5.20") to multiaddr "/ip4/{ip}/tcp/8780".
fn normalize_multiaddr(input: &str) -> String {
    if input.starts_with('/') {
        input.to_string()
    } else {
        format!("/ip4/{}/tcp/8780", input)
    }
}

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
        // Lock order: Storage(2) before PeerInfo(6).
        // Read peer records first, then drop storage lock before acquiring peer_info.
        let records = {
            let storage = self.storage.read();
            storage.list_peer_records().unwrap_or_default()
        };

        // Build lookup: hex(peer_id_bytes) → PeerRecord for name/country enrichment.
        let record_map: std::collections::HashMap<String, &noble_core::PeerRecord> = records
            .iter()
            .map(|r| (hex::encode(&r.peer_id_bytes), r))
            .collect();

        let info = self.peer_info.read();

        // Track which peer_ids we've already added (from live connections).
        let mut seen_peer_ids = std::collections::HashSet::new();

        // 1. Live connected peers (enriched with announce data).
        let mut peers: Vec<PeerInfoResponse> = info
            .values()
            .map(|entry| {
                seen_peer_ids.insert(entry.peer_id.clone());

                let announce = record_map
                    .get(&entry.peer_id)
                    .and_then(|r| r.last_announce.as_ref());

                let addr = if entry.addr.is_empty() {
                    announce.and_then(|a| a.host_address.clone())
                } else {
                    Some(entry.addr.clone())
                };

                PeerInfoResponse {
                    peer_id: entry.peer_id.clone(),
                    direction: entry.direction.clone(),
                    addr,
                    node_name: announce.map(|a| a.node_name.clone()),
                    country_code: announce.and_then(|a| a.country_code.clone()),
                    connected_at: entry.connected_at,
                    ban_score: entry.ban_score,
                    last_ban_reason: None,
                    status: "connected".to_string(),
                    chain_tip_height: entry.chain_tip_height,
                    chain_tip_hash: entry.chain_tip_hash.clone(),
                }
            })
            .collect();

        // 2. Known validators/peers from peer_records that are NOT currently connected.
        for rec in &records {
            let hex_pid = hex::encode(&rec.peer_id_bytes);
            if seen_peer_ids.contains(&hex_pid) {
                continue;
            }
            let announce = rec.last_announce.as_ref();
            let addr = rec
                .last_addr
                .clone()
                .or_else(|| announce.and_then(|a| a.host_address.clone()));

            peers.push(PeerInfoResponse {
                peer_id: hex_pid,
                direction: "none".to_string(),
                addr,
                node_name: announce.map(|a| a.node_name.clone()),
                country_code: announce.and_then(|a| a.country_code.clone()),
                connected_at: 0,
                ban_score: 0,
                last_ban_reason: None,
                status: "disconnected".to_string(),
                chain_tip_height: None,
                chain_tip_hash: None,
            });
        }

        // Sort: connected first, then disconnected; within each group sort by peer_id.
        peers.sort_by(|a, b| {
            let ord = a.status.cmp(&b.status); // "connected" < "disconnected"
            if ord == std::cmp::Ordering::Equal {
                a.peer_id.cmp(&b.peer_id)
            } else {
                ord
            }
        });

        Ok(peers)
    }

    async fn get_network_info(&self) -> Result<NetworkInfoResponse, ErrorObjectOwned> {
        let stats = self.network_stats.read();
        Ok(NetworkInfoResponse {
            peer_count: stats.peer_count,
            inbound: stats.inbound_count,
            outbound: stats.outbound_count,
            clock_offset_ms: stats.median_clock_offset_ms,
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
                    host_address: announce.and_then(|a| a.host_address.clone()),
                    country_code: announce.and_then(|a| a.country_code.clone()),
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
        let multiaddr = normalize_multiaddr(&multiaddr);
        let addr: libp2p::Multiaddr = multiaddr
            .parse()
            .map_err(|e| ApiError::InvalidAddress(format!("invalid multiaddr: {e}")))?;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.network_cmd
            .send(NetworkCommand::DialPeer(addr, Some(tx)))
            .await
            .map_err(|e| ApiError::Internal(format!("failed to send dial command: {e}")))?;
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(Ok(()))) => Ok(DialPeerResponse {
                success: true,
                message: format!("Connected to {multiaddr}"),
            }),
            Ok(Ok(Err(reason))) => Ok(DialPeerResponse {
                success: false,
                message: reason,
            }),
            Ok(Err(_)) => Ok(DialPeerResponse {
                success: false,
                message: "Dial cancelled".into(),
            }),
            Err(_) => Ok(DialPeerResponse {
                success: false,
                message: "Connection timed out (10s)".into(),
            }),
        }
    }

    async fn get_seeds(&self) -> Result<SeedsResponse, ErrorObjectOwned> {
        let seeds = self.seeds.read().clone();
        Ok(SeedsResponse { seeds })
    }

    async fn add_seed(&self, multiaddr: String) -> Result<SeedsResponse, ErrorObjectOwned> {
        let multiaddr = normalize_multiaddr(&multiaddr);
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

        // Dial immediately (fire-and-forget for seed dial).
        let _ = self
            .network_cmd
            .send(NetworkCommand::DialPeer(addr, None))
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
