// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network-related RPC methods: getPeerInfo, getNetworkInfo, getSyncStatus, peer memory,
//! dialPeer, seed management.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_codec::NobleCbor;
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

    /// List all currently banned peers.
    #[method(name = "listBannedPeers")]
    async fn list_banned_peers(&self) -> Result<Vec<BannedPeerResponse>, ErrorObjectOwned>;

    /// Manually ban a peer by peer ID (hex-encoded).
    #[method(name = "banPeer")]
    async fn ban_peer(
        &self,
        peer_id: String,
        reason: String,
        duration_secs: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned>;

    /// Unban a peer by peer ID (hex-encoded).
    #[method(name = "unbanPeer")]
    async fn unban_peer(&self, peer_id: String) -> Result<serde_json::Value, ErrorObjectOwned>;
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

                let cat_names: Vec<String> = entry.misbehavior_categories.iter()
                    .filter_map(|&code| {
                        noble_network::BanCategory::from_u8(code)
                            .map(|c| c.as_str().to_string())
                    })
                    .collect();

                PeerInfoResponse {
                    peer_id: entry.peer_id.clone(),
                    direction: entry.direction.clone(),
                    addr,
                    node_name: announce.map(|a| a.node_name.clone()),
                    country_code: announce.and_then(|a| a.country_code.clone()),
                    connected_at: entry.connected_at,
                    ban_score: entry.ban_score,
                    misbehavior_categories: cat_names,
                    last_ban_reason: entry.last_ban_reason.as_ref().map(|(cat, subj)| {
                        crate::types::BanReasonResponse {
                            category: cat.clone(),
                            subject: subj.clone(),
                        }
                    }),
                    status: "connected".to_string(),
                    chain_tip_height: entry.chain_tip_height,
                    chain_tip_hash: entry.chain_tip_hash.clone(),
                    latency_ms: entry.latency_ms,
                }
            })
            .collect();

        // 2. Known validators/peers from peer_records that are NOT currently connected.
        for rec in &records {
            if rec.peer_id_bytes.is_empty() {
                continue; // Skip stubs with no real PeerId (safety net)
            }
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
                misbehavior_categories: Vec::new(),
                last_ban_reason: None,
                status: "disconnected".to_string(),
                chain_tip_height: None,
                chain_tip_hash: None,
                latency_ms: None,
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
            max_peers: self.max_peers.load(std::sync::atomic::Ordering::Relaxed),
            clock_offset_ms: stats.median_clock_offset_ms,
        })
    }

    async fn get_sync_status(&self) -> Result<SyncStatusResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read();
        let (height, _hash) = consensus.chain_tip();
        drop(consensus); // Release lock before acquiring peer_info (lock order).

        // Compute highest_known from connected peers' chain tips.
        let highest_known = {
            let info = self.peer_info.read();
            info.values()
                .filter_map(|entry| entry.chain_tip_height)
                .max()
                .unwrap_or(height)
                .max(height)
        };

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
        // Lock order: Storage(2) before Consensus(3).
        let storage = self.storage.read();
        let records = storage
            .list_peer_records()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        drop(storage);

        let mut seen_keys = std::collections::HashSet::new();
        let mut result: Vec<PeerRecordResponse> = records
            .into_iter()
            .map(|rec| {
                let key = hex::encode(&rec.identity_key);
                seen_keys.insert(key.clone());
                let announce = rec.last_announce.as_ref();
                PeerRecordResponse {
                    identity_key: key,
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
            .collect();

        // Merge CBOR-persistent known_peers for any identity keys not in PeerRecords.
        // This ensures candidate discovery survives chain resets (PeerRecords wiped).
        let engine = self.consensus.read();
        for (key_hex, peer) in engine.validator_list().known_peers() {
            if seen_keys.contains(key_hex) {
                continue;
            }
            result.push(PeerRecordResponse {
                identity_key: key_hex.clone(),
                first_seen: peer.first_seen,
                last_seen: peer.last_seen,
                connection_count: 0,
                peer_id: peer.peer_id_hex.clone().unwrap_or_default(),
                last_addr: peer.host_address.clone(),
                node_name: peer.node_name.clone(),
                org_type: peer.org_type.clone(),
                node_role: peer.node_role.clone(),
                host_address: peer.host_address.clone(),
                country_code: peer.country_code.clone(),
                wants_to_validate: peer.wants_to_validate,
                wants_to_vote: peer.wants_to_vote,
            });
        }

        Ok(result)
    }

    async fn remove_peer_record(
        &self,
        identity_key: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let key_bytes = hex::decode(&identity_key)
            .map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?;
        // Lock order: Storage(2) before Consensus(3).
        let storage = self.storage.read();
        storage
            .remove_peer_record(&key_bytes)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        drop(storage);
        // Also remove from CBOR known_peers so it doesn't reappear after chain reset.
        {
            let mut engine = self.consensus.write();
            engine.validator_list_mut().remove_known_peer(&identity_key);
            // Persist CBOR.
            if let Some(ref path) = self.validator_list_path {
                if let Ok(bytes) = engine.validator_list().to_cbor() {
                    let _ = std::fs::write(path, &bytes);
                }
            }
        }
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

    async fn list_banned_peers(&self) -> Result<Vec<BannedPeerResponse>, ErrorObjectOwned> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.network_cmd
            .send(NetworkCommand::ListBannedPeers(tx))
            .await
            .map_err(|e| ApiError::Internal(format!("failed to send list bans command: {e}")))?;
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(entries)) => {
                // Enrich with node_name from peer records
                let records = {
                    let storage = self.storage.read();
                    storage.list_peer_records().unwrap_or_default()
                };
                let name_map: std::collections::HashMap<String, String> = records
                    .iter()
                    .filter_map(|r| {
                        r.last_announce
                            .as_ref()
                            .map(|a| (hex::encode(&r.peer_id_bytes), a.node_name.clone()))
                    })
                    .collect();
                let result = entries
                    .into_iter()
                    .map(|e| {
                        let pid_hex = hex::encode(&e.peer_id_bytes);
                        BannedPeerResponse {
                            peer_id: pid_hex.clone(),
                            ban_score: e.ban_score,
                            banned_until: e.banned_until,
                            reason_category: e.reason_category,
                            reason_subject: e.reason_subject,
                            reason_codes: e.reason_codes,
                            node_name: name_map.get(&pid_hex).cloned(),
                            evidence_hash: e.evidence_hash,
                        }
                    })
                    .collect();
                Ok(result)
            }
            Ok(Err(_)) => Err(ApiError::Internal("list bans cancelled".into()).into()),
            Err(_) => Err(ApiError::Internal("list bans timed out".into()).into()),
        }
    }

    async fn ban_peer(
        &self,
        peer_id: String,
        reason: String,
        duration_secs: Option<u64>,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        let peer_bytes = hex::decode(&peer_id)
            .map_err(|_| ApiError::InvalidAddress("invalid hex peer_id".into()))?;
        let dur = duration_secs.unwrap_or(86400); // default 24h
        self.network_cmd
            .send(NetworkCommand::ManualBanPeer {
                peer_id: peer_bytes.clone(),
                reason: reason.clone(),
                duration_secs: dur,
            })
            .await
            .map_err(|e| ApiError::Internal(format!("failed to send ban command: {e}")))?;

        // Persist to storage
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let banned_until = now + dur;
        {
            let storage = self.storage.read();
            let _ = storage.store_ban(&peer_bytes, banned_until, 0x0C, None); // ManualBan
        }

        Ok(serde_json::json!({ "success": true, "banned_until": banned_until }))
    }

    async fn unban_peer(&self, peer_id: String) -> Result<serde_json::Value, ErrorObjectOwned> {
        let peer_bytes = hex::decode(&peer_id)
            .map_err(|_| ApiError::InvalidAddress("invalid hex peer_id".into()))?;
        self.network_cmd
            .send(NetworkCommand::UnbanPeer(peer_bytes.clone()))
            .await
            .map_err(|e| ApiError::Internal(format!("failed to send unban command: {e}")))?;

        // Remove from storage
        {
            let storage = self.storage.read();
            let _ = storage.remove_ban(&peer_bytes);
        }

        Ok(serde_json::json!({ "success": true }))
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
