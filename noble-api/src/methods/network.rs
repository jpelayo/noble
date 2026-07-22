// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network-related RPC methods: getPeerInfo, getNetworkInfo, getSyncStatus, peer memory,
//! dialPeer, seed management.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_network::NetworkCommand;
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

/// Maximum length for a raw multiaddr/address input (bytes).
const MAX_ADDR_INPUT_LEN: usize = 512;

/// Maximum number of seed nodes a node will store.
const MAX_SEED_COUNT: usize = 64;

/// Default P2P port appended when the user omits one.
const DEFAULT_P2P_PORT: u16 = 8780;

/// Robustly convert user input into a libp2p multiaddr string.
///
/// Accepts:
/// - Full multiaddr: `/ip4/1.2.3.4/tcp/8780`, `/dns4/host.com/tcp/8780`
/// - Bare IPv4: `192.168.5.20` → `/ip4/192.168.5.20/tcp/8780`
/// - Bare IPv6: `::1`, `[::1]` → `/ip6/::1/tcp/8780`
/// - Hostname: `node.infinitecontext.com` → `/dns4/node.infinitecontext.com/tcp/8780`
/// - `host:port` or `ip:port`: `1.2.3.4:9000` → `/ip4/1.2.3.4/tcp/9000`
/// - URL form: `https://host:8783` → `/dns4/host/tcp/8783` (explicit port preserved)
///
/// Returns `Err` if the input is empty, overlong, or contains invalid characters.
fn normalize_multiaddr(input: &str) -> Result<String, String> {
    let input = input.trim();

    if input.is_empty() {
        return Err("address is empty".into());
    }
    if input.len() > MAX_ADDR_INPUT_LEN {
        return Err(format!("address too long ({} bytes, max {})", input.len(), MAX_ADDR_INPUT_LEN));
    }

    // Already a multiaddr — pass through (libp2p will validate).
    if input.starts_with('/') {
        return Ok(input.to_string());
    }

    // Strip URL scheme if present (https://host:port → host:port).
    let stripped = input
        .strip_prefix("https://")
        .or_else(|| input.strip_prefix("http://"))
        .unwrap_or(input);

    // Strip path/query from URL-style input (host:port/path?q → host:port).
    let stripped = stripped.split('/').next().unwrap_or(stripped);
    let stripped = stripped.split('?').next().unwrap_or(stripped);

    // Strip brackets from IPv6 (e.g. [::1]:8780 → ::1:8780 handled below, [::1] → ::1).
    let stripped = if stripped.starts_with('[') {
        // [::1]:8780 or [::1]
        if let Some(bracket_end) = stripped.find(']') {
            let ip6 = &stripped[1..bracket_end];
            let rest = &stripped[bracket_end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                // [::1]:8780
                if let Ok(port) = port_str.parse::<u16>() {
                    return Ok(format!("/ip6/{}/tcp/{}", ip6, port));
                }
            }
            // [::1] without port
            return Ok(format!("/ip6/{}/tcp/{}", ip6, DEFAULT_P2P_PORT));
        }
        stripped
    } else {
        stripped
    };

    // Reject control characters and whitespace within the address.
    if stripped.chars().any(|c| c.is_control() || c == ' ') {
        return Err("address contains invalid characters".into());
    }

    // Determine if this is IPv4, IPv6, or hostname, with optional :port.
    let has_alpha = stripped.chars().any(|c| c.is_ascii_alphabetic());
    let colon_count = stripped.chars().filter(|&c| c == ':').count();

    // IPv6 (multiple colons, e.g. "::1" or "fe80::1")
    if colon_count > 1 {
        return Ok(format!("/ip6/{}/tcp/{}", stripped, DEFAULT_P2P_PORT));
    }

    // host:port or ip:port (exactly one colon)
    if colon_count == 1 {
        let (host, port_str) = stripped.rsplit_once(':').unwrap();
        let port = port_str.parse::<u16>().unwrap_or(DEFAULT_P2P_PORT);
        if host.is_empty() {
            return Err("empty hostname before port".into());
        }
        return if has_alpha {
            Ok(format!("/dns4/{}/tcp/{}", host, port))
        } else {
            Ok(format!("/ip4/{}/tcp/{}", host, port))
        };
    }

    // Bare hostname or bare IPv4 (no colon).
    if has_alpha {
        Ok(format!("/dns4/{}/tcp/{}", stripped, DEFAULT_P2P_PORT))
    } else {
        Ok(format!("/ip4/{}/tcp/{}", stripped, DEFAULT_P2P_PORT))
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

    /// Get the list of discovered faucets on the network.
    ///
    /// The node probes peers' faucet endpoints periodically (configurable
    /// via `[faucet]` in noble.toml). Returns cached results.
    #[method(name = "getAvailableFaucets")]
    async fn get_available_faucets(&self) -> Result<AvailableFaucetsResponse, ErrorObjectOwned>;
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
                    verified_height: entry.verified_height,
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
                verified_height: None,
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
        // Single source of truth: read from the shared AlignmentSnapshot
        // computed by HealingManager::compute_alignment() per tick.
        let snap = self.alignment.read().clone();
        Ok(SyncStatusResponse {
            synced: matches!(snap.state, noble_consensus::AlignmentState::Aligned),
            current_height: snap.height,
            highest_known: snap.highest_known,
            progress: snap.progress,
            state: snap.state.label().to_string(),
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
                let key = noble_crypto::noble_addr::encode_wire_bytes(&rec.identity_key)
                    .unwrap_or_else(|| hex::encode(&rec.identity_key));
                seen_keys.insert(key.clone());
                let announce = rec.last_announce.as_ref();
                let key_hex = hex::encode(&rec.identity_key);
                PeerRecordResponse {
                    identity_key: key,
                    identity_key_hex: key_hex,
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
                    min_fee_rate: announce.and_then(|a| a.min_fee_rate),
                }
            })
            .collect();

        // Merge CBOR-persistent known_peers: enrich existing PeerRecords that lack
        // announce data, and add entries for peers not in PeerRecords at all.
        // This ensures candidate discovery survives chain resets (PeerRecords wiped)
        // and handles the case where the PeerRecord exists but has no announce yet.
        let registry = self.validator_registry.read();
        for (key_hex, peer) in registry.known_peers() {
            let display_key = hex::decode(key_hex).ok()
                .and_then(|wire| noble_crypto::noble_addr::encode_wire_bytes(&wire))
                .unwrap_or_else(|| key_hex.clone());
            if seen_keys.contains(&display_key) {
                // PeerRecord exists — enrich it with known_peer data if the
                // PeerRecord has no announce (wants_to_validate/vote are false).
                if let Some(entry) = result.iter_mut().find(|r| r.identity_key == display_key) {
                    if !entry.wants_to_validate && peer.wants_to_validate {
                        entry.wants_to_validate = true;
                    }
                    if !entry.wants_to_vote && peer.wants_to_vote {
                        entry.wants_to_vote = true;
                    }
                    if entry.node_name.is_none() {
                        entry.node_name = peer.node_name.clone();
                    }
                    if entry.org_type.is_none() {
                        entry.org_type = peer.org_type.clone();
                    }
                    if entry.node_role.is_none() {
                        entry.node_role = peer.node_role.clone();
                    }
                    if entry.host_address.is_none() {
                        entry.host_address = peer.host_address.clone();
                    }
                    if entry.country_code.is_none() {
                        entry.country_code = peer.country_code.clone();
                    }
                }
                continue;
            }
            result.push(PeerRecordResponse {
                identity_key: display_key,
                identity_key_hex: key_hex.clone(),
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
                min_fee_rate: None, // CBOR-persistent peers don't carry fee rate
            });
        }

        Ok(result)
    }

    async fn remove_peer_record(
        &self,
        identity_key: String,
    ) -> Result<serde_json::Value, ErrorObjectOwned> {
        // Accept both bech32m (nbl1...) and hex wire bytes.
        let key_bytes = if identity_key.starts_with("nbl1") {
            noble_crypto::noble_addr::decode(&identity_key)
                .map(|pk| pk.to_wire_bytes())
                .map_err(|e| ApiError::InvalidAddress(format!("invalid address: {e}")))?
        } else {
            hex::decode(&identity_key)
                .map_err(|_| ApiError::InvalidAddress("invalid hex".into()))?
        };
        // Lock order: Storage(2) before ValidatorRegistry(3).
        let storage = self.storage.read();
        storage
            .remove_peer_record(&key_bytes)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        drop(storage);
        // Also remove from CBOR known_peers so it doesn't reappear after chain reset.
        {
            let mut registry = self.validator_registry.write();
            let key_hex = hex::encode(&key_bytes);
            registry.remove_known_peer(&key_hex);
            if let Err(e) = registry.persist_if_dirty() {
                tracing::warn!("Failed to persist validator registry after peer removal: {e}");
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
        let multiaddr = normalize_multiaddr(&multiaddr)
            .map_err(|e| ApiError::InvalidAddress(e))?;
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
        let multiaddr = normalize_multiaddr(&multiaddr)
            .map_err(|e| ApiError::InvalidAddress(e))?;
        // Validate multiaddr syntax.
        let addr: libp2p::Multiaddr = multiaddr
            .parse()
            .map_err(|e| ApiError::InvalidAddress(format!("invalid multiaddr: {e}")))?;

        // Add to live list (skip duplicates, enforce max count).
        {
            let mut seeds = self.seeds.write();
            if seeds.len() >= MAX_SEED_COUNT {
                return Err(ApiError::InvalidAddress(
                    format!("maximum seed count reached ({MAX_SEED_COUNT})")
                ).into());
            }
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
        // Normalize so the match key is the same form as what add_seed stored.
        let normalized = normalize_multiaddr(&multiaddr).unwrap_or_else(|_| multiaddr.clone());
        {
            let mut seeds = self.seeds.write();
            seeds.retain(|s| s != &normalized && s != &multiaddr);
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
            if let Err(e) = storage.store_ban(&peer_bytes, banned_until, 0x0C, None) { // ManualBan
                tracing::warn!(task = "api", "failed to persist ban to storage: {e}");
            }
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
            if let Err(e) = storage.remove_ban(&peer_bytes) {
                tracing::warn!(task = "api", "failed to remove ban from storage: {e}");
            }
        }

        Ok(serde_json::json!({ "success": true }))
    }

    async fn get_available_faucets(&self) -> Result<AvailableFaucetsResponse, ErrorObjectOwned> {
        let faucets = self.faucet_cache.lock().clone();
        Ok(AvailableFaucetsResponse { faucets })
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
