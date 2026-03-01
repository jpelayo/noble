// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network service: main event loop connecting the swarm to the node via channels.

use std::sync::Arc;
use std::time::Duration;

use libp2p::gossipsub::{self, IdentTopic};
use libp2p::kad;
use libp2p::swarm::SwarmEvent;
use libp2p::{identify, ping, request_response};
use libp2p::{Multiaddr, PeerId, Swarm};

use libp2p::futures::StreamExt;
use tokio::sync::mpsc;

use crate::behaviour::{NobleBehaviour, NobleBehaviourEvent};
use crate::codec;
use crate::config::NetworkConfig;
use crate::diversity;
use crate::error::NetworkError;
use crate::messages::{
    GossipMessage, NetworkCommand, NetworkEvent, SyncRequest, SyncResponse, TxRequest, TxResponse,
};
use crate::peer_manager::{BanCategory, BanReason, Direction, PeerManager};
use crate::rate_limiter::TxRateLimiter;
use crate::seen_cache::{self, SeenCache};
use crate::topics;
use crate::traits::{BlockProvider, TxProvider};
use crate::transport::build_swarm;

/// Channel buffer size for commands and events.
const CHANNEL_BUFFER: usize = 256;

/// Interval for periodic maintenance tasks (ban cleanup, outbound connections).
const MAINTENANCE_INTERVAL_SECS: u64 = 60;

/// Handle to the running network service.
///
/// The node uses this to send commands and receive events.
pub struct NetworkHandle {
    command_tx: mpsc::Sender<NetworkCommand>,
    event_rx: mpsc::Receiver<NetworkEvent>,
    /// The P2P port that was actually bound (may differ from config if fallback was used).
    pub bound_port: u16,
    /// The stable PeerId of this node (loaded from or saved to `p2p_identity.key`).
    pub local_peer_id: PeerId,
}

impl NetworkHandle {
    /// Get a clone of the command sender (cheap, can be shared across tasks).
    pub fn command_sender(&self) -> mpsc::Sender<NetworkCommand> {
        self.command_tx.clone()
    }

    /// Receive the next event from the network (blocks until available).
    pub async fn recv_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.recv().await
    }

    /// Try to receive an event without blocking.
    pub fn try_recv_event(&mut self) -> Option<NetworkEvent> {
        self.event_rx.try_recv().ok()
    }
}

/// Start the network service. Returns a [`NetworkHandle`] for the node to interact with.
///
/// This spawns a tokio task that runs the libp2p swarm event loop.
pub async fn start_network(
    config: NetworkConfig,
    block_provider: Arc<dyn BlockProvider>,
    tx_provider: Arc<dyn TxProvider>,
) -> Result<NetworkHandle, NetworkError> {
    // Load or generate the P2P identity keypair.
    // When data_dir is set, the keypair is persisted to `p2p_identity.key` so
    // the node retains the same PeerId across restarts.
    let keypair = if let Some(ref data_dir) = config.data_dir {
        let key_path = data_dir.join("p2p_identity.key");
        if key_path.exists() {
            match std::fs::read(&key_path) {
                Ok(file_bytes) => {
                    // Decrypt Noble envelope (with legacy IKM fallback) or read legacy protobuf.
                    let proto_bytes =
                        if noble_crypto::file_encrypt::is_noble_envelope(&file_bytes) {
                            match config.chain_meta.as_ref().and_then(|cm| {
                                noble_crypto::file_encrypt::decrypt_file_data_with_migration(&file_bytes, cm).ok()
                            }) {
                                Some((d, migrated)) => {
                                    if migrated {
                                        if let Some(ref cm) = config.chain_meta {
                                            if let Ok(re_encrypted) = noble_crypto::file_encrypt::encrypt_file_data(&d, cm) {
                                                let _ = std::fs::write(&key_path, &re_encrypted);
                                            }
                                            tracing::info!(task = "key_migration", "Migrated P2P identity key to current encryption key");
                                        }
                                    }
                                    d
                                }
                                None => {
                                    tracing::warn!(
                                        task = "network_startup",
                                        "Failed to decrypt P2P keypair, generating new one"
                                    );
                                    Vec::new() // will fail protobuf decode → generate new
                                }
                            }
                        } else {
                            // Legacy plaintext protobuf — migrate in place.
                            if let Some(ref cm) = config.chain_meta {
                                if let Ok(encrypted) =
                                    noble_crypto::file_encrypt::encrypt_file_data(&file_bytes, cm)
                                {
                                    if std::fs::write(&key_path, &encrypted).is_ok() {
                                        #[cfg(unix)]
                                        {
                                            use std::os::unix::fs::PermissionsExt;
                                            let _ = std::fs::set_permissions(
                                                &key_path,
                                                std::fs::Permissions::from_mode(0o600),
                                            );
                                        }
                                        tracing::info!(
                                            task = "network_startup",
                                            "Migrated p2p_identity.key to encrypted Noble envelope"
                                        );
                                    }
                                }
                            }
                            file_bytes
                        };
                    match libp2p::identity::Keypair::from_protobuf_encoding(&proto_bytes) {
                        Ok(kp) => {
                            tracing::info!(
                                task = "network_startup",
                                "Loaded persistent P2P keypair from {}",
                                key_path.display()
                            );
                            kp
                        }
                        Err(e) => {
                            tracing::warn!(
                                task = "network_startup",
                                "Failed to decode P2P keypair ({}), generating new one",
                                e
                            );
                            let kp = libp2p::identity::Keypair::generate_ed25519();
                            save_p2p_keypair(&kp, &key_path, config.chain_meta.as_ref());
                            kp
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        task = "network_startup",
                        "Failed to read P2P keypair file ({}), generating new one",
                        e
                    );
                    libp2p::identity::Keypair::generate_ed25519()
                }
            }
        } else {
            let kp = libp2p::identity::Keypair::generate_ed25519();
            save_p2p_keypair(&kp, &key_path, config.chain_meta.as_ref());
            kp
        }
    } else {
        libp2p::identity::Keypair::generate_ed25519()
    };

    let local_peer_id = keypair.public().to_peer_id();
    tracing::info!(task = "network_startup", %local_peer_id, "starting network service");

    let mut swarm = build_swarm(keypair, &config)?;

    // Auto-bind: try the configured port first, then fall back to the other P2P ports.
    let base_addr = extract_base_addr(&config.listen_addr);
    let configured_port = extract_port(&config.listen_addr).unwrap_or(crate::config::P2P_PORT_PRIMARY);
    let mut ports_to_try: Vec<u16> = vec![configured_port];
    for &port in &crate::config::P2P_PORTS {
        if port != configured_port {
            ports_to_try.push(port);
        }
    }
    let bound_port = {
        let mut bound = None;
        for port in ports_to_try {
            let addr_str = format!("{base_addr}/tcp/{port}");
            match addr_str.parse::<Multiaddr>() {
                Ok(maddr) => match swarm.listen_on(maddr) {
                    Ok(_) => {
                        tracing::info!(
                            task = "network_startup",
                            port,
                            "P2P listening on {addr_str}"
                        );
                        bound = Some(port);
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(task = "network_startup", port, err = %e, "failed to bind P2P port, trying next");
                    }
                },
                Err(e) => {
                    tracing::warn!(task = "network_startup", port, err = %e, "invalid multiaddr");
                }
            }
        }
        bound.ok_or_else(|| {
            NetworkError::Transport("failed to bind on any P2P port (8780-8782)".into())
        })?
    };

    // Dial bootstrap peers and add them to Kademlia routing table.
    for addr_str in &config.bootstrap_peers {
        if let Ok(addr) = addr_str.parse::<Multiaddr>() {
            // Extract peer ID from multiaddr if present (e.g. /p2p/<peer_id>).
            let peer_id_from_addr = addr.iter().find_map(|p| {
                if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
                    Some(peer_id)
                } else {
                    None
                }
            });
            if let Err(e) = swarm.dial(addr.clone()) {
                tracing::warn!(task = "network_startup", %addr, err = %e, "failed to dial bootstrap peer");
            }
            // Add to Kademlia routing table for discovery.
            if config.enable_kademlia {
                if let Some(pid) = peer_id_from_addr {
                    swarm.behaviour_mut().kad.add_address(&pid, addr.clone());
                    // Also add port variants for multi-port discovery.
                    for variant in generate_port_variants(&addr) {
                        swarm.behaviour_mut().kad.add_address(&pid, variant);
                    }
                }
            }
        }
    }

    // Bootstrap Kademlia if enabled and we have bootstrap peers.
    if config.enable_kademlia && !config.bootstrap_peers.is_empty() {
        if let Err(e) = swarm.behaviour_mut().kad.bootstrap() {
            tracing::debug!(task = "network_startup", err = %e, "kademlia bootstrap (will retry on walk timer)");
        }
    }

    let (command_tx, command_rx) = mpsc::channel(CHANNEL_BUFFER);
    let (event_tx, event_rx) = mpsc::channel(CHANNEL_BUFFER);

    let peer_manager = PeerManager::new(&config);

    tokio::spawn(run_event_loop(
        swarm,
        config,
        peer_manager,
        block_provider,
        tx_provider,
        command_rx,
        event_tx,
    ));

    Ok(NetworkHandle {
        command_tx,
        event_rx,
        bound_port,
        local_peer_id,
    })
}

/// Save a P2P keypair to disk, optionally encrypted with Noble envelope.
fn save_p2p_keypair(
    kp: &libp2p::identity::Keypair,
    key_path: &std::path::Path,
    chain_meta: Option<&[u8; 32]>,
) {
    match kp.to_protobuf_encoding() {
        Ok(encoded) => {
            let file_data = if let Some(cm) = chain_meta {
                noble_crypto::file_encrypt::encrypt_file_data(&encoded, cm)
                    .unwrap_or_else(|_| encoded.clone())
            } else {
                encoded
            };
            if let Err(e) = std::fs::write(key_path, &file_data) {
                tracing::warn!(
                    task = "network_startup",
                    "Failed to save P2P keypair ({}), continuing with ephemeral identity",
                    e
                );
            } else {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        key_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                tracing::info!(
                    task = "network_startup",
                    "Generated and saved P2P keypair to {}",
                    key_path.display()
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                task = "network_startup",
                "Failed to encode P2P keypair for persistence ({}), continuing",
                e
            );
        }
    }
}

/// Internal event loop.
#[allow(clippy::too_many_lines)]
async fn run_event_loop(
    mut swarm: Swarm<NobleBehaviour>,
    config: NetworkConfig,
    mut peer_manager: PeerManager,
    block_provider: Arc<dyn BlockProvider>,
    tx_provider: Arc<dyn TxProvider>,
    mut command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
) {
    let mut maintenance_interval =
        tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
    let mut kad_walk_interval =
        tokio::time::interval(Duration::from_secs(config.kad_walk_interval_secs));
    let mut peer_exchange_interval =
        tokio::time::interval(Duration::from_secs(config.peer_exchange_interval_secs));
    let mut peer_rotation_interval =
        tokio::time::interval(Duration::from_secs(config.peer_rotation_interval_secs));
    // Skip the first immediate tick for periodic timers.
    kad_walk_interval.reset();
    peer_exchange_interval.reset();
    peer_rotation_interval.reset();

    // Gossip dedup caches (GAP-L12).
    let mut seen_blocks = SeenCache::new(Duration::from_secs(120), 10_000);
    let mut seen_txs = SeenCache::new(Duration::from_secs(120), 50_000);
    let mut seen_votes = SeenCache::new(Duration::from_secs(60), 10_000);

    // Per-peer tx relay rate limiter.
    let mut tx_rate_limiter =
        TxRateLimiter::new(config.tx_relay_burst, config.tx_relay_rate_per_sec);

    loop {
        tokio::select! {
            // --- Swarm events ---
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &config,
                    &mut peer_manager,
                    &block_provider,
                    &tx_provider,
                    &event_tx,
                    &mut seen_blocks,
                    &mut seen_txs,
                    &mut seen_votes,
                    &mut tx_rate_limiter,
                ).await;
            }

            // --- Commands from the node ---
            Some(cmd) = command_rx.recv() => {
                if handle_command(cmd, &mut swarm, &mut peer_manager, &config).await {
                    tracing::info!(task = "network_shutdown", "network service shutting down");
                    return;
                }
            }

            // --- Periodic maintenance ---
            _ = maintenance_interval.tick() => {
                let cleaned = peer_manager.cleanup_expired_bans();
                if cleaned > 0 {
                    tracing::debug!(task = "network_maintenance", cleaned, "expired bans removed");
                }
                // Evict expired cache entries.
                seen_blocks.evict_expired();
                seen_txs.evict_expired();
                seen_votes.evict_expired();
                // Cleanup stale rate limiter buckets.
                tx_rate_limiter.cleanup(Duration::from_secs(300));
            }

            // --- Kademlia random walk for peer discovery ---
            _ = kad_walk_interval.tick() => {
                if config.enable_kademlia {
                    let random_peer = PeerId::random();
                    swarm.behaviour_mut().kad.get_closest_peers(random_peer);
                    tracing::debug!(task = "peer_discovery", "kademlia random walk triggered");
                }
            }

            // --- Peer address exchange (GAP-H5) ---
            _ = peer_exchange_interval.tick() => {
                let mut addrs = peer_manager.connected_addrs();
                addrs.truncate(config.max_addrs_per_exchange);
                if !addrs.is_empty() {
                    let msg = GossipMessage::PeerExchange { addrs };
                    if let Ok(data) = codec::encode_gossip(&msg) {
                        let topic = IdentTopic::new(topics::TOPIC_PEER_EXCHANGE);
                        if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                            tracing::debug!(task = "peer_discovery", err = %e, "failed to publish peer exchange");
                        }
                    }
                }
            }

            // --- Peer rotation: evict worst outbound and discover replacement ---
            _ = peer_rotation_interval.tick() => {
                // Collect outbound peers with addresses for quality scoring.
                let outbound_peers: Vec<(PeerId, String, f64)> = swarm
                    .connected_peers()
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .filter_map(|pid| {
                        let state = peer_manager.get_peer(&pid)?;
                        if state.direction != Direction::Outbound {
                            return None;
                        }
                        let addr = state.addr.clone()?;
                        let score = diversity::peer_quality_score(state);
                        Some((pid, addr, score))
                    })
                    .collect();

                if outbound_peers.len() > 1 {
                    if let Some((worst_pid, _, _)) = outbound_peers
                        .iter()
                        .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
                    {
                        tracing::debug!(task = "peer_discovery", %worst_pid, "rotating worst outbound peer");
                        let _ = swarm.disconnect_peer_id(*worst_pid);
                        // Trigger Kademlia walk to find a replacement.
                        if config.enable_kademlia {
                            swarm
                                .behaviour_mut()
                                .kad
                                .get_closest_peers(PeerId::random());
                        }
                    }
                }
            }
        }
    }
}

/// Handle a swarm event.
#[allow(clippy::too_many_arguments)]
async fn handle_swarm_event(
    event: SwarmEvent<NobleBehaviourEvent>,
    swarm: &mut Swarm<NobleBehaviour>,
    config: &NetworkConfig,
    peer_manager: &mut PeerManager,
    block_provider: &Arc<dyn BlockProvider>,
    tx_provider: &Arc<dyn TxProvider>,
    event_tx: &mpsc::Sender<NetworkEvent>,
    seen_blocks: &mut SeenCache,
    seen_txs: &mut SeenCache,
    seen_votes: &mut SeenCache,
    tx_rate_limiter: &mut TxRateLimiter,
) {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            let direction = if endpoint.is_dialer() {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            let remote_addr = endpoint.get_remote_address().to_string();

            // Check subnet diversity for outbound connections.
            if direction == Direction::Outbound {
                let outbound_addrs = peer_manager.outbound_addrs();
                if !diversity::check_subnet_diversity(
                    &outbound_addrs,
                    &remote_addr,
                    config.max_outbound_per_subnet,
                ) {
                    tracing::debug!(task = "peer_management", %peer_id, %remote_addr, "rejecting outbound: subnet diversity");
                    let _ = swarm.disconnect_peer_id(peer_id);
                    return;
                }
            }

            // AUD2-H6: Check inbound subnet diversity (max 4 from same /16).
            if direction == Direction::Inbound {
                let inbound_addrs = peer_manager.inbound_addrs();
                if !diversity::check_inbound_subnet_diversity(
                    &inbound_addrs,
                    &remote_addr,
                    diversity::MAX_INBOUND_PER_SUBNET,
                ) {
                    tracing::debug!(task = "peer_management", %peer_id, %remote_addr, "rejecting inbound: subnet diversity (>4 from same /16)");
                    let _ = swarm.disconnect_peer_id(peer_id);
                    return;
                }
            }

            if peer_manager.on_connected(peer_id, direction) {
                peer_manager.update_addr(&peer_id, remote_addr.clone());
                tracing::debug!(task = "peer_management", %peer_id, ?direction, "peer connected");
                if event_tx
                    .try_send(NetworkEvent::PeerConnected {
                        peer_id: peer_id.to_bytes().to_vec(),
                        addr: remote_addr,
                        chain_tip: None,
                    })
                    .is_err()
                {
                    tracing::warn!(
                        task = "event_channel",
                        "event channel full: PeerConnected dropped"
                    );
                }
            } else {
                tracing::debug!(task = "peer_management", %peer_id, "peer rejected (limit or banned)");
                let _ = swarm.disconnect_peer_id(peer_id);
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            peer_manager.on_disconnected(&peer_id);
            tx_rate_limiter.remove_peer(&peer_id);
            if event_tx
                .try_send(NetworkEvent::PeerDisconnected {
                    peer_id: peer_id.to_bytes().to_vec(),
                })
                .is_err()
            {
                tracing::warn!(
                    task = "event_channel",
                    "event channel full: PeerDisconnected dropped"
                );
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Gossip(gossipsub::Event::Message {
            propagation_source,
            message,
            message_id,
            ..
        })) => {
            let topic_str = message.topic.as_str();
            tracing::debug!(
                task = "gossip_receive",
                "received message on topic: {}",
                topic_str
            );
            match codec::decode_gossip(&message.data) {
                Ok(gossip_msg) => {
                    let peer_bytes = propagation_source.to_bytes().to_vec();
                    let net_event = match gossip_msg {
                        GossipMessage::BlockAnnounce { block_hash, height } => {
                            handle_block_announce(
                                block_hash,
                                height,
                                &propagation_source,
                                peer_bytes,
                                seen_blocks,
                                swarm,
                            )
                        }
                        GossipMessage::TxAnnounce { tx_id } => handle_tx_announce(
                            tx_id,
                            &propagation_source,
                            peer_bytes,
                            seen_txs,
                            tx_rate_limiter,
                            peer_manager,
                        ),
                        GossipMessage::PorVote {
                            cycle,
                            candidate_hash,
                            voter_id,
                            signature,
                            round,
                        } => handle_por_vote(
                            peer_bytes.clone(),
                            cycle,
                            candidate_hash,
                            voter_id,
                            signature,
                            round,
                            seen_votes,
                        ),
                        GossipMessage::PeerExchange { addrs } => {
                            handle_peer_exchange(&addrs, config, swarm);
                            None
                        }
                        GossipMessage::NodeAnnounce {
                            identity_key,
                            node_name,
                            org_type,
                            org_name,
                            node_role,
                            contact_email,
                            website,
                            host_address,
                            software_version,
                            wants_to_validate,
                            wants_to_vote,
                            timestamp,
                            signature_scheme,
                            signature_pubkey,
                            signature_bytes,
                            attestation_scheme,
                            attestation_scope,
                            attestation_fingerprint,
                            attestation_data,
                        } => {
                            let result = convert_and_validate_announce(
                                &identity_key,
                                &node_name,
                                &org_type,
                                &org_name,
                                &node_role,
                                &contact_email,
                                &website,
                                &host_address,
                                &software_version,
                                wants_to_validate,
                                wants_to_vote,
                                timestamp,
                                signature_scheme,
                                &signature_pubkey,
                                &signature_bytes,
                                attestation_scheme.as_deref(),
                                attestation_scope.as_deref(),
                                attestation_fingerprint.as_deref(),
                                attestation_data.as_deref(),
                            );
                            handle_gossip_node_announce(
                                result,
                                &propagation_source,
                                peer_bytes,
                                peer_manager,
                            )
                        }
                        GossipMessage::DoubleProposalEvidence { evidence_bytes } => {
                            handle_double_proposal(&evidence_bytes, peer_bytes)
                        }
                    };
                    if let Some(evt) = net_event {
                        if event_tx.try_send(evt).is_err() {
                            tracing::warn!(
                                task = "event_channel",
                                "event channel full: gossip event dropped"
                            );
                        }
                    }
                    // Accept valid message for propagation.
                    let _ = swarm
                        .behaviour_mut()
                        .gossip
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            libp2p::gossipsub::MessageAcceptance::Accept,
                        );
                }
                Err(e) => {
                    tracing::warn!(task = "gossip_receive", %propagation_source, err = %e, "invalid gossip message");
                    peer_manager.record_misbehavior(
                        &propagation_source,
                        BanReason::new(
                            BanCategory::ProtocolViolation,
                            format!("malformed gossip: {e}"),
                        ),
                    );
                    let _ = swarm
                        .behaviour_mut()
                        .gossip
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            libp2p::gossipsub::MessageAcceptance::Reject,
                        );
                }
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::SyncRpc(request_response::Event::Message {
            peer: _,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) => {
            let response = handle_sync_request(&request, block_provider, config);
            let _ = swarm
                .behaviour_mut()
                .sync_rpc
                .send_response(channel, response);
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::SyncRpc(request_response::Event::Message {
            peer,
            message: request_response::Message::Response { response, .. },
            ..
        })) => {
            // Forward sync responses as block-received events.
            match response {
                SyncResponse::Blocks(blocks) => {
                    let peer_bytes = peer.to_bytes().to_vec();
                    for block in blocks {
                        if event_tx
                            .try_send(NetworkEvent::BlockReceived {
                                peer_id: peer_bytes.clone(),
                                block,
                            })
                            .is_err()
                        {
                            tracing::warn!(
                                task = "sync",
                                "event channel full: BlockReceived dropped"
                            );
                            break; // stop sending remaining blocks if channel is full
                        }
                    }
                }
                SyncResponse::Block(Some(block)) => {
                    if event_tx
                        .try_send(NetworkEvent::BlockReceived {
                            peer_id: peer.to_bytes().to_vec(),
                            block,
                        })
                        .is_err()
                    {
                        tracing::warn!(task = "sync", "event channel full: BlockReceived dropped");
                    }
                }
                SyncResponse::Status {
                    height,
                    tip_hash,
                    chain_id,
                    protocol_version,
                } => {
                    // GAP-H4: Verify chain_id and protocol_version.
                    if chain_id != config.chain_id || protocol_version != config.protocol_version {
                        tracing::warn!(
                            task = "sync",
                            %peer,
                            remote_chain_id = chain_id,
                            local_chain_id = config.chain_id,
                            "chain/protocol mismatch — disconnecting"
                        );
                        if peer_manager.record_misbehavior(
                            &peer,
                            BanReason::new(
                                BanCategory::ProtocolViolation,
                                format!(
                                    "chain_id mismatch: expected {}, got {}",
                                    config.chain_id, chain_id
                                ),
                            ),
                        ) {
                            let _ = swarm.disconnect_peer_id(peer);
                            if event_tx
                                .try_send(NetworkEvent::PeerBanned {
                                    peer_id: peer.to_bytes().to_vec(),
                                    reason: "chain/protocol mismatch".into(),
                                })
                                .is_err()
                            {
                                tracing::warn!(
                                    task = "event_channel",
                                    "event channel full: PeerBanned dropped"
                                );
                            }
                        }
                    } else {
                        peer_manager.update_chain_tip(&peer, height, tip_hash);
                    }
                }
                _ => {}
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::TxRpc(request_response::Event::Message {
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        })) => {
            handle_tx_rpc_request(tx_provider, request, channel, swarm);
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            handle_ping_event(peer_manager, &peer, rtt);
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            tracing::debug!(
                task = "peer_discovery",
                %peer_id,
                protocol = %info.protocol_version,
                agent = %info.agent_version,
                "identified peer"
            );

            // AUD-M5: Parse peer's protocol version and check major version compatibility.
            // Expected format: "/noble/1.0.0/<chain_id>/v<protocol_version>"
            let our_identify = format!(
                "{}/{}/v{}",
                crate::topics::IDENTIFY_PROTOCOL,
                config.chain_id,
                config.protocol_version,
            );
            // Extract the major version from our identify string (e.g. "1" from "/noble/1.0.0/...")
            let our_major = crate::topics::IDENTIFY_PROTOCOL
                .trim_start_matches("/noble/")
                .split('.')
                .next()
                .and_then(|s| s.parse::<u64>().ok());
            let peer_major = info
                .protocol_version
                .trim_start_matches("/noble/")
                .split('.')
                .next()
                .and_then(|s| s.parse::<u64>().ok());
            if let (Some(ours), Some(theirs)) = (our_major, peer_major) {
                if ours != theirs {
                    tracing::warn!(
                        task = "peer_discovery",
                        %peer_id,
                        our_version = %our_identify,
                        peer_version = %info.protocol_version,
                        "major protocol version mismatch with peer",
                    );
                }
            }

            // Feed identified peer addresses into Kademlia routing table.
            if config.enable_kademlia {
                for addr in &info.listen_addrs {
                    swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, addr.clone());
                    // Multi-port discovery: add variants for alternate ports.
                    for variant in generate_port_variants(addr) {
                        swarm.behaviour_mut().kad.add_address(&peer_id, variant);
                    }
                }
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Kad(event)) => {
            handle_kad_event(&event);
        }

        _ => {}
    }
}

/// Handle a block announce gossip message.
fn handle_block_announce(
    block_hash: [u8; 32],
    height: u64,
    source: &PeerId,
    peer_bytes: Vec<u8>,
    seen_blocks: &mut SeenCache,
    swarm: &mut Swarm<NobleBehaviour>,
) -> Option<NetworkEvent> {
    if !seen_blocks.insert_if_new(block_hash) {
        None
    } else {
        let request = SyncRequest::GetBlocks {
            hashes: vec![block_hash],
        };
        swarm.behaviour_mut().sync_rpc.send_request(source, request);
        Some(NetworkEvent::BlockAnnounced {
            peer_id: peer_bytes,
            hash: block_hash,
            height,
        })
    }
}

/// Handle a transaction announce gossip message.
fn handle_tx_announce(
    tx_id: [u8; 32],
    source: &PeerId,
    peer_bytes: Vec<u8>,
    seen_txs: &mut SeenCache,
    tx_rate_limiter: &mut TxRateLimiter,
    peer_manager: &mut PeerManager,
) -> Option<NetworkEvent> {
    if !tx_rate_limiter.try_consume(source) {
        peer_manager.record_misbehavior(
            source,
            BanReason::new(BanCategory::TxFlood, "tx relay rate limit exceeded"),
        );
        None
    } else if !seen_txs.insert_if_new(tx_id) {
        None
    } else {
        Some(NetworkEvent::TransactionAnnounced {
            peer_id: peer_bytes,
            tx_id,
        })
    }
}

/// Handle a Proof of Reputation vote gossip message.
fn handle_por_vote(
    peer_id: Vec<u8>,
    cycle: u64,
    candidate_hash: [u8; 32],
    voter_id: Vec<u8>,
    signature: Vec<u8>,
    round: u8,
    seen_votes: &mut SeenCache,
) -> Option<NetworkEvent> {
    let dedup_key = seen_cache::vote_dedup_key(cycle, &voter_id, round);
    if !seen_votes.insert_if_new(dedup_key) {
        None
    } else {
        // AUD3-D9: Include transport PeerId so the consensus engine can verify
        // that the vote source matches the claimed voter identity.
        Some(NetworkEvent::VoteReceived {
            peer_id,
            cycle,
            candidate_hash,
            voter_id,
            signature,
            round,
        })
    }
}

/// Handle a peer exchange gossip message.
fn handle_peer_exchange(
    addrs: &[String],
    config: &NetworkConfig,
    swarm: &mut Swarm<NobleBehaviour>,
) {
    if config.enable_kademlia {
        for addr_str in addrs {
            if let Ok(maddr) = addr_str.parse::<Multiaddr>() {
                let pid = maddr.iter().find_map(|p| {
                    if let libp2p::multiaddr::Protocol::P2p(id) = p {
                        Some(id)
                    } else {
                        None
                    }
                });
                if let Some(pid) = pid {
                    swarm.behaviour_mut().kad.add_address(&pid, maddr.clone());
                    for variant in generate_port_variants(&maddr) {
                        swarm.behaviour_mut().kad.add_address(&pid, variant);
                    }
                }
            }
        }
    }
}

/// Handle a validated (or invalid) node announce result.
fn handle_gossip_node_announce(
    result: Result<noble_core::NodeAnnounce, String>,
    source: &PeerId,
    peer_bytes: Vec<u8>,
    peer_manager: &mut PeerManager,
) -> Option<NetworkEvent> {
    match result {
        Ok(announce) => {
            peer_manager.update_announce(source, announce.clone());
            Some(NetworkEvent::NodeAnnounceReceived {
                peer_id: peer_bytes,
                announce: Box::new(announce),
            })
        }
        Err(reason) => {
            tracing::warn!(task = "gossip_receive", %source, %reason, "invalid node announce");
            peer_manager.record_misbehavior(
                source,
                BanReason::new(
                    BanCategory::InvalidAnnounce,
                    format!("invalid announce: {reason}"),
                ),
            );
            None
        }
    }
}

/// Handle a double-proposal evidence gossip message.
fn handle_double_proposal(evidence_bytes: &[u8], peer_bytes: Vec<u8>) -> Option<NetworkEvent> {
    match ciborium::from_reader::<noble_core::DoubleProposalEvidence, _>(evidence_bytes) {
        Ok(evidence) => match evidence.verify() {
            Ok(()) => {
                tracing::warn!(
                    task = "gossip_receive",
                    "valid double-proposal evidence received"
                );
                Some(NetworkEvent::EvidenceReceived {
                    peer_id: peer_bytes,
                    evidence: Box::new(evidence),
                })
            }
            Err(e) => {
                tracing::debug!(task = "gossip_receive", %e, "invalid evidence rejected");
                None
            }
        },
        Err(e) => {
            tracing::debug!(task = "gossip_receive", %e, "failed to decode evidence CBOR");
            None
        }
    }
}

/// Handle an incoming transaction RPC request.
fn handle_tx_rpc_request(
    tx_provider: &Arc<dyn TxProvider>,
    request: TxRequest,
    channel: request_response::ResponseChannel<TxResponse>,
    swarm: &mut Swarm<NobleBehaviour>,
) {
    let tx = tx_provider.get_transaction(&request.tx_id);
    let _ = swarm
        .behaviour_mut()
        .tx_rpc
        .send_response(channel, TxResponse { transaction: tx });
}

/// Handle a ping event by updating peer latency.
fn handle_ping_event(peer_manager: &mut PeerManager, peer: &PeerId, rtt: Duration) {
    peer_manager.update_latency(peer, rtt);
}

/// Handle a Kademlia event (logging only).
fn handle_kad_event(event: &kad::Event) {
    match event {
        kad::Event::OutboundQueryProgressed {
            result: kad::QueryResult::GetClosestPeers(Ok(ok)),
            ..
        } => {
            tracing::debug!(
                task = "peer_discovery",
                peers_found = ok.peers.len(),
                "kademlia walk found peers"
            );
        }
        kad::Event::RoutingUpdated { peer, .. } => {
            tracing::debug!(task = "peer_discovery", %peer, "kademlia routing table updated");
        }
        _ => {}
    }
}

/// Handle an incoming sync request by serving data from the block provider.
fn handle_sync_request(
    request: &SyncRequest,
    block_provider: &Arc<dyn BlockProvider>,
    config: &NetworkConfig,
) -> SyncResponse {
    match request {
        SyncRequest::GetHeaders {
            start_hash,
            max_count,
        } => {
            // Walk forward from start_hash by height, collecting headers.
            let mut headers = Vec::new();
            let limit = (*max_count).min(2000) as usize;

            if let Some(start_header) = block_provider.get_block_header(start_hash) {
                let mut height = start_header.height + 1;
                for _ in 0..limit {
                    if let Some(block) = block_provider.get_block_by_height(height) {
                        headers.push(block.header);
                        height += 1;
                    } else {
                        break;
                    }
                }
            }

            SyncResponse::Headers(headers)
        }

        SyncRequest::GetBlocks { hashes } => {
            let blocks: Vec<_> = hashes
                .iter()
                .filter_map(|h| block_provider.get_block(h))
                .collect();
            SyncResponse::Blocks(blocks)
        }

        SyncRequest::GetBlockByHeight { height } => {
            let block = block_provider.get_block_by_height(*height);
            SyncResponse::Block(block)
        }

        SyncRequest::GetStatus => {
            let (height, tip_hash) = block_provider.chain_tip();
            SyncResponse::Status {
                height,
                tip_hash,
                chain_id: config.chain_id,
                protocol_version: config.protocol_version,
            }
        }
    }
}

/// Handle a command from the node. Returns `true` if shutdown was requested.
async fn handle_command(
    cmd: NetworkCommand,
    swarm: &mut Swarm<NobleBehaviour>,
    peer_manager: &mut PeerManager,
    config: &NetworkConfig,
) -> bool {
    match cmd {
        NetworkCommand::PublishBlock(block) => {
            let block_hash = block
                .header
                .compute_block_hash()
                .map(|h| *h.as_bytes())
                .unwrap_or([0; 32]);
            let msg = GossipMessage::BlockAnnounce {
                block_hash,
                height: block.header.height,
            };
            if let Ok(data) = codec::encode_gossip(&msg) {
                let topic = IdentTopic::new(topics::TOPIC_BLOCK_ANNOUNCE);
                tracing::debug!(
                    task = "gossip_publish",
                    "publishing to topic: {}",
                    topics::TOPIC_BLOCK_ANNOUNCE
                );
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(task = "gossip_publish", err = %e, "failed to publish block announce");
                }
            }
        }

        NetworkCommand::PublishTransaction(tx) => {
            let tx_id = tx
                .compute_tx_id(config.chain_id)
                .map(|h| *h.as_bytes())
                .unwrap_or([0; 32]);
            let msg = GossipMessage::TxAnnounce { tx_id };
            if let Ok(data) = codec::encode_gossip(&msg) {
                let topic = IdentTopic::new(topics::TOPIC_TX_ANNOUNCE);
                tracing::debug!(
                    task = "gossip_publish",
                    "publishing to topic: {}",
                    topics::TOPIC_TX_ANNOUNCE
                );
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(task = "gossip_publish", err = %e, "failed to publish tx announce");
                }
            }
        }

        NetworkCommand::PublishVote {
            cycle,
            candidate_hash,
            voter_id,
            signature,
            round,
        } => {
            let msg = GossipMessage::PorVote {
                cycle,
                candidate_hash,
                voter_id,
                signature,
                round,
            };
            if let Ok(data) = codec::encode_gossip(&msg) {
                let topic = IdentTopic::new(topics::TOPIC_POR_VOTE);
                tracing::debug!(
                    task = "gossip_publish",
                    "publishing to topic: {}",
                    topics::TOPIC_POR_VOTE
                );
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(task = "gossip_publish", err = %e, "failed to publish vote");
                }
            }
        }

        NetworkCommand::RequestBlock { peer_id, hash } => {
            if let Ok(pid) = PeerId::from_bytes(&peer_id) {
                let request = SyncRequest::GetBlocks { hashes: vec![hash] };
                swarm.behaviour_mut().sync_rpc.send_request(&pid, request);
            }
        }

        NetworkCommand::RequestSync => {
            // Request status from all connected peers to discover who's ahead.
            let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
            for pid in peers {
                swarm
                    .behaviour_mut()
                    .sync_rpc
                    .send_request(&pid, SyncRequest::GetStatus);
            }
        }

        NetworkCommand::PublishNodeAnnounce(announce) => {
            // Flatten optional attestation for wire format
            let (att_scheme, att_scope, att_fingerprint, att_data) =
                if let Some(ref att) = announce.identity_attestation {
                    (
                        Some(att.scheme.clone()),
                        Some(att.scope.clone()),
                        Some(att.signer_fingerprint.to_vec()),
                        Some(att.signature_data.clone()),
                    )
                } else {
                    (None, None, None, None)
                };
            let msg = GossipMessage::NodeAnnounce {
                identity_key: announce.identity_key.to_wire_bytes(),
                node_name: announce.node_name.clone(),
                org_type: format!("{:?}", announce.org_type),
                org_name: announce.org_name.clone(),
                node_role: format!("{:?}", announce.node_role),
                contact_email: announce.contact_email.clone(),
                website: announce.website.clone(),
                host_address: announce.host_address.clone(),
                software_version: announce.software_version.clone(),
                wants_to_validate: announce.wants_to_validate,
                wants_to_vote: announce.wants_to_vote,
                timestamp: announce.timestamp,
                signature_scheme: announce.signature.scheme_id,
                signature_pubkey: announce.signature.public_key.clone(),
                signature_bytes: announce.signature.signature.clone(),
                attestation_scheme: att_scheme,
                attestation_scope: att_scope,
                attestation_fingerprint: att_fingerprint,
                attestation_data: att_data,
            };
            if let Ok(data) = codec::encode_gossip(&msg) {
                let topic = IdentTopic::new(topics::TOPIC_NODE_ANNOUNCE);
                tracing::debug!(
                    task = "gossip_publish",
                    "publishing to topic: {}",
                    topics::TOPIC_NODE_ANNOUNCE
                );
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(task = "gossip_publish", err = %e, "failed to publish node announce");
                }
            }
        }

        NetworkCommand::PublishEvidence(evidence) => {
            let mut evidence_bytes = Vec::new();
            if ciborium::into_writer(&*evidence, &mut evidence_bytes).is_ok() {
                let msg = GossipMessage::DoubleProposalEvidence { evidence_bytes };
                if let Ok(data) = codec::encode_gossip(&msg) {
                    let topic = IdentTopic::new(topics::TOPIC_EVIDENCE);
                    tracing::debug!(
                        task = "gossip_publish",
                        "publishing to topic: {}",
                        topics::TOPIC_EVIDENCE
                    );
                    if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                        tracing::warn!(task = "gossip_publish", err = %e, "failed to publish evidence");
                    }
                }
            }
        }

        NetworkCommand::RequestBlockByHash { hash } => {
            // Request the block from any connected peer.
            let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
            if let Some(pid) = peers.first() {
                let request = SyncRequest::GetBlocks { hashes: vec![hash] };
                swarm.behaviour_mut().sync_rpc.send_request(pid, request);
            }
        }

        NetworkCommand::BanPeer(peer_bytes) => {
            if let Ok(pid) = PeerId::from_bytes(&peer_bytes) {
                peer_manager.record_misbehavior(
                    &pid,
                    BanReason::new(
                        BanCategory::DuplicateProposal,
                        "ban command from consensus engine",
                    ),
                );
                let _ = swarm.disconnect_peer_id(pid);
            }
        }

        NetworkCommand::Shutdown => {
            return true;
        }
    }

    false
}

/// Extract the TCP port from a multiaddr string.
///
/// E.g. "/ip4/0.0.0.0/tcp/8781" → Some(8781).
/// Returns None if no `/tcp/` segment is found or the port is not a valid u16.
fn extract_port(multiaddr_str: &str) -> Option<u16> {
    multiaddr_str
        .rsplit("/tcp/")
        .next()?
        .split('/')
        .next()?
        .parse()
        .ok()
}

/// Extract the base multiaddr (everything before `/tcp/PORT`).
///
/// E.g. "/ip4/1.2.3.4/tcp/8780/p2p/QmFoo" → "/ip4/1.2.3.4".
/// If no `/tcp/` is found, returns the full input.
pub fn extract_base_addr(multiaddr_str: &str) -> String {
    if let Some(idx) = multiaddr_str.find("/tcp/") {
        multiaddr_str[..idx].to_string()
    } else {
        multiaddr_str.to_string()
    }
}

/// Generate port variants for multi-port peer discovery.
///
/// If the multiaddr's TCP port is one of [`P2P_PORTS`], returns multiaddrs
/// with the other two ports (preserving any `/p2p/` suffix).
/// If the port is not in `P2P_PORTS`, returns an empty vec.
pub fn generate_port_variants(addr: &Multiaddr) -> Vec<Multiaddr> {
    use crate::config::P2P_PORTS;

    // Find the TCP port in the multiaddr.
    let tcp_port = addr.iter().find_map(|p| {
        if let libp2p::multiaddr::Protocol::Tcp(port) = p {
            Some(port)
        } else {
            None
        }
    });

    let Some(port) = tcp_port else {
        return Vec::new();
    };

    // Only generate variants for known P2P ports.
    if !P2P_PORTS.contains(&port) {
        return Vec::new();
    }

    let mut variants = Vec::with_capacity(2);
    for &alt_port in &P2P_PORTS {
        if alt_port == port {
            continue;
        }
        // Rebuild the multiaddr replacing the TCP port.
        let new_addr: Multiaddr = addr
            .iter()
            .map(|p| {
                if let libp2p::multiaddr::Protocol::Tcp(_) = p {
                    libp2p::multiaddr::Protocol::Tcp(alt_port)
                } else {
                    p
                }
            })
            .collect();
        variants.push(new_addr);
    }
    variants
}

fn parse_org_type(s: &str) -> Option<noble_core::OrgType> {
    use noble_core::OrgType;
    match s {
        "Individual" => Some(OrgType::Individual),
        "PrivateNonProfit" => Some(OrgType::PrivateNonProfit),
        "PrivateCorporation" => Some(OrgType::PrivateCorporation),
        "PrivateStartup" => Some(OrgType::PrivateStartup),
        "PrivateAcademic" => Some(OrgType::PrivateAcademic),
        "PrivateInstitution" => Some(OrgType::PrivateInstitution),
        "PublicNational" => Some(OrgType::PublicNational),
        "PublicRegional" => Some(OrgType::PublicRegional),
        "PublicSupranational" => Some(OrgType::PublicSupranational),
        "PublicCorporation" => Some(OrgType::PublicCorporation),
        "PublicAcademic" => Some(OrgType::PublicAcademic),
        "PublicInstitution" => Some(OrgType::PublicInstitution),
        _ => None,
    }
}

fn parse_node_role(s: &str) -> Option<noble_core::NodeRole> {
    use noble_core::NodeRole;
    match s {
        "FullNode" => Some(NodeRole::FullNode),
        "Validator" => Some(NodeRole::Validator),
        "ArchiveNode" => Some(NodeRole::ArchiveNode),
        "LightClient" => Some(NodeRole::LightClient),
        "Gateway" => Some(NodeRole::Gateway),
        _ => None,
    }
}

/// Convert wire-format NodeAnnounce fields to a `noble_core::NodeAnnounce`,
/// then validate signature, field lengths, and timestamp freshness.
#[allow(clippy::too_many_arguments)]
fn convert_and_validate_announce(
    identity_key_bytes: &[u8],
    node_name: &str,
    org_type_str: &str,
    org_name: &Option<String>,
    node_role_str: &str,
    contact_email: &Option<String>,
    website: &Option<String>,
    host_address: &Option<String>,
    software_version: &str,
    wants_to_validate: bool,
    wants_to_vote: bool,
    timestamp: u64,
    signature_scheme: u8,
    signature_pubkey: &[u8],
    signature_bytes: &[u8],
    attestation_scheme: Option<&str>,
    attestation_scope: Option<&str>,
    attestation_fingerprint: Option<&[u8]>,
    attestation_data: Option<&[u8]>,
) -> Result<noble_core::NodeAnnounce, String> {
    let identity_key = noble_crypto::NoblePublicKey::from_wire_bytes(identity_key_bytes)
        .map_err(|e| format!("invalid identity key: {e}"))?;

    let org_type =
        parse_org_type(org_type_str).ok_or_else(|| format!("unknown org_type: {org_type_str}"))?;

    let node_role = parse_node_role(node_role_str)
        .ok_or_else(|| format!("unknown node_role: {node_role_str}"))?;

    // Reconstruct attestation — all-or-nothing: all 4 fields must be present or absent
    let identity_attestation = match (
        attestation_scheme,
        attestation_scope,
        attestation_fingerprint,
        attestation_data,
    ) {
        (Some(scheme), Some(scope), Some(fp), Some(data)) => {
            if fp.len() != 32 {
                return Err(format!(
                    "attestation fingerprint must be 32 bytes, got {}",
                    fp.len()
                ));
            }
            let mut fingerprint = [0u8; 32];
            fingerprint.copy_from_slice(fp);
            Some(noble_core::ExternalAttestation {
                scheme: scheme.to_string(),
                scope: scope.to_string(),
                signer_fingerprint: fingerprint,
                signature_data: data.to_vec(),
            })
        }
        (None, None, None, None) => None,
        _ => return Err("attestation fields must be all present or all absent".to_string()),
    };

    let announce = noble_core::NodeAnnounce {
        version: noble_core::NODE_ANNOUNCE_VERSION,
        identity_key,
        node_name: node_name.to_string(),
        org_type,
        org_name: org_name.clone(),
        node_role,
        contact_email: contact_email.clone(),
        website: website.clone(),
        host_address: host_address.clone(),
        software_version: software_version.to_string(),
        wants_to_validate,
        wants_to_vote,
        timestamp,
        signature: noble_crypto::SignatureEnvelope {
            scheme_id: signature_scheme,
            public_key: signature_pubkey.to_vec(),
            signature: signature_bytes.to_vec(),
        },
        identity_attestation,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    announce
        .validate(now)
        .map_err(|e| format!("validation: {e}"))?;
    announce
        .verify_signature()
        .map_err(|e| format!("signature: {e}"))?;

    Ok(announce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{BlockProvider, TxProvider};
    use noble_core::{Block, BlockHeader, Transaction};
    use std::sync::Arc;

    /// Minimal block provider for tests.
    struct MockBlockProvider {
        tip: (u64, [u8; 32]),
    }

    impl BlockProvider for MockBlockProvider {
        fn get_block(&self, _hash: &[u8; 32]) -> Option<Block> {
            None
        }
        fn get_block_by_height(&self, _height: u64) -> Option<Block> {
            None
        }
        fn get_block_header(&self, _hash: &[u8; 32]) -> Option<BlockHeader> {
            None
        }
        fn chain_tip(&self) -> (u64, [u8; 32]) {
            self.tip
        }
    }

    struct MockTxProvider;

    impl TxProvider for MockTxProvider {
        fn get_transaction(&self, _tx_id: &[u8; 32]) -> Option<Transaction> {
            None
        }
        fn has_transaction(&self, _tx_id: &[u8; 32]) -> bool {
            false
        }
    }

    #[test]
    fn handle_sync_request_get_status() {
        let bp: Arc<dyn BlockProvider> = Arc::new(MockBlockProvider {
            tip: (42, [0xAA; 32]),
        });
        let config = NetworkConfig::testnet();
        let response = handle_sync_request(&SyncRequest::GetStatus, &bp, &config);
        match response {
            SyncResponse::Status {
                height,
                tip_hash,
                chain_id,
                ..
            } => {
                assert_eq!(height, 42);
                assert_eq!(tip_hash, [0xAA; 32]);
                assert_eq!(chain_id, config.chain_id);
            }
            _ => panic!("expected Status response"),
        }
    }

    #[test]
    fn handle_sync_request_get_block_not_found() {
        let bp: Arc<dyn BlockProvider> = Arc::new(MockBlockProvider { tip: (0, [0; 32]) });
        let config = NetworkConfig::testnet();
        let response =
            handle_sync_request(&SyncRequest::GetBlockByHeight { height: 999 }, &bp, &config);
        match response {
            SyncResponse::Block(None) => {}
            _ => panic!("expected Block(None)"),
        }
    }

    #[test]
    fn handle_sync_request_get_blocks_empty() {
        let bp: Arc<dyn BlockProvider> = Arc::new(MockBlockProvider { tip: (0, [0; 32]) });
        let config = NetworkConfig::testnet();
        let response = handle_sync_request(
            &SyncRequest::GetBlocks {
                hashes: vec![[0xFF; 32]],
            },
            &bp,
            &config,
        );
        match response {
            SyncResponse::Blocks(blocks) => assert!(blocks.is_empty()),
            _ => panic!("expected Blocks"),
        }
    }

    #[tokio::test]
    async fn network_starts_and_handles_shutdown() {
        let config = NetworkConfig::testnet();
        let bp: Arc<dyn BlockProvider> = Arc::new(MockBlockProvider { tip: (0, [0; 32]) });
        let tp: Arc<dyn TxProvider> = Arc::new(MockTxProvider);

        let handle = start_network(config, bp, tp).await.unwrap();

        // Send shutdown.
        handle
            .command_sender()
            .send(NetworkCommand::Shutdown)
            .await
            .unwrap();

        // After shutdown the event channel should eventually close.
        // Give the task a moment to process.
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn network_handle_clone_sender() {
        let config = NetworkConfig::testnet();
        let bp: Arc<dyn BlockProvider> = Arc::new(MockBlockProvider { tip: (0, [0; 32]) });
        let tp: Arc<dyn TxProvider> = Arc::new(MockTxProvider);

        let handle = start_network(config, bp, tp).await.unwrap();
        let sender1 = handle.command_sender();
        let sender2 = handle.command_sender();

        // Both senders should work.
        sender1.send(NetworkCommand::RequestSync).await.unwrap();
        sender2.send(NetworkCommand::Shutdown).await.unwrap();
    }

    // --- Port variant and extract_base_addr tests ---

    #[test]
    fn generate_port_variants_primary() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/8780".parse().unwrap();
        let variants = generate_port_variants(&addr);
        assert_eq!(variants.len(), 2);
        assert_eq!(
            variants[0],
            "/ip4/1.2.3.4/tcp/8781".parse::<Multiaddr>().unwrap()
        );
        assert_eq!(
            variants[1],
            "/ip4/1.2.3.4/tcp/8782".parse::<Multiaddr>().unwrap()
        );
    }

    #[test]
    fn generate_port_variants_alt1() {
        let addr: Multiaddr = "/ip4/10.0.0.1/tcp/8781".parse().unwrap();
        let variants = generate_port_variants(&addr);
        assert_eq!(variants.len(), 2);
        assert_eq!(
            variants[0],
            "/ip4/10.0.0.1/tcp/8780".parse::<Multiaddr>().unwrap()
        );
        assert_eq!(
            variants[1],
            "/ip4/10.0.0.1/tcp/8782".parse::<Multiaddr>().unwrap()
        );
    }

    #[test]
    fn generate_port_variants_unknown_port() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/9999".parse().unwrap();
        let variants = generate_port_variants(&addr);
        assert!(variants.is_empty());
    }

    #[test]
    fn generate_port_variants_no_tcp() {
        let addr: Multiaddr = "/ip4/1.2.3.4/udp/8780".parse().unwrap();
        let variants = generate_port_variants(&addr);
        assert!(variants.is_empty());
    }

    #[test]
    fn generate_port_variants_preserves_p2p_suffix() {
        let addr: Multiaddr =
            "/ip4/1.2.3.4/tcp/8780/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
                .parse()
                .unwrap();
        let variants = generate_port_variants(&addr);
        assert_eq!(variants.len(), 2);
        // Verify /p2p/ suffix is preserved
        let v0_str = variants[0].to_string();
        assert!(v0_str.contains("/tcp/8781/"));
        assert!(v0_str.contains("/p2p/"));
    }

    #[test]
    fn extract_base_addr_standard() {
        assert_eq!(extract_base_addr("/ip4/1.2.3.4/tcp/8780"), "/ip4/1.2.3.4");
    }

    #[test]
    fn extract_base_addr_no_tcp() {
        assert_eq!(
            extract_base_addr("/ip4/1.2.3.4/udp/1234"),
            "/ip4/1.2.3.4/udp/1234"
        );
    }

    // ---- AUD2-H6: Inbound subnet diversity test ----

    #[test]
    fn inbound_subnet_diversity_rejects_5th_from_same_slash16() {
        // The check_inbound_subnet_diversity function should reject the 5th peer
        // from the same /16 subnet when max_per_subnet = 4.
        let existing = vec![
            "/ip4/10.5.1.1/tcp/8780".to_string(),
            "/ip4/10.5.2.2/tcp/8780".to_string(),
            "/ip4/10.5.3.3/tcp/8780".to_string(),
            "/ip4/10.5.4.4/tcp/8780".to_string(), // 4 from 10.5.x.x
        ];
        // 5th from same /16 — should be rejected (max = 4).
        assert!(
            !diversity::check_inbound_subnet_diversity(
                &existing,
                "/ip4/10.5.5.5/tcp/8780",
                diversity::MAX_INBOUND_PER_SUBNET,
            ),
            "5th inbound from same /16 should be rejected"
        );
        // A peer from a different /16 should be accepted.
        assert!(
            diversity::check_inbound_subnet_diversity(
                &existing,
                "/ip4/192.168.1.1/tcp/8780",
                diversity::MAX_INBOUND_PER_SUBNET,
            ),
            "peer from different /16 should be accepted"
        );
    }
}
