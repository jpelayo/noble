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
    GossipMessage, NetworkCommand, NetworkEvent, SyncRequest, SyncResponse, TxResponse,
};
use crate::peer_manager::{Direction, Misbehavior, PeerManager};
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
    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = keypair.public().to_peer_id();
    tracing::info!(%local_peer_id, "starting network service");

    let mut swarm = build_swarm(keypair, &config)?;

    // Listen on configured address.
    let listen_addr: Multiaddr = config
        .listen_addr
        .parse()
        .map_err(|e: libp2p::multiaddr::Error| NetworkError::Transport(e.to_string()))?;
    swarm
        .listen_on(listen_addr)
        .map_err(|e| NetworkError::Transport(e.to_string()))?;

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
                tracing::warn!(%addr, err = %e, "failed to dial bootstrap peer");
            }
            // Add to Kademlia routing table for discovery.
            if config.enable_kademlia {
                if let Some(pid) = peer_id_from_addr {
                    swarm.behaviour_mut().kad.add_address(&pid, addr);
                }
            }
        }
    }

    // Bootstrap Kademlia if enabled and we have bootstrap peers.
    if config.enable_kademlia && !config.bootstrap_peers.is_empty() {
        if let Err(e) = swarm.behaviour_mut().kad.bootstrap() {
            tracing::debug!(err = %e, "kademlia bootstrap (will retry on walk timer)");
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
    })
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
                    tracing::info!("network service shutting down");
                    return;
                }
            }

            // --- Periodic maintenance ---
            _ = maintenance_interval.tick() => {
                let cleaned = peer_manager.cleanup_expired_bans();
                if cleaned > 0 {
                    tracing::debug!(cleaned, "expired bans removed");
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
                    tracing::debug!("kademlia random walk triggered");
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
                            tracing::debug!(err = %e, "failed to publish peer exchange");
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
                        tracing::debug!(%worst_pid, "rotating worst outbound peer");
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
                    tracing::debug!(%peer_id, %remote_addr, "rejecting outbound: subnet diversity");
                    let _ = swarm.disconnect_peer_id(peer_id);
                    return;
                }
            }

            if peer_manager.on_connected(peer_id, direction) {
                peer_manager.update_addr(&peer_id, remote_addr.clone());
                tracing::debug!(%peer_id, ?direction, "peer connected");
                let _ = event_tx
                    .send(NetworkEvent::PeerConnected {
                        peer_id: peer_id.to_bytes().to_vec(),
                        addr: remote_addr,
                        chain_tip: None,
                    })
                    .await;
            } else {
                tracing::debug!(%peer_id, "peer rejected (limit or banned)");
                let _ = swarm.disconnect_peer_id(peer_id);
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, .. } => {
            peer_manager.on_disconnected(&peer_id);
            tx_rate_limiter.remove_peer(&peer_id);
            let _ = event_tx
                .send(NetworkEvent::PeerDisconnected {
                    peer_id: peer_id.to_bytes().to_vec(),
                })
                .await;
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Gossip(gossipsub::Event::Message {
            propagation_source,
            message,
            message_id,
            ..
        })) => {
            let topic_str = message.topic.as_str();
            tracing::debug!(task = "gossip_receive", "received message on topic: {}", topic_str);
            match codec::decode_gossip(&message.data) {
                Ok(gossip_msg) => {
                    let peer_bytes = propagation_source.to_bytes().to_vec();
                    let net_event = match gossip_msg {
                        GossipMessage::BlockAnnounce { block_hash, height } => {
                            // Dedup: skip if already seen.
                            if !seen_blocks.insert_if_new(block_hash) {
                                None
                            } else {
                                // Auto-request full block via sync RPC.
                                let request = SyncRequest::GetBlocks {
                                    hashes: vec![block_hash],
                                };
                                swarm
                                    .behaviour_mut()
                                    .sync_rpc
                                    .send_request(&propagation_source, request);
                                Some(NetworkEvent::BlockAnnounced {
                                    peer_id: peer_bytes,
                                    hash: block_hash,
                                    height,
                                })
                            }
                        }
                        GossipMessage::TxAnnounce { tx_id } => {
                            // Rate limit check.
                            if !tx_rate_limiter.try_consume(&propagation_source) {
                                peer_manager
                                    .record_misbehavior(&propagation_source, Misbehavior::TxFlood);
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
                        GossipMessage::PorVote {
                            cycle,
                            candidate_hash,
                            voter_id,
                            signature,
                        } => {
                            // Vote dedup (GAP-L12).
                            let dedup_key = seen_cache::vote_dedup_key(cycle, &voter_id);
                            if !seen_votes.insert_if_new(dedup_key) {
                                None
                            } else {
                                Some(NetworkEvent::VoteReceived {
                                    cycle,
                                    candidate_hash,
                                    voter_id,
                                    signature,
                                })
                            }
                        }
                        GossipMessage::PeerExchange { addrs } => {
                            // Add received addresses to Kademlia routing table.
                            if config.enable_kademlia {
                                for addr_str in &addrs {
                                    if let Ok(maddr) = addr_str.parse::<Multiaddr>() {
                                        // Extract peer_id from the multiaddr if present.
                                        let pid = maddr.iter().find_map(|p| {
                                            if let libp2p::multiaddr::Protocol::P2p(id) = p {
                                                Some(id)
                                            } else {
                                                None
                                            }
                                        });
                                        if let Some(pid) = pid {
                                            swarm.behaviour_mut().kad.add_address(&pid, maddr);
                                        }
                                    }
                                }
                            }
                            None // No NetworkEvent for peer exchange.
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
                            match convert_and_validate_announce(
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
                            ) {
                                Ok(announce) => {
                                    peer_manager
                                        .update_announce(&propagation_source, announce.clone());
                                    Some(NetworkEvent::NodeAnnounceReceived {
                                        peer_id: peer_bytes,
                                        announce: Box::new(announce),
                                    })
                                }
                                Err(reason) => {
                                    tracing::warn!(
                                        %propagation_source,
                                        %reason,
                                        "invalid node announce"
                                    );
                                    peer_manager.record_misbehavior(
                                        &propagation_source,
                                        Misbehavior::InvalidAnnounce,
                                    );
                                    None
                                }
                            }
                        }
                        GossipMessage::DoubleProposalEvidence { evidence_bytes } => {
                            match ciborium::from_reader::<noble_core::DoubleProposalEvidence, _>(
                                &evidence_bytes[..],
                            ) {
                                Ok(evidence) => match evidence.verify() {
                                    Ok(()) => {
                                        tracing::warn!("valid double-proposal evidence received");
                                        Some(NetworkEvent::EvidenceReceived {
                                            peer_id: peer_bytes,
                                            evidence: Box::new(evidence),
                                        })
                                    }
                                    Err(e) => {
                                        tracing::debug!(%e, "invalid evidence rejected");
                                        None
                                    }
                                },
                                Err(e) => {
                                    tracing::debug!(%e, "failed to decode evidence CBOR");
                                    None
                                }
                            }
                        }
                    };
                    if let Some(evt) = net_event {
                        let _ = event_tx.send(evt).await;
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
                    tracing::warn!(%propagation_source, err = %e, "invalid gossip message");
                    peer_manager
                        .record_misbehavior(&propagation_source, Misbehavior::ProtocolViolation);
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
                        let _ = event_tx
                            .send(NetworkEvent::BlockReceived {
                                peer_id: peer_bytes.clone(),
                                block,
                            })
                            .await;
                    }
                }
                SyncResponse::Block(Some(block)) => {
                    let _ = event_tx
                        .send(NetworkEvent::BlockReceived {
                            peer_id: peer.to_bytes().to_vec(),
                            block,
                        })
                        .await;
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
                            %peer,
                            remote_chain_id = chain_id,
                            local_chain_id = config.chain_id,
                            "chain/protocol mismatch — disconnecting"
                        );
                        if peer_manager.record_misbehavior(&peer, Misbehavior::ProtocolViolation) {
                            let _ = swarm.disconnect_peer_id(peer);
                            let _ = event_tx
                                .send(NetworkEvent::PeerBanned {
                                    peer_id: peer.to_bytes().to_vec(),
                                    reason: "chain/protocol mismatch".into(),
                                })
                                .await;
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
            let tx = tx_provider.get_transaction(&request.tx_id);
            let _ = swarm
                .behaviour_mut()
                .tx_rpc
                .send_response(channel, TxResponse { transaction: tx });
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Ping(ping::Event {
            peer,
            result: Ok(rtt),
            ..
        })) => {
            peer_manager.update_latency(&peer, rtt);
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => {
            tracing::debug!(
                %peer_id,
                protocol = %info.protocol_version,
                agent = %info.agent_version,
                "identified peer"
            );
            // Feed identified peer addresses into Kademlia routing table.
            if config.enable_kademlia {
                for addr in &info.listen_addrs {
                    swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, addr.clone());
                }
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Kad(event)) => match &event {
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                ..
            } => {
                tracing::debug!(peers_found = ok.peers.len(), "kademlia walk found peers");
            }
            kad::Event::RoutingUpdated { peer, .. } => {
                tracing::debug!(%peer, "kademlia routing table updated");
            }
            _ => {}
        },

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
                tracing::debug!(task = "gossip_publish", "publishing to topic: {}", topics::TOPIC_BLOCK_ANNOUNCE);
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(err = %e, "failed to publish block announce");
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
                tracing::debug!(task = "gossip_publish", "publishing to topic: {}", topics::TOPIC_TX_ANNOUNCE);
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(err = %e, "failed to publish tx announce");
                }
            }
        }

        NetworkCommand::PublishVote {
            cycle,
            candidate_hash,
            voter_id,
            signature,
        } => {
            let msg = GossipMessage::PorVote {
                cycle,
                candidate_hash,
                voter_id,
                signature,
            };
            if let Ok(data) = codec::encode_gossip(&msg) {
                let topic = IdentTopic::new(topics::TOPIC_POR_VOTE);
                tracing::debug!(task = "gossip_publish", "publishing to topic: {}", topics::TOPIC_POR_VOTE);
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(err = %e, "failed to publish vote");
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
                tracing::debug!(task = "gossip_publish", "publishing to topic: {}", topics::TOPIC_NODE_ANNOUNCE);
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(err = %e, "failed to publish node announce");
                }
            }
        }

        NetworkCommand::PublishEvidence(evidence) => {
            let mut evidence_bytes = Vec::new();
            if ciborium::into_writer(&*evidence, &mut evidence_bytes).is_ok() {
                let msg = GossipMessage::DoubleProposalEvidence { evidence_bytes };
                if let Ok(data) = codec::encode_gossip(&msg) {
                    let topic = IdentTopic::new(topics::TOPIC_EVIDENCE);
                    tracing::debug!(task = "gossip_publish", "publishing to topic: {}", topics::TOPIC_EVIDENCE);
                    if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                        tracing::warn!(err = %e, "failed to publish evidence");
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
                peer_manager.record_misbehavior(&pid, Misbehavior::DuplicateProposal);
                let _ = swarm.disconnect_peer_id(pid);
            }
        }

        NetworkCommand::Shutdown => {
            return true;
        }
    }

    false
}

fn parse_org_type(s: &str) -> Option<noble_core::OrgType> {
    use noble_core::OrgType;
    match s {
        "Individual" => Some(OrgType::Individual),
        "IndependentResearcher" => Some(OrgType::IndependentResearcher),
        "University" => Some(OrgType::University),
        "ResearchLab" => Some(OrgType::ResearchLab),
        "NGO" => Some(OrgType::NGO),
        "Foundation" => Some(OrgType::Foundation),
        "OpenSourceProject" => Some(OrgType::OpenSourceProject),
        "Cooperative" => Some(OrgType::Cooperative),
        "CommunityGroup" => Some(OrgType::CommunityGroup),
        "ReligiousOrganization" => Some(OrgType::ReligiousOrganization),
        "Enterprise" => Some(OrgType::Enterprise),
        "Startup" => Some(OrgType::Startup),
        "InfrastructureProvider" => Some(OrgType::InfrastructureProvider),
        "FinancialInstitution" => Some(OrgType::FinancialInstitution),
        "GovernmentFederal" => Some(OrgType::GovernmentFederal),
        "GovernmentRegional" => Some(OrgType::GovernmentRegional),
        "GovernmentMunicipal" => Some(OrgType::GovernmentMunicipal),
        "MilitaryOrDefense" => Some(OrgType::MilitaryOrDefense),
        "CentralBank" => Some(OrgType::CentralBank),
        "Hospital" => Some(OrgType::Hospital),
        "Museum" => Some(OrgType::Museum),
        "MediaOutlet" => Some(OrgType::MediaOutlet),
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
}
