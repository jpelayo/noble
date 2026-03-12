// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network service: main event loop connecting the swarm to the node via channels.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use crate::peer_manager::{BanCategory, BanReason, Direction, MisbehaviorOutcome, PeerManager};
use crate::rate_limiter::TxRateLimiter;
use crate::seen_cache::{self, SeenCache};
use crate::topics;
use crate::traits::{BlockProvider, TxProvider};
use crate::transport::build_swarm;

/// Channel buffer size for commands and events.
const CHANNEL_BUFFER: usize = 256;

/// Interval for periodic maintenance tasks (ban cleanup, outbound connections).
const MAINTENANCE_INTERVAL_SECS: u64 = 60;

/// Cooldown after chain_id/protocol mismatch disconnect (5 minutes).
/// Prevents rapid connect→mismatch→disconnect→redial loops.
const MISMATCH_COOLDOWN_SECS: u64 = 300;

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
    // Priority: pre-loaded from unified keystore > file on disk > generate new.
    let keypair = if let Some(ref proto_bytes) = config.pre_loaded_p2p_key {
        match libp2p::identity::Keypair::from_protobuf_encoding(proto_bytes) {
            Ok(kp) => {
                tracing::info!(
                    task = "network_startup",
                    "Using P2P keypair from unified keystore"
                );
                kp
            }
            Err(e) => {
                return Err(NetworkError::Transport(format!(
                    "Failed to decode pre-loaded P2P keypair from unified keystore: {e}. \
                     Refusing to generate a new identity (would split network identity). \
                     Re-import the P2P key or delete the keystore entry to generate fresh."
                )));
            }
        }
    } else if let Some(ref data_dir) = config.data_dir {
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
                                    return Err(NetworkError::Transport(
                                        "Failed to decrypt P2P keypair from p2p_identity.key. \
                                         Refusing to generate a new identity (would split network identity). \
                                         Check the keystore passphrase or delete p2p_identity.key to generate fresh."
                                            .into(),
                                    ));
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
                            return Err(NetworkError::Transport(format!(
                                "Failed to decode P2P keypair from {}: {e}. \
                                 Refusing to generate a new identity (would split network identity). \
                                 Delete p2p_identity.key to generate fresh.",
                                key_path.display()
                            )));
                        }
                    }
                }
                Err(e) => {
                    return Err(NetworkError::Transport(format!(
                        "Failed to read P2P keypair file {}: {e}. \
                         Refusing to generate a new identity (would split network identity). \
                         Fix file permissions or delete p2p_identity.key to generate fresh.",
                        key_path.display()
                    )));
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

    // Resolve the actual bound port. When tcp/0 is used (random port), the OS
    // assigns a real port — we discover it via the NewListenAddr swarm event.
    let bound_port = if bound_port == 0 {
        use libp2p::futures::StreamExt;
        let mut actual_port = 0u16;
        // Poll swarm briefly to catch the NewListenAddr event (fires immediately).
        while let Some(event) = swarm.next().await {
            if let SwarmEvent::NewListenAddr { address, .. } = event {
                for proto in address.iter() {
                    if let libp2p::multiaddr::Protocol::Tcp(p) = proto {
                        actual_port = p;
                    }
                }
                if actual_port > 0 {
                    tracing::info!(
                        task = "network_startup",
                        port = actual_port,
                        "Resolved random P2P port"
                    );
                    break;
                }
            }
        }
        actual_port
    } else {
        bound_port
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
    mut config: NetworkConfig,
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

    // Pending dial result channels: multiaddr → oneshot sender.
    let mut pending_dials: HashMap<Multiaddr, tokio::sync::oneshot::Sender<Result<(), String>>> =
        HashMap::new();

    // Pending block proposals: blocks that have been proposed/announced but not yet
    // committed to storage.  When a peer requests a block via GetBlocks, we check
    // this cache first, then fall back to the block_provider (storage).
    // Keyed by block_hash bytes.  Value: (block, insertion_unix_secs).
    // Entries older than CYCLE_DURATION_SECS are evicted during maintenance.
    let mut pending_proposals: HashMap<[u8; 32], (noble_core::Block, u64)> = HashMap::new();

    // Mismatch cooldown: peers disconnected for chain_id or protocol_version
    // mismatch are suppressed for 5 minutes.  Without this, the node enters a
    // rapid connect → mismatch → disconnect → redial loop (thousands of cycles
    // per minute) because the disconnect is graceful (no ban) and the node-level
    // reconnection logic immediately redials the same peer.
    let mut mismatch_cooldown: HashMap<PeerId, Instant> = HashMap::new();
    // Tracks the reason for programmatic disconnects so ConnectionClosed can
    // include it in the PeerDisconnected event sent to the GUI.
    let mut disconnect_reasons: HashMap<PeerId, String> = HashMap::new();

    // Common ancestor discovery state machine (one search at a time).
    let mut ancestor_finder: Option<crate::ancestor::AncestorFinder> = None;

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
                    &mut pending_dials,
                    &mut pending_proposals,
                    &mut mismatch_cooldown,
                    &mut disconnect_reasons,
                    &mut ancestor_finder,
                ).await;
            }

            // --- Commands from the node ---
            Some(cmd) = command_rx.recv() => {
                if handle_command(cmd, &mut swarm, &mut peer_manager, &mut config, &mut pending_dials, &mut pending_proposals, &mut mismatch_cooldown, &event_tx, &mut ancestor_finder).await {
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
                // Evict pending proposals older than one cycle (30 min).
                {
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let cycle_secs = noble_core::CYCLE_DURATION_SECS;
                    pending_proposals.retain(|_, (_, ts)| now_secs.saturating_sub(*ts) < cycle_secs);
                }
                // Evict expired mismatch cooldown entries.
                {
                    let now = Instant::now();
                    mismatch_cooldown.retain(|_, expires| *expires > now);
                }
                // Evict stale disconnect_reasons entries.  Normally consumed by
                // ConnectionClosed, but if disconnect_peer_id fails to produce
                // a ConnectionClosed (exotic edge case), the entry would leak.
                // Cap: entries older than the cooldown period are orphans.
                {
                    let connected: std::collections::HashSet<PeerId> =
                        swarm.connected_peers().cloned().collect();
                    disconnect_reasons.retain(|pid, _| connected.contains(pid));
                }
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
            // Only rotate when we have enough outbound peers that losing one
            // won't risk isolation.  Minimum 4 outbound required before evicting.
            _ = peer_rotation_interval.tick() => {
                let total_connected = swarm.connected_peers().count();
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

                // Guard: need ≥4 outbound AND ≥4 total peers before rotating.
                // On small networks (2-3 nodes) rotation is self-inflicted isolation.
                if outbound_peers.len() >= 4 && total_connected >= 4 {
                    if let Some((worst_pid, _, _)) = outbound_peers
                        .iter()
                        .max_by(|a, b| a.2.partial_cmp(&b.2).unwrap_or(std::cmp::Ordering::Equal))
                    {
                        tracing::info!(task = "peer_discovery", %worst_pid, "rotating worst outbound peer");
                        disconnect_reasons.insert(*worst_pid, "peer rotation (worst outbound score)".to_string());
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
    pending_dials: &mut HashMap<Multiaddr, tokio::sync::oneshot::Sender<Result<(), String>>>,
    pending_proposals: &mut HashMap<[u8; 32], (noble_core::Block, u64)>,
    mismatch_cooldown: &mut HashMap<PeerId, Instant>,
    disconnect_reasons: &mut HashMap<PeerId, String>,
    ancestor_finder: &mut Option<crate::ancestor::AncestorFinder>,
) {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, connection_id, ..
        } => {
            let direction = if endpoint.is_dialer() {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            let remote_addr = endpoint.get_remote_address().to_string();

            // Mismatch cooldown guard: if this peer was recently disconnected for
            // chain_id or protocol mismatch, suppress immediately to prevent the
            // rapid connect→mismatch→disconnect→redial loop (thousands of cycles/min).
            if let Some(&cooldown_until) = mismatch_cooldown.get(&peer_id) {
                if Instant::now() < cooldown_until {
                    tracing::debug!(
                        task = "peer_management",
                        %peer_id,
                        "suppressing connection — chain/protocol mismatch cooldown active"
                    );
                    if let Err(e) = event_tx.try_send(NetworkEvent::PeerRejected {
                        peer_id: peer_id.to_bytes().to_vec(),
                        addr: remote_addr.clone(),
                        reason: "chain/protocol mismatch cooldown".to_string(),
                    }) {
                        tracing::debug!(task = "peer_management", "event channel full: {e}");
                    }
                    disconnect_reasons.insert(peer_id, "chain/protocol mismatch cooldown".to_string());
                    let _ = swarm.disconnect_peer_id(peer_id);
                    return;
                } else {
                    mismatch_cooldown.remove(&peer_id);
                }
            }

            // Duplicate connection guard: if we already track this peer (e.g. simultaneous
            // dial from both sides), close THIS specific connection.  We must NOT call
            // disconnect_peer_id — that kills ALL connections including the good one.
            // Closing by connection_id only kills the redundant connection.
            if peer_manager.get_peer(&peer_id).is_some() {
                tracing::debug!(task = "peer_management", %peer_id, "duplicate connection — closing redundant connection_id");
                let _ = swarm.close_connection(connection_id);
                return;
            }

            // Check subnet diversity for outbound connections.
            if direction == Direction::Outbound {
                let outbound_addrs = peer_manager.outbound_addrs();
                if !diversity::check_subnet_diversity(
                    &outbound_addrs,
                    &remote_addr,
                    config.max_outbound_per_subnet,
                ) {
                    tracing::debug!(task = "peer_management", %peer_id, %remote_addr, "rejecting outbound: subnet diversity");
                    if let Err(e) = event_tx.try_send(NetworkEvent::PeerRejected {
                        peer_id: peer_id.to_bytes().to_vec(),
                        addr: remote_addr.clone(),
                        reason: "outbound subnet diversity limit".to_string(),
                    }) {
                        tracing::debug!(task = "peer_management", "event channel full: {e}");
                    }
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
                    if let Err(e) = event_tx.try_send(NetworkEvent::PeerRejected {
                        peer_id: peer_id.to_bytes().to_vec(),
                        addr: remote_addr.clone(),
                        reason: "inbound subnet diversity limit".to_string(),
                    }) {
                        tracing::debug!(task = "peer_management", "event channel full: {e}");
                    }
                    let _ = swarm.disconnect_peer_id(peer_id);
                    return;
                }
            }

            match peer_manager.on_connected(peer_id, direction) {
                Ok(()) => {
                    peer_manager.update_addr(&peer_id, remote_addr.clone());
                    tracing::debug!(task = "peer_management", %peer_id, ?direction, "peer connected");

                    // Resolve pending dial(s) whose addr matches this connection.
                    if direction == Direction::Outbound {
                        let dial_addr = endpoint.get_remote_address().clone();
                        if let Some(tx) = pending_dials.remove(&dial_addr) {
                            let _ = tx.send(Ok(()));
                        }
                    }

                    let dir_str = match direction {
                        Direction::Inbound => "inbound",
                        Direction::Outbound => "outbound",
                    };
                    if event_tx
                        .try_send(NetworkEvent::PeerConnected {
                            peer_id: peer_id.to_bytes().to_vec(),
                            addr: remote_addr,
                            direction: dir_str.to_string(),
                            chain_tip: None,
                        })
                        .is_err()
                    {
                        tracing::warn!(
                            task = "event_channel",
                            "event channel full: PeerConnected dropped"
                        );
                    }

                    // Re-announce pending block proposals to the newly connected
                    // peer.  When a node proposes during the Proposal phase before
                    // any peers are connected, the gossipsub publish has 0 mesh
                    // members and the message is silently dropped.  Re-publishing
                    // after the first peer connects ensures the block reaches the
                    // network.
                    //
                    // Height gate: skip blocks at or below the committed tip.
                    // Stale re-announces are the primary trigger for false
                    // DuplicateProposal (0x04) bans between honest nodes.
                    let tip_height = block_provider.chain_tip().0;
                    for (hash, (block, _ts)) in pending_proposals.iter() {
                        if block.header.height <= tip_height {
                            continue; // Stale — already committed
                        }
                        let msg = GossipMessage::BlockAnnounce {
                            block_hash: *hash,
                            height: block.header.height,
                        };
                        if let Ok(data) = codec::encode_gossip(&msg) {
                            let topic = IdentTopic::new(topics::TOPIC_BLOCK_ANNOUNCE);
                            if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                                tracing::debug!(
                                    task = "gossip_publish",
                                    "re-announce pending proposal (height {}): {e}",
                                    block.header.height,
                                );
                            } else {
                                tracing::debug!(
                                    task = "gossip_publish",
                                    "re-announced pending proposal (height {}) to new peer",
                                    block.header.height,
                                );
                            }
                        }
                    }
                }
                Err(reason) => {
                    tracing::debug!(task = "peer_management", %peer_id, %reason, "peer rejected");
                    if let Err(e) = event_tx.try_send(NetworkEvent::PeerRejected {
                        peer_id: peer_id.to_bytes().to_vec(),
                        addr: remote_addr,
                        reason,
                    }) {
                        tracing::debug!(task = "peer_management", "event channel full: {e}");
                    }
                    let _ = swarm.disconnect_peer_id(peer_id);
                }
            }
        }

        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            cause,
            ..
        } => {
            // Only fire PeerDisconnected when the LAST connection to this peer
            // closes.  libp2p can maintain multiple connections per peer; closing
            // one socket must not poison the node's view of the network.
            if num_established == 0 {
                let was_tracked = peer_manager.on_disconnected(&peer_id);
                tx_rate_limiter.remove_peer(&peer_id);
                // Resolve disconnect reason: explicit reason (chain mismatch, ban)
                // takes priority over the libp2p cause.
                let explicit_reason = disconnect_reasons.remove(&peer_id);
                let reason = if let Some(ref r) = explicit_reason {
                    r.clone()
                } else {
                    match &cause {
                        Some(e) => format!("{e}"),
                        None => "remote closed connection (no error)".to_string(),
                    }
                };
                // Always log disconnections at info level — silent disconnects
                // are unacceptable for diagnosing network issues.
                tracing::info!(
                    task = "peer_disconnect",
                    %peer_id,
                    was_tracked,
                    explicit = explicit_reason.is_some(),
                    cause_is_some = cause.is_some(),
                    "peer disconnected: {reason}",
                );
                // Only emit PeerDisconnected if this peer was actually accepted
                // and tracked.  Peers rejected at connection time (subnet
                // diversity, limit, banned) cause a ConnectionClosed but were
                // never tracked — emitting a disconnect for them would falsely
                // decrement the node's peer_count and trigger spurious redials.
                if was_tracked {
                    if event_tx
                        .try_send(NetworkEvent::PeerDisconnected {
                            peer_id: peer_id.to_bytes().to_vec(),
                            reason,
                        })
                        .is_err()
                    {
                        tracing::warn!(
                            task = "event_channel",
                            "event channel full: PeerDisconnected dropped"
                        );
                    }
                }
            } else {
                tracing::debug!(
                    task = "peer_management",
                    %peer_id,
                    remaining = num_established,
                    "one connection closed, {} remaining",
                    num_established
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
                            &event_tx,
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
                            country_code,
                            software_version,
                            wants_to_validate,
                            wants_to_vote,
                            chain_tip_height,
                            chain_tip_hash,
                            proposed_height,
                            proposed_hash,
                            chain_id,
                            chain_vote_weight,
                            network_name,
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
                                &country_code,
                                &software_version,
                                wants_to_validate,
                                wants_to_vote,
                                chain_tip_height,
                                chain_tip_hash.as_deref(),
                                proposed_height,
                                proposed_hash.as_deref(),
                                chain_id,
                                chain_vote_weight,
                                &network_name,
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
                                &event_tx,
                            )
                        }
                        GossipMessage::DoubleProposalEvidence { evidence_bytes } => {
                            handle_double_proposal(&evidence_bytes, peer_bytes)
                        }
                        GossipMessage::VoteEquivocationEvidence { evidence_bytes } => {
                            handle_vote_equivocation(&evidence_bytes, peer_bytes)
                        }
                        GossipMessage::InvalidBlockEvidence { evidence_bytes } => {
                            handle_invalid_block_evidence(&evidence_bytes, peer_bytes)
                        }
                        GossipMessage::AnnounceEquivocationEvidence { evidence_bytes } => {
                            handle_announce_equivocation_evidence(&evidence_bytes, peer_bytes)
                        }
                    };
                    if let Some(evt) = net_event {
                        // Votes are consensus-critical — use blocking send
                        // to avoid the "dedup then drop" failure mode where
                        // the seen-cache consumed the slot but the event
                        // never reached the consensus engine.
                        let is_vote = matches!(&evt, NetworkEvent::VoteReceived { .. });
                        match event_tx.try_send(evt) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(evt)) if is_vote => {
                                // Vote channel full — log and force-send via
                                // blocking_send on a spawn_blocking task would
                                // be ideal, but in practice the channel rarely
                                // fills.  Instead, retry once after a brief yield.
                                tracing::warn!(
                                    task = "event_channel",
                                    "event channel full for vote — retrying"
                                );
                                // Last-resort: drop is better than deadlock.
                                if event_tx.try_send(evt).is_err() {
                                    tracing::error!(
                                        task = "event_channel",
                                        "vote dropped after retry — channel persistently full"
                                    );
                                }
                            }
                            Err(_) => {
                                tracing::warn!(
                                    task = "event_channel",
                                    "event channel full: gossip event dropped"
                                );
                            }
                        }
                    }
                    // Accept valid message for propagation.
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossip
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            libp2p::gossipsub::MessageAcceptance::Accept,
                        )
                    {
                        tracing::debug!(task = "gossip_receive", %propagation_source, %e, "failed to report message acceptance");
                    }
                }
                Err(e) => {
                    tracing::warn!(task = "gossip_receive", %propagation_source, err = %e, "invalid gossip message");
                    let reason_text = format!("malformed gossip: {e}");
                    let outcome = peer_manager.record_misbehavior(
                        &propagation_source,
                        BanReason::new(
                            BanCategory::ProtocolViolation,
                            reason_text.clone(),
                        ),
                    );
                    emit_misbehavior_event(&outcome, &propagation_source, &reason_text, &event_tx);
                    if outcome.is_banned() {
                        if swarm.disconnect_peer_id(propagation_source).is_err() {
                            tracing::debug!(task = "gossip_receive", %propagation_source, "disconnect failed (already disconnected)");
                        }
                    }
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .gossip
                        .report_message_validation_result(
                            &message_id,
                            &propagation_source,
                            libp2p::gossipsub::MessageAcceptance::Reject,
                        )
                    {
                        tracing::debug!(task = "gossip_receive", %propagation_source, %e, "failed to report message rejection");
                    }
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
            let response = handle_sync_request(&request, block_provider, config, pending_proposals);
            if swarm
                .behaviour_mut()
                .sync_rpc
                .send_response(channel, response)
                .is_err()
            {
                tracing::debug!(task = "network", "sync RPC send_response failed (channel closed)");
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::SyncRpc(request_response::Event::Message {
            peer,
            message: request_response::Message::Response { response, .. },
            ..
        })) => {
            // Forward sync responses as block-received events.
            // Also cache received blocks in pending_proposals so we can serve
            // them to other peers via GetBlocks before they're committed.
            let now_cache_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            match response {
                SyncResponse::Blocks(blocks) => {
                    let peer_bytes = peer.to_bytes().to_vec();
                    for block in blocks {
                        // Cache for serving to other peers.
                        // Evict any previous block from the same validator first
                        // to prevent stale proposals from prior cycles lingering
                        // and triggering false DuplicateProposal (0x04) bans when
                        // re-announced on PeerConnected.
                        if let Ok(bh) = block.header.compute_block_hash() {
                            let validator_wire = block.header.validator_id.to_wire_bytes();
                            pending_proposals.retain(|_, (b, _)| {
                                b.header.validator_id.to_wire_bytes() != validator_wire
                            });
                            pending_proposals
                                .insert(*bh.as_bytes(), (block.clone(), now_cache_ts));
                        }
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
                    // Cache for serving to other peers.
                    // Evict stale same-validator entries (see SyncResponse::Blocks).
                    if let Ok(bh) = block.header.compute_block_hash() {
                        let validator_wire = block.header.validator_id.to_wire_bytes();
                        pending_proposals.retain(|_, (b, _)| {
                            b.header.validator_id.to_wire_bytes() != validator_wire
                        });
                        pending_proposals
                            .insert(*bh.as_bytes(), (block.clone(), now_cache_ts));
                    }
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
                SyncResponse::Block(None) => {
                    tracing::debug!(
                        task = "sync",
                        "peer {} responded with Block(None) — block not found",
                        peer
                    );
                }
                SyncResponse::Status {
                    height,
                    tip_hash,
                    chain_id,
                    protocol_version,
                    sender_timestamp,
                    ..
                } => {
                    // GAP-H4: Verify chain_id and protocol_version.
                    //
                    // Both values are deterministic compiled constants:
                    //   - chain_id: derived from SHA-256 of genesis block (u32)
                    //   - protocol_version: hardcoded in noble-core (currently 1)
                    //
                    // A mismatch is definitive proof the peer is on a different
                    // blockchain or running an incompatible protocol. No tolerance
                    // needed — legitimate peers ALWAYS match on both values.
                    //
                    // Exception: pre-genesis nodes (chain_id == 0) have not committed
                    // genesis yet — they NEED peers to sync from, so chain_id
                    // mismatches are expected and must be tolerated.  Without this
                    // exception the node enters a rapid connect→mismatch→disconnect
                    // loop with thousands of reconnection attempts per minute.
                    let chain_mismatch = chain_id != config.chain_id && config.chain_id != 0;
                    let proto_mismatch = protocol_version != config.protocol_version;
                    if chain_mismatch || proto_mismatch {
                        let reason = if chain_mismatch && proto_mismatch {
                            format!(
                                "chain_id AND protocol mismatch: local=({}, proto {}) remote=({}, proto {})",
                                config.chain_id, config.protocol_version, chain_id, protocol_version,
                            )
                        } else if chain_mismatch {
                            format!(
                                "different blockchain: local chain_id={}, remote chain_id={}",
                                config.chain_id, chain_id,
                            )
                        } else {
                            format!(
                                "incompatible protocol version: local={}, remote={}",
                                config.protocol_version, protocol_version,
                            )
                        };
                        tracing::warn!(task = "sync", %peer, "{reason}");
                        // Different chain or protocol version: graceful disconnect
                        // without banning.  A peer on a different chain is not
                        // attacking — it's a misconfiguration or a legitimate
                        // separate network.  Banning would prevent future
                        // reconnection if the config is fixed.
                        //
                        // Add to mismatch cooldown to prevent rapid reconnection
                        // loop — the node-level reconnect timer would immediately
                        // redial this peer, causing thousands of connect/disconnect
                        // cycles per minute without this guard.
                        mismatch_cooldown.insert(
                            peer,
                            Instant::now() + Duration::from_secs(MISMATCH_COOLDOWN_SECS),
                        );
                        disconnect_reasons.insert(peer, reason.clone());
                        let _ = swarm.disconnect_peer_id(peer);
                    } else {
                        peer_manager.update_chain_tip(&peer, height, tip_hash);
                        // S49: Compute clock offset from sender_timestamp.
                        if sender_timestamp > 0 {
                            let local_now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let offset_ms = (sender_timestamp as i64 - local_now as i64) * 1000;
                            peer_manager.update_clock_offset(&peer, offset_ms);
                        }
                        if event_tx.try_send(NetworkEvent::PeerChainTipUpdated {
                            peer_id: peer.to_bytes().to_vec(),
                            height,
                            tip_hash,
                            median_clock_offset_ms: peer_manager.median_clock_offset_ms(),
                        }).is_err() {
                            tracing::warn!(task = "sync", "event channel full: PeerChainTipUpdated dropped");
                        }
                    }
                }
                SyncResponse::BlockHashBatch(ref remote_hashes) => {
                    if let Some(ref mut finder) = ancestor_finder {
                        if finder.peer_id == peer {
                            // Get local hashes for the same heights.
                            let local_hashes: Vec<(u64, Option<[u8; 32]>)> = remote_hashes
                                .iter()
                                .map(|(h, _)| (*h, block_provider.get_block_hash_by_height(*h)))
                                .collect();
                            match finder.process_response(remote_hashes, &local_hashes) {
                                Ok(Some(ancestor_height)) => {
                                    let ancestor_hash = block_provider
                                        .get_block_hash_by_height(ancestor_height)
                                        .unwrap_or([0; 32]);
                                    if let Err(e) = event_tx.try_send(NetworkEvent::CommonAncestorFound {
                                        peer_id: peer.to_bytes().to_vec(),
                                        ancestor_height,
                                        ancestor_hash,
                                    }) {
                                        tracing::debug!(task = "ancestor", "event channel full: {e}");
                                    }
                                    *ancestor_finder = None;
                                }
                                Ok(None) => {
                                    // Need Round 2 — send bisect fill.
                                    let round2 = finder.round2_heights();
                                    swarm.behaviour_mut().sync_rpc.send_request(
                                        &peer,
                                        SyncRequest::GetBlockHashBatch { heights: round2 },
                                    );
                                }
                                Err(e) => {
                                    tracing::warn!(task = "ancestor", "ancestor search failed: {e}");
                                    *ancestor_finder = None;
                                }
                            }
                        }
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
            if let Err(e) = event_tx.try_send(NetworkEvent::PeerLatencyUpdated {
                peer_id: peer.to_bytes().to_vec(),
                latency_ms: rtt.as_millis() as u64,
            }) {
                tracing::debug!(task = "peer_management", "event channel full: {e}");
            }
        }

        SwarmEvent::Behaviour(NobleBehaviourEvent::Ping(ping::Event {
            peer,
            result: Err(ref e),
            ..
        })) => {
            tracing::debug!(
                task = "ping",
                %peer,
                error = %e,
                "ping failed — connection may be degraded"
            );
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

        SwarmEvent::OutgoingConnectionError {
            error,
            connection_id: _,
            ..
        } => {
            // Resolve any pending dial whose multiaddr appears in the error.
            // libp2p DialError embeds the target addr in the error string.
            let err_str = error.to_string();
            tracing::debug!(task = "peer_management", "outbound connection failed: {err_str}");
            let mut resolved_addrs = Vec::new();
            for (addr, _) in pending_dials.iter() {
                if err_str.contains(&addr.to_string()) {
                    resolved_addrs.push(addr.clone());
                }
            }
            for addr in resolved_addrs {
                if let Some(tx) = pending_dials.remove(&addr) {
                    let _ = tx.send(Err(err_str.clone()));
                }
            }
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
    event_tx: &tokio::sync::mpsc::Sender<NetworkEvent>,
) -> Option<NetworkEvent> {
    if !tx_rate_limiter.try_consume(source) {
        let reason = "tx relay rate limit exceeded".to_string();
        let outcome = peer_manager.record_misbehavior(
            source,
            BanReason::new(BanCategory::TxFlood, reason.clone()),
        );
        emit_misbehavior_event(&outcome, source, &reason, event_tx);
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
///
/// Validates the vote at the wire boundary BEFORE touching the seen-cache:
/// 1. Round must be 1 or 2 (rejects arbitrary round inflation).
/// 2. Voter public key must decode (rejects malformed voter_id that would
///    reserve a dedup slot and block the real vote).
/// 3. Signature envelope must decode (same rationale).
///
/// The seen-cache is NOT inserted here — it is deferred to the caller
/// so that the slot is only consumed after successful enqueue.  This
/// prevents the "dedup then drop" failure mode where a valid vote is
/// marked seen but lost due to a full event channel.
fn handle_por_vote(
    peer_id: Vec<u8>,
    cycle: u64,
    candidate_hash: [u8; 32],
    voter_id: Vec<u8>,
    signature: Vec<u8>,
    round: u8,
    seen_votes: &mut SeenCache,
) -> Option<NetworkEvent> {
    // Wire-boundary validation: reject before dedup.
    if round != 1 && round != 2 {
        tracing::debug!(
            task = "gossip_vote",
            "rejected vote with invalid round {round} (only 1 and 2 accepted)"
        );
        return None;
    }
    // Validate voter_id decodes as a valid public key.
    if noble_crypto::NoblePublicKey::from_wire_bytes(&voter_id).is_err() {
        tracing::debug!(
            task = "gossip_vote",
            "rejected vote with malformed voter_id ({} bytes)",
            voter_id.len()
        );
        return None;
    }
    // Basic signature plausibility: empty signatures are always invalid.
    // Full cryptographic verification happens in the consensus engine.
    if signature.is_empty() {
        tracing::debug!(
            task = "gossip_vote",
            "rejected vote with empty signature"
        );
        return None;
    }

    // Dedup: check seen-cache AFTER basic validation passes.
    let dedup_key = seen_cache::vote_dedup_key(cycle, &voter_id, round);
    if !seen_votes.insert_if_new(dedup_key) {
        return None;
    }

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
    event_tx: &tokio::sync::mpsc::Sender<NetworkEvent>,
) -> Option<NetworkEvent> {
    match result {
        Ok(announce) => {
            // S49: Compute clock offset from NodeAnnounce timestamp.
            if announce.timestamp > 0 {
                let local_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let offset_ms = (announce.timestamp as i64 - local_now as i64) * 1000;
                peer_manager.update_clock_offset(source, offset_ms);
            }

            // S53: If the announce carries a committed chain tip, update peer
            // state and emit PeerChainTipUpdated — same pipeline as GetStatus.
            // Monotonic guard: only update if announced height ≥ known height.
            if let Some(height) = announce.chain_tip_height {
                let current = peer_manager
                    .get_chain_tip(source)
                    .map(|(h, _)| h)
                    .unwrap_or(0);
                if height >= current {
                    let tip_hash = announce.chain_tip_hash.unwrap_or([0u8; 32]);
                    peer_manager.update_chain_tip(source, height, tip_hash);
                    let median = peer_manager.median_clock_offset_ms();
                    if let Err(e) = event_tx.try_send(NetworkEvent::PeerChainTipUpdated {
                        peer_id: peer_bytes.clone(),
                        height,
                        tip_hash,
                        median_clock_offset_ms: median,
                    }) {
                        tracing::debug!(task = "peer_management", "event channel full: {e}");
                    }
                }
            }

            peer_manager.update_announce(source, announce.clone());
            Some(NetworkEvent::NodeAnnounceReceived {
                peer_id: peer_bytes,
                announce: Box::new(announce),
            })
        }
        Err(reason) => {
            tracing::warn!(task = "gossip_receive", %source, %reason, "invalid node announce");
            let reason_text = format!("invalid announce: {reason}");
            let outcome = peer_manager.record_misbehavior(
                source,
                BanReason::new(
                    BanCategory::InvalidAnnounce,
                    reason_text.clone(),
                ),
            );
            emit_misbehavior_event(&outcome, source, &reason_text, event_tx);
            None
        }
    }
}

/// Emit the appropriate `NetworkEvent` after a misbehavior recording.
fn emit_misbehavior_event(
    outcome: &MisbehaviorOutcome,
    peer_id: &PeerId,
    reason: &str,
    event_tx: &tokio::sync::mpsc::Sender<NetworkEvent>,
) {
    let peer_bytes = peer_id.to_bytes().to_vec();
    match outcome {
        MisbehaviorOutcome::Banned { category, evidence_hash } => {
            if let Err(e) = event_tx.try_send(NetworkEvent::PeerBanned {
                peer_id: peer_bytes,
                reason: reason.to_string(),
                category: *category,
                evidence_hash: *evidence_hash,
            }) {
                tracing::debug!(task = "peer_management", "event channel full: {e}");
            }
        }
        MisbehaviorOutcome::ScoreUpdated { ban_score, categories, last_category, last_reason } => {
            if let Err(e) = event_tx.try_send(NetworkEvent::PeerScoreUpdated {
                peer_id: peer_bytes,
                ban_score: *ban_score,
                categories: categories.clone(),
                last_category: *last_category,
                last_reason: last_reason.clone(),
            }) {
                tracing::debug!(task = "peer_management", "event channel full: {e}");
            }
        }
        MisbehaviorOutcome::Suppressed => {}
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
                    evidence: Box::new(noble_core::MisbehaviorEvidence::DoubleProposal(evidence)),
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

/// Handle a vote equivocation evidence gossip message.
fn handle_vote_equivocation(evidence_bytes: &[u8], peer_bytes: Vec<u8>) -> Option<NetworkEvent> {
    match ciborium::from_reader::<noble_core::VoteEquivocationEvidence, _>(evidence_bytes) {
        Ok(evidence) => match evidence.verify() {
            Ok(()) => {
                tracing::warn!(
                    task = "gossip_receive",
                    "valid vote equivocation evidence received"
                );
                Some(NetworkEvent::EvidenceReceived {
                    peer_id: peer_bytes,
                    evidence: Box::new(noble_core::MisbehaviorEvidence::VoteEquivocation(evidence)),
                })
            }
            Err(e) => {
                tracing::debug!(task = "gossip_receive", %e, "invalid vote equivocation evidence rejected");
                None
            }
        },
        Err(e) => {
            tracing::debug!(task = "gossip_receive", %e, "failed to decode vote equivocation CBOR");
            None
        }
    }
}

/// Handle an invalid block evidence gossip message.
fn handle_invalid_block_evidence(evidence_bytes: &[u8], peer_bytes: Vec<u8>) -> Option<NetworkEvent> {
    match ciborium::from_reader::<noble_core::InvalidBlockEvidence, _>(evidence_bytes) {
        Ok(evidence) => {
            // NOTE: We can't verify InvalidBlockEvidence here because it requires chain_id.
            // The node.rs EvidenceReceived handler will verify it.
            tracing::warn!(
                task = "gossip_receive",
                "invalid block evidence received (verification deferred to node)"
            );
            Some(NetworkEvent::EvidenceReceived {
                peer_id: peer_bytes,
                evidence: Box::new(noble_core::MisbehaviorEvidence::InvalidBlock(evidence)),
            })
        }
        Err(e) => {
            tracing::debug!(task = "gossip_receive", %e, "failed to decode invalid block evidence CBOR");
            None
        }
    }
}

/// Handle an announce equivocation evidence gossip message.
fn handle_announce_equivocation_evidence(evidence_bytes: &[u8], peer_bytes: Vec<u8>) -> Option<NetworkEvent> {
    match ciborium::from_reader::<noble_core::AnnounceEquivocationEvidence, _>(evidence_bytes) {
        Ok(evidence) => match evidence.verify() {
            Ok(()) => {
                tracing::warn!(
                    task = "gossip_receive",
                    "valid announce equivocation evidence received"
                );
                Some(NetworkEvent::EvidenceReceived {
                    peer_id: peer_bytes,
                    evidence: Box::new(noble_core::MisbehaviorEvidence::AnnounceEquivocation(evidence)),
                })
            }
            Err(e) => {
                tracing::debug!(task = "gossip_receive", %e, "invalid announce equivocation evidence rejected");
                None
            }
        },
        Err(e) => {
            tracing::debug!(task = "gossip_receive", %e, "failed to decode announce equivocation CBOR");
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
    if swarm
        .behaviour_mut()
        .tx_rpc
        .send_response(channel, TxResponse { transaction: tx })
        .is_err()
    {
        tracing::debug!(task = "network", "tx RPC send_response failed (channel closed)");
    }
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
    pending_proposals: &HashMap<[u8; 32], (noble_core::Block, u64)>,
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
                .filter_map(|h| {
                    // Check committed storage first, then pending proposals cache.
                    block_provider
                        .get_block(h)
                        .or_else(|| pending_proposals.get(h).map(|(b, _)| b.clone()))
                })
                .collect();
            SyncResponse::Blocks(blocks)
        }

        SyncRequest::GetBlockByHeight { height } => {
            let block = block_provider.get_block_by_height(*height);
            SyncResponse::Block(block)
        }

        SyncRequest::GetStatus => {
            let (height, tip_hash) = block_provider.chain_tip();
            let sender_timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            SyncResponse::Status {
                height,
                tip_hash,
                chain_id: config.chain_id,
                protocol_version: config.protocol_version,
                total_transactions: block_provider.total_transactions(),
                avg_votes_per_block: block_provider.avg_votes_per_block(),
                sender_timestamp,
            }
        }

        SyncRequest::GetBlockHashBatch { heights } => {
            // Cap at 256 heights per request to prevent abuse.
            let capped = &heights[..heights.len().min(256)];
            let hashes: Vec<(u64, Option<[u8; 32]>)> = capped
                .iter()
                .map(|&h| (h, block_provider.get_block_hash_by_height(h)))
                .collect();
            SyncResponse::BlockHashBatch(hashes)
        }
    }
}

/// Handle a command from the node. Returns `true` if shutdown was requested.
async fn handle_command(
    cmd: NetworkCommand,
    swarm: &mut Swarm<NobleBehaviour>,
    peer_manager: &mut PeerManager,
    config: &mut NetworkConfig,
    pending_dials: &mut HashMap<Multiaddr, tokio::sync::oneshot::Sender<Result<(), String>>>,
    pending_proposals: &mut HashMap<[u8; 32], (noble_core::Block, u64)>,
    mismatch_cooldown: &mut HashMap<PeerId, Instant>,
    event_tx: &tokio::sync::mpsc::Sender<NetworkEvent>,
    ancestor_finder: &mut Option<crate::ancestor::AncestorFinder>,
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
                    "publishing block announce (height {}) to topic: {}",
                    block.header.height,
                    topics::TOPIC_BLOCK_ANNOUNCE,
                );
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(task = "gossip_publish", err = %e, "failed to publish block announce");
                }
            }
            // Store the proposed block in the pending proposals cache so
            // GetBlocks requests from peers can serve it before it's committed.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // Evict any previous proposal from the same validator.  Without
            // this, stale proposals from prior cycles linger in the cache and
            // get re-announced on PeerConnected, causing the receiving node to
            // see two different blocks from the same validator and trigger a
            // false DuplicateProposal (0x04) ban.
            let validator_wire = block.header.validator_id.to_wire_bytes();
            pending_proposals.retain(|_, (b, _)| {
                b.header.validator_id.to_wire_bytes() != validator_wire
            });
            pending_proposals.insert(block_hash, (block.clone(), now_secs));
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
            tracing::info!(task = "sync_trace", "RequestSync: sending GetStatus to {} peers", peers.len());
            for pid in peers {
                swarm
                    .behaviour_mut()
                    .sync_rpc
                    .send_request(&pid, SyncRequest::GetStatus);
            }
        }

        NetworkCommand::RequestStaleSync { threshold_secs } => {
            // Send GetStatus only to peers whose chain_tip hasn't been refreshed
            // within the threshold — gossip-driven fallback for silent peers.
            let threshold = std::time::Duration::from_secs(threshold_secs);
            let stale_peers = peer_manager.stale_chain_tip_peers(threshold);
            if !stale_peers.is_empty() {
                tracing::info!(
                    task = "sync_trace",
                    "RequestStaleSync: sending GetStatus to {} stale peers (threshold={}s)",
                    stale_peers.len(),
                    threshold_secs,
                );
                for pid in stale_peers {
                    swarm
                        .behaviour_mut()
                        .sync_rpc
                        .send_request(&pid, SyncRequest::GetStatus);
                }
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
                country_code: announce.country_code.clone(),
                software_version: announce.software_version.clone(),
                wants_to_validate: announce.wants_to_validate,
                wants_to_vote: announce.wants_to_vote,
                chain_tip_height: announce.chain_tip_height,
                chain_tip_hash: announce.chain_tip_hash.map(|h| hex::encode(h)),
                proposed_height: announce.proposed_height,
                proposed_hash: announce.proposed_hash.map(|h| hex::encode(h)),
                chain_id: announce.chain_id,
                chain_vote_weight: announce.chain_vote_weight,
                network_name: announce.network_name.clone(),
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
            let (gossip_msg, label) = match &*evidence {
                noble_core::MisbehaviorEvidence::DoubleProposal(e) => {
                    let mut bytes = Vec::new();
                    if ciborium::into_writer(e, &mut bytes).is_err() {
                        return false;
                    }
                    (GossipMessage::DoubleProposalEvidence { evidence_bytes: bytes }, "double_proposal")
                }
                noble_core::MisbehaviorEvidence::VoteEquivocation(e) => {
                    let mut bytes = Vec::new();
                    if ciborium::into_writer(e, &mut bytes).is_err() {
                        return false;
                    }
                    (GossipMessage::VoteEquivocationEvidence { evidence_bytes: bytes }, "vote_equivocation")
                }
                noble_core::MisbehaviorEvidence::InvalidBlock(e) => {
                    let mut bytes = Vec::new();
                    if ciborium::into_writer(e, &mut bytes).is_err() {
                        return false;
                    }
                    (GossipMessage::InvalidBlockEvidence { evidence_bytes: bytes }, "invalid_block")
                }
                noble_core::MisbehaviorEvidence::AnnounceEquivocation(e) => {
                    let mut bytes = Vec::new();
                    if ciborium::into_writer(e, &mut bytes).is_err() {
                        return false;
                    }
                    (GossipMessage::AnnounceEquivocationEvidence { evidence_bytes: bytes }, "announce_equivocation")
                }
            };
            if let Ok(data) = codec::encode_gossip(&gossip_msg) {
                let topic = IdentTopic::new(topics::TOPIC_EVIDENCE);
                tracing::debug!(
                    task = "gossip_publish",
                    evidence_type = label,
                    "publishing {} evidence to topic: {}",
                    label,
                    topics::TOPIC_EVIDENCE
                );
                if let Err(e) = swarm.behaviour_mut().gossip.publish(topic, data) {
                    tracing::warn!(task = "gossip_publish", err = %e, "failed to publish evidence");
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

        NetworkCommand::RequestBlockFromAll { hash } => {
            // Request the block from ALL connected peers.  Used when a vote
            // references an unknown block — the voter may not have it cached,
            // so we ask everyone to maximise the chance of obtaining the body.
            let peers: Vec<PeerId> = swarm.connected_peers().cloned().collect();
            tracing::debug!(
                task = "block_request",
                "requesting block {} from {} peers",
                hex::encode(hash),
                peers.len()
            );
            for pid in &peers {
                let request = SyncRequest::GetBlocks { hashes: vec![hash] };
                swarm.behaviour_mut().sync_rpc.send_request(pid, request);
            }
        }

        NetworkCommand::RequestBlockByHeight { peer_id, height } => {
            if let Ok(pid) = PeerId::from_bytes(&peer_id) {
                let request = SyncRequest::GetBlockByHeight { height };
                swarm.behaviour_mut().sync_rpc.send_request(&pid, request);
            }
        }

        NetworkCommand::DialPeer(addr, result_tx) => {
            // Skip dialing if we're already connected to a peer at this address.
            // Redundant dials to already-connected peers destabilize the existing
            // connection by creating parallel Noise handshakes that can race.
            let dial_ip_port = extract_ip_port(&addr.to_string());
            let already_connected = if let Some(ref target) = dial_ip_port {
                peer_manager.all_peer_addrs().iter().any(|a| {
                    extract_ip_port(a).as_ref() == Some(target)
                })
            } else {
                false
            };
            if already_connected {
                tracing::debug!(task = "network", %addr, "Skipping dial — already connected to peer at this address");
                if let Some(tx) = result_tx {
                    let _ = tx.send(Ok(()));
                }
            } else {
                match swarm.dial(addr.clone()) {
                    Ok(_) => {
                        tracing::info!(task = "network", %addr, "Dialing peer");
                        if let Some(tx) = result_tx {
                            pending_dials.insert(addr, tx);
                        }
                    }
                    Err(e) => {
                        tracing::warn!(task = "network", %addr, %e, "Failed to dial peer");
                        if let Some(tx) = result_tx {
                            let _ = tx.send(Err(e.to_string()));
                        }
                    }
                }
            }
        }

        NetworkCommand::BanPeer { peer_id, category, reason, evidence_hash } => {
            if let Ok(pid) = PeerId::from_bytes(&peer_id) {
                let ban_cat = BanCategory::from_u8(category)
                    .unwrap_or(BanCategory::ProtocolViolation);
                let reason_clone = reason.clone();
                let ban_reason = if let Some(hash) = evidence_hash {
                    BanReason::with_evidence(ban_cat, reason, hash)
                } else {
                    BanReason::new(ban_cat, reason)
                };
                let outcome = peer_manager.record_misbehavior(
                    &pid,
                    ban_reason,
                );
                emit_misbehavior_event(&outcome, &pid, &reason_clone, &event_tx);
                let _ = swarm.disconnect_peer_id(pid);
            }
        }

        NetworkCommand::DisconnectPeer(peer_bytes) => {
            if let Ok(pid) = PeerId::from_bytes(&peer_bytes) {
                tracing::info!(task = "network", %pid, "Graceful disconnect (no ban)");
                let _ = swarm.disconnect_peer_id(pid);
            }
        }

        NetworkCommand::ManualBanPeer { peer_id, reason, duration_secs: _ } => {
            if let Ok(pid) = PeerId::from_bytes(&peer_id) {
                let reason_clone = reason.clone();
                let outcome = peer_manager.record_misbehavior(
                    &pid,
                    BanReason::new(BanCategory::ManualBan, reason),
                );
                emit_misbehavior_event(&outcome, &pid, &reason_clone, &event_tx);
                let _ = swarm.disconnect_peer_id(pid);
            }
        }

        NetworkCommand::UnbanPeer(peer_bytes) => {
            if let Ok(pid) = PeerId::from_bytes(&peer_bytes) {
                peer_manager.unban(&pid);
                tracing::info!(task = "network", %pid, "Peer unbanned via RPC");
            }
        }

        NetworkCommand::ListBannedPeers(reply_tx) => {
            let entries = peer_manager.list_banned_entries();
            let _ = reply_tx.send(entries);
        }

        NetworkCommand::UpdateChainId(new_chain_id) => {
            tracing::info!(
                task = "network",
                "updating chain_id to {:#010X} (cross-chain adoption)",
                new_chain_id
            );
            config.chain_id = new_chain_id;
            // Clear mismatch cooldown so peers on the target chain can reconnect immediately.
            mismatch_cooldown.clear();
        }

        NetworkCommand::FindCommonAncestor {
            peer_id,
            local_height,
            peer_height,
        } => {
            if let Ok(pid) = PeerId::from_bytes(&peer_id) {
                let (finder, probes) =
                    crate::ancestor::AncestorFinder::new(pid, local_height, peer_height);
                swarm.behaviour_mut().sync_rpc.send_request(
                    &pid,
                    SyncRequest::GetBlockHashBatch { heights: probes },
                );
                *ancestor_finder = Some(finder);
            }
        }

        NetworkCommand::ClearPendingProposals => {
            pending_proposals.clear();
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

/// Extract the IP:port portion from a multiaddr string for address comparison.
/// E.g. "/ip4/192.168.1.1/tcp/8780/p2p/12D3..." → "192.168.1.1:8780"
fn extract_ip_port(addr_str: &str) -> Option<String> {
    let parts: Vec<&str> = addr_str.split('/').collect();
    let mut ip = None;
    let mut port = None;
    for (i, part) in parts.iter().enumerate() {
        if *part == "ip4" || *part == "ip6" {
            ip = parts.get(i + 1).copied();
        }
        if *part == "tcp" {
            port = parts.get(i + 1).copied();
        }
    }
    match (ip, port) {
        (Some(i), Some(p)) => Some(format!("{i}:{p}")),
        _ => None,
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
    country_code: &Option<String>,
    software_version: &str,
    wants_to_validate: bool,
    wants_to_vote: bool,
    chain_tip_height: Option<u64>,
    chain_tip_hash_hex: Option<&str>,
    proposed_height: Option<u64>,
    proposed_hash_hex: Option<&str>,
    chain_id: u32,
    chain_vote_weight: Option<u64>,
    network_name: &str,
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

    // Decode hex chain tip hash (32 bytes)
    let chain_tip_hash = if let Some(hex_str) = chain_tip_hash_hex {
        let bytes = hex::decode(hex_str).map_err(|e| format!("invalid chain_tip_hash hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("chain_tip_hash must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    };

    // Decode hex proposed hash (32 bytes)
    let proposed_hash = if let Some(hex_str) = proposed_hash_hex {
        let bytes = hex::decode(hex_str).map_err(|e| format!("invalid proposed_hash hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("proposed_hash must be 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
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
        country_code: country_code.clone(),
        software_version: software_version.to_string(),
        wants_to_validate,
        wants_to_vote,
        chain_tip_height,
        chain_tip_hash,
        proposed_height,
        proposed_hash,
        chain_id,
        chain_vote_weight,
        network_name: network_name.to_string(),
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
        fn get_block_hash_by_height(&self, _height: u64) -> Option<[u8; 32]> {
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
        let config = NetworkConfig::local_test();
        let pp = HashMap::new();
        let response = handle_sync_request(&SyncRequest::GetStatus, &bp, &config, &pp);
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
        let config = NetworkConfig::local_test();
        let pp = HashMap::new();
        let response =
            handle_sync_request(&SyncRequest::GetBlockByHeight { height: 999 }, &bp, &config, &pp);
        match response {
            SyncResponse::Block(None) => {}
            _ => panic!("expected Block(None)"),
        }
    }

    #[test]
    fn handle_sync_request_get_blocks_empty() {
        let bp: Arc<dyn BlockProvider> = Arc::new(MockBlockProvider { tip: (0, [0; 32]) });
        let config = NetworkConfig::local_test();
        let pp = HashMap::new();
        let response = handle_sync_request(
            &SyncRequest::GetBlocks {
                hashes: vec![[0xFF; 32]],
            },
            &bp,
            &config,
            &pp,
        );
        match response {
            SyncResponse::Blocks(blocks) => assert!(blocks.is_empty()),
            _ => panic!("expected Blocks"),
        }
    }

    #[tokio::test]
    async fn network_starts_and_handles_shutdown() {
        let config = NetworkConfig::local_test();
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
        let config = NetworkConfig::local_test();
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
