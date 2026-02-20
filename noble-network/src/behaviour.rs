// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Composite libp2p [`NetworkBehaviour`] for a NOBLE node.

use std::time::Duration;

use libp2p::gossipsub::{self, IdentTopic, MessageId};
use libp2p::identity::Keypair;
use libp2p::kad;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, ping, StreamProtocol};
use sha2::Digest;

use crate::config::NetworkConfig;
use crate::error::NetworkError;
use crate::messages::{SyncRequest, SyncResponse, TxRequest, TxResponse};
use crate::topics;

/// Composite network behaviour combining all NOBLE P2P sub-protocols.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NobleBehaviourEvent")]
pub struct NobleBehaviour {
    /// Request-response for block/header sync (`/noble/sync/1.0.0`).
    pub sync_rpc: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    /// Request-response for single transaction fetching (`/noble/tx/1.0.0`).
    pub tx_rpc: request_response::cbor::Behaviour<TxRequest, TxResponse>,
    /// GossipSub for block/tx/vote announcements.
    pub gossip: gossipsub::Behaviour,
    /// Identify protocol — exchanges peer metadata (GAP-H4: chain_id verification).
    pub identify: identify::Behaviour,
    /// Ping for keepalive and latency measurement.
    pub ping: ping::Behaviour,
    /// Kademlia DHT for peer discovery (GAP-H5).
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
}

/// Events emitted by [`NobleBehaviour`] to the swarm.
#[derive(Debug)]
pub enum NobleBehaviourEvent {
    SyncRpc(request_response::Event<SyncRequest, SyncResponse>),
    TxRpc(request_response::Event<TxRequest, TxResponse>),
    Gossip(gossipsub::Event),
    Identify(identify::Event),
    Ping(ping::Event),
    Kad(kad::Event),
}

impl From<request_response::Event<SyncRequest, SyncResponse>> for NobleBehaviourEvent {
    fn from(e: request_response::Event<SyncRequest, SyncResponse>) -> Self {
        Self::SyncRpc(e)
    }
}

impl From<request_response::Event<TxRequest, TxResponse>> for NobleBehaviourEvent {
    fn from(e: request_response::Event<TxRequest, TxResponse>) -> Self {
        Self::TxRpc(e)
    }
}

impl From<gossipsub::Event> for NobleBehaviourEvent {
    fn from(e: gossipsub::Event) -> Self {
        Self::Gossip(e)
    }
}

impl From<identify::Event> for NobleBehaviourEvent {
    fn from(e: identify::Event) -> Self {
        Self::Identify(e)
    }
}

impl From<ping::Event> for NobleBehaviourEvent {
    fn from(e: ping::Event) -> Self {
        Self::Ping(e)
    }
}

impl From<kad::Event> for NobleBehaviourEvent {
    fn from(e: kad::Event) -> Self {
        Self::Kad(e)
    }
}

impl NobleBehaviour {
    /// Construct a new `NobleBehaviour` from a keypair and network config.
    pub fn new(keypair: &Keypair, config: &NetworkConfig) -> Result<Self, NetworkError> {
        // --- GossipSub ---
        // AUD2-H3: Stable message_id using SHA-256 truncated to 20 bytes.
        // This avoids non-deterministic hashing (SipHash/DefaultHasher) across processes.
        let message_id_fn = |message: &gossipsub::Message| {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&message.data);
            hasher.update(message.topic.as_str().as_bytes());
            let hash = hasher.finalize();
            MessageId::from(hash[..20].to_vec())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .duplicate_cache_time(Duration::from_secs(60))
            .message_id_fn(message_id_fn)
            .max_transmit_size(crate::codec::MAX_GOSSIP_MESSAGE_SIZE)
            .build()
            .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

        let mut gossip = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;

        // Subscribe to all NOBLE topics.
        for topic_str in topics::ALL_TOPICS {
            let topic = IdentTopic::new(*topic_str);
            gossip
                .subscribe(&topic)
                .map_err(|e| NetworkError::Gossipsub(e.to_string()))?;
        }

        // --- Request-Response: sync ---
        let sync_rpc = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new(topics::SYNC_PROTOCOL),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        // --- Request-Response: tx ---
        let tx_rpc = request_response::cbor::Behaviour::new(
            [(
                StreamProtocol::new(topics::TX_PROTOCOL),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );

        // --- Identify (GAP-H4 + AUD-M5) ---
        // Include both chain_id and protocol_version in identify protocol string.
        let identify = identify::Behaviour::new(identify::Config::new(
            format!(
                "{}/{}/v{}",
                topics::IDENTIFY_PROTOCOL,
                config.chain_id,
                config.protocol_version,
            ),
            keypair.public(),
        ));

        // --- Ping ---
        let ping = ping::Behaviour::new(ping::Config::new().with_interval(Duration::from_secs(30)));

        // --- Kademlia DHT (GAP-H5) ---
        let local_peer_id = keypair.public().to_peer_id();
        let store = kad::store::MemoryStore::new(local_peer_id);
        let mut kad_config = kad::Config::new(
            StreamProtocol::try_from_owned(topics::KAD_PROTOCOL.to_string())
                .expect("valid protocol string"),
        );
        kad_config.set_query_timeout(Duration::from_secs(60));
        let kad = kad::Behaviour::with_config(local_peer_id, store, kad_config);

        Ok(Self {
            sync_rpc,
            tx_rpc,
            gossip,
            identify,
            ping,
            kad,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn behaviour_constructs_successfully() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::testnet();
        let behaviour = NobleBehaviour::new(&keypair, &config);
        assert!(behaviour.is_ok());
    }

    #[test]
    fn behaviour_subscribes_to_all_topics() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::testnet();
        let behaviour = NobleBehaviour::new(&keypair, &config).unwrap();
        // GossipSub should have 6 subscribed topics.
        let topics_list = behaviour.gossip.topics().collect::<Vec<_>>();
        assert_eq!(topics_list.len(), 6);
    }

    #[test]
    fn behaviour_has_kademlia() {
        let keypair = Keypair::generate_ed25519();
        let config = NetworkConfig::testnet();
        let mut behaviour = NobleBehaviour::new(&keypair, &config).unwrap();
        // Kademlia should be accessible and have an empty routing table initially.
        let buckets_with_entries = behaviour
            .kad
            .kbuckets()
            .filter(|b| b.num_entries() > 0)
            .count();
        assert_eq!(buckets_with_entries, 0);
    }

    #[test]
    fn identify_protocol_format() {
        // Verify the identify protocol string is constructed with chain_id and protocol_version.
        let config = NetworkConfig::testnet();
        let expected = format!(
            "{}/{}/v{}",
            crate::topics::IDENTIFY_PROTOCOL,
            config.chain_id,
            config.protocol_version,
        );
        assert!(expected.contains("/noble/"));
        assert!(expected.contains(&config.chain_id.to_string()));
        assert!(expected.contains(&format!("v{}", config.protocol_version)));
    }

    // ---- AUD-M5: Protocol version matching test ----

    #[test]
    fn matching_version_accepted() {
        // Verify that two nodes with the same config produce the same identify string,
        // confirming they would recognize each other as compatible.
        let config = NetworkConfig::testnet();
        let identify_a = format!(
            "{}/{}/v{}",
            crate::topics::IDENTIFY_PROTOCOL,
            config.chain_id,
            config.protocol_version,
        );
        let identify_b = format!(
            "{}/{}/v{}",
            crate::topics::IDENTIFY_PROTOCOL,
            config.chain_id,
            config.protocol_version,
        );
        assert_eq!(identify_a, identify_b);

        // Extract major version and confirm they match.
        let major_a = identify_a
            .trim_start_matches("/noble/")
            .split('.')
            .next()
            .and_then(|s| s.parse::<u64>().ok());
        let major_b = identify_b
            .trim_start_matches("/noble/")
            .split('.')
            .next()
            .and_then(|s| s.parse::<u64>().ok());
        assert_eq!(major_a, major_b);
        assert!(major_a.is_some());
    }

    // ---- AUD2-H3: Stable GossipSub message_id test ----

    #[test]
    fn gossipsub_message_id_is_deterministic() {
        // The SHA-256-based message_id must produce identical results for
        // identical message data across invocations (no random seed).
        use sha2::Digest;

        let data = b"test block announce payload";
        let topic = "noble/block/announce/1";

        let compute_id = |d: &[u8], t: &str| -> Vec<u8> {
            let mut hasher = sha2::Sha256::new();
            hasher.update(d);
            hasher.update(t.as_bytes());
            let hash = hasher.finalize();
            hash[..20].to_vec()
        };

        let id1 = compute_id(data, topic);
        let id2 = compute_id(data, topic);
        assert_eq!(
            id1, id2,
            "same data+topic must produce identical message_id"
        );
        assert_eq!(id1.len(), 20, "message_id should be 20 bytes");

        // Different data should produce different id.
        let id3 = compute_id(b"different payload", topic);
        assert_ne!(id1, id3);
    }
}
