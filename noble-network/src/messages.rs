// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wire message types for NOBLE P2P protocols.
//!
//! - [`SyncRequest`] / [`SyncResponse`]: used by the `/noble/sync/1.0.0` request-response protocol.
//! - [`TxRequest`] / [`TxResponse`]: used by the `/noble/tx/1.0.0` request-response protocol.
//! - [`GossipMessage`]: CBOR-encoded payloads published on GossipSub topics.
//! - [`NetworkCommand`] / [`NetworkEvent`]: channel messages between node and network service.

use noble_core::{Block, BlockHeader, MisbehaviorEvidence, NodeAnnounce, Transaction};
use serde::{Deserialize, Serialize};

fn default_round() -> u8 {
    1
}

// ---------------------------------------------------------------------------
// Request-Response: sync protocol (/noble/sync/1.0.0)
// ---------------------------------------------------------------------------

/// Requests sent over the sync protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyncRequest {
    /// Request block headers starting from `start_hash`, up to `max_count`.
    GetHeaders {
        start_hash: [u8; 32],
        max_count: u32,
    },
    /// Request full blocks by their hashes.
    GetBlocks { hashes: Vec<[u8; 32]> },
    /// Request a single block by height.
    GetBlockByHeight { height: u64 },
    /// Request the peer's chain status.
    GetStatus,
}

/// Responses sent over the sync protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncResponse {
    /// A batch of block headers.
    Headers(Vec<BlockHeader>),
    /// A batch of full blocks.
    Blocks(Vec<Block>),
    /// A single block (or None if not found).
    Block(Option<Block>),
    /// Chain status information.
    Status {
        height: u64,
        tip_hash: [u8; 32],
        chain_id: u32,
        protocol_version: u16,
        /// Cumulative transaction count across all blocks (fork KPI).
        #[serde(default)]
        total_transactions: u64,
        /// Mean vote count in winning blocks (fork KPI).
        #[serde(default)]
        avg_votes_per_block: f32,
        /// Unix seconds when this status was generated (0 = old peer, no data).
        #[serde(default)]
        sender_timestamp: u64,
    },
    /// An error message from the remote peer.
    Error(String),
}

// ---------------------------------------------------------------------------
// Request-Response: transaction protocol (/noble/tx/1.0.0)
// ---------------------------------------------------------------------------

/// Request a single transaction by its ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRequest {
    pub tx_id: [u8; 32],
}

/// Response containing the requested transaction (or None).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxResponse {
    pub transaction: Option<Transaction>,
}

// ---------------------------------------------------------------------------
// GossipSub payloads (CBOR-encoded to raw bytes)
// ---------------------------------------------------------------------------

/// Messages broadcast via GossipSub topics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[allow(clippy::large_enum_variant)] // NodeAnnounce is large by design (many identity fields)
pub enum GossipMessage {
    /// Announce a new block (sent on `TOPIC_BLOCK_ANNOUNCE`).
    BlockAnnounce { block_hash: [u8; 32], height: u64 },
    /// Announce a new transaction (sent on `TOPIC_TX_ANNOUNCE`).
    TxAnnounce { tx_id: [u8; 32] },
    /// Broadcast a Proof-of-Reputation vote (sent on `TOPIC_POR_VOTE`).
    PorVote {
        cycle: u64,
        candidate_hash: [u8; 32],
        voter_id: Vec<u8>,
        signature: Vec<u8>,
        /// Voting round: 1 = R1, 2 = R2. Default: 1.
        #[serde(default = "default_round")]
        round: u8,
    },
    /// Exchange known peer addresses (sent on `TOPIC_PEER_EXCHANGE`).
    PeerExchange { addrs: Vec<String> },
    /// Broadcast double-proposal evidence (sent on `TOPIC_EVIDENCE`).
    DoubleProposalEvidence {
        /// CBOR-encoded `DoubleProposalEvidence`.
        evidence_bytes: Vec<u8>,
    },
    /// Broadcast vote equivocation evidence (sent on `TOPIC_EVIDENCE`).
    VoteEquivocationEvidence {
        /// CBOR-encoded `VoteEquivocationEvidence`.
        evidence_bytes: Vec<u8>,
    },
    /// Broadcast invalid block evidence (sent on `TOPIC_EVIDENCE`).
    InvalidBlockEvidence {
        /// CBOR-encoded `InvalidBlockEvidence`.
        evidence_bytes: Vec<u8>,
    },
    /// Broadcast announce equivocation evidence (sent on `TOPIC_EVIDENCE`).
    AnnounceEquivocationEvidence {
        /// CBOR-encoded `AnnounceEquivocationEvidence`.
        evidence_bytes: Vec<u8>,
    },
    /// Broadcast a node identity announcement (sent on `TOPIC_NODE_ANNOUNCE`).
    NodeAnnounce {
        identity_key: Vec<u8>,
        node_name: String,
        org_type: String,
        org_name: Option<String>,
        node_role: String,
        contact_email: Option<String>,
        website: Option<String>,
        host_address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        country_code: Option<String>,
        software_version: String,
        #[serde(default)]
        wants_to_validate: bool,
        #[serde(default)]
        wants_to_vote: bool,
        /// Committed chain tip height (gossip-level peer discovery).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chain_tip_height: Option<u64>,
        /// Committed chain tip hash as hex string (gossip-level peer discovery).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chain_tip_hash: Option<String>,
        /// Height of the block this node is currently proposing (if any).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proposed_height: Option<u64>,
        /// Hash of the block this node is currently proposing as hex string (if any).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proposed_hash: Option<String>,
        /// Chain ID of the blockchain this node is on.
        #[serde(default)]
        chain_id: u32,
        /// Decay-weighted cumulative vote weight for chain legitimacy comparison.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chain_vote_weight: Option<u64>,
        /// Human-readable chain label (hex chain ID or empty).
        #[serde(default)]
        network_name: String,
        timestamp: u64,
        signature_scheme: u8,
        signature_pubkey: Vec<u8>,
        signature_bytes: Vec<u8>,
        /// Optional PKI attestation fields (flattened for wire compat).
        /// All four must be present or all absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation_scheme: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation_scope: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation_fingerprint: Option<Vec<u8>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation_data: Option<Vec<u8>>,
    },
}

// ---------------------------------------------------------------------------
// Node ↔ NetworkService channel messages
// ---------------------------------------------------------------------------

/// Commands sent from the node to the network service.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Publish a new block to the network.
    PublishBlock(Block),
    /// Publish a new transaction to the network.
    PublishTransaction(Transaction),
    /// Publish a PoR vote to the network.
    PublishVote {
        cycle: u64,
        candidate_hash: [u8; 32],
        voter_id: Vec<u8>,
        signature: Vec<u8>,
        /// Voting round: 1 = R1, 2 = R2. Default: 1.
        round: u8,
    },
    /// Request a specific block from a peer.
    RequestBlock { peer_id: Vec<u8>, hash: [u8; 32] },
    /// Request a block by its hash from any connected peer.
    RequestBlockByHash { hash: [u8; 32] },
    /// Request a block by its hash from ALL connected peers.
    /// Used when a vote references a block we don't have — the voter may not
    /// cache it, so broadcast to maximise chance of obtaining the block body.
    RequestBlockFromAll { hash: [u8; 32] },
    /// Request a block by height from a specific peer (sync catch-up).
    RequestBlockByHeight { peer_id: Vec<u8>, height: u64 },
    /// Trigger a chain sync check.
    RequestSync,
    /// Ban a peer by their serialized PeerId bytes with a category code and reason.
    BanPeer {
        peer_id: Vec<u8>,
        /// BanCategory discriminant (0x01..0x0C). See `peer_manager::BanCategory`.
        category: u8,
        reason: String,
        /// SHA-256 of the CBOR-encoded evidence that backs this ban (if any).
        evidence_hash: Option<[u8; 32]>,
    },
    /// Gracefully disconnect a peer without banning (e.g. different chain).
    DisconnectPeer(Vec<u8>),
    /// Publish a node identity announcement to the network.
    PublishNodeAnnounce(Box<NodeAnnounce>),
    /// Publish misbehavior evidence (double-proposal or vote equivocation).
    PublishEvidence(Box<MisbehaviorEvidence>),
    /// Dial a specific peer by multiaddr (used by `noble_dialPeer` RPC).
    /// The optional oneshot sender receives `Ok(())` on connection success or
    /// `Err(reason)` on failure/timeout. When `None`, dial is fire-and-forget.
    DialPeer(libp2p::Multiaddr, Option<tokio::sync::oneshot::Sender<Result<(), String>>>),
    /// Manually ban a peer by their serialized PeerId bytes (operator RPC).
    ManualBanPeer {
        peer_id: Vec<u8>,
        reason: String,
        duration_secs: u64,
    },
    /// Unban a peer by their serialized PeerId bytes (operator RPC).
    UnbanPeer(Vec<u8>),
    /// List all currently banned peers. Response via oneshot channel.
    ListBannedPeers(
        tokio::sync::oneshot::Sender<Vec<BannedPeerEntry>>,
    ),
    /// Update the local chain_id in network config (cross-chain adoption).
    /// Also clears the mismatch cooldown map so peers can reconnect immediately.
    UpdateChainId(u32),
    /// Shut down the network service.
    Shutdown,
}

/// A single banned peer entry returned by `ListBannedPeers`.
#[derive(Debug, Clone)]
pub struct BannedPeerEntry {
    pub peer_id_bytes: Vec<u8>,
    pub ban_score: u32,
    pub banned_until: u64,
    pub reason_category: String,
    pub reason_subject: String,
    /// All misbehavior category codes that contributed to this ban (e.g. [0x01, 0x07]).
    pub reason_codes: Vec<u8>,
    /// SHA-256 of the CBOR-encoded evidence (hex), if this ban is evidence-backed.
    pub evidence_hash: Option<String>,
}

/// Events emitted from the network service to the node.
#[derive(Debug)]
pub enum NetworkEvent {
    /// A block was announced by a peer via gossip.
    BlockAnnounced {
        peer_id: Vec<u8>,
        hash: [u8; 32],
        height: u64,
    },
    /// A transaction was announced by a peer via gossip.
    TransactionAnnounced { peer_id: Vec<u8>, tx_id: [u8; 32] },
    /// A PoR vote was received from the network.
    VoteReceived {
        /// Transport-layer peer identity (libp2p PeerId bytes).
        peer_id: Vec<u8>,
        cycle: u64,
        candidate_hash: [u8; 32],
        voter_id: Vec<u8>,
        signature: Vec<u8>,
        /// Voting round: 1 = R1, 2 = R2. Default: 1.
        round: u8,
    },
    /// A full block was received (via request-response or sync).
    BlockReceived { peer_id: Vec<u8>, block: Block },
    /// Headers-first sync completed up to `new_height`.
    SyncComplete { new_height: u64 },
    /// A new peer connected.
    PeerConnected {
        peer_id: Vec<u8>,
        addr: String,
        /// Connection direction: "inbound" or "outbound".
        direction: String,
        chain_tip: Option<(u64, [u8; 32])>,
    },
    /// A peer disconnected.
    PeerDisconnected { peer_id: Vec<u8>, reason: String },
    /// A connection was rejected before the peer was tracked (silent disconnect).
    PeerRejected { peer_id: Vec<u8>, addr: String, reason: String },
    /// A peer's ban score was updated after misbehavior.
    PeerScoreUpdated {
        peer_id: Vec<u8>,
        ban_score: u32,
        categories: Vec<u8>,
        /// Category code of the latest misbehavior that triggered this update.
        last_category: u8,
        /// Human-readable reason for the latest misbehavior.
        last_reason: String,
    },
    /// A peer was banned for misbehavior.
    PeerBanned {
        peer_id: Vec<u8>,
        reason: String,
        category: u8,
        evidence_hash: Option<[u8; 32]>,
    },
    /// A node identity announcement was received from a peer.
    NodeAnnounceReceived {
        peer_id: Vec<u8>,
        announce: Box<NodeAnnounce>,
    },
    /// A peer's latency was measured (from libp2p ping).
    PeerLatencyUpdated {
        peer_id: Vec<u8>,
        latency_ms: u64,
    },
    /// Misbehavior evidence was received from a peer.
    EvidenceReceived {
        peer_id: Vec<u8>,
        evidence: Box<MisbehaviorEvidence>,
    },
    /// A peer's chain tip was updated (from status exchange).
    PeerChainTipUpdated {
        peer_id: Vec<u8>,
        height: u64,
        tip_hash: [u8; 32],
        /// Median clock offset across all peers with data (ms, positive = peers ahead).
        median_clock_offset_ms: Option<i64>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_request_cbor_roundtrip() {
        let req = SyncRequest::GetHeaders {
            start_hash: [0xAA; 32],
            max_count: 500,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let decoded: SyncRequest = ciborium::from_reader(&buf[..]).unwrap();
        match decoded {
            SyncRequest::GetHeaders {
                start_hash,
                max_count,
            } => {
                assert_eq!(start_hash, [0xAA; 32]);
                assert_eq!(max_count, 500);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn sync_request_get_blocks_roundtrip() {
        let req = SyncRequest::GetBlocks {
            hashes: vec![[1; 32], [2; 32]],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let decoded: SyncRequest = ciborium::from_reader(&buf[..]).unwrap();
        match decoded {
            SyncRequest::GetBlocks { hashes } => {
                assert_eq!(hashes.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn sync_request_get_status_roundtrip() {
        let req = SyncRequest::GetStatus;
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let decoded: SyncRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert!(matches!(decoded, SyncRequest::GetStatus));
    }

    #[test]
    fn sync_response_status_roundtrip() {
        let resp = SyncResponse::Status {
            height: 42,
            tip_hash: [0xBB; 32],
            chain_id: 0x4E4F_424C,
            protocol_version: 1,
            total_transactions: 128,
            avg_votes_per_block: 2.5,
            sender_timestamp: 1_700_000_000,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let decoded: SyncResponse = ciborium::from_reader(&buf[..]).unwrap();
        match decoded {
            SyncResponse::Status {
                height,
                chain_id,
                protocol_version,
                ..
            } => {
                assert_eq!(height, 42);
                assert_eq!(chain_id, 0x4E4F_424C);
                assert_eq!(protocol_version, 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn sync_response_error_roundtrip() {
        let resp = SyncResponse::Error("not found".into());
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let decoded: SyncResponse = ciborium::from_reader(&buf[..]).unwrap();
        match decoded {
            SyncResponse::Error(msg) => assert_eq!(msg, "not found"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tx_request_roundtrip() {
        let req = TxRequest { tx_id: [0xCC; 32] };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        let decoded: TxRequest = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded.tx_id, [0xCC; 32]);
    }

    #[test]
    fn tx_response_none_roundtrip() {
        let resp = TxResponse { transaction: None };
        let mut buf = Vec::new();
        ciborium::into_writer(&resp, &mut buf).unwrap();
        let decoded: TxResponse = ciborium::from_reader(&buf[..]).unwrap();
        assert!(decoded.transaction.is_none());
    }

    #[test]
    fn gossip_block_announce_roundtrip() {
        let msg = GossipMessage::BlockAnnounce {
            block_hash: [0xDD; 32],
            height: 100,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_tx_announce_roundtrip() {
        let msg = GossipMessage::TxAnnounce { tx_id: [0xEE; 32] };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_node_announce_roundtrip() {
        let msg = GossipMessage::NodeAnnounce {
            identity_key: vec![0x00; 33],
            node_name: "test-node".into(),
            org_type: "PrivateAcademic".into(),
            org_name: Some("MIT".into()),
            node_role: "ArchiveNode".into(),
            contact_email: Some("test@mit.edu".into()),
            website: Some("https://mit.edu".into()),
            host_address: Some("/ip4/1.2.3.4/tcp/8780".into()),
            country_code: Some("USA".into()),
            software_version: noble_core::SOFTWARE_VERSION.into(),
            wants_to_validate: true,
            wants_to_vote: false,
            chain_tip_height: Some(42),
            chain_tip_hash: Some(hex::encode([0xBB; 32])),
            proposed_height: Some(43),
            proposed_hash: Some(hex::encode([0xCC; 32])),
            chain_id: 0x34E9E7A4,
            chain_vote_weight: Some(42_000),
            network_name: "34E9E7A4".into(),
            timestamp: 1_700_000_000,
            signature_scheme: 0x00,
            signature_pubkey: vec![1; 32],
            signature_bytes: vec![2; 64],
            attestation_scheme: None,
            attestation_scope: None,
            attestation_fingerprint: None,
            attestation_data: None,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_node_announce_with_attestation_roundtrip() {
        let msg = GossipMessage::NodeAnnounce {
            identity_key: vec![0x00; 33],
            node_name: "test-node".into(),
            org_type: "PrivateCorporation".into(),
            org_name: Some("Acme Corp".into()),
            node_role: "FullNode".into(),
            contact_email: None,
            website: None,
            host_address: None,
            country_code: None,
            software_version: noble_core::SOFTWARE_VERSION.into(),
            wants_to_validate: false,
            wants_to_vote: false,
            chain_tip_height: None,
            chain_tip_hash: None,
            proposed_height: None,
            proposed_hash: None,
            chain_id: 0,
            chain_vote_weight: None,
            network_name: String::new(),
            timestamp: 1_700_000_000,
            signature_scheme: 0x01,
            signature_pubkey: vec![1; 32],
            signature_bytes: vec![2; 64],
            attestation_scheme: Some("pkcs7".into()),
            attestation_scope: Some("identity".into()),
            attestation_fingerprint: Some(vec![0xAB; 32]),
            attestation_data: Some(vec![0xCC; 256]),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_peer_exchange_roundtrip() {
        let msg = GossipMessage::PeerExchange {
            addrs: vec![
                "/ip4/1.2.3.4/tcp/8780".to_string(),
                "/ip4/5.6.7.8/tcp/8780".to_string(),
            ],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_double_proposal_evidence_roundtrip() {
        let evidence_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF]; // mock CBOR
        let msg = GossipMessage::DoubleProposalEvidence {
            evidence_bytes: evidence_bytes.clone(),
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_por_vote_roundtrip() {
        let msg = GossipMessage::PorVote {
            cycle: 7,
            candidate_hash: [0xFF; 32],
            voter_id: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            round: 1,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn gossip_por_vote_r2_roundtrip() {
        let msg = GossipMessage::PorVote {
            cycle: 7,
            candidate_hash: [0xFF; 32],
            voter_id: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            round: 2,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
        match decoded {
            GossipMessage::PorVote { round, .. } => assert_eq!(round, 2),
            _ => panic!("expected PorVote"),
        }
    }
}
