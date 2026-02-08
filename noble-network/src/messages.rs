// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wire message types for NOBLE P2P protocols.
//!
//! - [`SyncRequest`] / [`SyncResponse`]: used by the `/noble/sync/1.0.0` request-response protocol.
//! - [`TxRequest`] / [`TxResponse`]: used by the `/noble/tx/1.0.0` request-response protocol.
//! - [`GossipMessage`]: CBOR-encoded payloads published on GossipSub topics.
//! - [`NetworkCommand`] / [`NetworkEvent`]: channel messages between node and network service.

use noble_core::{Block, BlockHeader, Transaction};
use serde::{Deserialize, Serialize};

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
    },
    /// Request a specific block from a peer.
    RequestBlock { peer_id: Vec<u8>, hash: [u8; 32] },
    /// Trigger a chain sync check.
    RequestSync,
    /// Ban a peer by their serialized PeerId bytes.
    BanPeer(Vec<u8>),
    /// Shut down the network service.
    Shutdown,
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
        cycle: u64,
        candidate_hash: [u8; 32],
        voter_id: Vec<u8>,
        signature: Vec<u8>,
    },
    /// A full block was received (via request-response or sync).
    BlockReceived { peer_id: Vec<u8>, block: Block },
    /// Headers-first sync completed up to `new_height`.
    SyncComplete { new_height: u64 },
    /// A new peer connected.
    PeerConnected {
        peer_id: Vec<u8>,
        addr: String,
        chain_tip: Option<(u64, [u8; 32])>,
    },
    /// A peer disconnected.
    PeerDisconnected { peer_id: Vec<u8> },
    /// A peer was banned for misbehavior.
    PeerBanned { peer_id: Vec<u8>, reason: String },
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
    fn gossip_por_vote_roundtrip() {
        let msg = GossipMessage::PorVote {
            cycle: 7,
            candidate_hash: [0xFF; 32],
            voter_id: vec![1, 2, 3],
            signature: vec![4, 5, 6],
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&msg, &mut buf).unwrap();
        let decoded: GossipMessage = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(msg, decoded);
    }
}
