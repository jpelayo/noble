// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! GossipSub topic constants for the NOBLE protocol.

/// Topic for new block announcements.
pub const TOPIC_BLOCK_ANNOUNCE: &str = "noble/block/announce/1";

/// Topic for new transaction announcements.
pub const TOPIC_TX_ANNOUNCE: &str = "noble/tx/announce/1";

/// Topic for Proof-of-Reputation vote broadcasts.
pub const TOPIC_POR_VOTE: &str = "noble/porvote/1";

/// Topic for node identity announcements.
pub const TOPIC_NODE_ANNOUNCE: &str = "noble/node/announce/1";

/// Topic for peer address exchange.
pub const TOPIC_PEER_EXCHANGE: &str = "noble/peer/exchange/1";

/// All GossipSub topics that a NOBLE node subscribes to.
pub const ALL_TOPICS: &[&str] = &[
    TOPIC_BLOCK_ANNOUNCE,
    TOPIC_TX_ANNOUNCE,
    TOPIC_POR_VOTE,
    TOPIC_NODE_ANNOUNCE,
    TOPIC_PEER_EXCHANGE,
];

/// Protocol identifier for the block/header sync request-response protocol.
pub const SYNC_PROTOCOL: &str = "/noble/sync/1.0.0";

/// Protocol identifier for single-transaction request-response protocol.
pub const TX_PROTOCOL: &str = "/noble/tx/1.0.0";

/// Protocol identifier string sent via libp2p Identify.
pub const IDENTIFY_PROTOCOL: &str = "/noble/1.0.0";

/// User agent string sent via libp2p Identify.
pub const IDENTIFY_AGENT: &str = "noble-node/0.1.0";

/// Protocol identifier for Kademlia DHT.
pub const KAD_PROTOCOL: &str = "/noble/kad/1.0.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_topics_contains_expected() {
        assert_eq!(ALL_TOPICS.len(), 5);
        assert!(ALL_TOPICS.contains(&TOPIC_BLOCK_ANNOUNCE));
        assert!(ALL_TOPICS.contains(&TOPIC_TX_ANNOUNCE));
        assert!(ALL_TOPICS.contains(&TOPIC_POR_VOTE));
        assert!(ALL_TOPICS.contains(&TOPIC_NODE_ANNOUNCE));
        assert!(ALL_TOPICS.contains(&TOPIC_PEER_EXCHANGE));
    }

    #[test]
    fn kad_protocol_starts_with_noble() {
        assert!(KAD_PROTOCOL.starts_with("/noble/"));
    }

    #[test]
    fn protocol_strings_start_with_noble() {
        assert!(SYNC_PROTOCOL.starts_with("/noble/"));
        assert!(TX_PROTOCOL.starts_with("/noble/"));
        assert!(IDENTIFY_PROTOCOL.starts_with("/noble/"));
    }
}
