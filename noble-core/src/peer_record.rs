// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Persistent peer record for peer memory.
//!
//! Tracks identity announcements across disconnects and restarts.
//! Stored in the `peer_memory` column family, keyed by identity key wire bytes.

use crate::NodeAnnounce;
use serde::{Deserialize, Serialize};

/// A persistent record of a network peer, surviving disconnects and restarts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerRecord {
    /// Wire-format public key bytes (stable identifier).
    pub identity_key: Vec<u8>,
    /// Unix timestamp of first observation.
    pub first_seen: u64,
    /// Unix timestamp of most recent activity (updated on announce/connect).
    pub last_seen: u64,
    /// Total number of connections from this peer.
    pub connection_count: u32,
    /// Most recent NodeAnnounce from this peer.
    pub last_announce: Option<NodeAnnounce>,
    /// Serialized libp2p PeerId bytes.
    pub peer_id_bytes: Vec<u8>,
    /// Last known multiaddr string.
    pub last_addr: Option<String>,
}

impl PeerRecord {
    /// Create a new peer record with first observation timestamp.
    pub fn new(identity_key: Vec<u8>, peer_id_bytes: Vec<u8>, now: u64) -> Self {
        Self {
            identity_key,
            first_seen: now,
            last_seen: now,
            connection_count: 1,
            last_announce: None,
            peer_id_bytes,
            last_addr: None,
        }
    }

    /// Update the record with a new announce, bumping `last_seen`.
    pub fn update_announce(&mut self, announce: NodeAnnounce, now: u64) {
        self.last_announce = Some(announce);
        self.last_seen = now;
    }

    /// Increment connection count and bump `last_seen`.
    pub fn on_connected(&mut self, now: u64) {
        self.connection_count = self.connection_count.saturating_add(1);
        self.last_seen = now;
    }

    /// Whether the record is stale (older than `max_age_secs`).
    pub fn is_stale(&self, now: u64, max_age_secs: u64) -> bool {
        now.saturating_sub(self.last_seen) > max_age_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_peer_record() {
        let rec = PeerRecord::new(vec![1, 2, 3], vec![4, 5, 6], 1000);
        assert_eq!(rec.first_seen, 1000);
        assert_eq!(rec.last_seen, 1000);
        assert_eq!(rec.connection_count, 1);
        assert!(rec.last_announce.is_none());
    }

    #[test]
    fn on_connected_increments() {
        let mut rec = PeerRecord::new(vec![1], vec![2], 100);
        rec.on_connected(200);
        assert_eq!(rec.connection_count, 2);
        assert_eq!(rec.last_seen, 200);
    }

    #[test]
    fn staleness_check() {
        let rec = PeerRecord::new(vec![1], vec![2], 1000);
        assert!(!rec.is_stale(1500, 600)); // 500s < 600s threshold
        assert!(rec.is_stale(1700, 600)); // 700s > 600s threshold
    }

    #[test]
    fn cbor_roundtrip() {
        let rec = PeerRecord {
            identity_key: vec![0xAA; 32],
            first_seen: 1_700_000_000,
            last_seen: 1_700_001_000,
            connection_count: 5,
            last_announce: None,
            peer_id_bytes: vec![0xBB; 38],
            last_addr: Some("/ip4/1.2.3.4/tcp/8780".into()),
        };
        use noble_codec::NobleCbor;
        let buf = rec.to_cbor().unwrap();
        let decoded = PeerRecord::from_cbor(&buf).unwrap();
        assert_eq!(rec, decoded);
    }
}
