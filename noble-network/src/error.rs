// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network error types.

/// Errors that can occur in the network layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("gossipsub error: {0}")]
    Gossipsub(String),

    #[error("codec error: {0}")]
    Codec(String),

    #[error("peer banned: {0}")]
    PeerBanned(String),

    #[error("sync failed: {0}")]
    SyncFailed(String),

    #[error("connection limit reached")]
    ConnectionLimit,

    #[error("channel closed")]
    ChannelClosed,

    #[error("invalid header chain: {0}")]
    InvalidHeaderChain(String),

    #[error("invalid node announce: {0}")]
    InvalidAnnounce(String),

    #[error("kademlia error: {0}")]
    Kademlia(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let e = NetworkError::Transport("dial failed".into());
        assert!(e.to_string().contains("dial failed"));

        let e = NetworkError::Gossipsub("subscription failed".into());
        assert!(e.to_string().contains("subscription failed"));

        let e = NetworkError::Codec("invalid cbor".into());
        assert!(e.to_string().contains("invalid cbor"));

        let e = NetworkError::ConnectionLimit;
        assert!(e.to_string().contains("connection limit"));

        let e = NetworkError::ChannelClosed;
        assert!(e.to_string().contains("channel closed"));

        let e = NetworkError::InvalidHeaderChain("broken prev_hash".into());
        assert!(e.to_string().contains("broken prev_hash"));

        let e = NetworkError::Kademlia("routing table full".into());
        assert!(e.to_string().contains("routing table full"));
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NetworkError>();
    }
}
