// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! CBOR encoding/decoding for GossipSub payloads.
//!
//! GossipSub publishes raw `Vec<u8>`. This module serializes [`GossipMessage`]
//! to CBOR bytes for publishing and deserializes received bytes back.

use crate::error::NetworkError;
use crate::messages::GossipMessage;

/// Maximum encoded gossip message size (256 KB).
/// Block announcements are small; the largest messages are PoR votes with signatures.
pub const MAX_GOSSIP_MESSAGE_SIZE: usize = 256 * 1024;

/// Encode a [`GossipMessage`] to CBOR bytes.
pub fn encode_gossip(msg: &GossipMessage) -> Result<Vec<u8>, NetworkError> {
    let mut buf = Vec::new();
    ciborium::into_writer(msg, &mut buf).map_err(|e| NetworkError::Codec(e.to_string()))?;
    Ok(buf)
}

/// Decode CBOR bytes into a [`GossipMessage`].
///
/// Returns an error if the data exceeds [`MAX_GOSSIP_MESSAGE_SIZE`] or is invalid CBOR.
pub fn decode_gossip(data: &[u8]) -> Result<GossipMessage, NetworkError> {
    if data.len() > MAX_GOSSIP_MESSAGE_SIZE {
        return Err(NetworkError::Codec(format!(
            "gossip message too large: {} bytes (max {})",
            data.len(),
            MAX_GOSSIP_MESSAGE_SIZE
        )));
    }
    ciborium::from_reader(data).map_err(|e| NetworkError::Codec(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_block_announce() {
        let msg = GossipMessage::BlockAnnounce {
            block_hash: [0x11; 32],
            height: 42,
        };
        let encoded = encode_gossip(&msg).unwrap();
        let decoded = decode_gossip(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_tx_announce() {
        let msg = GossipMessage::TxAnnounce { tx_id: [0x22; 32] };
        let encoded = encode_gossip(&msg).unwrap();
        let decoded = decode_gossip(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn roundtrip_por_vote() {
        let msg = GossipMessage::PorVote {
            cycle: 99,
            candidate_hash: [0x33; 32],
            voter_id: vec![10, 20, 30],
            signature: vec![40, 50, 60],
        };
        let encoded = encode_gossip(&msg).unwrap();
        let decoded = decode_gossip(&encoded).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn decode_malformed_data() {
        let bad_data = b"this is not cbor";
        let result = decode_gossip(bad_data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("codec"));
    }

    #[test]
    fn decode_oversized_data() {
        let big_data = vec![0u8; MAX_GOSSIP_MESSAGE_SIZE + 1];
        let result = decode_gossip(&big_data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too large"));
    }

    #[test]
    fn decode_empty_data() {
        let result = decode_gossip(&[]);
        assert!(result.is_err());
    }
}
