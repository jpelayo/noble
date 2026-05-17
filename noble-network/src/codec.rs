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

/// Project-level cap on a single request_response frame (request or response).
///
/// libp2p's `request_response::cbor::Behaviour` codec already enforces
/// hard byte limits at decode time (in libp2p-request-response 0.27:
/// `REQUEST_SIZE_MAXIMUM = 1 MiB`, `RESPONSE_SIZE_MAXIMUM = 10 MiB`).
/// This constant declares OUR expectation so a future libp2p upgrade
/// that drops or widens those limits is visible at the project level.
///
/// 8 MB matches `MAX_BLOCK_SIZE` with headroom for CBOR envelope overhead;
/// larger than any honest peer ever sends, smaller than libp2p's response
/// cap so the inner-codec gate fires first.
///
/// The drift test in `noble-network/src/behaviour.rs::tests` asserts
/// libp2p's caps stay within these bounds.
pub const MAX_REQUEST_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Encode a [`GossipMessage`] to CBOR bytes.
pub fn encode_gossip(msg: &GossipMessage) -> Result<Vec<u8>, NetworkError> {
    noble_codec::cbor_ser::to_cbor(msg).map_err(|e| NetworkError::Codec(e.to_string()))
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
    noble_codec::cbor_de::from_cbor(data).map_err(|e| NetworkError::Codec(e.to_string()))
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
            round: 1,
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
