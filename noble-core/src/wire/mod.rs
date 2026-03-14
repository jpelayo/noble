// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Frozen wire format encoder for cryptographic hashing.
//!
//! This module provides architecture-independent, deterministic byte
//! encoding for all types that participate in block hashes, transaction
//! IDs, and signing messages. No serde, no ciborium in the critical path.

pub mod cbor;
pub mod v1;

/// Wire format version. Increment on breaking changes.
pub const WIRE_FORMAT_VERSION: u8 = 1;

/// Trait for types that participate in cryptographic hashing.
pub trait WireFormat {
    /// Encode this value into an existing buffer (zero intermediate allocations).
    fn encode_wire(&self, buf: &mut Vec<u8>);

    /// Encode this value to a new Vec (convenience wrapper).
    fn wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_wire(&mut buf);
        buf
    }
}
