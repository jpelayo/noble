// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
//! Frozen wire format encoder for the NOBLE protocol.
//!
//! This crate provides deterministic, architecture-independent byte
//! encoding for all types that participate in cryptographic hashing
//! (block hashes, transaction IDs, signing messages).
//!
//! # Design
//!
//! - **No serde, no ciborium** in the hashing path. Every type has a
//!   hand-written encoder that produces CBOR-compatible bytes.
//! - **Frozen per version**: once a wire format version is released,
//!   its output MUST NOT change. Breaking changes require a new version.
//! - **Usable by client apps**: Swift, JavaScript, and WRY clients can
//!   implement the same encoding to verify hashes locally.
//!
//! # Wire Format V1 Rules
//!
//! - Structs → CBOR map (major type 5) with text string keys, sorted
//!   alphabetically by key name (RFC 8949 deterministic encoding).
//! - `Hash256`, `Vec<u8>`, `[u8; N]` → CBOR byte string (major type 2).
//! - `NoblePublicKey` → CBOR byte string: `[scheme_id(1) || key_bytes]`.
//! - `NobleAddress` → CBOR byte string: `[prefix(1) || address_data]`.
//! - `SignatureEnvelope` → CBOR byte string: `[scheme_id(1) || pubkey_len(1) || pubkey || sig]`.
//! - `OrgType`, `NodeRole` → CBOR unsigned integer (variant index).
//! - `Option::None` → field omitted from map (count reduced).
//! - `Vec::is_empty()` → field omitted from map (count reduced).
//! - Unsigned integers → CBOR unsigned integer (major type 0), minimal encoding.
//! - Text strings → CBOR text string (major type 3).

pub mod cbor;
pub mod v1;
pub mod vectors;

/// Wire format version. Increment on breaking changes to the encoding.
///
/// V1: Initial frozen format. All existing block hashes, transaction IDs,
/// and signatures are computed using this version.
pub const WIRE_FORMAT_VERSION: u8 = 1;

/// Trait for types that participate in cryptographic hashing.
///
/// Produces deterministic, architecture-independent bytes suitable
/// for use as hash preimages (block hash, tx_id, signing messages).
///
/// # Contract
///
/// - `wire_bytes()` is infallible (no serde errors possible).
/// - Output is identical on all platforms (ARM, x86_64, etc.).
/// - Output is frozen per `WIRE_FORMAT_VERSION` — it MUST NOT change
///   for a given version, even across code refactors.
/// - Output is valid CBOR (RFC 8949 deterministic encoding).
pub trait WireFormat {
    /// Encode this value into an existing buffer (zero intermediate allocations).
    ///
    /// Nested encoders should call this to write directly into the parent
    /// buffer instead of allocating a temporary Vec.
    fn encode_wire(&self, buf: &mut Vec<u8>);

    /// Encode this value to a new Vec (convenience wrapper).
    fn wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_wire(&mut buf);
        buf
    }
}
