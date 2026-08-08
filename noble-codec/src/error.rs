// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for CBOR encoding and decoding operations.

use thiserror::Error;

/// Errors that can occur during CBOR serialization and deserialization.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecError {
    /// Failed to serialize a value to CBOR bytes.
    #[error("CBOR serialization failed: {0}")]
    Serialization(String),

    /// Failed to deserialize CBOR bytes into a value.
    #[error("CBOR deserialization failed: {0}")]
    Deserialization(String),

    /// Failed to produce canonical CBOR encoding.
    #[error("canonical encoding failed: {0}")]
    Canonicalization(String),

    /// A declared CBOR length cannot be represented on this platform, or
    /// advancing the cursor by it would overflow.
    ///
    /// CBOR arguments are `u64` and fully attacker-controlled, so a malformed
    /// message can declare a length near `u64::MAX`. Reaching this error means
    /// the decoder refused it as data; previously the arithmetic overflowed and
    /// panicked, taking down the task doing the decoding.
    #[error("declared length {declared} is not representable at position {pos}")]
    LengthOverflow { declared: u64, pos: usize },
}
