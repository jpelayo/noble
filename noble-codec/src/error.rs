// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for CBOR encoding and decoding operations.

use thiserror::Error;

/// Errors that can occur during CBOR serialization and deserialization.
#[derive(Debug, Error)]
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
}
