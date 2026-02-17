// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// Invalid key length or format.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// Unrecognized signature scheme.
    #[error("unknown scheme id: {0:#04x}")]
    UnknownScheme(u8),

    /// Hash computation error.
    #[error("hash error: {0}")]
    HashError(String),

    /// ECIES encryption failed.
    #[error("ECIES encryption failed: {0}")]
    EciesEncrypt(String),

    /// ECIES decryption failed.
    #[error("ECIES decryption failed: {0}")]
    EciesDecrypt(String),
}
