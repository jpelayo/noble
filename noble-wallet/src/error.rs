// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wallet error types.

use thiserror::Error;

/// Errors that can occur during wallet operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WalletError {
    /// Wallet is locked; sign/create operations rejected.
    #[error("wallet is locked")]
    Locked,

    /// Wrong passphrase on unlock or delete.
    #[error("invalid passphrase")]
    InvalidPassphrase,

    /// Requested key not found in keystore.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Key already exists in keystore.
    #[error("duplicate key: {0}")]
    DuplicateKey(String),

    /// Wraps a cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Wraps an I/O error.
    #[error("io error: {0}")]
    Io(String),

    /// Wraps a serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Insufficient balance for transfer.
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance {
        /// Available balance.
        have: u64,
        /// Required balance.
        need: u64,
    },

    /// Invalid recipient address.
    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    /// Unsupported signature scheme.
    #[error("unsupported scheme: {0:#04x}")]
    UnsupportedScheme(u8),

    /// Passphrase does not meet minimum strength requirements.
    #[error("passphrase too weak: {0}")]
    PassphraseTooWeak(String),

    /// Too many failed unlock attempts; keystore is temporarily locked out.
    #[error("too many unlock attempts ({attempts}), try again after {cooldown_secs}s")]
    TooManyAttempts { attempts: usize, cooldown_secs: u64 },
}

impl From<std::io::Error> for WalletError {
    fn from(e: std::io::Error) -> Self {
        WalletError::Io(e.to_string())
    }
}

impl From<noble_crypto::CryptoError> for WalletError {
    fn from(e: noble_crypto::CryptoError) -> Self {
        WalletError::Crypto(e.to_string())
    }
}

impl From<serde_json::Error> for WalletError {
    fn from(e: serde_json::Error) -> Self {
        WalletError::Serialization(e.to_string())
    }
}
