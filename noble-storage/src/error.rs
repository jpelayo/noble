// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for storage operations.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// The requested block was not found.
    #[error("block not found: {0}")]
    BlockNotFound(String),

    /// The requested transaction was not found.
    #[error("transaction not found: {0}")]
    TransactionNotFound(String),

    /// RocksDB returned an error.
    #[error("database error: {0}")]
    Database(String),

    /// Serialization or deserialization failed.
    #[error("codec error: {0}")]
    Codec(String),

    /// The database is not open or has been closed.
    #[error("database not open")]
    NotOpen,

    /// A checksum index entry exceeded the maximum registration limit.
    #[error("checksum index full: {checksum} has {count} registrations (max {max})")]
    ChecksumIndexFull {
        checksum: String,
        count: usize,
        max: usize,
    },

    /// A transfer would leave the sender with a negative balance (GAP-H19).
    #[error("insufficient balance: address has {available}, need {needed}")]
    InsufficientBalance { available: u64, needed: u64 },

    /// A credit would overflow the u64 balance (GAP-H19).
    #[error("balance overflow: current {current}, credit {amount}")]
    BalanceOverflow { current: u64, amount: u64 },
}

impl From<noble_codec::CodecError> for StorageError {
    fn from(e: noble_codec::CodecError) -> Self {
        StorageError::Codec(e.to_string())
    }
}
