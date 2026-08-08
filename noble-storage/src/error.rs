// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for storage operations.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// Generic record not found (peer records, etc.).
    #[error("record not found")]
    NotFound,

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

    /// C1/C2: a transaction failed shared stateful validation during commit
    /// (input ownership, maturity, or value conservation). Carries the typed
    /// cause so callers never parse message text to classify the failure.
    #[error("tx {tx_index} failed stateful validation: {reason}")]
    InvalidTransaction {
        tx_index: usize,
        reason: noble_core::error::ValidationError,
    },

    /// Corruption detected at a specific height.
    #[error("corruption detected at height {height}: {detail}")]
    CorruptionDetected { height: u64, detail: String },

    /// Committing this block would exceed MAX_SUPPLY.
    #[error("supply overflow: cumulative {cumulative} would exceed max {max}")]
    SupplyOverflow { cumulative: u64, max: u64 },

    /// Rollback depth exceeds MAX_REORG_DEPTH.
    #[error("reorg too deep: depth {depth} exceeds max {max}")]
    ReorgTooDeep { depth: u64, max: u64 },

    /// A transaction input references a UTXO that does not exist in the UTXO set.
    #[error("UTXO not found: txid={txid}, vout={vout}")]
    UtxoNotFound { txid: String, vout: u32 },

    /// A transaction input tries to spend an immature UTXO.
    #[error("immature UTXO: created at height {created_height}, current height {current_height}, need {maturity} confirmations")]
    ImmatureUtxo {
        created_height: u64,
        current_height: u64,
        maturity: u64,
    },

    /// Undo data for a rollback height is missing.
    #[error("undo data not found for height {height}")]
    UndoDataNotFound { height: u64 },
}

impl From<noble_codec::CodecError> for StorageError {
    fn from(e: noble_codec::CodecError) -> Self {
        StorageError::Codec(e.to_string())
    }
}
