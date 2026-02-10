// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Validation error types covering all T1-T17 and B1-B12 rules.

use thiserror::Error;

/// Errors from transaction validation (T1-T17) and block validation (B1-B12).
#[derive(Debug, Error)]
pub enum ValidationError {
    // --- Transaction validation (T1-T12) ---
    /// T1: Serialized transaction exceeds MAX_TX_SIZE.
    #[error("T1: transaction too large ({size} bytes, max {max})")]
    TxTooLarge { size: usize, max: usize },

    /// T2: Unrecognized protocol version.
    #[error("T2: unknown protocol version {0}")]
    UnknownVersion(u16),

    /// T3: Checksum is not exactly 32 bytes. (Enforced at compile time by `[u8; 32]`.)
    #[error("T3: invalid checksum length")]
    InvalidChecksum,

    /// T4: Timestamp too far from current time.
    #[error(
        "T4: timestamp {tx_time} out of range (current: {current_time}, max skew: ±{max_skew}s)"
    )]
    TimestampOutOfRange {
        tx_time: u64,
        current_time: u64,
        max_skew: u64,
    },

    /// T5: Publisher signature uses an unrecognized scheme.
    #[error("T5: unrecognized signature scheme {0:#04x}")]
    UnrecognizedScheme(u8),

    /// T6: Publisher signature verification failed.
    #[error("T6: publisher signature invalid: {0}")]
    PublisherSigInvalid(String),

    /// T7: An additional signature verification failed.
    #[error("T7: additional signature {index} invalid: {reason}")]
    AdditionalSigInvalid { index: usize, reason: String },

    /// T8: Metadata key or value out of bounds.
    #[error("T8: metadata bounds violation: {0}")]
    MetadataBounds(String),

    /// T9: Duplicate metadata key.
    #[error("T9: duplicate metadata key: {0}")]
    DuplicateMetadataKey(String),

    /// T10: Recomputed tx_id does not match.
    #[error("T10: tx_id mismatch (claimed: {claimed}, computed: {computed})")]
    TxIdMismatch { claimed: String, computed: String },

    /// T11: Fee below minimum.
    #[error("T11: fee {fee} below minimum {min_fee}")]
    FeeTooLow { fee: u64, min_fee: u64 },

    /// T12: secp256k1 signature with high-S value (handled by noble-crypto verify).
    #[error("T12: high-S signature detected")]
    HighSSignature,

    /// T13: Unrecognized transaction type.
    #[error("T13: unknown tx_type {0:#04x}")]
    UnknownTxType(u8),

    /// T14: Transfer transaction missing recipient.
    #[error("T14: transfer tx requires recipient")]
    TransferMissingRecipient,

    /// T15: Transfer transaction missing or zero amount.
    #[error("T15: transfer tx requires amount > 0")]
    TransferInvalidAmount,

    /// T16: Sender balance insufficient for amount + fee.
    /// (Checked at commit time, not structural validation.)
    #[error("T16: insufficient balance (need {needed}, have {available})")]
    InsufficientBalance { needed: u64, available: u64 },

    /// T17: Notarization tx has transfer-only fields set.
    #[error("T17: notarization tx must not have recipient or amount")]
    NotarizationHasTransferFields,

    // --- Block validation (B1-B12) ---
    /// B1: Serialized block exceeds MAX_BLOCK_SIZE.
    #[error("B1: block too large ({size} bytes, max {max})")]
    BlockTooLarge { size: usize, max: usize },

    /// B2: prev_block_hash does not match parent.
    #[error("B2: prev_block_hash mismatch")]
    PrevHashMismatch,

    /// B3: Height is not parent + 1.
    #[error("B3: height {height} != expected {expected}")]
    HeightMismatch { height: u64, expected: u64 },

    /// B4: Merkle root does not match recomputed tree.
    #[error("B4: merkle root mismatch")]
    MerkleRootMismatch,

    /// B5: Block timestamp not strictly after parent.
    #[error("B5: timestamp {block_time} not after parent {parent_time}")]
    TimestampNotAfterParent { block_time: u64, parent_time: u64 },

    /// B6: Block timestamp skew exceeds allowed range.
    #[error("B6: block timestamp {block_time} out of range (current: {current_time})")]
    BlockTimestampSkew { block_time: u64, current_time: u64 },

    /// B7: tx_count in header doesn't match actual transaction count.
    #[error("B7: tx_count {claimed} != actual {actual}")]
    TxCountMismatch { claimed: u32, actual: u32 },

    /// B8: Validator signature verification failed.
    #[error("B8: validator signature invalid: {0}")]
    ValidatorSigInvalid(String),

    /// B9: Validator not in the node's trusted validator list.
    #[error("B9: validator not in trusted list")]
    ValidatorNotTrusted,

    /// B10: Validator produced multiple blocks in one cycle.
    #[error("B10: duplicate block in cycle")]
    DuplicateBlockInCycle,

    /// B11: A transaction in the block failed validation.
    #[error("B11: transaction {index} invalid: {source}")]
    InvalidTransaction {
        index: usize,
        #[source]
        source: Box<ValidationError>,
    },

    /// B12: Validator's public key uses an unrecognized scheme.
    #[error("B12: validator scheme unrecognized: {0:#04x}")]
    ValidatorSchemeUnrecognized(u8),

    // --- General ---
    /// Codec or crypto error during validation.
    #[error("internal: {0}")]
    Internal(String),
}
