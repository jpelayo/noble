// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for mempool admission.

use thiserror::Error;

/// Errors returned by the 8-step admission pipeline.
///
/// Each variant maps to a specific admission step so callers can identify
/// exactly where rejection occurred.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MempoolError {
    /// Step 1: Transaction exceeds maximum size.
    #[error("step 1: transaction too large ({size} bytes, max {max})")]
    TxTooLarge { size: usize, max: usize },

    /// Step 2: Transaction already exists in mempool or confirmed chain.
    #[error("step 2: duplicate transaction {0}")]
    Duplicate(String),

    /// Step 3: Unrecognized protocol version.
    #[error("step 3: unrecognized version {0}")]
    UnrecognizedVersion(u16),

    /// Step 4: Structural validation failed (T1-T5, T8-T10).
    #[error("step 4: structural validation failed: {0}")]
    StructuralValidation(String),

    // Step 5 is signature cache lookup — not an error, it's an optimization.
    /// Step 6: Signature verification failed (T6, T7).
    #[error("step 6: signature verification failed: {0}")]
    SignatureInvalid(String),

    /// Step 6.5: Insufficient balance for transfer (amount + fee + pending debits).
    #[error("step 6.5: insufficient balance (have {have}, need {need})")]
    InsufficientBalance { have: u64, need: u64 },

    /// Step 7: Fee below dynamic minimum.
    #[error("step 7: fee {fee} below minimum {min_fee}")]
    FeeTooLow { fee: u64, min_fee: u64 },

    /// Sender has too many transactions in the mempool.
    #[error("sender rate limit: {count} txs from sender (max {max})")]
    SenderRateLimit { count: usize, max: usize },

    /// Step 8: Mempool is at capacity (should not normally be returned —
    /// eviction handles this, but included for defensive completeness).
    #[error("step 8: mempool at capacity")]
    AtCapacity,

    /// Step 2.6: doc:prev_checksum references a checksum not found on-chain.
    #[error("step 2.6: doc:prev_checksum not found on-chain: {0}")]
    PrevChecksumNotFound(String),

    /// Debit address resolution failed (S34).
    #[error("step 6.5: debit resolution failed: {0}")]
    ValidationFailed(String),

    /// Unconfirmed ancestor/descendant chain would exceed the configured
    /// limit (DoS bound on chain depth/width — Bitcoin's limitancestorcount /
    /// limitdescendantcount).
    #[error("chain too long: {kind} chain would exceed limit {limit}")]
    ChainTooLong { kind: &'static str, limit: usize },

    /// Eviction (make_room): the incoming tx's fee rate does not exceed the
    /// cheapest resident it would have to displace, so it is refused rather
    /// than evicting a higher-fee transaction.
    #[error("fee too low to evict: incoming {incoming} groat/byte does not exceed resident floor {resident}")]
    FeeTooLowToEvict { incoming: u64, resident: u64 },

    /// Internal error (codec, crypto, etc.).
    #[error("internal: {0}")]
    Internal(String),
}
