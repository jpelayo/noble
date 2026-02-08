// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Error types for mempool admission.

use thiserror::Error;

/// Errors returned by the 8-step admission pipeline.
///
/// Each variant maps to a specific admission step so callers can identify
/// exactly where rejection occurred.
#[derive(Debug, Error)]
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

    /// Step 7: Fee below dynamic minimum.
    #[error("step 7: fee {fee} below minimum {min_fee}")]
    FeeTooLow { fee: u64, min_fee: u64 },

    /// Step 8: Mempool is at capacity (should not normally be returned —
    /// eviction handles this, but included for defensive completeness).
    #[error("step 8: mempool at capacity")]
    AtCapacity,

    /// Internal error (codec, crypto, etc.).
    #[error("internal: {0}")]
    Internal(String),
}
