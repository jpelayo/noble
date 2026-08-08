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

    /// Step 6.5: An input references a UTXO that does not exist on-chain or
    /// in the mempool (missing, or already spent from our local view).
    #[error("step 6.5: input references a coin that does not exist or has already been spent")]
    MissingInput,

    /// Step 6.5: An input is already spent by another in-mempool transaction.
    #[error("step 6.5: double spend — input already used by a pending mempool transaction")]
    DoubleSpend,

    /// Step 6.5 (C1): An input UTXO is not controlled by the transaction's
    /// issuer — the signature does not authorise spending those coins.
    #[error("step 6.5: input not owned by the transaction issuer")]
    InputNotOwned,

    /// Step 6.5: An input UTXO has not yet reached COINBASE_MATURITY
    /// confirmations.
    #[error("step 6.5: output not yet spendable — available at block {available_at} ({blocks_remaining} block(s) remaining)")]
    ImmatureInput {
        available_at: u64,
        blocks_remaining: u64,
    },

    /// Step 6b: The transaction's protocol-level `expires_at` has passed.
    #[error("step 6b: transaction has expired (expires_at elapsed)")]
    Expired,

    /// Step 4 (T4): Transaction timestamp outside the allowed skew window.
    /// Clock-dependent — split out from StructuralValidation because it must
    /// never be treated as objective peer misbehavior (K3-01).
    #[error("step 4: timestamp out of range: {0}")]
    TimestampOutOfRange(String),

    /// Internal error (codec, crypto, etc.).
    #[error("internal: {0}")]
    Internal(String),
}

/// Typed transaction-admission outcome shared by the node and the network
/// service (K3-01). Decides seen-cache finalization, retry behavior, and —
/// only for `ObjectivelyInvalid` — an attributable penalty for the peer that
/// served the transaction body. Derived from `MempoolError` by TYPED mapping
/// only; deciding peer penalties by parsing error strings is forbidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Admitted to the mempool.
    Accepted,
    /// Already in the mempool or confirmed on-chain — benign duplicate.
    AlreadyKnown,
    /// Fails consensus/protocol rules verifiable by anyone (structure,
    /// signatures, size, version, coinbase-in-mempool). Attributable to the
    /// body-serving peer.
    ObjectivelyInvalid { reason: String },
    /// Valid transaction rejected by LOCAL policy (fee floor, sender limits,
    /// chain limits, capacity). Never a peer fault.
    PolicyRejected { reason: String },
    /// Rejected because of OUR local view or timing (missing/spent UTXO,
    /// mempool double-spend race, maturity, expiry, timestamp skew,
    /// balance). Never a peer fault.
    LocalViewRejected { reason: String },
    /// Could not be processed right now (overload/internal) — retryable,
    /// never a peer fault.
    Busy,
}

impl AdmissionOutcome {
    /// Typed mapping from an admission result. The ONLY place this
    /// classification is defined.
    pub fn from_result<T>(res: &Result<T, MempoolError>) -> Self {
        use MempoolError::*;
        match res {
            Ok(_) => AdmissionOutcome::Accepted,
            Err(Duplicate(_)) => AdmissionOutcome::AlreadyKnown,
            // InputNotOwned is objectively invalid, NOT a local-view rejection:
            // the issuer's signature does not authorise those coins under any
            // node's view of the chain, so relaying it is a peer fault.
            Err(e @ (TxTooLarge { .. } | UnrecognizedVersion(_) | StructuralValidation(_)
                | SignatureInvalid(_) | InputNotOwned)) => {
                AdmissionOutcome::ObjectivelyInvalid { reason: e.to_string() }
            }
            Err(e @ (FeeTooLow { .. } | SenderRateLimit { .. } | AtCapacity
                | ChainTooLong { .. } | FeeTooLowToEvict { .. })) => {
                AdmissionOutcome::PolicyRejected { reason: e.to_string() }
            }
            Err(e @ (InsufficientBalance { .. } | PrevChecksumNotFound(_)
                | ValidationFailed(_) | MissingInput | DoubleSpend
                | ImmatureInput { .. } | Expired | TimestampOutOfRange(_))) => {
                AdmissionOutcome::LocalViewRejected { reason: e.to_string() }
            }
            Err(Internal(_)) => AdmissionOutcome::Busy,
            // MempoolError is #[non_exhaustive]-shaped for future variants:
            // default any unknown rejection to the no-penalty class.
            #[allow(unreachable_patterns)]
            Err(e) => AdmissionOutcome::LocalViewRejected { reason: e.to_string() },
        }
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;

    #[test]
    fn typed_outcome_classification() {
        let ok: Result<(), MempoolError> = Ok(());
        assert_eq!(AdmissionOutcome::from_result(&ok), AdmissionOutcome::Accepted);

        let dup: Result<(), _> = Err(MempoolError::Duplicate("ab".into()));
        assert_eq!(AdmissionOutcome::from_result(&dup), AdmissionOutcome::AlreadyKnown);

        // Objective: attributable to the serving peer.
        for e in [
            MempoolError::SignatureInvalid("bad sig".into()),
            MempoolError::StructuralValidation("T8".into()),
            MempoolError::TxTooLarge { size: 9000, max: 8192 },
            MempoolError::UnrecognizedVersion(99),
        ] {
            let r: Result<(), _> = Err(e);
            assert!(
                matches!(AdmissionOutcome::from_result(&r), AdmissionOutcome::ObjectivelyInvalid { .. }),
                "{r:?} must be ObjectivelyInvalid"
            );
        }

        // Policy: never a peer fault.
        for e in [
            MempoolError::FeeTooLow { fee: 1, min_fee: 100 },
            MempoolError::SenderRateLimit { count: 9, max: 8 },
            MempoolError::AtCapacity,
            MempoolError::ChainTooLong { kind: "ancestor", limit: 25 },
            MempoolError::FeeTooLowToEvict { incoming: 1, resident: 5 },
        ] {
            let r: Result<(), _> = Err(e);
            assert!(
                matches!(AdmissionOutcome::from_result(&r), AdmissionOutcome::PolicyRejected { .. }),
                "{r:?} must be PolicyRejected"
            );
        }

        // Local view / timing: never a peer fault.
        for e in [
            MempoolError::MissingInput,
            MempoolError::DoubleSpend,
            MempoolError::ImmatureInput { available_at: 10, blocks_remaining: 3 },
            MempoolError::Expired,
            MempoolError::TimestampOutOfRange("T4".into()),
            MempoolError::InsufficientBalance { have: 1, need: 2 },
            MempoolError::PrevChecksumNotFound("aa".into()),
        ] {
            let r: Result<(), _> = Err(e);
            assert!(
                matches!(AdmissionOutcome::from_result(&r), AdmissionOutcome::LocalViewRejected { .. }),
                "{r:?} must be LocalViewRejected"
            );
        }

        let busy: Result<(), _> = Err(MempoolError::Internal("db".into()));
        assert_eq!(AdmissionOutcome::from_result(&busy), AdmissionOutcome::Busy);
    }
}
