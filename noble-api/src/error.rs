// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! API error types and JSON-RPC error code constants.

use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

// JSON-RPC error codes (application-specific range: -32000 to -32099)
// Aligned with Setup/rpc-api-specification.md §Error Codes
pub const TX_REJECTED: i32 = -32000;
pub const BLOCK_NOT_FOUND: i32 = -32001;
pub const TX_NOT_FOUND: i32 = -32002;
pub const CHECKSUM_NOT_FOUND: i32 = -32003;
pub const AUTH_REQUIRED: i32 = -32004;
pub const RATE_LIMITED: i32 = -32005;
pub const NODE_SYNCING: i32 = -32006;
pub const WALLET_LOCKED: i32 = -32007;
pub const INVALID_PASSPHRASE: i32 = -32008;
pub const INSUFFICIENT_BALANCE: i32 = -32009;
pub const INVALID_ADDRESS: i32 = -32010;
pub const INVALID_PARAM: i32 = -32011;
pub const PEER_NOT_FOUND: i32 = -32012;
pub const VALIDATOR_NOT_FOUND: i32 = -32013;
pub const UNKNOWN_TOPIC: i32 = -32014;
pub const ACCESS_DENIED: i32 = -32015;
pub const GATEKEEPER_REJECTED: i32 = -32016;
// Granular transaction rejection codes (split from TX_REJECTED omnibus)
pub const TX_TOO_LARGE: i32 = -32020;
pub const TX_DUPLICATE: i32 = -32021;
pub const TX_BAD_VERSION: i32 = -32022;
pub const TX_STRUCTURAL: i32 = -32023;
pub const TX_BAD_SIGNATURE: i32 = -32024;
pub const TX_FEE_TOO_LOW: i32 = -32025;
pub const TX_SENDER_LIMIT: i32 = -32026;
pub const TX_MEMPOOL_FULL: i32 = -32027;
pub const TX_IMMATURE_UTXO: i32 = -32028;
pub const TX_DOUBLE_SPEND: i32 = -32029;
pub const TX_MISSING_INPUT: i32 = -32030;
pub const TX_INSUFFICIENT_INPUT: i32 = -32031;
pub const TX_EXPIRED: i32 = -32032;

/// API error variants.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApiError {
    /// Generic transaction rejection (legacy catch-all).
    #[error("transaction rejected: {0}")]
    TxRejected(String),

    // ── Granular tx rejection variants ──

    #[error("{0}")]
    TxTooLarge(String),

    #[error("{0}")]
    TxDuplicate(String),

    #[error("{0}")]
    TxBadVersion(String),

    #[error("{0}")]
    TxStructural(String),

    #[error("{0}")]
    TxBadSignature(String),

    #[error("{0}")]
    TxFeeTooLow(String),

    #[error("{0}")]
    TxSenderLimit(String),

    #[error("{0}")]
    TxMempoolFull(String),

    #[error("{0}")]
    TxImmatureUtxo(String),

    #[error("{0}")]
    TxDoubleSpend(String),

    #[error("{0}")]
    TxMissingInput(String),

    #[error("{0}")]
    TxInsufficientInput(String),

    #[error("{0}")]
    TxExpired(String),

    #[error("transaction not found: {0}")]
    TxNotFound(String),

    #[error("block not found: {0}")]
    BlockNotFound(String),

    #[error("checksum not found: {0}")]
    ChecksumNotFound(String),

    #[error("peer not found: {0}")]
    PeerNotFound(String),

    #[error("validator not found: {0}")]
    ValidatorNotFound(String),

    #[error("wallet locked")]
    WalletLocked,

    #[error("unknown subscription topic: {0}")]
    UnknownTopic(String),

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("insufficient balance: {0}")]
    InsufficientBalance(String),

    #[error("invalid address: {0}")]
    InvalidAddress(String),

    #[error("invalid parameter: {0}")]
    InvalidParam(String),

    #[error("authentication required")]
    AuthRequired,

    #[error("access denied: {0}")]
    AccessDenied(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<ApiError> for ErrorObjectOwned {
    fn from(e: ApiError) -> Self {
        let (code, msg) = match &e {
            ApiError::TxRejected(m) => (TX_REJECTED, m.clone()),
            ApiError::TxTooLarge(m) => (TX_TOO_LARGE, m.clone()),
            ApiError::TxDuplicate(m) => (TX_DUPLICATE, m.clone()),
            ApiError::TxBadVersion(m) => (TX_BAD_VERSION, m.clone()),
            ApiError::TxStructural(m) => (TX_STRUCTURAL, m.clone()),
            ApiError::TxBadSignature(m) => (TX_BAD_SIGNATURE, m.clone()),
            ApiError::TxFeeTooLow(m) => (TX_FEE_TOO_LOW, m.clone()),
            ApiError::TxSenderLimit(m) => (TX_SENDER_LIMIT, m.clone()),
            ApiError::TxMempoolFull(m) => (TX_MEMPOOL_FULL, m.clone()),
            ApiError::TxImmatureUtxo(m) => (TX_IMMATURE_UTXO, m.clone()),
            ApiError::TxDoubleSpend(m) => (TX_DOUBLE_SPEND, m.clone()),
            ApiError::TxMissingInput(m) => (TX_MISSING_INPUT, m.clone()),
            ApiError::TxInsufficientInput(m) => (TX_INSUFFICIENT_INPUT, m.clone()),
            ApiError::TxExpired(m) => (TX_EXPIRED, m.clone()),
            ApiError::TxNotFound(m) => (TX_NOT_FOUND, m.clone()),
            ApiError::BlockNotFound(m) => (BLOCK_NOT_FOUND, m.clone()),
            ApiError::ChecksumNotFound(m) => (CHECKSUM_NOT_FOUND, m.clone()),
            ApiError::PeerNotFound(m) => (PEER_NOT_FOUND, m.clone()),
            ApiError::ValidatorNotFound(m) => (VALIDATOR_NOT_FOUND, m.clone()),
            ApiError::WalletLocked => (WALLET_LOCKED, "wallet is locked".into()),
            ApiError::UnknownTopic(m) => (UNKNOWN_TOPIC, m.clone()),
            ApiError::InvalidPassphrase => (INVALID_PASSPHRASE, "invalid passphrase".into()),
            ApiError::InsufficientBalance(m) => (INSUFFICIENT_BALANCE, m.clone()),
            ApiError::InvalidAddress(m) => (INVALID_ADDRESS, m.clone()),
            ApiError::InvalidParam(m) => (INVALID_PARAM, m.clone()),
            ApiError::AuthRequired => (AUTH_REQUIRED, "authentication required".into()),
            ApiError::AccessDenied(m) => (ACCESS_DENIED, m.clone()),
            ApiError::Storage(m) => (-32603, m.clone()),
            ApiError::Internal(m) => (-32603, m.clone()),
        };
        ErrorObjectOwned::owned(code, msg, None::<()>)
    }
}

impl From<noble_mempool::MempoolError> for ApiError {
    fn from(e: noble_mempool::MempoolError) -> Self {
        use noble_mempool::MempoolError::*;
        match &e {
            TxTooLarge { size, max } => ApiError::TxTooLarge(
                format!("Transaction too large ({size} bytes, maximum is {max} bytes)."),
            ),
            Duplicate(id) => ApiError::TxDuplicate(
                format!("Transaction already exists ({id})."),
            ),
            UnrecognizedVersion(v) => ApiError::TxBadVersion(
                format!("Unrecognized protocol version ({v})."),
            ),
            StructuralValidation(msg) => {
                // Route to more specific codes based on message content.
                if msg.contains("Output not yet spendable") {
                    ApiError::TxImmatureUtxo(msg.clone())
                } else if msg.contains("Double spend") {
                    ApiError::TxDoubleSpend(msg.clone())
                } else if msg.contains("does not exist or has already been spent") {
                    ApiError::TxMissingInput(msg.clone())
                } else if msg.contains("Insufficient funds") {
                    ApiError::TxInsufficientInput(msg.clone())
                } else if msg.contains("expired") {
                    ApiError::TxExpired(msg.clone())
                } else {
                    ApiError::TxStructural(msg.clone())
                }
            }
            SignatureInvalid(msg) => ApiError::TxBadSignature(msg.clone()),
            InsufficientBalance { have, need } => ApiError::TxInsufficientInput(
                format!("Insufficient funds. Have {have} groats, need {need} groats."),
            ),
            FeeTooLow { fee, min_fee } => ApiError::TxFeeTooLow(
                format!("Fee too low. Transaction fee is {fee} groats but the minimum is {min_fee} groats."),
            ),
            SenderRateLimit { count, max } => ApiError::TxSenderLimit(
                format!("Too many pending transactions from this sender ({count}/{max})."),
            ),
            AtCapacity => ApiError::TxMempoolFull(
                "Mempool is full. Try again later or increase the fee.".into(),
            ),
            PrevChecksumNotFound(cs) => ApiError::TxStructural(
                format!("Referenced previous document checksum not found on-chain: {cs}"),
            ),
            ValidationFailed(msg) => ApiError::TxStructural(msg.clone()),
            Internal(msg) => ApiError::Internal(msg.clone()),
            _ => ApiError::TxRejected(e.to_string()),
        }
    }
}

impl From<noble_storage::StorageError> for ApiError {
    fn from(e: noble_storage::StorageError) -> Self {
        match &e {
            noble_storage::StorageError::BlockNotFound(m) => ApiError::BlockNotFound(m.clone()),
            noble_storage::StorageError::TransactionNotFound(m) => ApiError::TxNotFound(m.clone()),
            _ => ApiError::Storage(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::types::ErrorObjectOwned;

    #[test]
    fn error_code_mapping() {
        let cases: Vec<(ApiError, i32)> = vec![
            (ApiError::TxRejected("r".into()), TX_REJECTED),
            (ApiError::TxTooLarge("r".into()), TX_TOO_LARGE),
            (ApiError::TxDuplicate("r".into()), TX_DUPLICATE),
            (ApiError::TxBadVersion("r".into()), TX_BAD_VERSION),
            (ApiError::TxStructural("r".into()), TX_STRUCTURAL),
            (ApiError::TxBadSignature("r".into()), TX_BAD_SIGNATURE),
            (ApiError::TxFeeTooLow("r".into()), TX_FEE_TOO_LOW),
            (ApiError::TxSenderLimit("r".into()), TX_SENDER_LIMIT),
            (ApiError::TxMempoolFull("r".into()), TX_MEMPOOL_FULL),
            (ApiError::TxImmatureUtxo("r".into()), TX_IMMATURE_UTXO),
            (ApiError::TxDoubleSpend("r".into()), TX_DOUBLE_SPEND),
            (ApiError::TxMissingInput("r".into()), TX_MISSING_INPUT),
            (ApiError::TxInsufficientInput("r".into()), TX_INSUFFICIENT_INPUT),
            (ApiError::TxExpired("r".into()), TX_EXPIRED),
            (ApiError::TxNotFound("t".into()), TX_NOT_FOUND),
            (ApiError::BlockNotFound("b".into()), BLOCK_NOT_FOUND),
            (ApiError::ChecksumNotFound("c".into()), CHECKSUM_NOT_FOUND),
            (ApiError::PeerNotFound("p".into()), PEER_NOT_FOUND),
            (ApiError::ValidatorNotFound("v".into()), VALIDATOR_NOT_FOUND),
            (ApiError::WalletLocked, WALLET_LOCKED),
            (ApiError::UnknownTopic("t".into()), UNKNOWN_TOPIC),
            (ApiError::InvalidPassphrase, INVALID_PASSPHRASE),
            (
                ApiError::InsufficientBalance("i".into()),
                INSUFFICIENT_BALANCE,
            ),
            (ApiError::InvalidAddress("a".into()), INVALID_ADDRESS),
            (ApiError::InvalidParam("p".into()), INVALID_PARAM),
            (ApiError::AuthRequired, AUTH_REQUIRED),
            (ApiError::AccessDenied("d".into()), ACCESS_DENIED),
            (ApiError::Storage("s".into()), -32603),
            (ApiError::Internal("i".into()), -32603),
        ];

        for (err, expected_code) in cases {
            let rpc_err: ErrorObjectOwned = err.into();
            assert_eq!(rpc_err.code(), expected_code, "wrong code for variant");
        }
    }

    #[test]
    fn storage_error_converts_to_api_error() {
        // BlockNotFound maps to ApiError::BlockNotFound
        let se = noble_storage::StorageError::BlockNotFound("hash_xyz".into());
        let ae: ApiError = se.into();
        match ae {
            ApiError::BlockNotFound(m) => assert_eq!(m, "hash_xyz"),
            other => panic!("expected BlockNotFound, got: {other:?}"),
        }

        // TransactionNotFound maps to ApiError::TxNotFound
        let se = noble_storage::StorageError::TransactionNotFound("tx_abc".into());
        let ae: ApiError = se.into();
        match ae {
            ApiError::TxNotFound(m) => assert_eq!(m, "tx_abc"),
            other => panic!("expected TxNotFound, got: {other:?}"),
        }

        // Other variants map to ApiError::Storage
        let se = noble_storage::StorageError::Database("disk full".into());
        let ae: ApiError = se.into();
        match ae {
            ApiError::Storage(m) => assert!(m.contains("disk full")),
            other => panic!("expected Storage, got: {other:?}"),
        }
    }
}
