// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! API error types and JSON-RPC error code constants.

use jsonrpsee::types::ErrorObjectOwned;
use thiserror::Error;

// JSON-RPC error codes (application-specific range: -32000 to -32099)
pub const TX_REJECTED: i32 = -32000;
pub const TX_NOT_FOUND: i32 = -32001;
pub const BLOCK_NOT_FOUND: i32 = -32002;
pub const CHECKSUM_NOT_FOUND: i32 = -32003;
pub const PEER_NOT_FOUND: i32 = -32004;
pub const VALIDATOR_NOT_FOUND: i32 = -32005;
pub const WALLET_LOCKED: i32 = -32006;
pub const UNKNOWN_TOPIC: i32 = -32007;
pub const INVALID_PASSPHRASE: i32 = -32008;
pub const INSUFFICIENT_BALANCE: i32 = -32009;
pub const INVALID_ADDRESS: i32 = -32010;
pub const INVALID_PARAM: i32 = -32011;

/// API error variants.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("transaction rejected: {0}")]
    TxRejected(String),

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

    #[error("storage error: {0}")]
    Storage(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<ApiError> for ErrorObjectOwned {
    fn from(e: ApiError) -> Self {
        let (code, msg) = match &e {
            ApiError::TxRejected(m) => (TX_REJECTED, m.clone()),
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
            ApiError::Storage(m) => (-32603, m.clone()),
            ApiError::Internal(m) => (-32603, m.clone()),
        };
        ErrorObjectOwned::owned(code, msg, None::<()>)
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
