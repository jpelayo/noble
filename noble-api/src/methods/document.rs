// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Document-related RPC methods: lookupChecksum, verifyDocument, getDocumentHistory.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait DocumentApi {
    /// Look up all transaction IDs that registered a given document checksum.
    #[method(name = "lookupChecksum")]
    async fn lookup_checksum(
        &self,
        checksum: String,
    ) -> Result<ChecksumLookupResponse, ErrorObjectOwned>;

    /// Verify whether a document checksum exists on-chain.
    #[method(name = "verifyDocument")]
    async fn verify_document(
        &self,
        checksum: String,
    ) -> Result<VerifyDocumentResponse, ErrorObjectOwned>;

    /// Get full transaction details for all registrations of a checksum.
    #[method(name = "getDocumentHistory")]
    async fn get_document_history(
        &self,
        checksum: String,
    ) -> Result<DocumentHistoryResponse, ErrorObjectOwned>;
}

/// Build `RegistrationRecord`s from a list of tx_ids using storage lookups.
fn build_registration_records<S: StorageEngine>(
    storage: &S,
    tx_ids: &[noble_crypto::Hash256],
) -> Vec<RegistrationRecord> {
    let mut records = Vec::with_capacity(tx_ids.len());
    for tx_id in tx_ids {
        let block_height = storage
            .get_transaction_location(tx_id)
            .map(|(h, _)| h)
            .unwrap_or(0);
        let timestamp = storage
            .get_transaction(tx_id)
            .map(|tx| tx.timestamp)
            .unwrap_or(0);
        records.push(RegistrationRecord {
            block_height,
            tx_id: hash_to_hex(tx_id),
            timestamp,
        });
    }
    records
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> DocumentApiServer for Arc<ApiState<S>> {
    async fn lookup_checksum(
        &self,
        checksum: String,
    ) -> Result<ChecksumLookupResponse, ErrorObjectOwned> {
        let checksum_hash = parse_hash(&checksum)?;
        let storage = self.storage.read().unwrap();
        let tx_ids = storage
            .lookup_checksum(&checksum_hash)
            .map_err(ApiError::from)?;

        let records = build_registration_records(&*storage, &tx_ids);
        Ok(ChecksumLookupResponse {
            found: !tx_ids.is_empty(),
            records,
        })
    }

    async fn verify_document(
        &self,
        checksum: String,
    ) -> Result<VerifyDocumentResponse, ErrorObjectOwned> {
        let checksum_hash = parse_hash(&checksum)?;
        let storage = self.storage.read().unwrap();
        let tx_ids = storage
            .lookup_checksum(&checksum_hash)
            .map_err(ApiError::from)?;

        let records = build_registration_records(&*storage, &tx_ids);
        let first_seen = records.iter().map(|r| r.timestamp).min();

        Ok(VerifyDocumentResponse {
            checksum,
            registered: !tx_ids.is_empty(),
            registrations: records,
            first_seen,
        })
    }

    async fn get_document_history(
        &self,
        checksum: String,
    ) -> Result<DocumentHistoryResponse, ErrorObjectOwned> {
        let checksum_hash = parse_hash(&checksum)?;
        let storage = self.storage.read().unwrap();
        let tx_ids = storage
            .lookup_checksum(&checksum_hash)
            .map_err(ApiError::from)?;

        if tx_ids.is_empty() {
            return Err(ApiError::ChecksumNotFound(checksum).into());
        }

        let history = build_registration_records(&*storage, &tx_ids);
        Ok(DocumentHistoryResponse { checksum, history })
    }
}
