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

        if tx_ids.is_empty() {
            return Err(ApiError::ChecksumNotFound(checksum).into());
        }

        Ok(ChecksumLookupResponse {
            checksum,
            registrations: tx_ids.iter().map(hash_to_hex).collect(),
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

        Ok(VerifyDocumentResponse {
            checksum,
            found: !tx_ids.is_empty(),
            registration_count: tx_ids.len(),
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

        let mut transactions = Vec::with_capacity(tx_ids.len());
        for tx_id in &tx_ids {
            if let Ok(tx) = storage.get_transaction(tx_id) {
                transactions.push(tx_to_response(&tx, &hash_to_hex(tx_id)));
            }
        }

        Ok(DocumentHistoryResponse {
            checksum,
            transactions,
        })
    }
}
