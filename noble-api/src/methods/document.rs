// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Document-related RPC methods: lookupChecksum, verifyDocument, getDocumentHistory,
//! getDocumentVersions, getDocumentsByIssuer.

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

    /// Walk the version chain starting from a root checksum.
    ///
    /// Returns the root plus all successors discovered by following
    /// `doc:prev_checksum` links in the `version_chain` storage index.
    #[method(name = "getDocumentVersions")]
    async fn get_document_versions(
        &self,
        checksum: String,
    ) -> Result<DocumentVersionsResponse, ErrorObjectOwned>;

    /// Find all documents registered by a specific issuer public key.
    #[method(name = "getDocumentsByIssuer")]
    async fn get_documents_by_issuer(
        &self,
        public_key: String,
    ) -> Result<DocumentsByIssuerResponse, ErrorObjectOwned>;

    /// Search documents by metadata key/value. Used for author/publisher search.
    #[method(name = "searchDocumentsByMetadata")]
    async fn search_documents_by_metadata(
        &self,
        key: String,
        value: String,
    ) -> Result<MetadataSearchResponse, ErrorObjectOwned>;
}

/// Build `RegistrationRecord`s from a list of tx_ids using storage lookups.
fn build_registration_records<S: StorageEngine>(
    storage: &S,
    tx_ids: &[noble_crypto::Hash256],
) -> Vec<RegistrationRecord> {
    use noble_core::constants::{META_KEY_PREV_CHECKSUM, META_KEY_VERSION};

    let mut records = Vec::with_capacity(tx_ids.len());
    for tx_id in tx_ids {
        let block_height = storage
            .get_transaction_location(tx_id)
            .map(|(h, _)| h)
            .unwrap_or(0);
        let (timestamp, version, prev_checksum, tx_type_name, locked_ref) = storage
            .get_transaction(tx_id)
            .map(|tx| {
                let ver = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_VERSION)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                    .and_then(|s| s.parse::<u32>().ok());
                let prev = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_PREV_CHECKSUM)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                    .map(|s| s.to_string());
                let type_name = noble_core::tx_types::type_name(tx.tx_type).to_string();
                let locked = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == noble_core::locked_tx::META_UNLOCK_TXID)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                    .map(|s| s.to_string());
                (tx.timestamp, ver, prev, Some(type_name), locked)
            })
            .unwrap_or((0, None, None, None, None));
        records.push(RegistrationRecord {
            block_height,
            tx_id: hash_to_hex(tx_id),
            timestamp,
            tx_type: tx_type_name,
            version,
            prev_checksum,
            locked_tx_id: locked_ref,
        });
    }
    records
}

/// Build the version chain starting from a root checksum via BFS traversal.
///
/// Returns `None` if there is no version chain (no successors and no `doc:prev_checksum`
/// on the root entry). Returns `Some(entries)` when the chain has >= 1 entry.
fn build_version_chain<S: StorageEngine>(
    storage: &S,
    root_checksum: &noble_crypto::Hash256,
    root_checksum_hex: &str,
) -> Option<Vec<VersionEntry>> {
    use noble_core::constants::META_KEY_VERSION;

    // Check if root has any successors
    let successors = storage
        .lookup_version_successors(root_checksum)
        .unwrap_or_default();

    // Check if the root itself references a prev_checksum (mid-chain document)
    let root_tx_ids = storage.lookup_checksum(root_checksum).unwrap_or_default();

    let root_has_prev = root_tx_ids.first().and_then(|tx_id| {
        storage.get_transaction(tx_id).ok().and_then(|tx| {
            tx.metadata
                .iter()
                .find(|m| m.key == noble_core::constants::META_KEY_PREV_CHECKSUM)
                .map(|_| ())
        })
    });

    // No version chain if no successors and root doesn't reference a prev_checksum
    if successors.is_empty() && root_has_prev.is_none() {
        return None;
    }

    // Build the root entry
    let mut versions = Vec::new();
    if let Some(first_tx_id) = root_tx_ids.first() {
        if let Ok(tx) = storage.get_transaction(first_tx_id) {
            let ver = tx
                .metadata
                .iter()
                .find(|m| m.key == META_KEY_VERSION)
                .and_then(|m| std::str::from_utf8(&m.value).ok())
                .and_then(|s| s.parse::<u32>().ok());
            let height = storage
                .get_transaction_location(first_tx_id)
                .map(|(h, _)| h)
                .unwrap_or(0);
            versions.push(VersionEntry {
                checksum: root_checksum_hex.to_string(),
                tx_id: hash_to_hex(first_tx_id),
                block_height: height,
                timestamp: tx.timestamp,
                version: ver,
            });
        }
    }

    // BFS traversal (capped at 100)
    const MAX_VERSIONS: usize = 100;
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(*root_checksum);

    while let Some(current_checksum) = queue.pop_front() {
        if versions.len() >= MAX_VERSIONS {
            break;
        }
        let succs = storage
            .lookup_version_successors(&current_checksum)
            .unwrap_or_default();

        for succ_tx_id in &succs {
            if versions.len() >= MAX_VERSIONS {
                break;
            }
            if let Ok(tx) = storage.get_transaction(succ_tx_id) {
                let ver = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_VERSION)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                    .and_then(|s| s.parse::<u32>().ok());
                let height = storage
                    .get_transaction_location(succ_tx_id)
                    .map(|(h, _)| h)
                    .unwrap_or(0);
                versions.push(VersionEntry {
                    checksum: hash_to_hex(&tx.checksum),
                    tx_id: hash_to_hex(succ_tx_id),
                    block_height: height,
                    timestamp: tx.timestamp,
                    version: ver,
                });
                queue.push_back(tx.checksum);
            }
        }
    }

    Some(versions)
}

/// Parse an issuer public key from hex. Accepts:
/// - 34 bytes (secp256k1 wire: 0x02 + 33B compressed key)
/// - 33 bytes (legacy wire format — validated via `from_wire_bytes`)
/// - 32 bytes (raw key bytes → prepend 0x02 secp256k1 scheme byte)
// Unified pubkey parser: accepts bech32 (nbl1…), hex wire format, and raw SEC1 keys.
fn parse_issuer_wire(input: &str) -> Result<Vec<u8>, ErrorObjectOwned> {
    let pk = crate::types::parse_pubkey(input)?;
    Ok(pk.to_wire_bytes())
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> DocumentApiServer for Arc<ApiState<S>> {
    async fn lookup_checksum(
        &self,
        checksum: String,
    ) -> Result<ChecksumLookupResponse, ErrorObjectOwned> {
        let checksum_hash = parse_hash(&checksum)?;
        let storage = self.storage.read();
        let tx_ids = storage
            .lookup_checksum(&checksum_hash)
            .map_err(ApiError::from)?;

        let records = build_registration_records(&*storage, &tx_ids);
        let version_chain = if !tx_ids.is_empty() {
            build_version_chain(&*storage, &checksum_hash, &checksum)
        } else {
            None
        };

        Ok(ChecksumLookupResponse {
            found: !tx_ids.is_empty(),
            records,
            version_chain,
        })
    }

    async fn verify_document(
        &self,
        checksum: String,
    ) -> Result<VerifyDocumentResponse, ErrorObjectOwned> {
        let checksum_hash = parse_hash(&checksum)?;
        let storage = self.storage.read();
        let tx_ids = storage
            .lookup_checksum(&checksum_hash)
            .map_err(ApiError::from)?;

        let records = build_registration_records(&*storage, &tx_ids);
        let first_seen = records.iter().map(|r| r.timestamp).min();

        let version_chain = if !tx_ids.is_empty() {
            build_version_chain(&*storage, &checksum_hash, &checksum)
        } else {
            None
        };

        Ok(VerifyDocumentResponse {
            checksum,
            registered: !tx_ids.is_empty(),
            registrations: records,
            first_seen,
            version_chain,
        })
    }

    async fn get_document_history(
        &self,
        checksum: String,
    ) -> Result<DocumentHistoryResponse, ErrorObjectOwned> {
        let checksum_hash = parse_hash(&checksum)?;
        let storage = self.storage.read();
        let tx_ids = storage
            .lookup_checksum(&checksum_hash)
            .map_err(ApiError::from)?;

        if tx_ids.is_empty() {
            return Err(ApiError::ChecksumNotFound(checksum).into());
        }

        let history = build_registration_records(&*storage, &tx_ids);
        Ok(DocumentHistoryResponse { checksum, history })
    }

    async fn get_document_versions(
        &self,
        checksum: String,
    ) -> Result<DocumentVersionsResponse, ErrorObjectOwned> {
        let root_hash = parse_hash(&checksum)?;
        let storage = self.storage.read();

        // Verify root checksum exists
        let root_tx_ids = storage
            .lookup_checksum(&root_hash)
            .map_err(ApiError::from)?;
        if root_tx_ids.is_empty() {
            return Err(ApiError::ChecksumNotFound(checksum.clone()).into());
        }

        let versions = build_version_chain(&*storage, &root_hash, &checksum).unwrap_or_default();

        let count = versions.len();
        Ok(DocumentVersionsResponse {
            root_checksum: checksum,
            versions,
            count,
        })
    }

    async fn get_documents_by_issuer(
        &self,
        public_key: String,
    ) -> Result<DocumentsByIssuerResponse, ErrorObjectOwned> {
        use noble_core::constants::META_KEY_VERSION;

        let wire = parse_issuer_wire(&public_key)?;
        let storage = self.storage.read();
        let tx_ids = storage.lookup_by_issuer(&wire).map_err(ApiError::from)?;

        let mut documents = Vec::with_capacity(tx_ids.len());
        for tx_id in &tx_ids {
            if let Ok(tx) = storage.get_transaction(tx_id) {
                let block_height = storage
                    .get_transaction_location(tx_id)
                    .map(|(h, _)| h)
                    .unwrap_or(0);
                let version = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_VERSION)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                    .and_then(|s| s.parse::<u32>().ok());
                documents.push(IssuerDocumentRecord {
                    tx_id: hash_to_hex(tx_id),
                    checksum: hash_to_hex(&tx.checksum),
                    block_height,
                    timestamp: tx.timestamp,
                    version,
                });
            }
        }

        let count = documents.len();
        Ok(DocumentsByIssuerResponse {
            issuer: public_key,
            documents,
            count,
        })
    }

    async fn search_documents_by_metadata(
        &self,
        key: String,
        value: String,
    ) -> Result<MetadataSearchResponse, ErrorObjectOwned> {
        use noble_core::constants::META_KEY_VERSION;

        if key.is_empty() || value.is_empty() {
            return Err(ApiError::InvalidParam("key and value must be non-empty".into()).into());
        }
        if key.len() > 64 {
            return Err(ApiError::InvalidParam("key too long (max 64 bytes)".into()).into());
        }
        if value.len() > 256 {
            return Err(ApiError::InvalidParam("value too long (max 256 bytes)".into()).into());
        }

        let storage = self.storage.read();
        let tx_ids = storage
            .lookup_by_metadata(&key, value.as_bytes())
            .map_err(ApiError::from)?;

        let mut documents = Vec::with_capacity(tx_ids.len());
        for tx_id in &tx_ids {
            if let Ok(tx) = storage.get_transaction(tx_id) {
                let block_height = storage
                    .get_transaction_location(tx_id)
                    .map(|(h, _)| h)
                    .unwrap_or(0);
                let version = tx
                    .metadata
                    .iter()
                    .find(|m| m.key == META_KEY_VERSION)
                    .and_then(|m| std::str::from_utf8(&m.value).ok())
                    .and_then(|s| s.parse::<u32>().ok());
                documents.push(IssuerDocumentRecord {
                    tx_id: hash_to_hex(tx_id),
                    checksum: hash_to_hex(&tx.checksum),
                    block_height,
                    timestamp: tx.timestamp,
                    version,
                });
            }
        }

        let count = documents.len();
        Ok(MetadataSearchResponse {
            key,
            value,
            documents,
            count,
        })
    }
}
