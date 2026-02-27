// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Transaction-related RPC methods: submitTransaction, getTransaction, getTransactionStatus.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_codec::NobleCbor;
use noble_core::Transaction;
use noble_crypto::Hash256;
use noble_mempool::{BalanceLookup, ChainLookup};
use noble_network::NetworkCommand;
use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

// ---------------------------------------------------------------------------
// Adapter structs for mempool admission
// ---------------------------------------------------------------------------

/// Adapter that implements `ChainLookup` by querying the storage engine.
struct StorageChainLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> ChainLookup for StorageChainLookup<'_, S> {
    fn is_confirmed(&self, tx_id: &Hash256) -> bool {
        self.storage.has_transaction(tx_id).unwrap_or(false)
    }
}

/// Adapter that implements `BalanceLookup` by querying the storage engine.
struct StorageBalanceLookup<'a, S: StorageEngine> {
    storage: &'a S,
}

impl<S: StorageEngine> BalanceLookup for StorageBalanceLookup<'_, S> {
    fn get_balance(&self, address: &noble_core::NobleAddress) -> u64 {
        self.storage.get_balance(address).unwrap_or(0)
    }
}

#[rpc(server, namespace = "noble")]
pub trait TransactionApi {
    /// Submit a hex-encoded CBOR transaction to the mempool.
    #[method(name = "submitTransaction")]
    async fn submit_transaction(
        &self,
        tx_hex: String,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned>;

    /// Get a transaction by its hex-encoded tx_id.
    /// Checks mempool first, then on-chain storage.
    #[method(name = "getTransaction")]
    async fn get_transaction(&self, tx_id: String)
        -> Result<TransactionResponse, ErrorObjectOwned>;

    /// Get the status of a transaction (pending, confirmed, or unknown).
    #[method(name = "getTransactionStatus")]
    async fn get_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<TransactionStatusResponse, ErrorObjectOwned>;

    /// Get a full receipt for a transaction including block location and confirmations.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(
        &self,
        tx_id: String,
    ) -> Result<TransactionReceiptResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> TransactionApiServer for Arc<ApiState<S>> {
    async fn submit_transaction(
        &self,
        tx_hex: String,
    ) -> Result<SubmitTxResponse, ErrorObjectOwned> {
        // Decode hex to bytes
        let tx_bytes = hex::decode(&tx_hex)
            .map_err(|_| ApiError::TxRejected("invalid hex encoding".into()))?;

        // Decode CBOR to Transaction
        let tx = Transaction::from_cbor(&tx_bytes)
            .map_err(|e| ApiError::TxRejected(format!("CBOR decode failed: {e}")))?;

        // Current time for mempool admission
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Admit to mempool with storage-backed lookups
        let tx_id = {
            let storage = self.storage.read();
            let chain_lookup = StorageChainLookup { storage: &*storage };
            let balance_lookup = StorageBalanceLookup { storage: &*storage };

            let mut mempool = self.mempool.lock();
            mempool
                .admit(&tx, now, &chain_lookup, &balance_lookup)
                .map_err(|e| ApiError::TxRejected(e.to_string()))?
        };

        // Broadcast to network (best-effort, log if channel is full).
        if let Err(e) = self
            .network_cmd
            .try_send(NetworkCommand::PublishTransaction(tx))
        {
            tracing::warn!(task = "tx_broadcast", %tx_id, "network broadcast dropped (channel full): {e}");
        }

        Ok(SubmitTxResponse {
            tx_id: hash_to_hex(&tx_id),
            accepted: true,
        })
    }

    async fn get_transaction(
        &self,
        tx_id: String,
    ) -> Result<TransactionResponse, ErrorObjectOwned> {
        let tx_id_hash = parse_hash(&tx_id)?;

        // Check mempool first
        {
            let mempool = self.mempool.lock();
            if let Some(entry) = mempool.get(&tx_id_hash) {
                return Ok(tx_to_response(&entry.tx, &tx_id));
            }
        }

        // Check on-chain storage
        let storage = self.storage.read();
        let tx = storage
            .get_transaction(&tx_id_hash)
            .map_err(ApiError::from)?;

        Ok(tx_to_response(&tx, &tx_id))
    }

    async fn get_transaction_status(
        &self,
        tx_id: String,
    ) -> Result<TransactionStatusResponse, ErrorObjectOwned> {
        let tx_id_hash = parse_hash(&tx_id)?;

        // Check mempool
        {
            let mempool = self.mempool.lock();
            if mempool.contains(&tx_id_hash) {
                return Ok(TransactionStatusResponse {
                    tx_id,
                    status: "pending".to_string(),
                });
            }
        }

        // Check storage
        let storage = self.storage.read();
        if storage.has_transaction(&tx_id_hash).unwrap_or(false) {
            return Ok(TransactionStatusResponse {
                tx_id,
                status: "confirmed".to_string(),
            });
        }

        Ok(TransactionStatusResponse {
            tx_id,
            status: "unknown".to_string(),
        })
    }

    async fn get_transaction_receipt(
        &self,
        tx_id: String,
    ) -> Result<TransactionReceiptResponse, ErrorObjectOwned> {
        let tx_id_hash = parse_hash(&tx_id)?;

        // Check mempool first — pending transactions have no block info
        {
            let mempool = self.mempool.lock();
            if let Some(entry) = mempool.get(&tx_id_hash) {
                return Ok(TransactionReceiptResponse {
                    transaction: tx_to_response(&entry.tx, &tx_id),
                    status: "pending".to_string(),
                    block_height: None,
                    block_hash: None,
                    tx_index: None,
                    confirmations: None,
                });
            }
        }

        // Look up on-chain location
        let storage = self.storage.read();
        let (height, offset) = storage
            .get_transaction_location(&tx_id_hash)
            .map_err(ApiError::from)?;
        let tx = storage
            .get_transaction(&tx_id_hash)
            .map_err(ApiError::from)?;
        let block_hash = storage
            .get_block_hash_by_height(height)
            .map_err(ApiError::from)?;
        let tip = storage.get_chain_tip().map_err(ApiError::from)?;

        let confirmations = tip.map(|t| t.height - height + 1);

        Ok(TransactionReceiptResponse {
            transaction: tx_to_response(&tx, &tx_id),
            status: "confirmed".to_string(),
            block_height: Some(height),
            block_hash: Some(hash_to_hex(&block_hash)),
            tx_index: Some(offset),
            confirmations,
        })
    }
}
