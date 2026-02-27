// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Storage-related RPC methods: getStorageInfo, setStorageMode, getPruningStatus.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait StorageApi {
    /// Get storage information including chain height and pruning status.
    #[method(name = "getStorageInfo")]
    async fn get_storage_info(&self) -> Result<StorageInfoResponse, ErrorObjectOwned>;

    /// Get the current pruning status and last run result.
    #[method(name = "getPruningStatus")]
    async fn get_pruning_status(&self) -> Result<PruningStatusResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> StorageApiServer for Arc<ApiState<S>> {
    async fn get_storage_info(&self) -> Result<StorageInfoResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let chain_height = storage
            .get_chain_tip()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map(|t| t.height)
            .unwrap_or(0);
        let pruned_up_to = storage.get_pruning_marker().unwrap_or(0);
        let lowest_full = if pruned_up_to > 0 {
            pruned_up_to + 1
        } else {
            0
        };

        Ok(StorageInfoResponse {
            chain_height,
            pruning_mode: self.pruning_mode.clone(),
            keep_blocks: self.keep_blocks,
            pruned_up_to,
            lowest_full_height: lowest_full,
        })
    }

    async fn get_pruning_status(&self) -> Result<PruningStatusResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let pruned_up_to = storage.get_pruning_marker().unwrap_or(0);
        let lowest_full = if pruned_up_to > 0 {
            pruned_up_to + 1
        } else {
            0
        };

        Ok(PruningStatusResponse {
            mode: self.pruning_mode.clone(),
            blocks_pruned: 0,
            transactions_removed: 0,
            lowest_full_height: lowest_full,
            more_remaining: false,
        })
    }
}
