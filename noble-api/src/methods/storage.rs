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

    /// Get detailed storage statistics: disk usage, column family breakdown, config.
    #[method(name = "getStorageStats")]
    async fn get_storage_stats(&self) -> Result<StorageStatsResponse, ErrorObjectOwned>;
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

    async fn get_storage_stats(&self) -> Result<StorageStatsResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let stats = storage
            .get_storage_stats()
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let column_families: Vec<CfStatsEntry> = stats
            .column_families
            .into_iter()
            .map(|cf| CfStatsEntry {
                name: cf.name,
                estimated_bytes: cf.estimated_bytes,
                estimated_keys: cf.estimated_keys,
            })
            .collect();

        let total_db_bytes: u64 = column_families.iter().map(|cf| cf.estimated_bytes).sum();

        let (data_dir_str, available_bytes, total_volume_bytes) =
            if let Some(ref dd) = self.data_dir {
                let dir_str = dd.display().to_string();
                let avail = super::node::disk_available(dd);
                let cap = super::node::disk_capacity(dd);
                (Some(dir_str), avail, cap)
            } else {
                (None, 0, 0)
            };

        Ok(StorageStatsResponse {
            data_dir: data_dir_str,
            total_db_bytes,
            available_bytes,
            total_volume_bytes,
            cache_size_bytes: u64::from(self.cache_size_mb) * 1024 * 1024,
            compression_enabled: self.compression_enabled,
            column_families,
        })
    }
}
