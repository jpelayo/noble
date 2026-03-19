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

    /// Get the current storage configuration values.
    #[method(name = "getStorageConfig")]
    async fn get_storage_config(&self) -> Result<StorageConfigResponse, ErrorObjectOwned>;

    /// Update storage configuration (writes to noble.toml, restart required).
    #[method(name = "setStorageConfig")]
    async fn set_storage_config(
        &self,
        data_dir: String,
        cache_size_mb: u32,
        compression: bool,
        pruning_mode: String,
        keep_blocks: u64,
        max_db_size_gb: u64,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned>;

    /// Run a chain integrity check over a range of blocks.
    /// Verifies block hashes, merkle roots, prev_hash linkage, and height continuity.
    /// Defaults to the full chain if no range is specified. Capped at 10,000 blocks per call.
    #[method(name = "checkChainIntegrity")]
    async fn check_chain_integrity(
        &self,
        from_height: Option<u64>,
        to_height: Option<u64>,
    ) -> Result<ChainIntegrityResponse, ErrorObjectOwned>;
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
            max_db_size_bytes: self.max_db_size_gb * 1024 * 1024 * 1024,
        })
    }

    async fn get_storage_config(&self) -> Result<StorageConfigResponse, ErrorObjectOwned> {
        let data_dir = self
            .data_dir
            .as_ref()
            .map(|d| d.display().to_string())
            .unwrap_or_default();

        Ok(StorageConfigResponse {
            data_dir,
            cache_size_mb: self.cache_size_mb,
            compression: self.compression_enabled,
            pruning_mode: self.pruning_mode.clone(),
            keep_blocks: self.keep_blocks,
            max_db_size_gb: self.max_db_size_gb,
        })
    }

    async fn set_storage_config(
        &self,
        data_dir: String,
        cache_size_mb: u32,
        compression: bool,
        pruning_mode: String,
        keep_blocks: u64,
        max_db_size_gb: u64,
    ) -> Result<SetConfigValueResponse, ErrorObjectOwned> {
        let set_fn = self
            .set_config_value
            .as_ref()
            .ok_or_else(|| ApiError::Internal("config updates not available".into()))?;

        let fields: &[(&str, String)] = &[
            ("data_dir", data_dir),
            ("cache_size_mb", cache_size_mb.to_string()),
            ("compression", compression.to_string()),
            ("pruning_mode", pruning_mode),
            ("keep_blocks", keep_blocks.to_string()),
            ("max_db_size_gb", max_db_size_gb.to_string()),
        ];

        for (key, value) in fields {
            set_fn("storage", key, value)
                .map_err(|e| ApiError::Internal(format!("failed to set storage.{key}: {e}")))?;
        }

        Ok(SetConfigValueResponse {
            success: true,
            restart_required: true,
        })
    }

    async fn check_chain_integrity(
        &self,
        from_height: Option<u64>,
        to_height: Option<u64>,
    ) -> Result<ChainIntegrityResponse, ErrorObjectOwned> {
        let storage = self.storage.read();
        let tip = storage
            .get_chain_tip()
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .map(|t| t.height)
            .unwrap_or(0);

        let start = from_height.unwrap_or(0);
        let end = to_height.unwrap_or(tip);

        if end < start {
            return Err(ApiError::InvalidParam("to_height must be >= from_height".into()).into());
        }
        let range = end.saturating_sub(start) + 1;
        if range > 10_000 {
            return Err(ApiError::InvalidParam(
                format!("range too large ({range} blocks, max 10,000). Use from_height/to_height to paginate."),
            ).into());
        }

        let chain_id = self.chain_id.load(std::sync::atomic::Ordering::Relaxed);
        let report = noble_storage::verify_chain_integrity(&*storage, chain_id, start, end);

        Ok(ChainIntegrityResponse {
            heights_checked: report.heights_checked,
            is_clean: report.is_clean(),
            findings_count: report.findings.len(),
            first_corrupt_height: report.first_corrupt_height,
            findings: report.findings.iter().map(|f| ChainIntegrityFinding {
                height: f.height,
                kind: format!("{:?}", f.kind),
                detail: f.detail.clone(),
            }).collect(),
        })
    }
}
