// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Mempool-related RPC methods: estimateFee, getMempoolInfo.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;
use noble_wallet::TransactionBuilder;

use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait MempoolApi {
    /// Estimate transaction fees at low, medium, and high priority levels.
    #[method(name = "estimateFee")]
    async fn estimate_fee(&self) -> Result<FeeEstimateResponse, ErrorObjectOwned>;

    /// Get mempool size and total byte usage.
    #[method(name = "getMempoolInfo")]
    async fn get_mempool_info(&self) -> Result<MempoolInfoResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> MempoolApiServer for Arc<ApiState<S>> {
    async fn estimate_fee(&self) -> Result<FeeEstimateResponse, ErrorObjectOwned> {
        let (low, medium, high) = TransactionBuilder::estimate_fee();
        Ok(FeeEstimateResponse { low, medium, high })
    }

    async fn get_mempool_info(&self) -> Result<MempoolInfoResponse, ErrorObjectOwned> {
        let mempool = self.mempool.lock().unwrap();
        Ok(MempoolInfoResponse {
            size: mempool.len(),
            total_bytes: mempool.total_size(),
        })
    }
}
