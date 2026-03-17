// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Mempool-related RPC methods: estimateFee, getMempoolInfo.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_storage::StorageEngine;

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
        let floor = noble_core::MIN_RELAY_FEE_RATE;

        // Compute fee rate percentiles from mempool.
        let mempool = self.mempool.lock();
        let mut rates: Vec<u64> = mempool.iter_by_fee_rate_desc()
            .map(|e| e.fee_rate)
            .collect();
        drop(mempool);

        let (low, recommended, high) = if rates.is_empty() {
            (floor, floor, floor)
        } else {
            rates.sort();
            let p25 = rates[rates.len() / 4].max(floor);
            let p50 = rates[rates.len() / 2].max(floor);
            let p75 = rates[rates.len() * 3 / 4].max(floor);
            (p25, p50, p75)
        };

        // Network fee landscape from peer NodeAnnounce data.
        let mut peer_rates: Vec<u64> = {
            let info = self.peer_info.read();
            info.values().filter_map(|e| e.min_fee_rate).collect()
        };
        let (net_min, net_median) = if peer_rates.is_empty() {
            (floor, floor)
        } else {
            peer_rates.sort();
            let min = peer_rates[0];
            let median = peer_rates[peer_rates.len() / 2];
            (min, median)
        };

        Ok(FeeEstimateResponse {
            low_fee_rate: low,
            recommended_fee_rate: recommended,
            high_priority_fee_rate: high,
            network_min_fee_rate: net_min,
            network_median_fee_rate: net_median,
        })
    }

    async fn get_mempool_info(&self) -> Result<MempoolInfoResponse, ErrorObjectOwned> {
        let mempool = self.mempool.lock();
        let (min_fee_rate, max_fee_rate, avg_fee_rate) = mempool.fee_stats();
        Ok(MempoolInfoResponse {
            count: mempool.len(),
            total_bytes: mempool.total_size(),
            min_fee_rate,
            max_fee_rate,
            avg_fee_rate,
        })
    }
}
