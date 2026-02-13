// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Network-related RPC methods: getPeerInfo, getNetworkInfo, getSyncStatus.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_consensus::ConsensusStateMachine;
use noble_storage::StorageEngine;

use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait NetworkApi {
    /// Get information about connected peers.
    #[method(name = "getPeerInfo")]
    async fn get_peer_info(&self) -> Result<Vec<PeerInfoResponse>, ErrorObjectOwned>;

    /// Get network summary statistics.
    #[method(name = "getNetworkInfo")]
    async fn get_network_info(&self) -> Result<NetworkInfoResponse, ErrorObjectOwned>;

    /// Get current sync status.
    #[method(name = "getSyncStatus")]
    async fn get_sync_status(&self) -> Result<SyncStatusResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> NetworkApiServer for Arc<ApiState<S>> {
    async fn get_peer_info(&self) -> Result<Vec<PeerInfoResponse>, ErrorObjectOwned> {
        // Detailed per-peer info is not currently tracked in ApiState.
        // Return an empty list; the node event loop would populate a peer registry
        // in a future sprint.
        Ok(vec![])
    }

    async fn get_network_info(&self) -> Result<NetworkInfoResponse, ErrorObjectOwned> {
        let stats = self.network_stats.read().unwrap();
        Ok(NetworkInfoResponse {
            peer_count: stats.peer_count,
            inbound: stats.inbound_count,
            outbound: stats.outbound_count,
        })
    }

    async fn get_sync_status(&self) -> Result<SyncStatusResponse, ErrorObjectOwned> {
        let consensus = self.consensus.read().unwrap();
        let (height, _hash) = consensus.chain_tip();

        // Simple heuristic: consider synced if height > 0 or chain is fresh.
        // A real implementation would compare with the best-known peer height.
        Ok(SyncStatusResponse {
            synced: true,
            current_height: height,
        })
    }
}
