// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Node-related RPC methods: getNodeInfo.

use std::sync::Arc;

use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;

use noble_core::PROTOCOL_VERSION;
use noble_storage::StorageEngine;

use crate::state::ApiState;
use crate::types::*;

#[rpc(server, namespace = "noble")]
pub trait NodeApi {
    /// Get general node information.
    #[method(name = "getNodeInfo")]
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned>;
}

#[jsonrpsee::core::async_trait]
impl<S: StorageEngine + Send + Sync + 'static> NodeApiServer for Arc<ApiState<S>> {
    async fn get_node_info(&self) -> Result<NodeInfoResponse, ErrorObjectOwned> {
        let uptime = self.start_time.elapsed().as_secs();
        Ok(NodeInfoResponse {
            version: PROTOCOL_VERSION as u32,
            chain_id: self.chain_id,
            uptime_secs: uptime,
        })
    }
}
