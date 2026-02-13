// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 server startup and module registration.

use std::sync::Arc;

use jsonrpsee::server::Server;
use jsonrpsee::RpcModule;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::methods::address::AddressApiServer;
use crate::methods::block::BlockApiServer;
use crate::methods::consensus::ConsensusApiServer;
use crate::methods::document::DocumentApiServer;
use crate::methods::mempool::MempoolApiServer;
use crate::methods::network::NetworkApiServer;
use crate::methods::node::NodeApiServer;
use crate::methods::transaction::TransactionApiServer;
use crate::methods::wallet::WalletApiServer;
use crate::state::ApiState;

/// Start the JSON-RPC server on the given address (e.g. "127.0.0.1:9333").
///
/// Returns a `ServerHandle` that can be used for graceful shutdown.
pub async fn start_server<S: StorageEngine + Send + Sync + 'static>(
    state: Arc<ApiState<S>>,
    addr: &str,
) -> Result<jsonrpsee::server::ServerHandle, ApiError> {
    let server = Server::builder()
        .build(addr)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to bind server: {e}")))?;

    let mut module = RpcModule::new(());

    // Merge all RPC method modules.
    module
        .merge(DocumentApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge DocumentApi: {e}")))?;
    module
        .merge(TransactionApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge TransactionApi: {e}")))?;
    module
        .merge(BlockApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge BlockApi: {e}")))?;
    module
        .merge(MempoolApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge MempoolApi: {e}")))?;
    module
        .merge(NetworkApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge NetworkApi: {e}")))?;
    module
        .merge(ConsensusApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge ConsensusApi: {e}")))?;
    module
        .merge(AddressApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge AddressApi: {e}")))?;
    module
        .merge(WalletApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge WalletApi: {e}")))?;
    module
        .merge(NodeApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge NodeApi: {e}")))?;

    let handle = server.start(module);

    tracing::info!("JSON-RPC server listening on {}", addr);

    Ok(handle)
}
