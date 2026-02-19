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
use crate::methods::trace::TraceApiServer;
use crate::methods::transaction::TransactionApiServer;
use crate::methods::wallet::WalletApiServer;
use crate::middleware::AuthLayer;
use crate::state::ApiState;

/// Start the JSON-RPC server on the given address (e.g. "127.0.0.1:8783").
///
/// When `ApiState.totp_validator` is `Some`, all requests require a valid
/// `Authorization: Bearer <SHA-256 hex of TOTP code>` header.
/// CORS headers allow requests from the dashboard GUI on port 8785.
///
/// Returns a `ServerHandle` that can be used for graceful shutdown.
pub async fn start_server<S: StorageEngine + Send + Sync + 'static>(
    state: Arc<ApiState<S>>,
    addr: &str,
) -> Result<jsonrpsee::server::ServerHandle, ApiError> {
    let auth_layer = AuthLayer::new(state.totp_validator.clone());

    // CORS: permissive when remote access is enabled (IP filter provides security),
    // restrictive to the local GUI origin when localhost-only.
    let remote_access = state
        .ip_filter
        .as_ref()
        .is_some_and(|f| f.has_remote_access());

    let cors = if remote_access {
        tower_http::cors::CorsLayer::permissive()
    } else {
        tower_http::cors::CorsLayer::new()
            .allow_origin(
                "http://127.0.0.1:8785"
                    .parse::<http::HeaderValue>()
                    .unwrap(),
            )
            .allow_methods([http::Method::GET, http::Method::POST, http::Method::OPTIONS])
            .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
    };

    // RPC server security: bind address controls access (127.0.0.1 vs 0.0.0.0),
    // CORS restricts browser origins, auth layer checks TOTP tokens.
    let server = Server::builder()
        .set_http_middleware(tower::ServiceBuilder::new().layer(cors).layer(auth_layer))
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
    module
        .merge(TraceApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge TraceApi: {e}")))?;

    let handle = server.start(module);

    tracing::info!(task = "rpc_server", "RPC server starting on {}", addr);

    Ok(handle)
}
