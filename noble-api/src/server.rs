// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 server startup and module registration.

use std::sync::Arc;

use jsonrpsee::server::Server;
use jsonrpsee::RpcModule;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::ip_filter::{IpFilter, IpFilterLayer};
use crate::methods::address::AddressApiServer;
use crate::methods::block::BlockApiServer;
use crate::methods::consensus::ConsensusApiServer;
use crate::methods::document::DocumentApiServer;
use crate::methods::mempool::MempoolApiServer;
use crate::methods::network::NetworkApiServer;
use crate::methods::node::NodeApiServer;
use crate::methods::subscriptions::SubscriptionApiServer;
use crate::methods::trace::TraceApiServer;
use crate::methods::transaction::TransactionApiServer;
use crate::methods::wallet::WalletApiServer;
use crate::middleware::AuthLayer;
use crate::rate_limit::RateLimitLayer;
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

    // AUD3-D2: Always layer IpFilter — use allow_all() fallback when no list configured.
    let ip_filter = state.ip_filter.clone().unwrap_or_else(IpFilter::allow_all);
    let ip_filter_layer = IpFilterLayer::new(ip_filter);

    // AUD3-D3: Always layer RateLimiter — pass-through when None.
    let rate_limit_layer = RateLimitLayer::new(state.rate_limiter.clone());

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

    // RPC server security stack (applied in order):
    //   1. CORS — browser origin control
    //   2. IP filter — allow-list access control
    //   3. Rate limiter — per-IP token bucket
    //   4. Auth — TOTP bearer token validation
    let server = Server::builder()
        // Explicit body size limit (2 MB). The largest valid RPC payload is a
        // max-size CBOR transaction (~64 KB per T1); 2 MB provides headroom while
        // preventing large-payload DoS. Overrides the jsonrpsee 10 MB default.
        .max_request_body_size(2 * 1024 * 1024)
        .set_http_middleware(
            tower::ServiceBuilder::new()
                .layer(cors)
                .layer(ip_filter_layer)
                .layer(rate_limit_layer)
                .layer(auth_layer),
        )
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
    module
        .merge(SubscriptionApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge SubscriptionApi: {e}")))?;

    let handle = server.start(module);

    tracing::info!(task = "rpc_server", "RPC server starting on {}", addr);

    Ok(handle)
}
