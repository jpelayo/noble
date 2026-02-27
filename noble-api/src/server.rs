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
use crate::methods::storage::StorageApiServer;
use crate::methods::subscriptions::SubscriptionApiServer;
use crate::methods::trace::TraceApiServer;
use crate::methods::transaction::TransactionApiServer;
use crate::methods::wallet::WalletApiServer;
use crate::middleware::AuthLayer;
use crate::rate_limit::RateLimitLayer;
use crate::rpc_metrics::MetricsMiddleware;
use crate::state::ApiState;

/// Start the JSON-RPC server on the given address (e.g. "127.0.0.1:8783").
///
/// When `ApiState.totp_validator` is `Some`, all requests require a valid
/// `Authorization: Bearer <SHA-256 hex of TOTP code>` header.
/// CORS headers allow requests from the dashboard GUI on port 8785.
///
/// If `rpc_histogram` is provided, per-method request durations are recorded
/// in the Prometheus histogram (label: `method`).
///
/// When `tls_config` is `Some`, a custom TCP accept loop is used with
/// tokio-rustls TLS termination so that Tauri client apps (which run in a
/// secure context) can connect over HTTPS/WSS without mixed-content errors.
/// The same port handles both HTTP JSON-RPC requests and WebSocket upgrades.
///
/// `max_connections` limits how many concurrent connections the server accepts.
/// In the plain-HTTP path this is enforced by jsonrpsee; in the TLS path a
/// tokio Semaphore provides the same guarantee.
///
/// Returns a `ServerHandle` that can be used for graceful shutdown.
pub async fn start_server<S: StorageEngine + Send + Sync + 'static>(
    state: Arc<ApiState<S>>,
    addr: &str,
    rpc_histogram: Option<Arc<prometheus::HistogramVec>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    max_connections: u32,
) -> Result<jsonrpsee::server::ServerHandle, ApiError> {
    let auth_layer = AuthLayer::new(state.totp_validator.clone(), state.totp_scope, state.setup_token.clone());

    // AUD3-D2: Always layer IpFilter — use allow_all() fallback when no list configured.
    let ip_filter = state.ip_filter.clone().unwrap_or_else(IpFilter::allow_all);
    let ip_filter_layer = IpFilterLayer::new(ip_filter);

    // AUD3-D3: Always layer RateLimiter — pass-through when None.
    let rate_limit_layer = RateLimitLayer::new(state.rate_limiter.clone());

    // CORS: read origins dynamically from Arc<RwLock> so that setAllowedIps
    // can update the allow-list at runtime without restarting the server.
    let cors = {
        let cors_origins_arc = state.allowed_cors_origins.clone();
        tower_http::cors::CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::predicate(
                move |origin: &http::HeaderValue, _parts: &http::request::Parts| {
                    let allowed = cors_origins_arc.read();
                    allowed.iter().any(|s| {
                        s.parse::<http::HeaderValue>().ok().as_ref() == Some(origin)
                    })
                },
            ))
            .allow_methods([http::Method::GET, http::Method::POST, http::Method::OPTIONS])
            .allow_headers([http::header::CONTENT_TYPE, http::header::AUTHORIZATION])
    };

    // S18-B: API version header on all responses.
    let api_version_layer = tower_http::set_header::SetResponseHeaderLayer::overriding(
        http::HeaderName::from_static("x-noble-api-version"),
        http::HeaderValue::from_static(crate::API_VERSION),
    );

    // HTTP middleware stack (applied in order):
    //   1. CORS — browser origin control
    //   2. API version header — X-Noble-API-Version on all responses
    //   3. IP filter — allow-list access control
    //   4. Rate limiter — per-IP token bucket
    //   5. Auth — TOTP bearer token validation
    let http_middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(api_version_layer)
        .layer(ip_filter_layer)
        .layer(rate_limit_layer)
        .layer(auth_layer);

    // RPC-level middleware: per-method latency instrumentation.
    // When Prometheus is disabled, the middleware still wraps but records nothing.
    let rpc_middleware = jsonrpsee::server::middleware::rpc::RpcServiceBuilder::new()
        .layer_fn(move |service| MetricsMiddleware::new(service, rpc_histogram.clone()));

    // Build and merge all RPC method modules.
    let module = build_rpc_module(state)?;

    // ── TLS path: custom accept loop with tokio-rustls ──────────────────────
    if let Some(tls_cfg) = tls_config {
        let (stop_handle, server_handle) = jsonrpsee::server::stop_channel();

        let svc_builder = Server::builder()
            .max_request_body_size(2 * 1024 * 1024)
            .set_http_middleware(http_middleware)
            .set_rpc_middleware(rpc_middleware)
            .to_service_builder();

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to bind TLS RPC server: {e}")))?;

        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);

        // F4: connection semaphore — enforces max_connections in the custom accept loop.
        let conn_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max_connections as usize));

        let stop_outer = stop_handle.clone();
        tokio::spawn(async move {
            loop {
                let sock = tokio::select! {
                    res = listener.accept() => match res {
                        Ok((s, _)) => s,
                        Err(e) => {
                            tracing::warn!(task = "rpc_server", "accept error: {e}");
                            continue;
                        }
                    },
                    _ = stop_outer.clone().shutdown() => break,
                };

                // Acquire a connection permit; drop the socket if at capacity.
                let permit = match conn_sem.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::warn!(
                            task = "rpc_server",
                            "max_connections ({max_connections}) reached — dropping connection"
                        );
                        drop(sock);
                        continue;
                    }
                };

                let acceptor_c = acceptor.clone();
                let svc_builder_c = svc_builder.clone();
                let module_c = module.clone();
                let stop_conn = stop_outer.clone();

                tokio::spawn(async move {
                    let _permit = permit; // released when this task ends
                    let tls = match acceptor_c.accept(sock).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!(task = "rpc_server", "TLS handshake failed: {e}");
                            return;
                        }
                    };
                    // Build one TowerService per connection (builder is consumed).
                    let svc = svc_builder_c.build(module_c, stop_conn.clone());
                    let _ = jsonrpsee::server::serve_with_graceful_shutdown(
                        tls,
                        svc,
                        stop_conn.shutdown(),
                    )
                    .await;
                });
            }
        });

        tracing::info!(
            task = "rpc_server",
            "RPC+WS server (TLS) listening on {} (max_connections={})",
            addr, max_connections
        );
        return Ok(server_handle);
    }

    // ── Plain HTTP path ──────────────────────────────────────────────────────
    let server = Server::builder()
        // Explicit body size limit (2 MB). The largest valid RPC payload is a
        // max-size CBOR transaction (~64 KB per T1); 2 MB provides headroom while
        // preventing large-payload DoS. Overrides the jsonrpsee 10 MB default.
        .max_request_body_size(2 * 1024 * 1024)
        // F4: enforce the configured connection limit.
        .max_connections(max_connections as u32)
        .set_http_middleware(http_middleware)
        .set_rpc_middleware(rpc_middleware)
        .build(addr)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to bind server: {e}")))?;

    let handle = server.start(module);

    tracing::info!(
        task = "rpc_server",
        "RPC server starting on {} (max_connections={})",
        addr, max_connections
    );

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Module assembly
// ---------------------------------------------------------------------------

fn build_rpc_module<S: StorageEngine + Send + Sync + 'static>(
    state: Arc<ApiState<S>>,
) -> Result<RpcModule<()>, ApiError> {
    let mut module = RpcModule::new(());

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
        .merge(StorageApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge StorageApi: {e}")))?;
    module
        .merge(SubscriptionApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge SubscriptionApi: {e}")))?;

    Ok(module)
}
