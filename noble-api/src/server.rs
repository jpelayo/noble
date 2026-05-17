// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 server startup and module registration.
//!
//! The RPC server is split into two listeners:
//! - **HTTP-only** on `rpc_addr` (default 8783) — handles JSON-RPC POST requests.
//! - **WS-only** on `ws_addr` (default 8784) — handles WebSocket subscriptions.
//!
//! Both share the same `RpcModule`, middleware stack, and TLS configuration.

use std::sync::Arc;

use jsonrpsee::server::Server;
use jsonrpsee::RpcModule;
use tower::Layer;

use noble_storage::StorageEngine;

use crate::error::ApiError;
use crate::ip_filter::{IpFilter, IpFilterLayer};
use crate::methods::address::AddressApiServer;
use crate::methods::badge::BadgeApiServer;
use crate::methods::dao::DaoApiServer;
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
use crate::gatekeeper::GatekeeperLayer;
use crate::middleware::AuthLayer;
use crate::rate_limit::RateLimitLayer;
use crate::rpc_metrics::MetricsMiddleware;
use crate::state::ApiState;

/// Handles for both the HTTP-only RPC server and the WS-only server.
pub struct ServerHandles {
    pub rpc_handle: jsonrpsee::server::ServerHandle,
    pub ws_handle: jsonrpsee::server::ServerHandle,
}

/// Start the JSON-RPC HTTP-only server on `rpc_addr` and a WS-only server on `ws_addr`.
///
/// Both servers share the same `RpcModule`, middleware, TLS config, and auth layer.
///
/// When `tls_config` is `Some`, custom TCP accept loops with tokio-rustls TLS
/// termination are used so that Tauri client apps (secure context) can connect
/// over HTTPS/WSS without mixed-content errors.
pub async fn start_server<S: StorageEngine + Send + Sync + 'static>(
    state: Arc<ApiState<S>>,
    rpc_addr: &str,
    ws_addr: &str,
    rpc_histogram: Option<Arc<prometheus::HistogramVec>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    max_connections: u32,
) -> Result<ServerHandles, ApiError> {
    // Build shared middleware and module once.
    let module = build_rpc_module(state.clone())?;

    let rpc_handle = start_single_server(
        state.clone(),
        rpc_addr,
        rpc_histogram.clone(),
        tls_config.clone(),
        max_connections,
        module.clone(),
        ServerMode::HttpOnly,
    )
    .await?;

    let ws_handle = start_single_server(
        state,
        ws_addr,
        rpc_histogram,
        tls_config,
        max_connections,
        module,
        ServerMode::WsOnly,
    )
    .await?;

    Ok(ServerHandles {
        rpc_handle,
        ws_handle,
    })
}

#[derive(Clone, Copy)]
enum ServerMode {
    HttpOnly,
    WsOnly,
}

/// Start a single jsonrpsee server in the given mode (HTTP-only or WS-only).
async fn start_single_server<S: StorageEngine + Send + Sync + 'static>(
    state: Arc<ApiState<S>>,
    addr: &str,
    rpc_histogram: Option<Arc<prometheus::HistogramVec>>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    max_connections: u32,
    module: RpcModule<()>,
    mode: ServerMode,
) -> Result<jsonrpsee::server::ServerHandle, ApiError> {
    let auth_layer = AuthLayer::new(state.totp_validator.clone(), state.totp_scope);

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
            .allow_headers([
                http::header::CONTENT_TYPE,
                http::header::AUTHORIZATION,
                http::HeaderName::from_static(crate::gatekeeper::GATEKEEPER_HEADER),
            ])
    };

    // S18-B: API version header on all responses.
    let api_version_layer = tower_http::set_header::SetResponseHeaderLayer::overriding(
        http::HeaderName::from_static("x-noble-api-version"),
        http::HeaderValue::from_static(crate::API_VERSION),
    );

    // HTTP middleware stack (applied in order):
    //   1. CORS — browser origin control (must be outermost for preflight)
    //   2. Gatekeeper — reject if `Gatekeeper: noble` header missing (fast reject)
    //   3. API version header — X-Noble-API-Version on all responses
    //   4. IP filter — allow-list access control
    //   5. Rate limiter — per-IP token bucket
    //   6. Auth — TOTP bearer token validation
    let http_middleware = tower::ServiceBuilder::new()
        .layer(cors)
        .layer(GatekeeperLayer)
        .layer(api_version_layer)
        .layer(ip_filter_layer)
        .layer(rate_limit_layer)
        .layer(auth_layer);

    // RPC-level middleware: per-method latency instrumentation.
    // When Prometheus is disabled, the middleware still wraps but records nothing.
    let rpc_middleware = jsonrpsee::server::middleware::rpc::RpcServiceBuilder::new()
        .layer_fn(move |service| MetricsMiddleware::new(service, rpc_histogram.clone()));

    let mode_label = match mode {
        ServerMode::HttpOnly => "HTTP-only RPC",
        ServerMode::WsOnly => "WS-only",
    };

    // ── TLS path: custom accept loop with tokio-rustls ──────────────────────
    if let Some(tls_cfg) = tls_config {
        let (stop_handle, server_handle) = jsonrpsee::server::stop_channel();

        let mut builder = Server::builder()
            .max_request_body_size(2 * 1024 * 1024);
        builder = match mode {
            ServerMode::HttpOnly => builder.http_only(),
            ServerMode::WsOnly => builder.ws_only(),
        };
        let svc_builder = builder
            .set_http_middleware(http_middleware)
            .set_rpc_middleware(rpc_middleware)
            .to_service_builder();

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| ApiError::Internal(format!("failed to bind TLS {mode_label} server: {e}")))?;

        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);

        // F4: connection semaphore — enforces max_connections in the custom accept loop.
        let conn_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(max_connections as usize));

        let stop_outer = stop_handle.clone();
        tokio::spawn(async move {
            loop {
                // Capture the peer SocketAddr at accept time so the per-connection
                // PeerAddrLayer can inject it into request extensions. Without it,
                // IpFilterLayer and RateLimitLayer silently pass every TLS request.
                let (sock, peer_addr) = tokio::select! {
                    res = listener.accept() => match res {
                        Ok(pair) => pair,
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
                            "max_connections ({max_connections}) reached — dropping connection from {peer_addr}"
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
                    // Build one TowerService per connection (builder is consumed),
                    // then wrap with PeerAddrLayer so the captured peer SocketAddr
                    // reaches IpFilterLayer / RateLimitLayer via request extensions.
                    let svc = svc_builder_c.build(module_c, stop_conn.clone());
                    let svc = crate::peer_addr::PeerAddrLayer::new(peer_addr).layer(svc);
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
            "{mode_label} server (TLS) listening on {} (max_connections={})",
            addr, max_connections
        );
        return Ok(server_handle);
    }

    // ── Plain HTTP path ──────────────────────────────────────────────────────
    let mut builder = Server::builder()
        .max_request_body_size(2 * 1024 * 1024)
        .max_connections(max_connections as u32);
    builder = match mode {
        ServerMode::HttpOnly => builder.http_only(),
        ServerMode::WsOnly => builder.ws_only(),
    };
    let server = builder
        .set_http_middleware(http_middleware)
        .set_rpc_middleware(rpc_middleware)
        .build(addr)
        .await
        .map_err(|e| ApiError::Internal(format!("failed to bind {mode_label} server: {e}")))?;

    let handle = server.start(module);

    tracing::info!(
        task = "rpc_server",
        "{mode_label} server starting on {} (max_connections={})",
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
        .merge(BadgeApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge BadgeApi: {e}")))?;
    module
        .merge(DaoApiServer::into_rpc(state.clone()))
        .map_err(|e| ApiError::Internal(format!("merge DaoApi: {e}")))?;
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
