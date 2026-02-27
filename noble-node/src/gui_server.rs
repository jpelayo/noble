// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Embedded HTTP server for the NOBLE dashboard GUI.
//!
//! Serves static files from the `noble-gui/` directory on a dedicated port
//! (default 8785). Uses `tower_http::services::ServeDir` without an SPA
//! fallback — NOBLE uses hash-based routing so all navigation stays on `/`.
//!
//! When `tls_config` is provided, connections are served over HTTPS using
//! tokio-rustls so Tauri client apps (running in a secure context) are not
//! blocked by mixed-content policy when they open the dashboard.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::middleware;
use axum::response::IntoResponse;
use axum::Router;
use tower_http::services::ServeDir;

use noble_api::ip_filter::IpFilter;

/// Start the embedded GUI HTTP(S) server.
///
/// Serves all files under `gui_dir` with `index.html` as the SPA fallback.
/// Adds a Content-Security-Policy header that restricts `connect-src` to the
/// RPC port (both HTTP JSON-RPC and WebSocket are served on 8783 by jsonrpsee).
///
/// `rpc_origins` is the live list of allowed RPC endpoints (e.g.
/// `["https://127.0.0.1:8783", "wss://127.0.0.1:8783"]`), wrapped in
/// `Arc<RwLock>` so `setAllowedIps` can update it at runtime without restart.
/// The CSP header is computed on each request from the live list.
///
/// `rpc_port` is injected into the `/` route as `window.NOBLE_RPC_PORT` so
/// that `app.js` always connects to the correct port even when non-default.
///
/// When `tls_config` is `Some`, a custom tokio-rustls accept loop is used in
/// place of `axum::serve`.  IP filtering is applied at the TCP accept level so
/// blocked peers never complete a TLS handshake.
pub async fn start_gui_server(
    addr: SocketAddr,
    gui_dir: PathBuf,
    ip_filter: Option<IpFilter>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    rpc_origins: Arc<parking_lot::RwLock<Vec<String>>>,
    rpc_port: u16,
    setup_mode: bool,
    setup_token: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let serve_dir = ServeDir::new(&gui_dir);

    let proto = if tls_config.is_some() { "https" } else { "http" };

    // Root route: serve index.html with injected NOBLE_RPC_PORT script tag.
    let gui_dir_clone = gui_dir.clone();
    let root_handler = axum::routing::get(move || {
        let dir = gui_dir_clone.clone();
        let token_clone = setup_token.clone();
        async move {
            let index_path = dir.join("index.html");
            match tokio::fs::read_to_string(&index_path).await {
                Ok(html) => {
                    let mut script = format!(
                        "<script>window.NOBLE_RPC_PORT={};</script>",
                        rpc_port
                    );
                    // Issue 8: inject setup mode flag synchronously so app.js can
                    // redirect to #/setup before router.start() — no async RPC needed.
                    if setup_mode {
                        script.push_str("<script>window.NOBLE_SETUP_MODE=true;</script>");
                    }
                    // Issue 9: inject setup token so the wizard can auto-apply it.
                    // Token is 64 hex chars (safe to embed in a JS string literal).
                    if let Some(ref tok) = token_clone {
                        script.push_str(&format!(
                            "<script>window.NOBLE_SETUP_TOKEN='{tok}';</script>"
                        ));
                    }
                    // Inject before </head> so the variables are available when app.js loads.
                    let injected = if html.contains("</head>") {
                        html.replacen("</head>", &format!("{script}</head>"), 1)
                    } else {
                        // Fallback: prepend the script.
                        format!("{script}{html}")
                    };
                    axum::response::Response::builder()
                        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
                        .body(axum::body::Body::from(injected))
                        .unwrap_or_default()
                }
                Err(_) => (http::StatusCode::NOT_FOUND, "index.html not found")
                    .into_response(),
            }
        }
    });

    let mut app = Router::new()
        .route("/", root_handler)
        .fallback_service(serve_dir);

    // Dynamic CSP middleware — reads rpc_origins on every request so that
    // setAllowedIps updates are reflected immediately without a restart.
    let rpc_origins_csp = rpc_origins.clone();
    app = app.layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
        let origins = rpc_origins_csp.clone();
        async move {
            let mut resp: axum::response::Response = next.run(req).await;
            let connect_src = {
                let guard = origins.read();
                if guard.is_empty() {
                    "http://127.0.0.1:8783 http://localhost:8783 ws://127.0.0.1:8783 ws://localhost:8783"
                        .to_string()
                } else {
                    guard.join(" ")
                }
            };
            let csp = format!(
                "default-src 'self' 'unsafe-inline'; \
                 connect-src {connect_src}; \
                 script-src 'self' 'unsafe-inline'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data:"
            );
            if let Ok(val) = http::HeaderValue::from_str(&csp) {
                resp.headers_mut().insert(
                    http::header::HeaderName::from_static("content-security-policy"),
                    val,
                );
            }
            resp
        }
    }));

    // ── TLS path: custom tokio-rustls accept loop ────────────────────────────
    if let Some(tls_cfg) = tls_config {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
        tracing::info!("Dashboard available at {proto}://{addr}");

        loop {
            let (tcp, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(task = "gui_server", "accept error: {e}");
                    continue;
                }
            };

            // IP filter: check before TLS handshake so blocked peers are dropped cheaply.
            if let Some(ref f) = ip_filter {
                if !f.is_allowed(peer_addr.ip()) {
                    tracing::warn!(
                        task = "ip_filter",
                        ip = %peer_addr.ip(),
                        "GUI access denied"
                    );
                    drop(tcp);
                    continue;
                }
            }

            let acceptor_c = acceptor.clone();
            let app_c = app.clone();
            let https_port = addr.port();

            tokio::spawn(async move {
                // Peek at the first byte: TLS ClientHello starts with 0x16.
                // If a plain-HTTP client connects, send a 301 redirect to https://
                // instead of letting them see raw TLS bytes.
                let mut first = [0u8; 1];
                if tcp.peek(&mut first).await.is_ok() && first[0] != 0x16 {
                    use tokio::io::AsyncWriteExt as _;
                    let mut tcp = tcp;
                    let host = peer_addr.ip();
                    let redirect = format!(
                        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}:{https_port}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = tcp.write_all(redirect.as_bytes()).await;
                    return;
                }

                let tls = match acceptor_c.accept(tcp).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!(task = "gui_server", "TLS handshake failed: {e}");
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let svc = hyper_util::service::TowerToHyperService::new(app_c);
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection_with_upgrades(io, svc)
                    .await
                    .ok();
            });
        }
    }

    // ── Plain HTTP path (existing axum::serve) ───────────────────────────────

    // Apply IP filter middleware when configured (used only in plain HTTP path;
    // TLS path filters at the TCP accept level above).
    if let Some(filter) = ip_filter {
        app = app.layer(middleware::from_fn(move |req, next| {
            let f = filter.clone();
            ip_filter_middleware(f, req, next)
        }));
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Dashboard available at http://{addr}");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Axum middleware that checks client IP against the IpFilter allow-list.
async fn ip_filter_middleware(
    filter: IpFilter,
    req: axum::extract::Request,
    next: middleware::Next,
) -> impl IntoResponse {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        if !filter.is_allowed(addr.ip()) {
            tracing::warn!(task = "ip_filter", ip = %addr.ip(), "GUI access denied");
            return (http::StatusCode::FORBIDDEN, "access denied").into_response();
        }
    }
    next.run(req).await.into_response()
}

/// Auto-detect the GUI directory relative to the current executable.
///
/// Looks for `noble-gui/` in the following locations:
/// 1. `<binary_dir>/../noble-gui/`  (typical cargo workspace layout)
/// 2. `<binary_dir>/noble-gui/`
/// 3. `./noble-gui/`
pub fn detect_gui_dir() -> Option<PathBuf> {
    // Try relative to executable
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            // <binary_dir>/../noble-gui/
            let candidate = parent.join("../noble-gui");
            if candidate.join("index.html").exists() {
                return Some(candidate.canonicalize().unwrap_or(candidate));
            }
            // <binary_dir>/noble-gui/
            let candidate = parent.join("noble-gui");
            if candidate.join("index.html").exists() {
                return Some(candidate.canonicalize().unwrap_or(candidate));
            }
        }
    }

    // Try current working directory
    let candidate = PathBuf::from("noble-gui");
    if candidate.join("index.html").exists() {
        return Some(candidate.canonicalize().unwrap_or(candidate));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_gui_dir_returns_none_in_test() {
        // In the test environment, noble-gui/ is unlikely to be at the
        // binary path, so this exercises the fallback logic.
        // We just verify it doesn't panic.
        let _ = detect_gui_dir();
    }
}
