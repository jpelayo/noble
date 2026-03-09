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
//!
//! ## RPC Proxy (`/rpc`) and WS Proxy (`/ws`)
//!
//! The GUI (8785), JSON-RPC (8783), and WebSocket (8784) servers run on
//! different ports.  Each port has its own TLS certificate acceptance in
//! the browser, so cross-port requests fail with a NetworkError until the
//! user manually accepts the cert for each port.
//!
//! To avoid this, the GUI server exposes:
//! - `/rpc` POST endpoint — proxies to the HTTP-only RPC server (8783)
//! - `/ws` WebSocket endpoint — proxies to the WS-only server (8784)
//!
//! The browser sends all requests to `https://localhost:8785` (same origin,
//! already trusted) and never touches ports 8783/8784 directly.
//!
//! The proxy uses a `NoCertVerifier` for its outbound TLS connections to the
//! RPC and WS servers.  This is safe: the connections never leave localhost.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::middleware;
use axum::response::IntoResponse;
use axum::Router;
use http_body_util::{BodyExt, Full};
use tower_http::services::ServeDir;

use axum::extract::ws::{Message as AxumWsMsg, WebSocket};
use futures_util::{SinkExt, StreamExt};
use noble_api::gatekeeper::{GATEKEEPER_HEADER, GATEKEEPER_VALUE};
use noble_api::ip_filter::IpFilter;

// ── NoCertVerifier ─────────────────────────────────────────────────────────

/// Permissive TLS verifier used **only** for localhost loopback proxy
/// connections.  Accepts any certificate — safe because the connection
/// stays on 127.0.0.1 and is our own node's self-signed cert.
#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dsa: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}

/// Build a `TlsConnector` that accepts any server certificate.
/// Used only for the localhost proxy connection.
fn build_client_tls_connector() -> tokio_rustls::TlsConnector {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

// ── RPC proxy ──────────────────────────────────────────────────────────────

/// Proxy a POST request body to the RPC server on `127.0.0.1:rpc_port`.
/// Forwards `Content-Type` and `Authorization` headers, returns the raw
/// JSON-RPC response body to the browser.
async fn proxy_to_rpc(
    rpc_port: u16,
    tls_connector: Option<tokio_rustls::TlsConnector>,
    headers: http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use hyper::Request;

    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| http::HeaderValue::from_static("application/json"));

    let mut req_builder = Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header(http::header::HOST, format!("127.0.0.1:{rpc_port}"))
        .header(http::header::CONTENT_TYPE, content_type);

    if let Some(auth) = headers.get(http::header::AUTHORIZATION) {
        req_builder = req_builder.header(http::header::AUTHORIZATION, auth.clone());
    }

    // Inject gatekeeper header so the RPC server accepts proxied requests.
    req_builder = req_builder.header(GATEKEEPER_HEADER, GATEKEEPER_VALUE);

    let req = match req_builder.body(Full::new(body)) {
        Ok(r) => r,
        Err(e) => {
            return (http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    let tcp = match tokio::net::TcpStream::connect(("127.0.0.1", rpc_port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(task = "rpc_proxy", "TCP connect to RPC port {rpc_port} failed: {e}");
            return (
                http::StatusCode::BAD_GATEWAY,
                "RPC server unreachable — ensure the node is running",
            )
                .into_response();
        }
    };

    // Run the HTTP/1.1 request over TLS or plain TCP.
    let hyper_response = if let Some(connector) = tls_connector {
        let server_name = match rustls_pki_types::ServerName::try_from("localhost") {
            Ok(n) => n.to_owned(),
            Err(_) => {
                return (http::StatusCode::INTERNAL_SERVER_ERROR, "invalid server name")
                    .into_response();
            }
        };
        let tls_stream = match connector.connect(server_name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(task = "rpc_proxy", "TLS handshake to RPC failed: {e}");
                return (http::StatusCode::BAD_GATEWAY, "TLS handshake failed").into_response();
            }
        };
        let io = hyper_util::rt::TokioIo::new(tls_stream);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(p) => p,
            Err(e) => {
                return (http::StatusCode::BAD_GATEWAY, e.to_string()).into_response();
            }
        };
        tokio::spawn(conn);
        match sender.send_request(req).await {
            Ok(r) => r,
            Err(e) => {
                return (http::StatusCode::BAD_GATEWAY, e.to_string()).into_response();
            }
        }
    } else {
        let io = hyper_util::rt::TokioIo::new(tcp);
        let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
            Ok(p) => p,
            Err(e) => {
                return (http::StatusCode::BAD_GATEWAY, e.to_string()).into_response();
            }
        };
        tokio::spawn(conn);
        match sender.send_request(req).await {
            Ok(r) => r,
            Err(e) => {
                return (http::StatusCode::BAD_GATEWAY, e.to_string()).into_response();
            }
        }
    };

    let status = hyper_response.status();
    let resp_headers = hyper_response.headers().clone();
    let resp_body = match hyper_response.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            return (http::StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };

    let mut builder = axum::response::Response::builder().status(status);
    if let Some(ct) = resp_headers.get(http::header::CONTENT_TYPE) {
        builder = builder.header(http::header::CONTENT_TYPE, ct.clone());
    }
    builder
        .body(axum::body::Body::from(resp_body))
        .unwrap_or_else(|_| {
            (http::StatusCode::INTERNAL_SERVER_ERROR, "response build error").into_response()
        })
}

// ── WebSocket proxy ─────────────────────────────────────────────────────

/// Proxy a WebSocket connection from the browser (port 8785) to the WS-only
/// server (port 8784) over localhost.  Bidirectionally forwards all frames.
async fn ws_proxy_handler(
    ws: axum::extract::WebSocketUpgrade,
    axum::extract::State(state): axum::extract::State<WsProxyState>,
) -> axum::response::Response {
    ws.on_upgrade(move |browser_ws| ws_proxy_bridge(browser_ws, state))
}

#[derive(Clone)]
struct WsProxyState {
    ws_port: u16,
    tls_connector: Option<tokio_rustls::TlsConnector>,
}

async fn ws_proxy_bridge(browser_ws: WebSocket, state: WsProxyState) {
    use tokio_tungstenite::tungstenite::Message as TungMsg;

    let url = if state.tls_connector.is_some() {
        format!("wss://127.0.0.1:{}", state.ws_port)
    } else {
        format!("ws://127.0.0.1:{}", state.ws_port)
    };

    // Timeout on backend connect — don't hang forever if WS server is slow/dead.
    let tcp = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(("127.0.0.1", state.ws_port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::warn!(task = "ws_proxy", "TCP connect to RPC port failed: {e}");
            return;
        }
        Err(_) => {
            tracing::warn!(task = "ws_proxy", "TCP connect to RPC port timed out (5s)");
            return;
        }
    };

    let (mut browser_tx, mut browser_rx): (
        futures_util::stream::SplitSink<WebSocket, AxumWsMsg>,
        futures_util::stream::SplitStream<WebSocket>,
    ) = browser_ws.split();

    // Helper: bidirectionally forward frames between axum WS halves and tungstenite WS.
    macro_rules! run_bridge {
        ($backend:expr) => {{
            let (mut backend_tx, mut backend_rx) = $backend.split();
            let b2b = async {
                while let Some(Ok(msg)) = StreamExt::next(&mut browser_rx).await {
                    let t = match msg {
                        AxumWsMsg::Text(t) => TungMsg::Text(t),
                        AxumWsMsg::Binary(b) => TungMsg::Binary(b),
                        AxumWsMsg::Ping(p) => TungMsg::Ping(p),
                        AxumWsMsg::Pong(p) => TungMsg::Pong(p),
                        AxumWsMsg::Close(_) => break,
                    };
                    if backend_tx.send(t).await.is_err() { break; }
                }
            };
            let b2f = async {
                while let Some(Ok(msg)) = StreamExt::next(&mut backend_rx).await {
                    let a = match msg {
                        TungMsg::Text(t) => AxumWsMsg::Text(t),
                        TungMsg::Binary(b) => AxumWsMsg::Binary(b),
                        TungMsg::Ping(p) => AxumWsMsg::Ping(p),
                        TungMsg::Pong(p) => AxumWsMsg::Pong(p),
                        TungMsg::Close(_) => break,
                        _ => continue,
                    };
                    if browser_tx.send(a).await.is_err() { break; }
                }
            };
            tokio::select! { _ = b2b => {} _ = b2f => {} }
        }};
    }

    // Build a WebSocket upgrade request with the gatekeeper header so the
    // WS-only server (which runs the same middleware stack) accepts the proxy
    // connection.  `tokio_tungstenite::client_async` accepts `Into<Request>`.
    let ws_req = || {
        tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&url)
            .header("Host", format!("127.0.0.1:{}", state.ws_port))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header(GATEKEEPER_HEADER, GATEKEEPER_VALUE)
            .body(())
            .expect("ws request must build")
    };

    if let Some(connector) = &state.tls_connector {
        let server_name = rustls_pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let tls_stream = match connector.connect(server_name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(task = "ws_proxy", "TLS handshake failed: {e}");
                return;
            }
        };
        let (ws, _) = match tokio_tungstenite::client_async(ws_req(), tls_stream).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(task = "ws_proxy", "WS handshake (TLS) failed: {e}");
                return;
            }
        };
        run_bridge!(ws);
    } else {
        let (ws, _) = match tokio_tungstenite::client_async(ws_req(), tcp).await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(task = "ws_proxy", "WS handshake failed: {e}");
                return;
            }
        };
        run_bridge!(ws);
    }
}

/// Start the embedded GUI HTTP(S) server.
///
/// Serves all files under `gui_dir` with `index.html` as the SPA fallback.
/// Adds a Content-Security-Policy header that restricts `connect-src` to the
/// RPC port (8783, HTTP JSON-RPC) and the WS port (8784, WebSocket subscriptions).
///
/// `rpc_origins` is the live list of allowed RPC endpoints (e.g.
/// `["https://127.0.0.1:8783", "wss://127.0.0.1:8784"]`), wrapped in
/// `Arc<RwLock>` so `setAllowedIps` can update it at runtime without restart.
/// The CSP header is computed on each request from the live list.
///
/// `rpc_port` is injected into the `/` route as `window.NOBLE_RPC_PORT` so
/// that `app.js` always connects to the correct port even when non-default.
///
/// `ws_port` is the dedicated WebSocket server port (default 8784), used by
/// the `/ws` proxy route to connect to the WS-only backend.
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
    ws_port: u16,
    setup_mode: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let serve_dir = ServeDir::new(&gui_dir);

    let proto = if tls_config.is_some() { "https" } else { "http" };

    // Root route: serve index.html with injected NOBLE_RPC_PORT script tag.
    let gui_dir_clone = gui_dir.clone();
    let root_handler = axum::routing::get(move || {
        let dir = gui_dir_clone.clone();
        async move {
            let index_path = dir.join("index.html");
            match tokio::fs::read_to_string(&index_path).await {
                Ok(html) => {
                    let mut script = format!(
                        "<script>window.NOBLE_RPC_PORT={};window.NOBLE_VERSION='{}';</script>",
                        rpc_port,
                        noble_core::SOFTWARE_VERSION
                    );
                    // Issue 8: inject setup mode flag synchronously so app.js can
                    // redirect to #/setup before router.start() — no async RPC needed.
                    if setup_mode {
                        script.push_str("<script>window.NOBLE_SETUP_MODE=true;</script>");
                    }
                    // Cache busting: append ?v=VERSION to all .css and .js asset
                    // references in the HTML so browsers fetch fresh assets on
                    // every version bump.  The version comes from Cargo.toml via
                    // noble_core::SOFTWARE_VERSION — no hardcoded strings.
                    let bust = format!("?v={}", noble_core::SOFTWARE_VERSION);
                    let html = html
                        .replace(".css\"", &format!(".css{bust}\""))
                        .replace(".js\"", &format!(".js{bust}\""))
                        .replace(".js'", &format!(".js{bust}'"));

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

    // /rpc proxy — same-origin POST endpoint that forwards to the RPC server.
    // The browser sends requests to /rpc (port 8785, already trusted) and the
    // proxy opens a loopback connection to the RPC port internally.
    let proxy_port = rpc_port;
    let proxy_tls = if tls_config.is_some() {
        Some(build_client_tls_connector())
    } else {
        None
    };
    let rpc_proxy_handler = axum::routing::post(
        move |headers: http::HeaderMap, body: axum::body::Bytes| {
            let conn = proxy_tls.clone();
            async move { proxy_to_rpc(proxy_port, conn, headers, body).await }
        },
    );

    // /ws proxy — WebSocket upgrade handler that proxies to the WS-only server
    // on ws_port (8784).  Same-origin connection avoids self-signed cert rejection.
    let ws_proxy_state = WsProxyState {
        ws_port,
        tls_connector: if tls_config.is_some() {
            Some(build_client_tls_connector())
        } else {
            None
        },
    };

    let mut app = Router::new()
        .route("/", root_handler)
        .route("/rpc", rpc_proxy_handler)
        .route("/ws", axum::routing::get(ws_proxy_handler).with_state(ws_proxy_state))
        .fallback_service(serve_dir);

    // Dynamic CSP middleware — reads rpc_origins on every request so that
    // setAllowedIps updates are reflected immediately without a restart.
    // 'self' is included in connect-src so the /rpc proxy route is allowed.
    let rpc_origins_csp = rpc_origins.clone();
    app = app.layer(axum::middleware::from_fn(move |req: axum::extract::Request, next: axum::middleware::Next| {
        let origins = rpc_origins_csp.clone();
        async move {
            // Capture request metadata for version-based cache decisions.
            let uri_path = req.uri().path().to_string();
            let is_versioned = req.uri().query().map_or(false, |q| q.contains("v="));

            let mut resp: axum::response::Response = next.run(req).await;

            // ── CSP header (dynamic, reads live rpc_origins) ──
            let connect_src = {
                let guard = origins.read();
                if guard.is_empty() {
                    "'self' http://127.0.0.1:8783 http://localhost:8783 ws://127.0.0.1:8784 ws://localhost:8784"
                        .to_string()
                } else {
                    format!("'self' {}", guard.join(" "))
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

            // ── Cache busting: rewrite import paths in JS modules ──
            //
            // Append ?v=VERSION to .js import specifiers so that when the
            // version in Cargo.toml changes, every module in the import graph
            // gets a fresh URL and the browser fetches updated code.  Only
            // applied to files under /js/ to skip vendor libraries (echarts).
            if uri_path.starts_with("/js/") && uri_path.ends_with(".js") && resp.status().is_success() {
                let bust = format!("?v={}", noble_core::SOFTWARE_VERSION);
                let (parts, body) = resp.into_parts();
                match body.collect().await {
                    Ok(collected) => {
                        let bytes = collected.to_bytes();
                        let content = String::from_utf8_lossy(&bytes);
                        let rewritten = content
                            .replace(".js'", &format!(".js{bust}'"))
                            .replace(".js\"", &format!(".js{bust}\""));
                        resp = axum::response::Response::from_parts(
                            parts,
                            axum::body::Body::from(rewritten),
                        );
                        // Content-Length changed; remove so hyper recalculates.
                        resp.headers_mut().remove(http::header::CONTENT_LENGTH);
                    }
                    Err(_) => {
                        resp = axum::response::Response::from_parts(
                            parts,
                            axum::body::Body::empty(),
                        );
                    }
                }
            }

            // ── Version-aware Cache-Control ──
            //
            // Assets requested with ?v=VERSION (from the HTML/JS rewriting
            // above) are immutable for that version — cache for 1 day, busted
            // automatically when Cargo.toml version changes.  Everything else
            // (HTML, API, unversioned assets) must revalidate each request.
            if is_versioned {
                resp.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("public, max-age=86400"),
                );
            } else {
                resp.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-cache"),
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
                // Panic-safe: catch_unwind ensures a single bad connection
                // can never crash the entire accept loop.
                let handler = std::panic::AssertUnwindSafe(async {
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
                if let Err(panic) = futures_util::FutureExt::catch_unwind(handler).await {
                    let msg = if let Some(s) = panic.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = panic.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "unknown".to_string()
                    };
                    tracing::error!(
                        task = "gui_server",
                        peer = %peer_addr,
                        "connection handler panicked: {msg}"
                    );
                }
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
