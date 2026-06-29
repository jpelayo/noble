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

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
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
use noble_api::middleware::GUI_PROXY_AUTH_HEADER;
use noble_api::peer_addr::PeerAddrLayer;
use tower::Layer as _;

use crate::gui_session::{self, GuiLockState};

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

    // GUI admin-lock bridge: forward the per-boot proxy secret the session gate
    // set on authenticated requests so the RPC server accepts them under any
    // totp_scope. The gate strips any client-supplied copy, so this only carries
    // the gate's value.
    if let Some(gui_auth) = headers.get(GUI_PROXY_AUTH_HEADER) {
        req_builder = req_builder.header(GUI_PROXY_AUTH_HEADER, gui_auth.clone());
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
///
/// TOTP: The browser sends `?token=<sha256_hash>` on the WS URL.  We extract
/// it and forward as `Authorization: Bearer <hash>` to the backend so the
/// TOTP middleware can validate it.
async fn ws_proxy_handler(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: http::HeaderMap,
    ws: axum::extract::WebSocketUpgrade,
    axum::extract::State(state): axum::extract::State<WsProxyState>,
) -> axum::response::Response {
    let auth_token = params.get("token").cloned();
    // GUI admin-lock bridge: the session gate (which already validated this
    // upgrade) sets the per-boot proxy secret; forward it to the backend WS so it
    // is accepted under any totp_scope. Browser-supplied values are stripped by
    // the gate, so only the gate's value reaches here.
    let gui_proxy_auth = headers
        .get(GUI_PROXY_AUTH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    ws.on_upgrade(move |browser_ws| ws_proxy_bridge(browser_ws, state, auth_token, gui_proxy_auth))
}

#[derive(Clone)]
struct WsProxyState {
    ws_port: u16,
    tls_connector: Option<tokio_rustls::TlsConnector>,
}

async fn ws_proxy_bridge(
    browser_ws: WebSocket,
    state: WsProxyState,
    auth_token: Option<String>,
    gui_proxy_auth: Option<String>,
) {
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

    // Build a WebSocket upgrade request with the gatekeeper header and
    // TOTP auth (if provided) so the WS-only server (which runs the same
    // middleware stack) accepts the proxy connection.
    let ws_req = || {
        let mut builder = tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&url)
            .header("Host", format!("127.0.0.1:{}", state.ws_port))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .header(GATEKEEPER_HEADER, GATEKEEPER_VALUE);
        // Forward TOTP token from browser ?token=<hash> as Authorization header.
        if let Some(ref token) = auth_token {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        // GUI admin-lock bridge secret (set by the session gate after validating
        // the session) so the backend WS accepts the proxied upgrade under any scope.
        if let Some(ref secret) = gui_proxy_auth {
            builder = builder.header(GUI_PROXY_AUTH_HEADER, secret.clone());
        }
        builder.body(())
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
/// Build the GUI server's Axum router: static dashboard, `/rpc` + `/ws` reverse
/// proxies, the `/gui/login` + `/gui/logout` endpoints, the CSP layer, and the
/// admin-lock session gate (outermost). Extracted from [`start_gui_server`] so
/// the gate's route coverage can be exercised with `oneshot` without binding a
/// socket (see the tests at the bottom of this file).
#[allow(clippy::too_many_arguments)]
fn build_gui_app(
    gui_lock_state: GuiLockState,
    gui_dir: PathBuf,
    tls_enabled: bool,
    rpc_origins: Arc<parking_lot::RwLock<Vec<String>>>,
    rpc_port: u16,
    ws_port: u16,
    setup_mode: bool,
) -> Router {
    let serve_dir = ServeDir::new(&gui_dir);

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
    let proxy_tls = if tls_enabled {
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
        tls_connector: if tls_enabled {
            Some(build_client_tls_connector())
        } else {
            None
        },
    };

    // GUI admin-lock login/logout endpoints (always reachable without a session).
    let login_lock = gui_lock_state.clone();
    let login_handler = axum::routing::post(move |req: axum::extract::Request| {
        let lock = login_lock.clone();
        async move { handle_gui_login(lock, req).await }
    });
    let logout_lock = gui_lock_state.clone();
    let logout_handler = axum::routing::post(move |req: axum::extract::Request| {
        let lock = logout_lock.clone();
        async move { handle_gui_logout(lock, req).await }
    });

    let mut app = Router::new()
        .route("/", root_handler)
        .route("/rpc", rpc_proxy_handler)
        .route("/ws", axum::routing::get(ws_proxy_handler).with_state(ws_proxy_state))
        .route("/gui/login", login_handler)
        .route("/gui/logout", logout_handler)
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

    // ── GUI admin-lock session gate ──────────────────────────────────────────
    // Added last → outermost layer → runs FIRST on each request, before CSP.
    // Gates every request (pages, /rpc, /ws) behind a TOTP session when enabled.
    let gate_lock = gui_lock_state.clone();
    let gate_gui_dir = gui_dir.clone();
    app = app.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let lock = gate_lock.clone();
            let dir = gate_gui_dir.clone();
            async move { gui_lock_gate(lock, dir, req, next).await }
        },
    ));

    app
}

/// Start the GUI HTTP(S) server: build the router via [`build_gui_app`], then
/// bind and serve it (custom tokio-rustls accept loop for TLS, or `axum::serve`
/// for plain HTTP). IP filtering is applied at the TCP accept level so blocked
/// peers never complete a TLS handshake.
#[allow(clippy::too_many_arguments)]
pub async fn start_gui_server(
    addr: SocketAddr,
    gui_dir: PathBuf,
    ip_filter: Option<IpFilter>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
    rpc_origins: Arc<parking_lot::RwLock<Vec<String>>>,
    rpc_port: u16,
    ws_port: u16,
    setup_mode: bool,
    gui_lock_state: GuiLockState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let proto = if tls_config.is_some() { "https" } else { "http" };
    let mut app = build_gui_app(
        gui_lock_state,
        gui_dir,
        tls_config.is_some(),
        rpc_origins,
        rpc_port,
        ws_port,
        setup_mode,
    );

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
                    // Inject the peer address (the plain-HTTP path gets it from
                    // `into_make_service_with_connect_info`; this custom TLS loop
                    // must add it so the GUI-login limiter can key by client IP).
                    let svc = hyper_util::service::TowerToHyperService::new(
                        PeerAddrLayer::new(peer_addr).layer(app_c),
                    );
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

// ── GUI admin lock: session gate + login/logout handlers ────────────────────

/// Extract the client IP from request extensions. The plain-HTTP path injects
/// `ConnectInfo<SocketAddr>`; the TLS accept loop injects a raw `SocketAddr` via
/// [`PeerAddrLayer`]. Falls back to `0.0.0.0` (a shared limiter bucket) if neither
/// is present.
fn client_ip(req: &axum::extract::Request) -> IpAddr {
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return addr.ip();
    }
    if let Some(addr) = req.extensions().get::<SocketAddr>() {
        return addr.ip();
    }
    IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
}

/// JSON-RPC 401 returned for an unauthenticated `/rpc` call while the lock is on.
fn unauthorized_rpc_response() -> axum::response::Response {
    let body = r#"{"jsonrpc":"2.0","error":{"code":-32004,"message":"gui session required"},"id":null}"#;
    axum::response::Response::builder()
        .status(http::StatusCode::UNAUTHORIZED)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

/// Build an HTML response with hard security headers for the gate's
/// directly-served pages (login / recovery). These bypass the inner CSP
/// middleware, so the headers are set here explicitly: `frame-ancestors 'none'`
/// + `X-Frame-Options: DENY` block clickjacking, `form-action 'self'` +
/// `base-uri 'none'` lock the form down, and `no-store` prevents caching the
/// most sensitive pages.
fn secure_html_response(html: String) -> axum::response::Response {
    const CSP: &str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
                       form-action 'self'; script-src 'self' 'unsafe-inline'; \
                       style-src 'self' 'unsafe-inline'; img-src 'self' data:";
    axum::response::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(http::header::CACHE_CONTROL, "no-store")
        .header("content-security-policy", CSP)
        .header("x-frame-options", "DENY")
        .body(axum::body::Body::from(html))
        .unwrap_or_default()
}

/// Serve the login page. Prefers `gui_dir/login.html`; falls back to a minimal
/// inline page so the wall works even if the asset isn't deployed.
async fn serve_login_page(gui_dir: &Path) -> axum::response::Response {
    let html = match tokio::fs::read_to_string(gui_dir.join("login.html")).await {
        Ok(h) => h,
        Err(_) => FALLBACK_LOGIN_HTML.to_string(),
    };
    secure_html_response(html)
}

/// Recovery page shown to REMOTE clients when the lock is enabled but TOTP is
/// unavailable. Never reveals dashboard content; tells the operator to recover
/// from localhost or the CLI.
async fn serve_recovery_page() -> axum::response::Response {
    secure_html_response(RECOVERY_HTML.to_string())
}

/// The GUI admin-lock session gate. Runs on every request; when the lock is
/// enabled it requires a valid session cookie for everything except the login
/// surface, and vouches authenticated requests to the loopback RPC/WS.
async fn gui_lock_gate(
    lock: GuiLockState,
    gui_dir: PathBuf,
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Always strip any client-supplied proxy-trust header: it must never reach
    // the loopback RPC unless WE re-add it after validating a session.
    req.headers_mut().remove(GUI_PROXY_AUTH_HEADER);

    if !lock.is_enabled() {
        return next.run(req).await;
    }

    let path = req.uri().path().to_string();
    // The login surface is always reachable without a session.
    if path == "/login.html" || path == "/gui/login" || path == "/gui/logout" {
        return next.run(req).await;
    }

    // Recovery mode: the lock is on but no TOTP validator is available, so nobody
    // can sign in. Fail CLOSED — never serve the dashboard remotely. Let loopback
    // through for on-host recovery (localhost / CLI); show a recovery page to
    // remote clients. (At boot the in-memory session store is empty, so there are
    // no valid sessions to honour here anyway.)
    if lock.totp_slot.read().is_none() {
        if client_ip(&req).is_loopback() {
            return next.run(req).await;
        }
        if path == "/rpc" || path == "/ws" {
            return (
                http::StatusCode::SERVICE_UNAVAILABLE,
                "GUI admin lock: TOTP is unavailable — recover from localhost or the CLI",
            )
                .into_response();
        }
        return serve_recovery_page().await;
    }

    let authed = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(gui_session::parse_session_cookie)
        .map(|tok| lock.store.validate(tok))
        .unwrap_or(false);

    if authed {
        // Vouch for the request to the loopback RPC/WS so they accept it under
        // any totp_scope.
        if let Ok(val) = http::HeaderValue::from_str(&lock.proxy_secret) {
            req.headers_mut().insert(
                http::HeaderName::from_static(GUI_PROXY_AUTH_HEADER),
                val,
            );
        }
        return next.run(req).await;
    }

    // Unauthenticated.
    if path == "/rpc" {
        return unauthorized_rpc_response();
    }
    if path == "/ws" {
        return (http::StatusCode::UNAUTHORIZED, "gui session required").into_response();
    }
    serve_login_page(&gui_dir).await
}

/// `POST /gui/login` — validate a TOTP code and mint a session cookie.
async fn handle_gui_login(
    lock: GuiLockState,
    req: axum::extract::Request,
) -> axum::response::Response {
    // CSRF defense: require the custom Gatekeeper header (a cross-site form POST
    // cannot set custom headers without a CORS preflight we don't grant).
    let has_gatekeeper = req
        .headers()
        .get(GATEKEEPER_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == GATEKEEPER_VALUE)
        .unwrap_or(false);
    if !has_gatekeeper {
        return (http::StatusCode::FORBIDDEN, "missing gatekeeper header").into_response();
    }

    let ip = client_ip(&req);
    if let Some(retry) = lock.limiter.locked_for(ip) {
        return axum::response::Response::builder()
            .status(http::StatusCode::TOO_MANY_REQUESTS)
            .header("Retry-After", retry.to_string())
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(format!(
                r#"{{"ok":false,"error":"too many attempts","retry_after":{retry}}}"#
            )))
            .unwrap_or_default();
    }

    let body_bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
        Ok(b) => b,
        Err(_) => return (http::StatusCode::BAD_REQUEST, "invalid body").into_response(),
    };
    let code_hash = serde_json::from_slice::<serde_json::Value>(&body_bytes)
        .ok()
        .and_then(|v| {
            v.get("code_hash")
                .and_then(|c| c.as_str())
                .map(String::from)
        });
    let code_hash = match code_hash {
        Some(h) => h,
        None => return (http::StatusCode::BAD_REQUEST, "missing code_hash").into_response(),
    };

    match lock.validate_totp(&code_hash) {
        Ok(true) => {
            lock.limiter.record_success(ip);
            let token = lock.store.create();
            let cookie = gui_session::set_cookie_value(&token, lock.secure_cookie);
            tracing::info!(task = "gui_auth", "GUI admin session established");
            axum::response::Response::builder()
                .status(http::StatusCode::OK)
                .header(http::header::SET_COOKIE, cookie)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"ok":true}"#))
                .unwrap_or_default()
        }
        Ok(false) => {
            lock.limiter.record_failure(ip);
            tracing::warn!(task = "gui_auth", ip = %ip, "GUI login rejected: invalid code");
            axum::response::Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"ok":false,"error":"invalid code"}"#))
                .unwrap_or_default()
        }
        Err(()) => {
            tracing::error!(
                task = "gui_auth",
                "GUI lock is enabled but no TOTP validator is available"
            );
            axum::response::Response::builder()
                .status(http::StatusCode::SERVICE_UNAVAILABLE)
                .header(http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(
                    r#"{"ok":false,"error":"totp not available"}"#,
                ))
                .unwrap_or_default()
        }
    }
}

/// `POST /gui/logout` — revoke the caller's session and clear the cookie.
async fn handle_gui_logout(
    lock: GuiLockState,
    req: axum::extract::Request,
) -> axum::response::Response {
    // Same CSRF posture as login: require the custom Gatekeeper header.
    let has_gatekeeper = req
        .headers()
        .get(GATEKEEPER_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == GATEKEEPER_VALUE)
        .unwrap_or(false);
    if !has_gatekeeper {
        return (http::StatusCode::FORBIDDEN, "missing gatekeeper header").into_response();
    }

    if let Some(tok) = req
        .headers()
        .get(http::header::COOKIE)
        .and_then(|c| c.to_str().ok())
        .and_then(gui_session::parse_session_cookie)
    {
        lock.store.remove(tok);
    }
    axum::response::Response::builder()
        .status(http::StatusCode::OK)
        .header(
            http::header::SET_COOKIE,
            gui_session::clear_cookie_value(lock.secure_cookie),
        )
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(r#"{"ok":true}"#))
        .unwrap_or_default()
}

/// Minimal fallback login page used only if `gui_dir/login.html` is missing.
const FALLBACK_LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NOBLE — Sign in</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#1a1d27;border:1px solid #2a2f3a;border-radius:10px;padding:2rem;width:320px;text-align:center}
h1{font-size:1.1rem;margin:0 0 .25rem}p{color:#9aa3b2;font-size:.85rem;margin:0 0 1rem}
input{width:100%;box-sizing:border-box;padding:.6rem;font-size:1.3rem;letter-spacing:.3em;text-align:center;border:1px solid #2a2f3a;border-radius:6px;background:#11141c;color:#e6e6e6;margin-bottom:1rem}
button{width:100%;padding:.6rem;border:0;border-radius:6px;background:#3b5bdb;color:#fff;font-size:.95rem;cursor:pointer}
.err{color:#ff6b6b;font-size:.8rem;min-height:1em;margin-top:.5rem}
</style></head><body>
<div class="card">
<h1>Administrator sign-in</h1>
<p>Enter your 6-digit TOTP code to access the dashboard.</p>
<input id="c" type="text" inputmode="numeric" maxlength="6" placeholder="000000" autocomplete="one-time-code" autofocus>
<button id="b">Unlock</button>
<div class="err" id="e"></div>
</div>
<script>
const c=document.getElementById('c'),b=document.getElementById('b'),e=document.getElementById('e');
async function sha256hex(s){const d=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s));return Array.from(new Uint8Array(d)).map(x=>x.toString(16).padStart(2,'0')).join('');}
async function go(){const code=c.value.trim();if(!/^\d{6}$/.test(code)){e.textContent='Enter a 6-digit code.';return;}b.disabled=true;e.textContent='';
try{const r=await fetch('/gui/login',{method:'POST',headers:{'Content-Type':'application/json','Gatekeeper':'noble'},body:JSON.stringify({code_hash:await sha256hex(code)})});
if(r.ok){location.href='/';return;}if(r.status===429){const j=await r.json().catch(()=>({}));e.textContent='Too many attempts. Wait '+(j.retry_after||30)+'s.';}else{e.textContent='Invalid code. Try again.';c.value='';}}catch(_){e.textContent='Network error.';}b.disabled=false;}
b.onclick=go;c.addEventListener('keydown',ev=>{if(ev.key==='Enter')go();});
</script></body></html>"#;

/// Recovery page served to REMOTE clients when the lock is enabled but TOTP is
/// unavailable. Self-contained; reveals no dashboard content.
const RECOVERY_HTML: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>NOBLE — Dashboard locked</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:1rem}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2rem;max-width:440px;text-align:center}
h1{font-size:1.1rem;margin:0 0 .75rem}p{color:#94a3b8;font-size:.88rem;line-height:1.55;margin:0 0 .75rem}
code{background:#0f172a;padding:1px 6px;border-radius:4px;color:#e2e8f0}
</style></head><body>
<div class="card">
<h1>Dashboard locked — TOTP unavailable</h1>
<p>The administrator lock is enabled, but this node could not load its TOTP
secret, so no one can sign in remotely.</p>
<p>Recover from the host machine: open <code>http://localhost:8785</code> on the
node itself, or repair the TOTP configuration with the <code>noble-tool</code>
CLI, then restart the node.</p>
</div></body></html>"#;

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

    // ── Route-topology tests for the admin-lock gate ────────────────────────
    // These freeze "the whole GUI is gated" so a future stray route, misplaced
    // layer, or static-fallback change can't silently reopen the dashboard.

    use axum::body::Body;
    use noble_api::auth::TotpValidator;
    use std::sync::atomic::AtomicBool;
    use tower::ServiceExt as _; // oneshot

    /// Temp `gui_dir` with marker files so we can tell login vs dashboard apart.
    fn temp_gui_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(
            p.join("index.html"),
            "<html><head></head><body>DASHBOARD_MARKER</body></html>",
        )
        .unwrap();
        std::fs::write(p.join("login.html"), "<html><body>LOGIN_PAGE_MARKER</body></html>").unwrap();
        std::fs::create_dir_all(p.join("js")).unwrap();
        std::fs::write(p.join("js").join("app.js"), "/*APP_JS_MARKER*/").unwrap();
        std::fs::create_dir_all(p.join("css")).unwrap();
        std::fs::write(p.join("css").join("style.css"), "/*CSS_MARKER*/").unwrap();
        std::fs::create_dir_all(p.join("assets")).unwrap();
        std::fs::write(p.join("assets").join("x"), "ASSET_MARKER").unwrap();
        dir
    }

    fn make_state(enabled: bool, with_validator: bool) -> GuiLockState {
        let slot: noble_api::state::SharedTotpSlot = if with_validator {
            let (v, _) = TotpValidator::generate().unwrap();
            Arc::new(parking_lot::RwLock::new(Some(Arc::new(parking_lot::RwLock::new(v)))))
        } else {
            Arc::new(parking_lot::RwLock::new(None))
        };
        GuiLockState::new(
            Arc::new(AtomicBool::new(enabled)),
            slot,
            false, // secure_cookie
            Arc::new("test-proxy-secret".to_string()),
        )
    }

    fn app_for(state: GuiLockState, dir: &Path) -> Router {
        build_gui_app(
            state,
            dir.to_path_buf(),
            false, // tls_enabled
            Arc::new(parking_lot::RwLock::new(Vec::new())),
            8783,
            8784,
            false, // setup_mode
        )
    }

    async fn body_of(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn get(uri: &str) -> http::Request<Body> {
        http::Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn locked_gui_gates_all_dashboard_paths() {
        let dir = temp_gui_dir();
        let state = make_state(true, true);

        // Every dashboard/static path, unauthenticated → login page, never dashboard.
        for path in ["/", "/index.html", "/js/app.js", "/css/style.css", "/assets/x", "/anything"] {
            let resp = app_for(state.clone(), dir.path()).oneshot(get(path)).await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK, "{path}");
            let body = body_of(resp).await;
            assert!(body.contains("LOGIN_PAGE_MARKER"), "{path} should serve login, got: {body}");
            assert!(
                !body.contains("DASHBOARD_MARKER") && !body.contains("APP_JS_MARKER")
                    && !body.contains("ASSET_MARKER") && !body.contains("CSS_MARKER"),
                "{path} leaked dashboard content"
            );
        }

        // /rpc and /ws unauthenticated → 401 (never proxied).
        let resp = app_for(state.clone(), dir.path())
            .oneshot(http::Request::builder().method("POST").uri("/rpc").body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED, "/rpc");
        let resp = app_for(state.clone(), dir.path()).oneshot(get("/ws")).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::UNAUTHORIZED, "/ws");

        // Login surface stays reachable without a session.
        let resp = app_for(state.clone(), dir.path()).oneshot(get("/login.html")).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(body_of(resp).await.contains("LOGIN_PAGE_MARKER"));

        // POST /gui/login reaches the handler (not gated): no Gatekeeper → 403.
        let resp = app_for(state.clone(), dir.path())
            .oneshot(http::Request::builder().method("POST").uri("/gui/login").body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN, "/gui/login must reach the handler");
    }

    #[tokio::test]
    async fn authenticated_cookie_reaches_dashboard() {
        let dir = temp_gui_dir();
        let state = make_state(true, true);
        let token = state.store.create();
        let cookie = format!("{}={}", gui_session::SESSION_COOKIE, token);

        let req = |uri: &str| {
            http::Request::builder()
                .method("GET")
                .uri(uri)
                .header(http::header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap()
        };
        let resp = app_for(state.clone(), dir.path()).oneshot(req("/js/app.js")).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(body_of(resp).await.contains("APP_JS_MARKER"));

        let resp = app_for(state.clone(), dir.path()).oneshot(req("/")).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(body_of(resp).await.contains("DASHBOARD_MARKER"));
    }

    #[tokio::test]
    async fn disabled_lock_is_transparent() {
        let dir = temp_gui_dir();
        let state = make_state(false, true);
        let resp = app_for(state, dir.path()).oneshot(get("/")).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert!(body_of(resp).await.contains("DASHBOARD_MARKER"));
    }

    #[tokio::test]
    async fn no_validator_serves_recovery_not_dashboard() {
        // Lock on but no TOTP validator: remote (non-loopback in oneshot, which
        // has no ConnectInfo → UNSPECIFIED) must get the recovery page, not the UI.
        let dir = temp_gui_dir();
        let state = make_state(true, false);
        let resp = app_for(state.clone(), dir.path()).oneshot(get("/")).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let body = body_of(resp).await;
        assert!(body.contains("Dashboard locked"), "expected recovery page, got: {body}");
        assert!(!body.contains("DASHBOARD_MARKER"));
        // /rpc → 503 in recovery mode.
        let resp = app_for(state, dir.path())
            .oneshot(http::Request::builder().method("POST").uri("/rpc").body(Body::from("{}")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    }
}
