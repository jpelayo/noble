// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Embedded HTTP server for the NOBLE dashboard GUI.
//!
//! Serves static files from the `noble-gui/` directory on a dedicated port
//! (default 8785). Uses `tower_http::services::ServeDir` with SPA fallback
//! so that unknown paths resolve to `index.html`.

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::extract::ConnectInfo;
use axum::middleware;
use axum::response::IntoResponse;
use axum::Router;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use noble_api::ip_filter::IpFilter;

/// Start the embedded GUI HTTP server.
///
/// Serves all files under `gui_dir` with `index.html` as the SPA fallback.
/// Adds a Content-Security-Policy header that restricts `connect-src` to
/// the RPC and WebSocket ports. When remote access is enabled, CSP uses `*`
/// (the IP filter layer provides the actual security boundary).
pub async fn start_gui_server(
    addr: SocketAddr,
    gui_dir: PathBuf,
    ip_filter: Option<IpFilter>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let index_path = gui_dir.join("index.html");

    let serve_dir = ServeDir::new(&gui_dir).fallback(ServeFile::new(index_path));

    let remote_access = ip_filter.as_ref().is_some_and(|f| f.has_remote_access());

    let csp = if remote_access {
        "default-src 'self' 'unsafe-inline'; \
         connect-src *; \
         script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:"
    } else {
        "default-src 'self' 'unsafe-inline'; \
         connect-src http://127.0.0.1:8783 ws://127.0.0.1:8784; \
         script-src 'self' 'unsafe-inline'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:"
    };

    let mut app =
        Router::new()
            .fallback_service(serve_dir)
            .layer(SetResponseHeaderLayer::overriding(
                http::header::HeaderName::from_static("content-security-policy"),
                http::HeaderValue::from_static(csp),
            ));

    // Apply IP filter middleware when configured.
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
