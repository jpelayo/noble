// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Bearer-token authentication for the faucet's HTTP admin endpoints
//! (`/api/faucet/reset-limits` today, plus any future admin op).
//!
//! The token is owned by the **node** — stored in the node's keystore
//! under `SCHEME_FAUCET_ADMIN_TOKEN` (0x86), displayed/rotated in the
//! node's Faucet settings panel. The faucet binary fetches it via the
//! `noble_getFaucetAdminToken` RPC at boot and refreshes every 60 s,
//! caching the current value in a shared `RwLock`.
//!
//! Security posture:
//! - Empty cache (fetch failed, e.g. node down) → 503 Service Unavailable.
//!   The admin endpoint refuses to operate as an unauthenticated surface
//!   even if the cross-process token sync is momentarily broken.
//! - Mismatched bearer → 401 Unauthorized.
//! - Constant-time compare to prevent timing oracles on the bearer.
//!
//! Public faucet endpoints (`POST /api/faucet`, `GET /api/faucet/status`)
//! do NOT go through this layer; they keep permissive CORS and no auth.

use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use tower::{Layer, Service};

/// Shared cache holding the current admin token. Updated by the
/// 60-second refresh task in `main.rs`; read by [`AdminAuthService`]
/// on every admin-endpoint request.
pub type AdminTokenCache = Arc<RwLock<Option<String>>>;

/// Tower layer producing [`AdminAuthService`].
#[derive(Clone)]
pub struct AdminAuthLayer {
    cache: AdminTokenCache,
}

impl AdminAuthLayer {
    pub fn new(cache: AdminTokenCache) -> Self {
        Self { cache }
    }
}

impl<S> Layer<S> for AdminAuthLayer {
    type Service = AdminAuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AdminAuthService { inner, cache: self.cache.clone() }
    }
}

#[derive(Clone)]
pub struct AdminAuthService<S> {
    inner: S,
    cache: AdminTokenCache,
}

impl<S> Service<Request<Body>> for AdminAuthService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        // OPTIONS preflight passes through so the tightened admin CORS
        // can negotiate before the bearer is required.
        if req.method() == axum::http::Method::OPTIONS {
            let fut = self.inner.call(req);
            return Box::pin(async move { fut.await });
        }

        let cache_snapshot: Option<String> = self
            .cache
            .read()
            .map(|g| g.clone())
            .unwrap_or(None);
        let bearer = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer ").map(str::to_string));

        match (cache_snapshot, bearer) {
            (None, _) => {
                // Token cache not yet populated (RPC fetch failed or hasn't
                // run). Refuse — secure-by-default; do NOT silently allow.
                tracing::warn!(
                    task = "faucet_admin",
                    "admin endpoint hit with no token cached — returning 503"
                );
                Box::pin(async move { Ok(error_resp(StatusCode::SERVICE_UNAVAILABLE, "admin token not yet available")) })
            }
            (Some(_), None) => {
                tracing::debug!(task = "faucet_admin", "admin endpoint hit without Authorization header");
                Box::pin(async move { Ok(error_resp(StatusCode::UNAUTHORIZED, "missing bearer token")) })
            }
            (Some(expected), Some(provided)) => {
                if constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
                    let fut = self.inner.call(req);
                    Box::pin(async move { fut.await })
                } else {
                    tracing::debug!(task = "faucet_admin", "admin endpoint hit with wrong bearer");
                    Box::pin(async move { Ok(error_resp(StatusCode::UNAUTHORIZED, "invalid bearer token")) })
                }
            }
        }
    }
}

fn error_resp(status: StatusCode, msg: &str) -> Response<Body> {
    let body = serde_json::json!({ "success": false, "message": msg });
    let mut resp = Response::new(Body::from(body.to_string()));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/json"),
    );
    resp
}

/// Constant-time byte-slice equality. Always touches every byte of the
/// longer slice so timing does not leak the position of the first
/// mismatch. Returns `false` on length mismatch (length is not secret).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;

    #[test]
    fn ct_eq_matches_eq() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"x"));
    }
}
