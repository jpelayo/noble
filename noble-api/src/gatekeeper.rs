// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Lightweight pre-auth gatekeeper middleware for the NOBLE RPC and WS servers.
//!
//! Requires a `Gatekeeper: noble` HTTP header on every request.  Rejects
//! drive-by port scanners (Shodan, Censys, bots) before they touch any
//! application logic — not real auth (the value is public/hardcoded), just
//! a cheap bouncer that drops 99% of automated probes.
//!
//! CORS preflight (`OPTIONS`) requests are always passed through.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use tower::{Layer, Service};

use crate::error::GATEKEEPER_REJECTED;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Required header name.
pub const GATEKEEPER_HEADER: &str = "gatekeeper";

/// Required header value.
pub const GATEKEEPER_VALUE: &str = "noble";

// ---------------------------------------------------------------------------
// Tower Layer / Service
// ---------------------------------------------------------------------------

/// Tower [`Layer`] that produces [`GatekeeperService`] instances.
#[derive(Clone, Copy)]
pub struct GatekeeperLayer;

impl<S> Layer<S> for GatekeeperLayer {
    type Service = GatekeeperService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GatekeeperService { inner }
    }
}

/// Tower [`Service`] that rejects requests missing the gatekeeper header.
#[derive(Clone)]
pub struct GatekeeperService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for GatekeeperService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: Send + 'static,
    ResBody: http_body::Body<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = Response<http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        use http_body_util::BodyExt;

        // Always let CORS preflight through.
        if req.method() == http::Method::OPTIONS {
            let fut = self.inner.call(req);
            return Box::pin(async move {
                let resp = fut.await?;
                Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()))
            });
        }

        // Check for the gatekeeper header.
        let passed = req
            .headers()
            .get(GATEKEEPER_HEADER)
            .and_then(|v| v.to_str().ok())
            .map_or(false, |v| v == GATEKEEPER_VALUE);

        if !passed {
            return Box::pin(async move {
                let resp = gatekeeper_rejected_response();
                Ok(resp.map(|b| {
                    b.map_err(|never: std::convert::Infallible| -> BoxError { match never {} })
                        .boxed_unsync()
                }))
            });
        }

        // Passed — forward to inner service.
        let fut = self.inner.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()))
        })
    }
}

/// Construct a `403 Forbidden` response containing a JSON-RPC error.
fn gatekeeper_rejected_response() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": GATEKEEPER_REJECTED,
            "message": "gatekeeper rejected"
        },
        "id": null
    });

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Full::from(Bytes::from(body.to_string())))
        .expect("static response must build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_correct() {
        assert_eq!(GATEKEEPER_HEADER, "gatekeeper");
        assert_eq!(GATEKEEPER_VALUE, "noble");
        assert_eq!(GATEKEEPER_REJECTED, -32016);
    }

    #[test]
    fn rejected_response_has_403_status() {
        let resp = gatekeeper_rejected_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn rejected_response_has_correct_content_type() {
        let resp = gatekeeper_rejected_response();
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json"
        );
    }

    /// Verify that the Layer produces a Service (compile-time check, mostly).
    #[test]
    fn layer_produces_service() {
        let _layer = GatekeeperLayer;
        // GatekeeperLayer is Copy — verify that trait is derived.
        let _copy = _layer;
    }
}
