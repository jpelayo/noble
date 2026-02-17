// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Tower HTTP middleware for TOTP-based authentication.
//!
//! When a [`TotpValidator`] is configured, every incoming HTTP request must
//! include an `Authorization: Bearer <SHA-256 hex of TOTP code>` header.
//! Invalid or missing credentials receive a JSON-RPC error response with
//! code `-32012 AUTH_REQUIRED`.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use tower::{Layer, Service};

use crate::auth::TotpValidator;
use crate::error::AUTH_REQUIRED;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Tower [`Layer`] that produces [`AuthService`] instances.
#[derive(Clone)]
pub struct AuthLayer {
    validator: Option<Arc<RwLock<TotpValidator>>>,
}

impl AuthLayer {
    /// Create a new auth layer.
    ///
    /// Pass `None` to disable authentication (all requests pass through).
    pub fn new(validator: Option<Arc<RwLock<TotpValidator>>>) -> Self {
        Self { validator }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            validator: self.validator.clone(),
        }
    }
}

/// Tower [`Service`] that checks the `Authorization` header before
/// forwarding requests to the inner service.
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    validator: Option<Arc<RwLock<TotpValidator>>>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AuthService<S>
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
        // If no validator is configured, pass through.
        let Some(validator) = &self.validator else {
            let fut = self.inner.call(req);
            return Box::pin(async move {
                let resp = fut.await?;
                Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()))
            });
        };

        // Extract and validate the Bearer token.
        tracing::debug!(task = "rpc_auth", "authentication attempt");
        let valid = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|hash_hex| {
                validator
                    .read()
                    .map(|v| v.validate_hash(hash_hex))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if valid {
            tracing::info!(task = "rpc_auth", "authentication successful");
            let fut = self.inner.call(req);
            Box::pin(async move {
                let resp = fut.await?;
                Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()))
            })
        } else {
            tracing::warn!(task = "rpc_auth", "authentication failed");
            Box::pin(async move {
                let resp = auth_error_response();
                Ok(resp.map(|b| {
                    b.map_err(|never: std::convert::Infallible| -> BoxError { match never {} })
                        .boxed_unsync()
                }))
            })
        }
    }
}

/// Construct a `401 Unauthorized` response containing a JSON-RPC error.
fn auth_error_response() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": AUTH_REQUIRED,
            "message": "authentication required"
        },
        "id": null
    });

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Full::from(Bytes::from(body.to_string())))
        .expect("static response must build")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_error_response_has_correct_status() {
        let resp = auth_error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn auth_error_response_is_json_rpc() {
        let resp = auth_error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn auth_layer_none_creates_passthrough() {
        let layer = AuthLayer::new(None);
        let _service = layer.layer(DummyService);
    }

    #[test]
    fn auth_layer_some_creates_checking_service() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer = AuthLayer::new(Some(Arc::new(RwLock::new(validator))));
        let _service = layer.layer(DummyService);
    }

    /// Minimal no-op service for layer construction tests.
    #[derive(Clone)]
    struct DummyService;

    impl Service<Request<Full<Bytes>>> for DummyService {
        type Response = Response<Full<Bytes>>;
        type Error = std::convert::Infallible;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Full<Bytes>>) -> Self::Future {
            Box::pin(async { Ok(Response::new(Full::from(Bytes::from_static(b"ok")))) })
        }
    }
}
