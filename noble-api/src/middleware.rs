// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Tower HTTP middleware for TOTP-based authentication.
//!
//! When a [`TotpValidator`] is configured, incoming HTTP requests must
//! include an `Authorization: Bearer <SHA-256 hex of TOTP code>` header.
//! Invalid or missing credentials receive a JSON-RPC error response with
//! code `-32012 AUTH_REQUIRED`.
//!
//! Supports three scopes via [`TotpScope`]:
//! - `All`: every request requires authentication (default).
//! - `WriteOnly`: only write/mutation methods require authentication;
//!   read methods (get*, estimate*, lookup*, verify*, validate*) pass through.
//! - `None`: authentication is disabled (equivalent to no validator).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use tower::{Layer, Service};
use tracing::Instrument;

use subtle::ConstantTimeEq;

use crate::auth::TotpValidator;
use crate::error::AUTH_REQUIRED;

/// Try to extract the JSON-RPC "method" field from a body slice.
/// Returns `None` if parsing fails or the field is absent.
fn extract_rpc_method(body: &[u8]) -> Option<String> {
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    val.get("method")?.as_str().map(|s| s.to_string())
}

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// TOTP enforcement scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpScope {
    /// Every request requires authentication.
    All,
    /// Only write/mutation RPC methods require authentication.
    /// Read methods (get*, estimate*, lookup*, verify*, validate*) pass through.
    WriteOnly,
    /// Authentication is disabled.
    None,
}

impl TotpScope {
    /// Parse from config string ("all", "write_only", "none").
    pub fn from_config(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "write_only" | "writeonly" | "write" => Self::WriteOnly,
            "none" | "disabled" | "off" => Self::None,
            _ => Self::All, // default
        }
    }
}

impl std::fmt::Display for TotpScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::WriteOnly => write!(f, "write_only"),
            Self::None => write!(f, "none"),
        }
    }
}

/// Returns `true` if the given JSON-RPC method name is a read-only method
/// that does not require authentication in `WriteOnly` scope.
///
/// Exposed for use by dashboard/client code that needs to determine
/// whether to include auth headers.
pub fn is_read_method(method: &str) -> bool {
    // Strip the "noble_" namespace prefix if present.
    let name = method.strip_prefix("noble_").unwrap_or(method);
    // Trace methods expose sensitive operational data and always require auth,
    // even in WriteOnly scope (AUD4-F1).
    if name.starts_with("getTrace")
        || name.starts_with("setTrace")
        || name.starts_with("clearTrace")
    {
        return false;
    }
    name.starts_with("get")
        || name.starts_with("estimate")
        || name.starts_with("lookup")
        || name.starts_with("verify")
        || name.starts_with("validate")
}

/// Tower [`Layer`] that produces [`AuthService`] instances.
#[derive(Clone)]
pub struct AuthLayer {
    validator: Option<Arc<RwLock<TotpValidator>>>,
    scope: TotpScope,
    /// AUD4-F3: Monotonic counter for per-request correlation IDs.
    next_request_id: Arc<AtomicU64>,
    /// F1: Setup-mode authorization token. When `Some`, write methods require
    /// `Authorization: Bearer <token>` when no TOTP validator is configured.
    setup_token: Option<String>,
}

impl AuthLayer {
    /// Create a new auth layer.
    ///
    /// Pass `None` for `validator` to disable TOTP authentication.
    /// Pass `Some(token)` for `setup_token` to enforce setup-mode write authorization.
    pub fn new(
        validator: Option<Arc<RwLock<TotpValidator>>>,
        scope: TotpScope,
        setup_token: Option<String>,
    ) -> Self {
        Self {
            validator,
            scope,
            next_request_id: Arc::new(AtomicU64::new(1)),
            setup_token,
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            validator: self.validator.clone(),
            scope: self.scope,
            next_request_id: self.next_request_id.clone(),
            setup_token: self.setup_token.clone(),
        }
    }
}

/// Tower [`Service`] that checks the `Authorization` header before
/// forwarding requests to the inner service.
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    validator: Option<Arc<RwLock<TotpValidator>>>,
    scope: TotpScope,
    /// AUD4-F3: Monotonic counter for per-request correlation IDs.
    next_request_id: Arc<AtomicU64>,
    /// F1: Setup-mode authorization token.
    setup_token: Option<String>,
}

/// In `WriteOnly` scope, the middleware must inspect the JSON-RPC method name
/// to distinguish read vs write methods. This requires buffering the request body.
/// The inner service therefore receives `Request<Full<Bytes>>` instead of the
/// original body type. jsonrpsee's server handler is generic over body types
/// that implement `http_body::Body<Data = Bytes>`, so this is transparent.
impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AuthService<S>
where
    S: Service<Request<Full<Bytes>>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Send,
    ReqBody: http_body::Body<Data = Bytes> + Send + 'static,
    ReqBody::Error: Into<BoxError>,
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
        // Clone the inner service so the future owns it (standard tower pattern).
        let mut inner = self.inner.clone();
        std::mem::swap(&mut self.inner, &mut inner);

        let validator = self.validator.clone();
        let scope = self.scope;
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let setup_token = self.setup_token.clone();

        Box::pin(async move {
            // Collect the request body upfront. JSON-RPC payloads are small (< 2 MB
            // by our server limit), so buffering is inexpensive and allows method
            // name inspection for WriteOnly scope enforcement.
            let (parts, body) = req.into_parts();
            let body_bytes = BodyExt::collect(body)
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();

            // AUD4-F3: Extract method name and create a correlation span that
            // propagates request_id + rpc_method through all child log events.
            let rpc_method =
                extract_rpc_method(&body_bytes).unwrap_or_else(|| "unknown".to_string());
            let rpc_span = tracing::info_span!(
                "rpc_request",
                request_id,
                rpc_method = %rpc_method,
            );

            // --- OPTIONS preflight: pass through without auth. ---
            if parts.method == http::Method::OPTIONS {
                let new_req = Request::from_parts(parts, Full::new(body_bytes));
                let resp = inner.call(new_req).instrument(rpc_span).await?;
                return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
            }

            // --- No validator: setup-token check (F1) or pass-through. ---
            let Some(validator) = &validator else {
                if let Some(ref token) = setup_token {
                    // F1: Setup mode — write methods require Bearer token.
                    // WebSocket upgrades are treated as read-only (subscription only).
                    let is_ws = parts
                        .headers
                        .get("upgrade")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("websocket"))
                        .unwrap_or(false);
                    if !is_ws && !is_read_method(&rpc_method) {
                        let provided = parts
                            .headers
                            .get(http::header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .and_then(|s| s.strip_prefix("Bearer "));
                        let valid = provided
                            .map(|p| p.as_bytes().ct_eq(token.as_bytes()).into())
                            .unwrap_or(false);
                        if !valid {
                            tracing::warn!(
                                task = "rpc_auth",
                                method = %rpc_method,
                                "setup mode: write rejected — missing/invalid setup token"
                            );
                            let resp = auth_error_response();
                            return Ok(resp.map(|b| {
                                b.map_err(|never: std::convert::Infallible| -> BoxError {
                                    match never {}
                                })
                                .boxed_unsync()
                            }));
                        }
                    }
                }
                let new_req = Request::from_parts(parts, Full::new(body_bytes));
                let resp = inner.call(new_req).instrument(rpc_span).await?;
                return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
            };
            if scope == TotpScope::None {
                let new_req = Request::from_parts(parts, Full::new(body_bytes));
                let resp = inner.call(new_req).instrument(rpc_span).await?;
                return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
            }

            // --- F3: WebSocket upgrade — auth via ?token= query string. ---
            // Browser WebSocket API cannot set Authorization headers, so TOTP
            // hashes are passed as a query parameter on the upgrade request.
            let is_ws_upgrade = parts
                .headers
                .get("upgrade")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("websocket"))
                .unwrap_or(false);
            if is_ws_upgrade {
                let query_token = parts.uri.query().and_then(|q| {
                    q.split('&').find_map(|seg| seg.strip_prefix("token="))
                });
                if let Some(hash_hex) = query_token {
                    let valid = validator.read().validate_hash(hash_hex);
                    if valid {
                        tracing::info!(task = "rpc_auth", "WS auth via query token successful");
                        let new_req = Request::from_parts(parts, Full::new(body_bytes));
                        let resp = inner.call(new_req).instrument(rpc_span).await?;
                        return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
                    }
                }
                tracing::warn!(task = "rpc_auth", "WS upgrade rejected: missing/invalid query token");
                let resp = auth_error_response();
                return Ok(resp.map(|b| {
                    b.map_err(|never: std::convert::Infallible| -> BoxError { match never {} })
                        .boxed_unsync()
                }));
            }

            // --- WriteOnly scope: inspect method name for headerless requests. ---
            if scope == TotpScope::WriteOnly {
                let has_auth = parts.headers.get(http::header::AUTHORIZATION).is_some();
                if !has_auth {
                    // Use the method name already extracted for the correlation span.
                    let is_read = is_read_method(&rpc_method);

                    if is_read {
                        // Read method without auth header: allow through.
                        let new_req = Request::from_parts(parts, Full::new(body_bytes));
                        let resp = inner.call(new_req).instrument(rpc_span).await?;
                        return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
                    } else {
                        // Write method (or unparseable) without auth: reject.
                        tracing::warn!(
                            task = "rpc_auth",
                            method = %rpc_method,
                            "write method rejected: missing auth in WriteOnly mode"
                        );
                        let resp = auth_error_response();
                        return Ok(resp.map(|b| {
                            b.map_err(|never: std::convert::Infallible| -> BoxError {
                                match never {}
                            })
                            .boxed_unsync()
                        }));
                    }
                }
                // Auth header present in WriteOnly mode — fall through to validation.
            }

            // --- All scope (or WriteOnly with header): validate Bearer token. ---
            tracing::debug!(task = "rpc_auth", "authentication attempt");
            let valid = parts
                .headers
                .get(http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(|hash_hex| validator.read().validate_hash(hash_hex))
                .unwrap_or(false);

            if valid {
                tracing::info!(task = "rpc_auth", "authentication successful");
                let new_req = Request::from_parts(parts, Full::new(body_bytes));
                let resp = inner.call(new_req).instrument(rpc_span).await?;
                Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()))
            } else {
                tracing::warn!(task = "rpc_auth", "authentication failed");
                let resp = auth_error_response();
                Ok(resp.map(|b| {
                    b.map_err(|never: std::convert::Infallible| -> BoxError { match never {} })
                        .boxed_unsync()
                }))
            }
        })
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
        let layer = AuthLayer::new(None, TotpScope::All, None);
        let _service = layer.layer(DummyService);
    }

    #[test]
    fn auth_layer_some_creates_checking_service() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer = AuthLayer::new(Some(Arc::new(RwLock::new(validator))), TotpScope::All, None);
        let _service = layer.layer(DummyService);
    }

    #[test]
    fn totp_scope_from_config_parses_variants() {
        assert_eq!(TotpScope::from_config("all"), TotpScope::All);
        assert_eq!(TotpScope::from_config("write_only"), TotpScope::WriteOnly);
        assert_eq!(TotpScope::from_config("writeonly"), TotpScope::WriteOnly);
        assert_eq!(TotpScope::from_config("write"), TotpScope::WriteOnly);
        assert_eq!(TotpScope::from_config("none"), TotpScope::None);
        assert_eq!(TotpScope::from_config("disabled"), TotpScope::None);
        assert_eq!(TotpScope::from_config("off"), TotpScope::None);
        assert_eq!(TotpScope::from_config("unknown"), TotpScope::All);
        assert_eq!(TotpScope::from_config("ALL"), TotpScope::All);
    }

    #[test]
    fn is_read_method_classification() {
        // Read methods
        assert!(is_read_method("noble_getBlockCount"));
        assert!(is_read_method("noble_getTransaction"));
        assert!(is_read_method("noble_estimateFee"));
        assert!(is_read_method("noble_lookupChecksum"));
        assert!(is_read_method("noble_verifyDocument"));
        assert!(is_read_method("noble_validateAddress"));
        assert!(is_read_method("noble_getGatewayInfo"));
        assert!(is_read_method("noble_getNodeInfo"));
        assert!(is_read_method("noble_getMempoolInfo"));
        assert!(is_read_method("noble_getAllowedIps"));

        // Write methods
        assert!(!is_read_method("noble_submitTransaction"));
        assert!(!is_read_method("noble_walletUnlock"));
        assert!(!is_read_method("noble_walletLock"));
        assert!(!is_read_method("noble_walletSendTransfer"));
        assert!(!is_read_method("noble_createAddress"));
        assert!(!is_read_method("noble_addValidator"));
        assert!(!is_read_method("noble_removeValidator"));
        assert!(!is_read_method("noble_setAllowedIps"));
        assert!(!is_read_method("noble_rotateTotpSecret"));
        assert!(!is_read_method("noble_rotateGatewayKey"));
        assert!(!is_read_method("noble_castVote"));
        assert!(!is_read_method("noble_submitDocumentBatch"));
        assert!(!is_read_method("noble_importMnemonic"));

        // AUD4-F1: Trace methods always require auth (sensitive operational data).
        assert!(!is_read_method("noble_getTraceBuffer"));
        assert!(!is_read_method("noble_getTraceStatus"));
        assert!(!is_read_method("noble_setTraceFilter"));
        assert!(!is_read_method("noble_clearTraceBuffer"));
    }

    #[test]
    fn auth_layer_write_only_scope_propagates() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer =
            AuthLayer::new(Some(Arc::new(RwLock::new(validator))), TotpScope::WriteOnly, None);
        let service = layer.layer(DummyService);
        assert_eq!(service.scope, TotpScope::WriteOnly);
    }

    // F1: Setup token enforced for write methods (async service tests).

    #[tokio::test]
    async fn setup_token_blocks_write_without_auth() {
        let layer = AuthLayer::new(None, TotpScope::All, Some("secret-token".to_string()));
        let mut service = layer.layer(DummyService);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Full::from(Bytes::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"noble_setNodeIdentity","params":{}}"#,
            )))
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn setup_token_allows_write_with_valid_bearer() {
        let layer = AuthLayer::new(None, TotpScope::All, Some("secret-token".to_string()));
        let mut service = layer.layer(DummyService);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header("Authorization", "Bearer secret-token")
            .body(Full::from(Bytes::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"noble_setNodeIdentity","params":{}}"#,
            )))
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn setup_token_allows_read_without_auth() {
        let layer = AuthLayer::new(None, TotpScope::All, Some("secret-token".to_string()));
        let mut service = layer.layer(DummyService);

        let req = Request::builder()
            .method("POST")
            .uri("/")
            .body(Full::from(Bytes::from(
                r#"{"jsonrpc":"2.0","id":1,"method":"noble_getBlockCount","params":{}}"#,
            )))
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // F3: WebSocket upgrade authenticated via ?token= query parameter.

    #[tokio::test]
    async fn ws_upgrade_rejected_without_query_token() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer = AuthLayer::new(
            Some(Arc::new(RwLock::new(validator))),
            TotpScope::All,
            None,
        );
        let mut service = layer.layer(DummyService);

        let req = Request::builder()
            .method("GET")
            .uri("/?no_token=here")
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .body(Full::from(Bytes::new()))
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ws_upgrade_rejected_with_invalid_query_token() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer = AuthLayer::new(
            Some(Arc::new(RwLock::new(validator))),
            TotpScope::All,
            None,
        );
        let mut service = layer.layer(DummyService);

        let req = Request::builder()
            .method("GET")
            .uri("/?token=notavalidhash00000000000000000000000000000000000000000000000000")
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .body(Full::from(Bytes::new()))
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ws_upgrade_allowed_with_valid_query_token() {
        let (validator, base32) = TotpValidator::generate().unwrap();
        // Derive the current TOTP hash using the same secret.
        let totp = totp_rs::TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(base32).to_bytes().unwrap(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();
        let hash = crate::auth::hash_code(&code);

        let layer = AuthLayer::new(
            Some(Arc::new(RwLock::new(validator))),
            TotpScope::All,
            None,
        );
        let mut service = layer.layer(DummyService);

        let req = Request::builder()
            .method("GET")
            .uri(format!("/?token={hash}"))
            .header("upgrade", "websocket")
            .header("connection", "upgrade")
            .body(Full::from(Bytes::new()))
            .unwrap();

        let resp = service.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
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
