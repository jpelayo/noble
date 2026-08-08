// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Tower HTTP middleware for TOTP-based authentication.
//!
//! When a [`crate::auth::TotpValidator`] is configured, incoming HTTP requests must
//! include an `Authorization: Bearer <SHA-256 hex of TOTP code>` header.
//! Invalid or missing credentials receive a JSON-RPC error response with
//! code `-32004 AUTH_REQUIRED`.
//!
//! Supports three scopes via [`TotpScope`]:
//! - `All`: every request requires authentication (default).
//! - `WriteOnly`: only write/mutation methods require authentication;
//!   methods in [`READ_METHODS`] pass through without TOTP.
//! - `None`: authentication is disabled (equivalent to no validator).
//!
//! ## Auth policy: default-deny
//!
//! The classification of `WriteOnly` reads is **allowlist-driven**, not
//! prefix-based. A method whose name is not in [`READ_METHODS`] REQUIRES
//! TOTP — including any future `get*` method that hasn't been deliberately
//! classified.
//!
//! [`LEGACY_PUBLIC_METHODS`] is currently empty. It exists as a documented
//! place to register short-window public carve-outs (e.g. for a future
//! migration). Audit follow-up #2 closed the prior carve-out for the
//! faucet legacy RPC handoff: with the default deploy now using local-FS
//! bootstrap, `getFaucetSecret` / `storeFaucetSecret` aren't hit on the
//! happy path, and tightening them to require TOTP is the cleaner posture.
//!
//! To add a new pure-read RPC method, append its name to [`READ_METHODS`]
//! with a one-line justification. The coverage test at the bottom of this
//! module enforces that every registered RPC method is either in the
//! allowlist or write-classified.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

#[cfg(test)]
use parking_lot::RwLock;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use subtle::ConstantTimeEq;
use tower::{Layer, Service};
use tracing::Instrument;

#[cfg(test)]
use crate::auth::TotpValidator;
use crate::error::AUTH_REQUIRED;

/// Try to extract the JSON-RPC "method" field from a body slice.
/// Returns `None` if parsing fails or the field is absent.
fn extract_rpc_method(body: &[u8]) -> Option<String> {
    let val: serde_json::Value = serde_json::from_slice(body).ok()?;
    val.get("method")?.as_str().map(|s| s.to_string())
}

/// JSON-RPC methods that do NOT require TOTP in [`TotpScope::WriteOnly`].
/// Default-deny: a method whose name is not here REQUIRES TOTP, including
/// any future `get*` method. See module docs.
pub static READ_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        // ── Pure reads (return state without mutation) ──────────────────
        "getActivePolls", "getActiveProposals", "getAddressBalance",
        "getAddressHistory", "getAddressPending", "getAddressUtxos",
        "getAllowedIps", "getApiVersion", "getAvailableFaucets",
        "getBadgeHolders", "getBadgeStrategies", "getBlock",
        "getBlockCount", "getBlockHeader", "getBlockRange",
        "getBlockVotes", "getChainStats", "getCheckpoints",
        "getCycleHistory", "getCycleStatus", "getDetectedForks",
        "getDiscoveredBlockchains", "getDocumentHistory",
        "getDocumentsByIssuer", "getDocumentVersions",
        "getEncryptionStatus", "getEvidence", "getEvidenceList",
        "getFinalityStatus", "getForkResolutionStatus",
        "getGatewayInfo", "getLatestBlock", "getMempoolInfo",
        "getMyBadgeStatus", "getNetworkInfo", "getNodeIdentity",
        "getNodeInfo", "getPeerInfo", "getPeerMemory",
        "getPollHistory", "getProposalHistory", "getPruningStatus",
        "getReputationScore", "getRewardAddress", "getSeeds",
        "getSetupStatus", "getStorageConfig", "getStorageInfo",
        "getStoragePaths", "getStorageStats", "getSyncStatus", "getTlsCertInfo",
        // Multi-path sharding read methods (Phase 5):
        "discoverShards", "listShards",
        "getGuiLockStatus",
        "getTlsFingerprint", "getTotpStatus", "getTransaction",
        "getTransactionReceipt", "getTransactionStatus",
        "getValidatorKeyInfo", "getValidatorList", "getVoteTallies",
        "getVotingStrategy", "getWalletInfo", "getWalletSnapshot",
        "getWalletTransactions", "listAddresses", "listBannedPeers",
        "lookupChecksum",
        // ── Estimates / validation (no state change) ────────────────────
        "estimateFee", "validateAddress", "verifyDocument",
        // ── Read-like ops that don't mutate node state ──────────────────
        "checkChainIntegrity",        // pure read, expensive
        "detectExternalIp",           // external probe (no node mutation)
        "searchDocumentsByMetadata",  // pure read
        // NOTE: the following are NOT in READ_METHODS even though their
        // names suggest "read":
        //   • generateMnemonic — persists a secp256k1 key + validator.key
        //   • backupChain — writes a tarball of operator data to disk
        //   • checkDataDir — writes .noble_write_test at caller path
        //   • listDirectory — writes test files in every child dir
        // All four require TOTP (operator-grade ops).
        // ── Public protocol ops (auth via tx signature) ─────────────────
        "submitTransaction",
        "submitDocumentBatch",
    ]
    .iter()
    .copied()
    .collect()
});

/// Empty as of audit follow-up #2. Previously held `getFaucetSecret` and
/// `storeFaucetSecret` during the Group A migration window so legacy
/// faucet binaries (pre-`--node-data-dir`) could bootstrap without TOTP.
/// The migration window was closed early at the auditor's request — the
/// security posture is cleaner without a public-bypass carve-out, and the
/// default deploy uses the local-FS path so the legacy RPC handoff isn't
/// hit anyway.
///
/// The symbol is kept (rather than deleted) so future callers needing a
/// short-window public carve-out have a documented place to register one.
pub static LEGACY_PUBLIC_METHODS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(HashSet::new);

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

/// Returns `true` if the given JSON-RPC method does NOT require TOTP
/// in [`TotpScope::WriteOnly`].
///
/// Allowlist-driven (default-deny): a method passes through TOTP only if
/// its name is in [`READ_METHODS`] or [`LEGACY_PUBLIC_METHODS`]. Any
/// other method — including new `get*` methods that haven't been
/// classified — requires authentication.
///
/// Exposed for use by dashboard/client code that needs to determine
/// whether to include auth headers.
/// Operator/write methods this build recognises.
///
/// Not an authorisation list — classification for metrics only (M13). Write
/// methods are already gated by requiring TOTP for anything absent from
/// [`READ_METHODS`]; naming them here just keeps their latency series instead
/// of collapsing them into `other`.
pub static WRITE_METHODS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "importMnemonic", "importSecp256k1Key", "setConfigValue",
        "uploadTlsCert", "resetChain", "rotateTotpSecret",
        "rotateGatewayKey", "rotateFaucetAdminToken",
        "getFaucetAdminToken", "walletUnlock", "setEncryptionMode",
        "getTraceBuffer", "setTraceFilter", "generateMnemonic",
        "backupChain", "checkDataDir", "listDirectory",
        "setStoragePaths", "reconcileStorage",
    ])
});

/// M13: whether `method` is a name this build knows about.
///
/// Used to bound metrics label cardinality — an unknown name must not mint a
/// permanent time series. Deliberately generous: anything in the read or
/// legacy-public tables, plus anything carrying the `noble_` prefix (those are
/// our own registered methods; a typo'd one still collapses to `other` because
/// it will not be in either table).
pub fn is_known_method(method: &str) -> bool {
    let bare = method.strip_prefix("noble_").unwrap_or(method);
    READ_METHODS.contains(method)
        || READ_METHODS.contains(bare)
        || LEGACY_PUBLIC_METHODS.contains(method)
        || LEGACY_PUBLIC_METHODS.contains(bare)
        || WRITE_METHODS.contains(bare)
}

pub fn is_read_method(method: &str) -> bool {
    let name = method.strip_prefix("noble_").unwrap_or(method);
    READ_METHODS.contains(name) || LEGACY_PUBLIC_METHODS.contains(name)
}

/// HTTP header carrying the GUI admin-lock proxy-trust secret. When the GUI
/// server has validated an admin session, its reverse proxy attaches this header
/// (value = the per-boot secret) so the loopback RPC accepts the request without
/// per-request TOTP — which the GUI session has already superseded. The secret is
/// random per boot and known only in-process, so an external/on-host client
/// cannot forge it, and the GUI proxy builds a fresh outbound request (it never
/// copies an inbound copy through). See `gui_session.rs` / `gui_server.rs`.
pub const GUI_PROXY_AUTH_HEADER: &str = "x-noble-gui-auth";

/// Tower [`Layer`] that produces [`AuthService`] instances.
#[derive(Clone)]
pub struct AuthLayer {
    /// Live, swappable TOTP validator handle (survives runtime enable/rotate).
    totp_slot: crate::state::SharedTotpSlot,
    scope: TotpScope,
    /// Per-boot GUI proxy-trust secret (see [`GUI_PROXY_AUTH_HEADER`]).
    gui_proxy_secret: Arc<String>,
    /// K3-08: one-use WS upgrade tickets.
    ws_tickets: crate::state::WsTicketStore,
    /// K3-08: legacy `?token=` acceptance flag.
    ws_legacy_token: bool,
    /// AUD4-F3: Monotonic counter for per-request correlation IDs.
    next_request_id: Arc<AtomicU64>,
}

impl AuthLayer {
    /// Create a new auth layer.
    ///
    /// The validator is read live from `totp_slot`; a `None` slot value disables
    /// TOTP authentication. `gui_proxy_secret` is the GUI admin-lock bridge secret.
    pub fn new(
        totp_slot: crate::state::SharedTotpSlot,
        scope: TotpScope,
        gui_proxy_secret: Arc<String>,
        ws_tickets: crate::state::WsTicketStore,
        ws_legacy_token: bool,
    ) -> Self {
        Self {
            totp_slot,
            scope,
            gui_proxy_secret,
            ws_tickets,
            ws_legacy_token,
            next_request_id: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            totp_slot: self.totp_slot.clone(),
            scope: self.scope,
            gui_proxy_secret: self.gui_proxy_secret.clone(),
            ws_tickets: self.ws_tickets.clone(),
            ws_legacy_token: self.ws_legacy_token,
            next_request_id: self.next_request_id.clone(),
        }
    }
}

/// Tower [`Service`] that checks the `Authorization` header before
/// forwarding requests to the inner service.
#[derive(Clone)]
pub struct AuthService<S> {
    inner: S,
    totp_slot: crate::state::SharedTotpSlot,
    scope: TotpScope,
    gui_proxy_secret: Arc<String>,
    ws_tickets: crate::state::WsTicketStore,
    ws_legacy_token: bool,
    /// AUD4-F3: Monotonic counter for per-request correlation IDs.
    next_request_id: Arc<AtomicU64>,
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

        // Read the validator live from the shared slot so runtime enable/rotate
        // take effect without a restart.
        let validator = self.totp_slot.read().clone();
        let scope = self.scope;
        let gui_proxy_secret = self.gui_proxy_secret.clone();
        let ws_tickets = self.ws_tickets.clone();
        let ws_legacy_token = self.ws_legacy_token;
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);

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

            // --- GUI admin-lock proxy bridge: a request bearing the per-boot
            // secret was vouched for by the in-process GUI reverse proxy AFTER
            // it validated an admin session, so it is authenticated and bypasses
            // per-request TOTP. The secret is high-entropy and never exposed to
            // clients; the proxy builds a fresh outbound request and only sets
            // this header when authenticated, so it cannot be forged. ---
            if let Some(hdr) = parts.headers.get(GUI_PROXY_AUTH_HEADER) {
                let provided = hdr.as_bytes();
                let expected = gui_proxy_secret.as_bytes();
                if !expected.is_empty()
                    && provided.len() == expected.len()
                    && bool::from(provided.ct_eq(expected))
                {
                    tracing::debug!(task = "rpc_auth", "authenticated via GUI session proxy bridge");
                    let new_req = Request::from_parts(parts, Full::new(body_bytes));
                    let resp = inner.call(new_req).instrument(rpc_span).await?;
                    return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
                }
            }

            // --- No validator: pass through without auth. ---
            let Some(validator) = &validator else {
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
                // K3-08: preferred WS auth — a one-use ticket issued over the
                // authenticated HTTP channel (noble_issueWsTicket). Consumed
                // atomically here: found → removed → single use by design.
                let query_ticket = parts.uri.query().and_then(|q| {
                    q.split('&').find_map(|seg| seg.strip_prefix("ticket="))
                });
                if let Some(ticket) = query_ticket {
                    let now = std::time::Instant::now();
                    let consumed = {
                        let mut tickets = ws_tickets.lock();
                        // Expire first (30s TTL), then consume on match.
                        tickets.retain(|(_, at)| now.duration_since(*at).as_secs() < 30);
                        if let Some(pos) = tickets.iter().position(|(t, _)| t == ticket) {
                            tickets.remove(pos);
                            true
                        } else {
                            false
                        }
                    };
                    if consumed {
                        tracing::info!(task = "rpc_auth", "WS auth via one-use ticket successful");
                        let new_req = Request::from_parts(parts, Full::new(body_bytes));
                        let resp = inner.call(new_req).instrument(rpc_span).await?;
                        return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
                    }
                    tracing::warn!(task = "rpc_auth", "WS upgrade rejected: unknown/expired/reused ticket");
                    let resp = auth_error_response();
                    return Ok(resp.map(|b| {
                        b.map_err(|never: std::convert::Infallible| -> BoxError { match never {} })
                            .boxed_unsync()
                    }));
                }
                // Legacy `?token=<sha256(TOTP)>` — deprecated (K3-08): the
                // hash is credential material in a URL that histories and
                // intermediary logs retain. Accepted only while the
                // `ws_legacy_token` flag is on.
                let query_token = parts.uri.query().and_then(|q| {
                    q.split('&').find_map(|seg| seg.strip_prefix("token="))
                });
                if ws_legacy_token {
                    if let Some(hash_hex) = query_token {
                        let valid = validator.read().validate_hash(hash_hex);
                        if valid {
                            tracing::info!(
                                task = "rpc_auth",
                                "WS auth via legacy query token successful (deprecated — migrate to noble_issueWsTicket)"
                            );
                            let new_req = Request::from_parts(parts, Full::new(body_bytes));
                            let resp = inner.call(new_req).instrument(rpc_span).await?;
                            return Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()));
                        }
                    }
                }
                tracing::warn!(task = "rpc_auth", "WS upgrade rejected: missing/invalid ticket or token");
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

    /// Build a `SharedTotpSlot` from an optional validator for tests.
    fn test_slot(validator: Option<TotpValidator>) -> crate::state::SharedTotpSlot {
        Arc::new(RwLock::new(validator.map(|v| Arc::new(RwLock::new(v)))))
    }
    /// Empty GUI proxy secret = bridge disabled (the default for TOTP tests).
    fn no_gui_secret() -> Arc<String> {
        Arc::new(String::new())
    }

    #[test]
    fn auth_error_response_has_correct_status() {
        let resp = auth_error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Total RPC method roster — hand-maintained ground truth used by the
    /// coverage test below. Bumping the live trait method count requires
    /// adding the new name here AND classifying it in `READ_METHODS`,
    /// `LEGACY_PUBLIC_METHODS`, or leaving it out (write-classified).
    ///
    /// 127 entries as of 0.117 (sharding RPCs added). If
    /// `RpcModule::method_names` reports a different count at runtime,
    /// that's the signal to update.
    const ALL_RPC_METHODS: &[&str] = &[
        "addSeed", "addValidator", "backupChain", "banPeer", "castVote",
        "checkChainIntegrity", "checkDataDir", "clearTraceBuffer",
        "createAddress", "createPoll", "deleteAddress", "detectExternalIp",
        "dialPeer", "enableTotp", "estimateFee", "generateMnemonic",
        "getActivePolls", "getActiveProposals", "getAddressBalance",
        "getAddressHistory", "getAddressPending", "getAddressUtxos",
        "getAllowedIps", "getApiVersion", "getAvailableFaucets",
        "getBadgeHolders", "getBadgeStrategies", "getBlock",
        "getBlockCount", "getBlockHeader", "getBlockRange",
        "getBlockVotes", "getChainStats", "getCheckpoints",
        "getCycleHistory", "getCycleStatus", "getDetectedForks",
        "getDiscoveredBlockchains", "getDocumentHistory",
        "getDocumentsByIssuer", "getDocumentVersions",
        "getEncryptionStatus", "getEvidence", "getEvidenceList",
        "getFaucetAdminToken", "getFinalityStatus",
        "getForkResolutionStatus", "getGatewayInfo", "getGuiLockStatus",
        "getLatestBlock",
        "getMempoolInfo", "getMyBadgeStatus", "getNetworkInfo",
        "getNodeIdentity", "getNodeInfo", "getPeerInfo", "getPeerMemory",
        "getPollHistory", "getProposalHistory", "getPruningStatus",
        "getReputationScore", "getRewardAddress", "getSeeds",
        "getSetupStatus", "getStorageConfig", "getStorageInfo",
        "getStorageStats", "getSyncStatus", "getTlsCertInfo",
        "getTlsFingerprint", "getTotpStatus", "getTraceBuffer",
        "getTraceStatus", "getTransaction", "getTransactionReceipt",
        "getTransactionStatus", "getValidatorKeyInfo", "getValidatorList",
        "getVoteTallies", "getVotingStrategy", "getWalletInfo",
        "getWalletSnapshot", "getWalletTransactions", "importMnemonic",
        "importSecp256k1Key", "listAddresses", "listBannedPeers",
        "listDirectory", "lookupChecksum", "proposeBadge",
        "pruneStalePeers", "regenerateTlsCert", "removePeerRecord",
        "removeSeed", "removeValidator", "resetChain", "resetFaucetLimits",
        "rotateFaucetAdminToken", "rotateGatewayKey", "rotateTotpSecret",
        "searchDocumentsByMetadata", "setAllowedIps",
        "setBadgeApprovalStrategy", "setBadgeRevocationStrategy",
        "setConfigValue", "setEncryptionMode", "setNodeIdentity",
        "setRewardAddress", "setStorageConfig", "setStoragePaths",
        "setTraceFilter", "setValidatorOrder", "setVotingStrategy",
        "submitDocumentBatch", "submitTransaction", "unbanPeer",
        "uploadTlsCert", "validateAddress", "verifyDocument",
        "voteBadgeProposal", "votePoll", "walletLock",
        "walletSendTransfer", "walletUnlock",
        // Multi-path sharding (Phase 5):
        "discoverShards", "listShards", "reconcileStorage",
        "getStoragePaths",
    ];

    /// Allowlist-policy coverage test. Every method registered with the
    /// RPC server must be deliberately classified — either passing through
    /// without TOTP (`READ_METHODS`), legacy-grandfathered during the
    /// faucet local-FS migration (`LEGACY_PUBLIC_METHODS`), or treated as
    /// write (NOT in either set, so requires TOTP by default-deny).
    ///
    /// This test exists to catch the case where someone adds a new RPC
    /// method without thinking about its auth classification. Add the
    /// method to `ALL_RPC_METHODS`, then either add it to `READ_METHODS`
    /// or accept the write-classification and the test passes.
    #[test]
    fn every_rpc_method_is_classified() {
        let mut unclassified = Vec::new();
        let mut writes = Vec::new();
        for &name in ALL_RPC_METHODS {
            let in_reads = READ_METHODS.contains(name);
            let in_legacy = LEGACY_PUBLIC_METHODS.contains(name);
            if !in_reads && !in_legacy {
                // Write-classified — the default. We collect them for the
                // human-readable summary below but don't fail.
                writes.push(name);
            } else if in_reads && in_legacy {
                unclassified.push((name, "in BOTH read and legacy sets"));
            }
        }

        for (name, why) in &unclassified {
            eprintln!("[middleware coverage] {name}: {why}");
        }
        assert!(
            unclassified.is_empty(),
            "{} method(s) are double-classified — see stderr",
            unclassified.len()
        );

        // Sanity check: the size of the manual roster matches expectations.
        // If a new method was registered without updating ALL_RPC_METHODS,
        // someone will hit a 401 in production. This catches drift at test
        // time. Count bumped to 127 in 0.117 (sharding: +5 methods —
        // getStoragePaths, setStoragePaths, discoverShards, listShards,
        // reconcileStorage).
        assert_eq!(
            ALL_RPC_METHODS.len(),
            128,
            "ALL_RPC_METHODS drifted from the 128 registered RPC methods — \
             update the roster and classify any new methods in READ_METHODS \
             (read) or leave them out (write-classified, require TOTP)"
        );

        // For visibility — print the write classification summary on test run.
        eprintln!(
            "[middleware coverage] {} reads, {} legacy, {} writes (total {})",
            READ_METHODS.len(),
            LEGACY_PUBLIC_METHODS.len(),
            writes.len(),
            ALL_RPC_METHODS.len()
        );
    }

    #[test]
    fn allowlist_has_no_duplicate_classification() {
        for read in READ_METHODS.iter() {
            assert!(
                !LEGACY_PUBLIC_METHODS.contains(read),
                "method {read} is in BOTH READ_METHODS and LEGACY_PUBLIC_METHODS"
            );
        }
    }

    #[test]
    fn sensitive_methods_require_totp() {
        // Explicit verification of the most-sensitive methods. If anyone
        // accidentally adds these to READ_METHODS, this test fails loudly.
        for sensitive in [
            "importMnemonic", "importSecp256k1Key", "setConfigValue",
            "uploadTlsCert", "resetChain", "rotateTotpSecret",
            "rotateGatewayKey", "rotateFaucetAdminToken",
            "getFaucetAdminToken", "walletUnlock", "setEncryptionMode",
            "getTraceBuffer", "setTraceFilter",
            // Audit follow-up #1: generateMnemonic creates AND persists a
            // secp256k1 key + writes validator.key. Never a read.
            "generateMnemonic",
            // Open-node hardening: operator-grade ops that touch the host
            // filesystem or export operator-only data. Never bypass TOTP.
            "backupChain",      // tarballs operator data to disk
            "checkDataDir",     // writes test file at caller path
            "listDirectory",    // writes test files in every child dir
            // Multi-path sharding (Phase 5): writes that mutate
            // operator's storage layout or refresh on-disk catalogs.
            "setStoragePaths",  // persists noble.toml + restart required
            "reconcileStorage", // rewrites catalogs across every tier
        ] {
            assert!(
                !is_read_method(sensitive),
                "{sensitive} must require TOTP — never add to READ_METHODS"
            );
        }
    }

    #[test]
    fn public_protocol_methods_are_classified_read() {
        // Transactions carry their own signature — public by design.
        assert!(is_read_method("submitTransaction"));
        assert!(is_read_method("submitDocumentBatch"));
        // The `noble_` prefix variant is also accepted.
        assert!(is_read_method("noble_submitTransaction"));
    }

    #[test]
    fn legacy_faucet_methods_gone() {
        // Open-node hardening: getFaucetSecret + storeFaucetSecret were
        // deleted entirely. Default deploy uses local-FS bootstrap, which
        // never called them. The methods being absent from the roster is
        // the canonical assertion here.
        assert!(
            !ALL_RPC_METHODS.contains(&"getFaucetSecret"),
            "getFaucetSecret must be removed from the roster"
        );
        assert!(
            !ALL_RPC_METHODS.contains(&"storeFaucetSecret"),
            "storeFaucetSecret must be removed from the roster"
        );
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
        let layer = AuthLayer::new(test_slot(None), TotpScope::All, no_gui_secret(), std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())), true);
        let _service = layer.layer(DummyService);
    }

    #[test]
    fn auth_layer_some_creates_checking_service() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer = AuthLayer::new(test_slot(Some(validator)), TotpScope::All, no_gui_secret(), std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())), true);
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

        // Public protocol operations (no TOTP — tx carries its own signature)
        assert!(is_read_method("noble_submitTransaction"));
        assert!(is_read_method("noble_submitDocumentBatch"));

        // Write methods (require TOTP in WriteOnly mode)
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
            AuthLayer::new(test_slot(Some(validator)), TotpScope::WriteOnly, no_gui_secret(), std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())), true);
        let service = layer.layer(DummyService);
        assert_eq!(service.scope, TotpScope::WriteOnly);
    }

    // F3: WebSocket upgrade authenticated via ?token= query parameter.

    #[tokio::test]
    async fn ws_upgrade_rejected_without_query_token() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let layer = AuthLayer::new(
            test_slot(Some(validator)),
            TotpScope::All,
            no_gui_secret(),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            true,
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
            test_slot(Some(validator)),
            TotpScope::All,
            no_gui_secret(),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            true,
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
            test_slot(Some(validator)),
            TotpScope::All,
            no_gui_secret(),
            std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())),
            true,
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

    #[tokio::test]
    async fn gui_proxy_bridge_secret_bypasses_totp_under_scope_all() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let secret = Arc::new("per-boot-secret-abc123".to_string());
        let layer = AuthLayer::new(test_slot(Some(validator)), TotpScope::All, secret.clone(), std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())), true);
        let mut service = layer.layer(DummyService);

        // No Authorization header — only the in-process proxy-trust secret.
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header(GUI_PROXY_AUTH_HEADER, secret.as_str())
            .body(Full::from(Bytes::from_static(b"{\"method\":\"noble_getBlockCount\"}")))
            .unwrap();
        let resp = service.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a request bearing the per-boot proxy secret must bypass TOTP"
        );
    }

    #[tokio::test]
    async fn gui_proxy_bridge_forged_secret_is_rejected() {
        let (validator, _) = TotpValidator::generate().unwrap();
        let secret = Arc::new("per-boot-secret-abc123".to_string());
        let layer = AuthLayer::new(test_slot(Some(validator)), TotpScope::All, secret, std::sync::Arc::new(parking_lot::Mutex::new(Vec::new())), true);
        let mut service = layer.layer(DummyService);

        // A client-supplied (forged) marker that does NOT equal the per-boot
        // secret must NOT bypass auth — it falls through to TOTP and is rejected.
        let req = Request::builder()
            .method("POST")
            .uri("/")
            .header(GUI_PROXY_AUTH_HEADER, "not-the-secret")
            .body(Full::from(Bytes::from_static(b"{\"method\":\"noble_getBlockCount\"}")))
            .unwrap();
        let resp = service.call(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "a forged proxy secret must not bypass auth"
        );
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
