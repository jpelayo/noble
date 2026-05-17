// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! IP-based access control middleware for the NOBLE RPC and GUI servers.
//!
//! When a non-empty allow-list is configured, the middleware checks the
//! client's IP against the list and rejects non-matching requests with
//! `403 Forbidden` (JSON-RPC error code `-32015 ACCESS_DENIED`).
//! `127.0.0.1` and `::1` are always allowed regardless of the list.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::RwLock;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use ipnet::IpNet;
use tower::{Layer, Service};

use crate::error::ACCESS_DENIED;

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Parsed IP allow-list with hot-reload support.
///
/// `127.0.0.1` and `::1` are always allowed, even when the list is empty.
/// An empty list means localhost-only (default).
#[derive(Clone)]
pub struct IpFilter {
    inner: Arc<RwLock<Vec<IpNet>>>,
}

impl IpFilter {
    /// Parse an allow-list of IP strings and CIDR blocks.
    ///
    /// Single IPs are promoted to `/32` (IPv4) or `/128` (IPv6).
    pub fn new(allowed: &[String]) -> Result<Self, String> {
        let nets = parse_allow_list(allowed)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(nets)),
        })
    }

    /// Check whether `ip` is allowed.
    ///
    /// Returns `true` for localhost (`127.0.0.1`, `::1`), then checks the
    /// allow-list. If the allow-list is empty, only localhost passes.
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Localhost is always allowed.
        if ip.is_loopback() {
            return true;
        }

        let nets = self.inner.read();

        // Empty list = localhost-only.
        if nets.is_empty() {
            return false;
        }

        nets.iter().any(|net| net.contains(&ip))
    }

    /// Hot-reload the allow-list at runtime.
    pub fn update(&self, new_list: &[String]) -> Result<(), String> {
        let nets = parse_allow_list(new_list)?;
        let mut guard = self.inner.write();
        *guard = nets;
        Ok(())
    }

    /// Return the current allow-list as strings.
    pub fn list(&self) -> Vec<String> {
        let guard = self.inner.read();
        guard.iter().map(|n| n.to_string()).collect()
    }

    /// Create a permissive filter that allows all IP addresses.
    ///
    /// Used when no explicit allow-list is configured so that the
    /// `IpFilterLayer` can always be present in the middleware stack
    /// (avoids Tower `ServiceBuilder` type gymnastics for conditional layers).
    pub fn allow_all() -> Self {
        Self {
            inner: Arc::new(RwLock::new(vec![
                "0.0.0.0/0".parse().unwrap(),
                "::/0".parse().unwrap(),
            ])),
        }
    }

    /// Deny every IP. Fail-safe used by setup mode when allowed_ips
    /// parsing errors mid-bootstrap — better to lock everyone out than
    /// silently fall back to allow-all on bad config.
    pub fn deny_all() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Whether the allow-list is non-empty (remote access enabled).
    pub fn has_remote_access(&self) -> bool {
        let guard = self.inner.read();
        !guard.is_empty()
    }
}

/// Parse a list of IP/CIDR strings into `IpNet` values.
fn parse_allow_list(entries: &[String]) -> Result<Vec<IpNet>, String> {
    let mut nets = Vec::with_capacity(entries.len());
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Try parsing as CIDR first, then as bare IP.
        let net: IpNet = if trimmed.contains('/') {
            trimmed
                .parse()
                .map_err(|e| format!("invalid CIDR '{trimmed}': {e}"))?
        } else {
            let ip: IpAddr = trimmed
                .parse()
                .map_err(|e| format!("invalid IP '{trimmed}': {e}"))?;
            IpNet::from(ip)
        };
        nets.push(net);
    }
    Ok(nets)
}

// ---------------------------------------------------------------------------
// Tower Layer / Service
// ---------------------------------------------------------------------------

/// Tower [`Layer`] that produces [`IpFilterService`] instances.
#[derive(Clone)]
pub struct IpFilterLayer {
    filter: IpFilter,
}

impl IpFilterLayer {
    pub fn new(filter: IpFilter) -> Self {
        Self { filter }
    }
}

impl<S> Layer<S> for IpFilterLayer {
    type Service = IpFilterService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFilterService {
            inner,
            filter: self.filter.clone(),
        }
    }
}

/// Tower [`Service`] that checks the client IP before forwarding requests.
#[derive(Clone)]
pub struct IpFilterService<S> {
    inner: S,
    filter: IpFilter,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for IpFilterService<S>
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
        // Extract client IP from request extensions.
        // Works with hyper's ConnectInfo or a raw SocketAddr extension.
        let client_ip = req
            .extensions()
            .get::<std::net::SocketAddr>()
            .map(|addr| addr.ip());

        // If we can determine the client IP and it's not allowed, reject.
        if let Some(ip) = client_ip {
            if !self.filter.is_allowed(ip) {
                tracing::warn!(task = "ip_filter", ip = %ip, "access denied");
                return Box::pin(async move {
                    let resp = access_denied_response();
                    Ok(resp.map(|b| {
                        b.map_err(|never: std::convert::Infallible| -> BoxError { match never {} })
                            .boxed_unsync()
                    }))
                });
            }
        }

        // Allowed — forward to inner service.
        let fut = self.inner.call(req);
        Box::pin(async move {
            let resp = fut.await?;
            Ok(resp.map(|b| b.map_err(Into::into).boxed_unsync()))
        })
    }
}

/// Construct a `403 Forbidden` response containing a JSON-RPC error.
fn access_denied_response() -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": ACCESS_DENIED,
            "message": "access denied"
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    // T1: 127.0.0.1 always allowed (empty list)
    #[test]
    fn localhost_allowed_empty_list() {
        let filter = IpFilter::new(&[]).unwrap();
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    // T2: 127.0.0.1 always allowed (non-empty list)
    #[test]
    fn localhost_allowed_nonempty_list() {
        let filter = IpFilter::new(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    // T3: ::1 always allowed
    #[test]
    fn ipv6_localhost_allowed() {
        let filter = IpFilter::new(&[]).unwrap();
        assert!(filter.is_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    // T4: Single IP in allow-list passes
    #[test]
    fn single_ip_allowed() {
        let filter = IpFilter::new(&["192.168.1.100".to_string()]).unwrap();
        assert!(filter.is_allowed("192.168.1.100".parse().unwrap()));
    }

    // T5: IP not in allow-list rejected
    #[test]
    fn ip_not_in_list_rejected() {
        let filter = IpFilter::new(&["192.168.1.100".to_string()]).unwrap();
        assert!(!filter.is_allowed("10.0.0.5".parse().unwrap()));
    }

    // T6: CIDR block: IP in range passes
    #[test]
    fn cidr_ip_in_range_allowed() {
        let filter = IpFilter::new(&["192.168.1.0/24".to_string()]).unwrap();
        assert!(filter.is_allowed("192.168.1.42".parse().unwrap()));
        assert!(filter.is_allowed("192.168.1.254".parse().unwrap()));
    }

    // T7: CIDR block: IP outside range rejected
    #[test]
    fn cidr_ip_outside_range_rejected() {
        let filter = IpFilter::new(&["192.168.1.0/24".to_string()]).unwrap();
        assert!(!filter.is_allowed("192.168.2.1".parse().unwrap()));
        assert!(!filter.is_allowed("10.0.0.1".parse().unwrap()));
    }

    // T8: Hot-reload update works
    #[test]
    fn hot_reload_update() {
        let filter = IpFilter::new(&["10.0.0.5".to_string()]).unwrap();
        assert!(filter.is_allowed("10.0.0.5".parse().unwrap()));
        assert!(!filter.is_allowed("10.0.0.6".parse().unwrap()));

        filter.update(&["10.0.0.6".to_string()]).unwrap();
        assert!(!filter.is_allowed("10.0.0.5".parse().unwrap()));
        assert!(filter.is_allowed("10.0.0.6".parse().unwrap()));
    }

    // T9: Invalid CIDR string returns error
    #[test]
    fn invalid_cidr_returns_error() {
        let result = IpFilter::new(&["not-an-ip".to_string()]);
        assert!(result.is_err());

        let result = IpFilter::new(&["192.168.1.0/99".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn empty_string_entries_ignored() {
        let filter = IpFilter::new(&["".to_string(), "  ".to_string()]).unwrap();
        assert!(filter.list().is_empty());
    }

    #[test]
    fn list_returns_current_entries() {
        let filter =
            IpFilter::new(&["192.168.1.0/24".to_string(), "10.0.0.5".to_string()]).unwrap();
        let list = filter.list();
        assert_eq!(list.len(), 2);
        assert!(list[0].contains("192.168.1.0"));
        assert!(list[1].contains("10.0.0.5"));
    }

    #[test]
    fn has_remote_access_reflects_list() {
        let filter = IpFilter::new(&[]).unwrap();
        assert!(!filter.has_remote_access());

        let filter = IpFilter::new(&["10.0.0.0/8".to_string()]).unwrap();
        assert!(filter.has_remote_access());
    }

    #[test]
    fn access_denied_response_has_correct_status() {
        let resp = access_denied_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn non_loopback_rejected_with_empty_list() {
        let filter = IpFilter::new(&[]).unwrap();
        assert!(!filter.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!filter.is_allowed("10.0.0.1".parse().unwrap()));
    }
}
