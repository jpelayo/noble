// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Per-connection tower layer that injects the connection's peer
//! `SocketAddr` into request extensions.
//!
//! The plain-HTTP path uses jsonrpsee's default [`Server::builder()`]
//! which goes through hyper, and hyper's `ConnectInfo` already populates
//! request extensions with the peer address. The TLS path uses a
//! custom accept loop (see [`crate::server::start_single_server`]) that
//! wraps the raw socket in `tokio_rustls::TlsAcceptor` and passes the
//! result to `jsonrpsee::server::serve_with_graceful_shutdown` — that
//! path does NOT inject a peer address.
//!
//! Without the address, [`crate::ip_filter::IpFilterLayer`] and
//! [`crate::rate_limit::RateLimitLayer`] silently pass every request
//! through, defeating the configured allowlist and rate limits over
//! TLS. This layer closes that gap by wrapping the per-connection
//! service and inserting the captured peer address on every request.

use std::net::SocketAddr;
use std::task::{Context, Poll};

use http::Request;
use tower::{Layer, Service};

/// Per-connection layer carrying the peer `SocketAddr`.
#[derive(Clone)]
pub struct PeerAddrLayer {
    addr: SocketAddr,
}

impl PeerAddrLayer {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl<S> Layer<S> for PeerAddrLayer {
    type Service = PeerAddrService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        PeerAddrService { inner, addr: self.addr }
    }
}

/// Service produced by [`PeerAddrLayer`]. Inserts the captured peer
/// `SocketAddr` into request extensions before forwarding.
#[derive(Clone)]
pub struct PeerAddrService<S> {
    inner: S,
    addr: SocketAddr,
}

impl<S, ReqBody> Service<Request<ReqBody>> for PeerAddrService<S>
where
    S: Service<Request<ReqBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        req.extensions_mut().insert(self.addr);
        self.inner.call(req)
    }
}
