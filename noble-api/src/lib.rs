// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 server with WebSocket subscriptions for the NOBLE protocol.

pub mod auth;
pub mod error;
pub mod gatekeeper;
pub mod ip_filter;
pub mod middleware;
pub mod rate_limit;
pub mod rpc_metrics;
pub mod state;
pub mod trace_types;
pub mod types;

pub mod methods;
pub mod server;

pub use error::ApiError;
pub use rate_limit::RpcRateLimiter;
pub use server::{start_server, ServerHandles};
pub use state::{ApiState, NetworkStats, NodeIdentityData, resolve_node_name};

/// API version string, included in the `X-Noble-API-Version` response header
/// and returned by `noble_getApiVersion`.
pub const API_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Number of registered RPC methods (excluding subscriptions).
pub const API_METHOD_COUNT: u32 = 67;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_version_is_semver_like() {
        assert!(!API_VERSION.is_empty());
        assert!(
            API_VERSION.contains('.'),
            "API version should contain a dot"
        );
    }

    #[test]
    fn api_method_count_is_reasonable() {
        // We have 60 RPC methods registered; guard against accidental reset.
        assert!(API_METHOD_COUNT >= 67, "expected at least 67 RPC methods");
    }
}
