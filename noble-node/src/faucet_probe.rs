// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Faucet peer discovery via active probing.
//!
//! Periodically probes connected peers' faucet status endpoints
//! (`GET http://<ip>:<port>/api/faucet/status`). Results are cached
//! and served via `noble_getAvailableFaucets` RPC.
//!
//! Configurable via `[faucet]` section in noble.toml.
//! Set `discovery_enabled = false` to disable entirely.

use noble_api::types::{FaucetCache, FaucetEntry};
use std::time::{SystemTime, UNIX_EPOCH};

/// Create an empty faucet cache.
pub fn new_cache() -> FaucetCache {
    std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()))
}

/// Probe a single peer's faucet endpoint.
///
/// Returns `Some(entry)` if the faucet is reachable and responds with valid JSON.
/// Returns `None` on any error (timeout, connection refused, bad JSON).
pub fn probe_faucet(ip: &str, port: u16) -> Option<FaucetEntry> {
    let url = format!("http://{}:{}/api/faucet/status", ip, port);

    let response = match ureq::get(&url)
        .timeout(std::time::Duration::from_secs(5))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::trace!("faucet probe {ip}:{port}: {e}");
            return None;
        }
    };

    let body = match response.into_string() {
        Ok(b) => b,
        Err(e) => {
            tracing::trace!("faucet probe {ip}:{port} body read: {e}");
            return None;
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(j) => j,
        Err(e) => {
            tracing::trace!("faucet probe {ip}:{port} JSON parse: {e}");
            return None;
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Some(FaucetEntry {
        url: format!("http://{}:{}", ip, port),
        faucet_address: json.get("faucet_address")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        faucet_balance: json.get("faucet_balance")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        drip_amount: json.get("drip_amount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        network: json.get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        last_probed: now,
    })
}

/// Probe all given peer IPs and update the cache.
///
/// Replaces the entire cache with fresh results. Peers that don't respond
/// are excluded. Also probes localhost if `include_local` is true.
pub fn probe_all(peer_ips: &[String], port: u16, include_local: bool, cache: &FaucetCache) {
    let mut results = Vec::new();

    // Probe localhost first
    if include_local {
        if let Some(entry) = probe_faucet("127.0.0.1", port) {
            tracing::debug!("faucet discovery: local faucet found at 127.0.0.1:{port}");
            results.push(entry);
        }
    }

    // Probe each peer
    for ip in peer_ips {
        if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
            continue; // already probed locally
        }
        match probe_faucet(ip, port) {
            Some(entry) => {
                tracing::debug!("faucet discovery: faucet found at {ip}:{port}");
                results.push(entry);
            }
            None => {
                tracing::trace!("faucet discovery: no faucet at {ip}:{port}");
            }
        }
    }

    tracing::info!(
        "faucet discovery: found {} faucet(s) across {} peer(s)",
        results.len(),
        peer_ips.len()
    );

    *cache.lock() = results;
}

/// Extract IP addresses from a list of libp2p multiaddrs.
///
/// Parses `/ip4/1.2.3.4/...` and `/ip6/::1/...` patterns.
pub fn extract_peer_ips(multiaddrs: &[String]) -> Vec<String> {
    let mut ips = Vec::new();
    for ma in multiaddrs {
        // Match /ip4/X.X.X.X or /ip6/X:X:X
        let parts: Vec<&str> = ma.split('/').collect();
        for (i, part) in parts.iter().enumerate() {
            if (*part == "ip4" || *part == "ip6") && i + 1 < parts.len() {
                ips.push(parts[i + 1].to_string());
                break;
            }
        }
    }
    ips.sort();
    ips.dedup();
    ips
}
