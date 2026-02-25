// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! `noble-node status` — quick health check for a running node.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::pidfile;

/// Display node status by checking the PID file and querying the RPC endpoint.
pub fn show_status(rpc: &str, pid_file: &str, totp: Option<&str>) {
    let (pid_status, is_running) = match pidfile::read_pid(pid_file) {
        Ok(Some(pid)) if pidfile::is_running(pid) => (format!("Running (PID {pid})"), true),
        Ok(Some(pid)) => (format!("Stopped (stale PID {pid})"), false),
        Ok(None) => ("Stopped (no PID file)".to_string(), false),
        Err(e) => (format!("Unknown (PID file error: {e})"), false),
    };

    println!("NOBLE Node Status");
    println!("{}", "\u{2550}".repeat(35));
    println!("  Process:       {pid_status}");
    println!("  Version:       {}", noble_core::SOFTWARE_VERSION);

    if !is_running {
        return;
    }

    // Query RPC for live status
    match query_rpc_status(rpc, totp) {
        Ok(info) => {
            if let Some(network) = info.network {
                println!("  Network:       {network}");
            }
            if let Some(height) = info.chain_height {
                println!("  Chain Height:  {}", format_number(height));
            }
            if let Some(peers) = info.peers {
                println!("  Peers:         {peers}");
            }
            if let Some(mempool) = info.mempool {
                println!("  Mempool:       {mempool}");
            }
            if let Some(consensus) = info.consensus {
                println!("  Consensus:     {consensus}");
            }
            if let Some(totp_status) = info.totp_enabled {
                println!(
                    "  TOTP:          {}",
                    if totp_status { "Enabled" } else { "Disabled" }
                );
            }
        }
        Err(e) => {
            println!("  RPC:           Unreachable ({e})");
        }
    }
}

/// Collected status information from RPC calls.
struct StatusInfo {
    network: Option<String>,
    chain_height: Option<u64>,
    peers: Option<String>,
    mempool: Option<String>,
    consensus: Option<String>,
    totp_enabled: Option<bool>,
}

/// Query the JSON-RPC endpoint for node status.
fn query_rpc_status(rpc: &str, totp: Option<&str>) -> Result<StatusInfo, String> {
    let mut info = StatusInfo {
        network: None,
        chain_height: None,
        peers: None,
        mempool: None,
        consensus: None,
        totp_enabled: None,
    };

    // Parse host:port from RPC URL
    let (host, port) = parse_rpc_url(rpc)?;

    // getBlockCount
    if let Ok(resp) = rpc_call(&host, port, "noble_getBlockCount", &[], totp) {
        if let Some(height) = resp.get("result").and_then(|r| r.as_u64()) {
            info.chain_height = Some(height);
        }
    }

    // getNodeInfo — returns network, totp_enabled, etc.
    if let Ok(resp) = rpc_call(&host, port, "noble_getNodeInfo", &[], totp) {
        if let Some(result) = resp.get("result") {
            info.network = result
                .get("network")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            info.totp_enabled = result.get("totp_enabled").and_then(|v| v.as_bool());
        }
    }

    // getNetworkInfo — peer counts
    if let Ok(resp) = rpc_call(&host, port, "noble_getNetworkInfo", &[], totp) {
        if let Some(result) = resp.get("result") {
            let total = result
                .get("peer_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let inbound = result
                .get("inbound_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let outbound = total.saturating_sub(inbound);
            info.peers = Some(format!("{total} ({outbound} out / {inbound} in)"));
        }
    }

    // getMempoolInfo — tx count
    if let Ok(resp) = rpc_call(&host, port, "noble_getMempoolInfo", &[], totp) {
        if let Some(result) = resp.get("result") {
            if let Some(count) = result.get("size").and_then(|v| v.as_u64()) {
                info.mempool = Some(format!("{} transactions", format_number(count)));
            }
        }
    }

    // getCycleStatus — consensus phase
    if let Ok(resp) = rpc_call(&host, port, "noble_getCycleStatus", &[], totp) {
        if let Some(result) = resp.get("result") {
            let phase = result
                .get("phase")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let remaining = result
                .get("remaining_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let mins = remaining / 60;
            let secs = remaining % 60;
            info.consensus = Some(format!("{phase} phase ({mins}:{secs:02} remaining)"));
        }
    }

    Ok(info)
}

/// Parse an RPC URL like `http://127.0.0.1:8783` into (host, port).
fn parse_rpc_url(url: &str) -> Result<(String, u16), String> {
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let (host, port_str) = stripped
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid RPC URL: {url}"))?;

    let port: u16 = port_str
        .trim_end_matches('/')
        .parse()
        .map_err(|_| format!("invalid port in URL: {url}"))?;

    Ok((host.to_string(), port))
}

/// Make a JSON-RPC 2.0 call over raw TCP (avoids pulling in reqwest).
fn rpc_call(
    host: &str,
    port: u16,
    method: &str,
    params: &[serde_json::Value],
    totp: Option<&str>,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let body_str = body.to_string();

    let mut headers = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}:{port}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n",
        body_str.len()
    );

    if let Some(code) = totp {
        headers.push_str(&format!("X-TOTP: {code}\r\n"));
    }
    headers.push_str("\r\n");

    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("invalid address: {e}"))?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("connect failed: {e}"))?;

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    stream
        .write_all(headers.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    stream
        .write_all(body_str.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("read failed: {e}")),
        }
    }

    let response_str = String::from_utf8_lossy(&response);

    // Find the JSON body after HTTP headers (separated by \r\n\r\n)
    let json_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let json_body = &response_str[json_start..];

    serde_json::from_str(json_body).map_err(|e| format!("JSON parse failed: {e}"))
}

/// Format a number with comma separators (e.g. 1247 → "1,247").
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result
}
