// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! `noble-node status` — quick health check for a running node.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::pidfile;

// ---------------------------------------------------------------------------
// TLS client support (no-cert verifier for self-signed certs)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme;
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn make_tls_client_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth()
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

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
}

/// Query the JSON-RPC endpoint for node status.
fn query_rpc_status(rpc: &str, totp: Option<&str>) -> Result<StatusInfo, String> {
    let mut info = StatusInfo {
        network: None,
        chain_height: None,
        peers: None,
        mempool: None,
        consensus: None,
    };

    // Parse host:port and TLS flag from RPC URL
    let (host, port, use_tls) = parse_rpc_url(rpc)?;

    // getBlockCount — returns {height, block_hash}
    if let Ok(resp) = rpc_call(&host, port, "noble_getBlockCount", &[], totp, use_tls) {
        if let Some(result) = resp.get("result") {
            info.chain_height = result.get("height").and_then(|v| v.as_u64());
        }
    }

    // getNodeInfo — returns version, protocol_version, chain_id, uptime_secs, ports.
    // Derive network label from chain_id.
    if let Ok(resp) = rpc_call(&host, port, "noble_getNodeInfo", &[], totp, use_tls) {
        if let Some(result) = resp.get("result") {
            if let Some(chain_id) = result.get("chain_id").and_then(|v| v.as_u64()) {
                let label = match chain_id as u32 {
                    0x4E4F424C => "mainnet",
                    0x4E4F4254 => "testnet",
                    0x4E4F4252 => "regtest",
                    _ => "unknown",
                };
                info.network = Some(label.to_string());
            }
        }
    }

    // getNetworkInfo — returns {peer_count, inbound, outbound}
    if let Ok(resp) = rpc_call(&host, port, "noble_getNetworkInfo", &[], totp, use_tls) {
        if let Some(result) = resp.get("result") {
            let total = result
                .get("peer_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let inbound = result.get("inbound").and_then(|v| v.as_u64()).unwrap_or(0);
            let outbound = result.get("outbound").and_then(|v| v.as_u64()).unwrap_or(0);
            info.peers = Some(format!("{total} ({outbound} out / {inbound} in)"));
        }
    }

    // getMempoolInfo — tx count
    if let Ok(resp) = rpc_call(&host, port, "noble_getMempoolInfo", &[], totp, use_tls) {
        if let Some(result) = resp.get("result") {
            if let Some(count) = result.get("size").and_then(|v| v.as_u64()) {
                info.mempool = Some(format!("{} transactions", format_number(count)));
            }
        }
    }

    // getCycleStatus — returns {cycle_number, phase, phase_index, phase_remaining_secs, cycle_remaining_secs}
    if let Ok(resp) = rpc_call(&host, port, "noble_getCycleStatus", &[], totp, use_tls) {
        if let Some(result) = resp.get("result") {
            let phase = result
                .get("phase")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let remaining = result
                .get("phase_remaining_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let mins = remaining / 60;
            let secs = remaining % 60;
            info.consensus = Some(format!("{phase} phase ({mins}:{secs:02} remaining)"));
        }
    }

    Ok(info)
}

/// Parse an RPC URL like `https://127.0.0.1:8783` or `http://127.0.0.1:8783`
/// into (host, port, use_tls).
fn parse_rpc_url(url: &str) -> Result<(String, u16, bool), String> {
    let (stripped, use_tls) = if let Some(s) = url.strip_prefix("https://") {
        (s, true)
    } else if let Some(s) = url.strip_prefix("http://") {
        (s, false)
    } else {
        (url, false)
    };

    let (host, port_str) = stripped
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid RPC URL: {url}"))?;

    let port: u16 = port_str
        .trim_end_matches('/')
        .parse()
        .map_err(|_| format!("invalid port in URL: {url}"))?;

    Ok((host.to_string(), port, use_tls))
}

/// Make a JSON-RPC 2.0 call over raw TCP or TLS (avoids pulling in reqwest).
fn rpc_call(
    host: &str,
    port: u16,
    method: &str,
    params: &[serde_json::Value],
    totp: Option<&str>,
    use_tls: bool,
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
        // NOBLE API expects Authorization: Bearer <sha256(code)>
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(code.as_bytes());
        let hash_hex = hex::encode(hash);
        headers.push_str(&format!("Authorization: Bearer {hash_hex}\r\n"));
    }
    headers.push_str("\r\n");

    let addr = format!("{host}:{port}");
    let tcp = TcpStream::connect_timeout(
        &addr.parse().map_err(|e| format!("invalid address: {e}"))?,
        Duration::from_secs(5),
    )
    .map_err(|e| format!("connect failed: {e}"))?;

    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let response = if use_tls {
        read_tls_response(tcp, host, headers.as_bytes(), body_str.as_bytes())?
    } else {
        read_plain_response(tcp, headers.as_bytes(), body_str.as_bytes())?
    };

    let response_str = String::from_utf8_lossy(&response);

    // Find the JSON body after HTTP headers (separated by \r\n\r\n)
    let json_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let json_body = &response_str[json_start..];

    serde_json::from_str(json_body).map_err(|e| format!("JSON parse failed: {e}"))
}

fn read_plain_response(
    mut stream: TcpStream,
    headers: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, String> {
    stream
        .write_all(headers)
        .map_err(|e| format!("write failed: {e}"))?;
    stream
        .write_all(body)
        .map_err(|e| format!("write failed: {e}"))?;
    read_all(&mut stream)
}

fn read_tls_response(
    tcp: TcpStream,
    host: &str,
    headers: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, String> {
    let server_name: rustls_pki_types::ServerName<'_> = host
        .try_into()
        .map_err(|e| format!("invalid server name '{host}': {e}"))?;
    let config = Arc::new(make_tls_client_config());
    let conn = rustls::ClientConnection::new(config, server_name.to_owned())
        .map_err(|e| format!("TLS init failed: {e}"))?;
    let mut stream = rustls::StreamOwned::new(conn, tcp);

    stream
        .write_all(headers)
        .map_err(|e| format!("TLS write failed: {e}"))?;
    stream
        .write_all(body)
        .map_err(|e| format!("TLS write failed: {e}"))?;
    read_all(&mut stream)
}

fn read_all<R: Read>(reader: &mut R) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("read failed: {e}")),
        }
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Peers / Consensus commands
// ---------------------------------------------------------------------------

/// Display connected peers by querying the RPC endpoint.
pub fn show_peers(rpc: &str, totp: Option<&str>) {
    let (host, port, use_tls) = match parse_rpc_url(rpc) {
        Ok(hp) => hp,
        Err(e) => {
            eprintln!("Invalid RPC URL: {e}");
            return;
        }
    };

    println!("NOBLE Connected Peers");
    println!("{}", "\u{2550}".repeat(70));

    match rpc_call(&host, port, "noble_getPeerInfo", &[], totp, use_tls) {
        Ok(resp) => {
            if let Some(peers) = resp.get("result").and_then(|r| r.as_array()) {
                if peers.is_empty() {
                    println!("  No peers connected.");
                    return;
                }
                println!("  {:<6} {:<50} {:<8}", "Index", "Peer ID", "Latency");
                println!("  {}", "-".repeat(66));
                for (i, peer) in peers.iter().enumerate() {
                    let peer_id = peer
                        .get("peer_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let display_id = if peer_id.len() > 48 {
                        format!("{}...", &peer_id[..45])
                    } else {
                        peer_id.to_string()
                    };
                    let latency = peer
                        .get("latency_ms")
                        .and_then(|v| v.as_u64())
                        .map(|ms| format!("{ms}ms"))
                        .unwrap_or_else(|| "N/A".to_string());
                    println!("  {:<6} {:<50} {:<8}", i + 1, display_id, latency);
                }
                println!();
                println!("  Total: {} peers", peers.len());
            } else {
                println!("  No peer data available.");
            }
        }
        Err(e) => {
            eprintln!("  RPC error: {e}");
        }
    }
}

/// Display consensus cycle status and validator list.
pub fn show_consensus(rpc: &str, totp: Option<&str>) {
    let (host, port, use_tls) = match parse_rpc_url(rpc) {
        Ok(hp) => hp,
        Err(e) => {
            eprintln!("Invalid RPC URL: {e}");
            return;
        }
    };

    println!("NOBLE Consensus Status");
    println!("{}", "\u{2550}".repeat(60));

    // Cycle status — {cycle_number, phase, phase_index, phase_remaining_secs, cycle_remaining_secs}
    match rpc_call(&host, port, "noble_getCycleStatus", &[], totp, use_tls) {
        Ok(resp) => {
            if let Some(result) = resp.get("result") {
                let cycle = result
                    .get("cycle_number")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let phase = result
                    .get("phase")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let remaining = result
                    .get("phase_remaining_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let mins = remaining / 60;
                let secs = remaining % 60;
                println!("  Cycle:         {}", format_number(cycle));
                println!("  Phase:         {phase}");
                println!("  Remaining:     {mins}:{secs:02}");
            }
        }
        Err(e) => {
            eprintln!("  Cycle status: unavailable ({e})");
        }
    }

    println!();

    // Validator list — returns {selection_policy, validators, count}
    match rpc_call(&host, port, "noble_getValidatorList", &[], totp, use_tls) {
        Ok(resp) => {
            if let Some(validators) = resp
                .get("result")
                .and_then(|r| r.get("validators"))
                .and_then(|v| v.as_array())
            {
                println!("  Validators ({}):", validators.len());
                println!(
                    "  {:<6} {:<40} {:<8} {:<10}",
                    "Index", "Public Key", "Weight", "Reputation"
                );
                println!("  {}", "-".repeat(66));
                for (i, v) in validators.iter().enumerate() {
                    let pubkey = v
                        .get("public_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let display_key = if pubkey.len() > 38 {
                        format!("{}...", &pubkey[..35])
                    } else {
                        pubkey.to_string()
                    };
                    let weight = v.get("weight").and_then(|v| v.as_u64()).unwrap_or(0);
                    let reputation = v
                        .get("reputation_score")
                        .and_then(|v| v.as_f64())
                        .map(|s| format!("{s:.2}"))
                        .unwrap_or_else(|| "N/A".to_string());
                    println!(
                        "  {:<6} {:<40} {:<8} {:<10}",
                        i + 1,
                        display_key,
                        weight,
                        reputation
                    );
                }
            } else {
                println!("  No validator data available.");
            }
        }
        Err(e) => {
            eprintln!("  Validator list: unavailable ({e})");
        }
    }
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
