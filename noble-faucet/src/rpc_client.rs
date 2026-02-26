// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Minimal JSON-RPC client for communicating with the NOBLE node.
//!
//! **Security hardening:**
//! - Connect/read/write timeouts (10s each) prevent indefinite hangs.
//! - Response size capped at 2 MB to prevent unbounded memory allocation.
//! - Only `http://` URLs are accepted; `https://` is rejected (no TLS in raw TCP).
//! - Optional TOTP bearer auth: client SHA-256 hashes the code before sending.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::FaucetError;

/// Maximum HTTP response size (2 MB). Prevents unbounded memory growth.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Timeout for TCP connect, read, and write operations.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Lightweight JSON-RPC 2.0 client over HTTP.
#[derive(Debug)]
pub struct NodeRpcClient {
    url: String,
    next_id: AtomicU64,
    /// Optional TOTP code for authenticated RPC calls.
    /// Stored as raw 6-digit code; hashed to SHA-256 before sending.
    totp_code: Option<String>,
}

#[derive(Serialize)]
struct RpcRequest<'a, P: Serialize> {
    jsonrpc: &'a str,
    method: &'a str,
    params: P,
    id: u64,
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
    #[allow(dead_code)]
    id: u64,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
pub struct TransferResult {
    pub tx_id: String,
}

#[derive(Deserialize)]
pub struct WalletInfoResult {
    pub key_count: u64,
    pub locked: bool,
    pub addresses: Vec<AddressEntry>,
}

#[derive(Deserialize)]
pub struct AddressEntry {
    pub public_key: String,
    pub scheme_id: u8,
}

#[derive(Deserialize)]
pub struct BalanceResult {
    pub balance: u64,
    pub available: u64,
    pub pending: u64,
    pub tx_count: u64,
}

#[derive(Deserialize)]
pub struct NodeInfoResult {
    pub chain_id: u64,
    #[serde(default)]
    pub network_label: String,
}

impl NodeRpcClient {
    /// Create a new RPC client.
    ///
    /// # Errors
    ///
    /// Returns `FaucetError::Config` if the URL uses `https://` (not supported).
    pub fn new(url: &str, totp_code: Option<String>) -> Result<Self, FaucetError> {
        if url.starts_with("https://") {
            return Err(FaucetError::Config(
                "https:// URLs are not supported (raw TCP client has no TLS). Use http://.".into(),
            ));
        }
        Ok(Self {
            url: url.to_string(),
            next_id: AtomicU64::new(1),
            totp_code,
        })
    }

    /// Send NOBLE tokens from the faucet wallet to the target address.
    pub async fn send_transfer(
        &self,
        from: &str,
        to: &str,
        amount: u64,
    ) -> Result<String, FaucetError> {
        #[derive(Serialize)]
        struct Params<'a> {
            from: &'a str,
            to: &'a str,
            amount: u64,
        }
        let params = Params { from, to, amount };
        let resp: TransferResult = self.call("noble_walletSendTransfer", &params).await?;
        Ok(resp.tx_id)
    }

    /// Get wallet info to check for available faucet address.
    pub async fn get_wallet_info(&self) -> Result<WalletInfoResult, FaucetError> {
        self.call("noble_getWalletInfo", &serde_json::Value::Null)
            .await
    }

    /// Get node info to detect the connected network.
    pub async fn get_node_info(&self) -> Result<NodeInfoResult, FaucetError> {
        self.call("noble_getNodeInfo", &serde_json::Value::Null)
            .await
    }

    /// Get balance for an address.
    pub async fn get_balance(&self, address: &str) -> Result<BalanceResult, FaucetError> {
        #[derive(Serialize)]
        struct Params<'a> {
            public_key: &'a str,
        }
        self.call(
            "noble_getAddressBalance",
            &Params {
                public_key: address,
            },
        )
        .await
    }

    async fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: &P,
    ) -> Result<R, FaucetError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let req = RpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };
        let body =
            serde_json::to_vec(&req).map_err(|e| FaucetError::Rpc(format!("serialize: {e}")))?;

        // Parse URL — only http:// is accepted (https:// rejected in constructor).
        let stripped = self.url.strip_prefix("http://").unwrap_or(&self.url);
        let (host_port, path) = match stripped.find('/') {
            Some(i) => (&stripped[..i], &stripped[i..]),
            None => (stripped, "/"),
        };
        let (host, port) = match host_port.rfind(':') {
            Some(i) => (
                &host_port[..i],
                host_port[i + 1..].parse::<u16>().unwrap_or(8783),
            ),
            None => (host_port, 8783),
        };
        let addr = format!("{host}:{port}");

        // Connect with timeout.
        let stream = tokio::time::timeout(RPC_TIMEOUT, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| FaucetError::Rpc(format!("connect timeout ({RPC_TIMEOUT:?})")))?
            .map_err(|e| FaucetError::Rpc(format!("connect: {e}")))?;
        let (reader, mut writer) = tokio::io::split(stream);

        // Build HTTP request with optional TOTP bearer auth.
        use tokio::io::AsyncWriteExt;
        let mut http_req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        if let Some(ref code) = self.totp_code {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(code.as_bytes());
            let hash_hex = hex::encode(hash);
            http_req.push_str(&format!("Authorization: Bearer {hash_hex}\r\n"));
        }
        http_req.push_str("\r\n");

        // Write with timeout.
        tokio::time::timeout(RPC_TIMEOUT, async {
            writer.write_all(http_req.as_bytes()).await?;
            writer.write_all(&body).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| FaucetError::Rpc(format!("write timeout ({RPC_TIMEOUT:?})")))?
        .map_err(|e| FaucetError::Rpc(format!("write: {e}")))?;

        // Read with timeout and size cap.
        use tokio::io::AsyncReadExt;
        let buf = tokio::time::timeout(RPC_TIMEOUT, async {
            let mut buf = Vec::new();
            let mut reader = tokio::io::BufReader::new(reader);
            let mut chunk = [0u8; 8192];
            loop {
                let n = reader.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESPONSE_BYTES {
                    return Err(std::io::Error::other(format!(
                        "response exceeds {MAX_RESPONSE_BYTES} byte limit"
                    )));
                }
            }
            Ok::<_, std::io::Error>(buf)
        })
        .await
        .map_err(|_| FaucetError::Rpc(format!("read timeout ({RPC_TIMEOUT:?})")))?
        .map_err(|e| FaucetError::Rpc(format!("read: {e}")))?;

        let response_str = String::from_utf8_lossy(&buf);

        // Parse HTTP response: find header/body separator, validate status line.
        let header_end = response_str.find("\r\n\r\n").ok_or_else(|| {
            FaucetError::Rpc("malformed HTTP response: no header/body separator".into())
        })?;
        let headers = &response_str[..header_end];
        let json_body = &response_str[header_end + 4..];

        // Validate HTTP status line.
        if let Some(status_line) = headers.lines().next() {
            if !status_line.contains("200") && !status_line.contains("401") {
                // Allow 200 OK and 401 Unauthorized (auth errors are JSON-RPC errors).
                tracing::warn!(status = status_line, "non-200 HTTP status from node");
            }
        }

        let resp: RpcResponse<R> = serde_json::from_str(json_body)
            .map_err(|e| FaucetError::Rpc(format!("deserialize: {e}")))?;

        if let Some(err) = resp.error {
            return Err(FaucetError::Rpc(format!(
                "RPC error {}: {}",
                err.code, err.message
            )));
        }
        resp.result
            .ok_or_else(|| FaucetError::Rpc("null result".into()))
    }
}
