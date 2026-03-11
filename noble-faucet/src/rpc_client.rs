// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Minimal JSON-RPC client for communicating with the NOBLE node.
//!
//! **Security hardening:**
//! - Connect/read/write timeouts (10s each) prevent indefinite hangs.
//! - Response size capped at 2 MB to prevent unbounded memory allocation.
//! - Both `http://` and `https://` URLs are accepted.
//! - HTTPS uses a no-cert-verify TLS client (self-signed node cert accepted).
//!   This is appropriate for localhost/trusted-network use; the faucet is
//!   intended to run on the same host as the node or on a private LAN.
//! - Optional TOTP bearer auth: client SHA-256 hashes the code before sending.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::FaucetError;

// ---------------------------------------------------------------------------
// TLS client support — no-cert-verify for self-signed node certificates
// ---------------------------------------------------------------------------

/// `ServerCertVerifier` that accepts any certificate.
///
/// The NOBLE node uses a self-signed certificate. The faucet is intended for
/// localhost/trusted-network use, so skipping certificate chain validation is
/// acceptable here. For production deployments that run over untrusted networks,
/// replace this with a proper certificate verifier.
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

/// Maximum HTTP response size (2 MB). Prevents unbounded memory growth.
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Timeout for TCP connect, read, and write operations.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Lightweight JSON-RPC 2.0 client over HTTP or HTTPS.
#[derive(Debug)]
pub struct NodeRpcClient {
    url: String,
    use_tls: bool,
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

#[derive(Deserialize, Clone)]
pub struct UtxoResult {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub height: u64,
    pub is_coinbase: bool,
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
    #[serde(default)]
    pub block_height: u64,
}

impl NodeRpcClient {
    /// Create a new RPC client.
    ///
    /// Accepts both `http://` and `https://` URLs.  HTTPS uses a no-cert-verify
    /// TLS client suitable for the node's self-signed certificate.
    ///
    /// # Errors
    ///
    /// Returns `FaucetError::Config` if the URL scheme is neither `http://` nor
    /// `https://`.
    pub fn new(url: &str, totp_code: Option<String>) -> Result<Self, FaucetError> {
        let use_tls = if url.starts_with("https://") {
            true
        } else if url.starts_with("http://") {
            false
        } else {
            return Err(FaucetError::Config(format!(
                "unsupported URL scheme: {url} — expected http:// or https://"
            )));
        };
        Ok(Self {
            url: url.to_string(),
            use_tls,
            next_id: AtomicU64::new(1),
            totp_code,
        })
    }

    /// Submit a pre-signed transaction (hex-encoded CBOR) to the node.
    pub async fn submit_raw_transaction(&self, tx_hex: &str) -> Result<String, FaucetError> {
        #[derive(Serialize)]
        struct Params<'a> {
            tx_hex: &'a str,
        }
        let params = Params { tx_hex };
        let resp: TransferResult = self.call("noble_submitTransaction", &params).await?;
        Ok(resp.tx_id)
    }

    /// Send NOBLE tokens from the faucet wallet to the target address (legacy, delegates to node).
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

    /// Get UTXOs for an address.
    pub async fn get_address_utxos(&self, address: &str) -> Result<Vec<UtxoResult>, FaucetError> {
        #[derive(Serialize)]
        struct Params<'a> {
            address: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            utxos: Vec<UtxoResult>,
        }
        let resp: Response = self.call(
            "noble_getAddressUtxos",
            &Params { address },
        ).await?;
        Ok(resp.utxos)
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

        // Parse URL — strip the scheme prefix to get host:port/path.
        let scheme_stripped = if self.use_tls {
            self.url.strip_prefix("https://").unwrap_or(&self.url)
        } else {
            self.url.strip_prefix("http://").unwrap_or(&self.url)
        };
        let (host_port, path) = match scheme_stripped.find('/') {
            Some(i) => (&scheme_stripped[..i], &scheme_stripped[i..]),
            None => (scheme_stripped, "/"),
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
        let tcp = tokio::time::timeout(RPC_TIMEOUT, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| FaucetError::Rpc(format!("connect timeout ({RPC_TIMEOUT:?})")))?
            .map_err(|e| FaucetError::Rpc(format!("connect: {e}")))?;

        // Build HTTP request with optional TOTP bearer auth.
        let mut http_req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        // Gatekeeper header — required by the RPC server middleware.
        http_req.push_str("Gatekeeper: noble\r\n");
        if let Some(ref code) = self.totp_code {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(code.as_bytes());
            let hash_hex = hex::encode(hash);
            http_req.push_str(&format!("Authorization: Bearer {hash_hex}\r\n"));
        }
        http_req.push_str("\r\n");

        // Send request and read response, with TLS wrapping when https://.
        let buf = if self.use_tls {
            self.send_https(tcp, host, http_req.as_bytes(), &body).await?
        } else {
            Self::send_http(tcp, http_req.as_bytes(), &body).await?
        };

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

    /// Send an HTTP (plain TCP) request and return the raw response bytes.
    async fn send_http(
        stream: tokio::net::TcpStream,
        header: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, FaucetError> {
        use tokio::io::AsyncWriteExt;
        let (reader, mut writer) = tokio::io::split(stream);

        tokio::time::timeout(RPC_TIMEOUT, async {
            writer.write_all(header).await?;
            writer.write_all(body).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| FaucetError::Rpc(format!("write timeout ({RPC_TIMEOUT:?})")))?
        .map_err(|e| FaucetError::Rpc(format!("write: {e}")))?;

        Self::read_response(reader).await
    }

    /// Send an HTTPS (TLS) request and return the raw response bytes.
    async fn send_https(
        &self,
        stream: tokio::net::TcpStream,
        host: &str,
        header: &[u8],
        body: &[u8],
    ) -> Result<Vec<u8>, FaucetError> {
        use tokio::io::AsyncWriteExt;

        let tls_config = make_tls_client_config();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| FaucetError::Rpc(format!("invalid server name '{host}': {e}")))?;

        let tls_stream = tokio::time::timeout(
            RPC_TIMEOUT,
            connector.connect(server_name, stream),
        )
        .await
        .map_err(|_| FaucetError::Rpc(format!("TLS handshake timeout ({RPC_TIMEOUT:?})")))?
        .map_err(|e| FaucetError::Rpc(format!("TLS handshake: {e}")))?;

        let (reader, mut writer) = tokio::io::split(tls_stream);

        tokio::time::timeout(RPC_TIMEOUT, async {
            writer.write_all(header).await?;
            writer.write_all(body).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| FaucetError::Rpc(format!("write timeout ({RPC_TIMEOUT:?})")))?
        .map_err(|e| FaucetError::Rpc(format!("write: {e}")))?;

        Self::read_response(reader).await
    }

    /// Read an HTTP response from any async reader with timeout and size cap.
    async fn read_response<R: tokio::io::AsyncRead + Unpin>(
        reader: R,
    ) -> Result<Vec<u8>, FaucetError> {
        use tokio::io::AsyncReadExt;

        tokio::time::timeout(RPC_TIMEOUT, async {
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
        .map_err(|e| FaucetError::Rpc(format!("read: {e}")))
    }
}
