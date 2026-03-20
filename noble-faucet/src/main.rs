// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE faucet server.
//!
//! Serves two HTTP endpoints:
//!   - `POST /api/faucet` — request NOBLE tokens
//!   - `GET  /api/faucet/status` — faucet balance, chain info, and distribution stats
//!
//! Auto-detects the connected chain via `noble_getNodeInfo`.
//! Rate limits: 1 request per IP per 24h, 1 request per address per 7d, daily cap.

pub mod db;
pub mod handlers;
pub mod rpc_client;
pub mod wallet;

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use thiserror::Error;

use db::FaucetDb;
use rpc_client::NodeRpcClient;

/// Faucet error types.
#[derive(Debug, Error)]
pub enum FaucetError {
    #[error("database: {0}")]
    Database(String),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("config: {0}")]
    Config(String),
}

/// Faucet configuration.
#[derive(Clone)]
pub struct FaucetConfig {
    /// Address of the faucet wallet on the NOBLE node.
    pub faucet_address: String,
    /// Amount to send per drip (in groats; 1 NOBLE = 100,000,000 groats).
    pub drip_amount: u64,
    /// Per-IP cooldown in seconds (default: 24h = 86400).
    pub ip_cooldown_secs: u64,
    /// Per-address cooldown in seconds (default: 24h = 86400).
    pub address_cooldown_secs: u64,
    /// Daily cap in groats (default: 50 NOBLE = 5,000,000,000 groats).
    pub daily_cap: u64,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            faucet_address: String::new(),
            drip_amount: noble_core::GROATS_PER_NOBLE, // 1 NOBLE per request
            ip_cooldown_secs: 86400, // 24h per IP
            address_cooldown_secs: 86400, // 24h per address (1 NOBLE/day/address)
            daily_cap: 5_000_000_000, // 50 NOBLE total daily faucet budget (10^8 atomic)
        }
    }
}

/// Derive a human-readable network label from the chain ID.
pub fn network_label_from_chain_id(chain_id: u64) -> String {
    format!("0x{chain_id:08X}")
}

/// Shared application state.
pub struct FaucetState {
    pub db: Arc<FaucetDb>,
    pub rpc: NodeRpcClient,
    pub config: FaucetConfig,
    /// Detected chain label (hex chain ID).
    pub network: String,
    /// Independent faucet wallet (when present, signs locally instead of via node RPC).
    pub wallet: Option<wallet::FaucetWallet>,
}

/// Gatekeeper middleware: requires `Gatekeeper: noble` header.
/// OPTIONS (CORS preflight) is exempt — browsers can't send custom headers in preflight.
async fn gatekeeper_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // Allow CORS preflight through without gatekeeper header.
    if req.method() == axum::http::Method::OPTIONS {
        return next.run(req).await;
    }
    let has_header = req
        .headers()
        .get("gatekeeper")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "noble")
        .unwrap_or(false);
    if !has_header {
        tracing::trace!(
            task = "gatekeeper",
            "rejected request without Gatekeeper: noble header"
        );
        return axum::response::Response::builder()
            .status(403)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"Missing Gatekeeper: noble header"}"#,
            ))
            .unwrap();
    }
    next.run(req).await
}

/// NOBLE Faucet — token dispenser for chain onboarding.
#[derive(Parser)]
#[command(
    name = "noble-faucet",
    version,
    about = "NOBLE faucet server"
)]
struct Cli {
    /// Listen address (e.g. "0.0.0.0:8786").
    #[arg(long, default_value = "0.0.0.0:8786")]
    listen: String,

    /// NOBLE node JSON-RPC URL.
    #[arg(long, default_value = "https://127.0.0.1:8783")]
    rpc_url: String,

    /// Faucet wallet address (hex public key on the node).
    /// If omitted, auto-detected from `--keystore-dir`.
    #[arg(long)]
    faucet_address: Option<String>,

    /// Path to faucet keystore directory (enables local signing).
    /// If omitted, uses `<platform_data_dir>/faucet-keystore`.
    #[arg(long)]
    keystore_dir: Option<PathBuf>,

    /// Keystore passphrase (overrides NOBLE_FAUCET_PASSPHRASE env).
    #[arg(long)]
    passphrase: Option<String>,

    /// Use a hardcoded passphrase for unattended operation (if --passphrase not set).
    #[arg(long)]
    auto_unlock: bool,

    /// Amount per drip in atomic units (default: 100,000,000 = 1 NOBLE).
    #[arg(long, default_value = "100000000")]
    drip_amount: u64,

    /// Per-IP cooldown in seconds (default: 86400 = 24h).
    #[arg(long, default_value = "86400")]
    ip_cooldown: u64,

    /// Per-address cooldown in seconds (default: 86400 = 24h, 1 NOBLE/day/address).
    #[arg(long, default_value = "86400")]
    address_cooldown: u64,

    /// Daily distribution cap in atomic units (default: 5,000,000,000 = 50 NOBLE).
    #[arg(long, default_value = "5000000000")]
    daily_cap: u64,

    /// Path to SQLite database file.
    /// If omitted, uses `<platform_data_dir>/faucet.db`.
    #[arg(long)]
    db_path: Option<PathBuf>,

    /// TOTP code for authenticated node RPC access (optional).
    /// The 6-digit code is SHA-256 hashed before sending as a Bearer token.
    #[arg(long)]
    totp_code: Option<String>,

    /// Path to static web directory to serve (optional).
    #[arg(long)]
    web_dir: Option<PathBuf>,

    /// Path to TLS certificate PEM file (required for HTTPS).
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key file (PEM or Noble-encrypted envelope).
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// Hex-encoded 32-byte chain_meta for decrypting Noble-envelope TLS key files.
    #[arg(long)]
    chain_meta: Option<String>,
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS usage.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Resolve paths using the canonical directory resolver (noble.toml → platform default).
    let base_dir = noble_core::paths::resolve_data_dir(std::path::Path::new(""));
    let db_path = cli.db_path.unwrap_or_else(|| base_dir.join("faucet.db"));
    let keystore_dir = cli.keystore_dir.unwrap_or_else(|| base_dir.join("faucet-keystore"));

    let db = FaucetDb::open(&db_path).expect("Failed to open faucet database");
    let rpc = NodeRpcClient::new(&cli.rpc_url, cli.totp_code)
        .expect("Failed to create RPC client (check URL scheme)");

    // Resolve passphrase via RPC or CLI fallback.
    // Check if a keystore exists — either old directory format or new .noble file format.
    let ks_noble_file = keystore_dir.with_extension("noble");
    let keystore_is_empty = !ks_noble_file.exists()
        && (!keystore_dir.exists()
            || std::fs::read_dir(&keystore_dir).map(|mut d| d.next().is_none()).unwrap_or(true));

    // Priority: --passphrase CLI > env var > RPC getFaucetSecret > generate new (first boot)
    // Also capture chain_meta from RPC for TLS key decryption.
    let mut rpc_chain_meta: Option<String> = None;

    let (passphrase, is_first_boot) = if let Some(p) = cli.passphrase.clone() {
        (p, false)
    } else if let Ok(p) = std::env::var("NOBLE_FAUCET_PASSPHRASE") {
        (p, false)
    } else {
        // Try to retrieve passphrase + chain_meta from node via RPC.
        match rpc.get_faucet_secret().await {
            Ok(resp) => {
                rpc_chain_meta = Some(resp.chain_meta);
                if let Some(p) = resp.passphrase {
                    tracing::info!("Faucet passphrase retrieved from node keystore via RPC");
                    (p, false)
                } else if keystore_is_empty {
                    // Node has no stored passphrase — first boot, generate one.
                    let entropy = format!(
                        "{}:{}:{}",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos(),
                        std::env::current_exe().unwrap_or_default().display(),
                    );
                    let rng_bytes = noble_crypto::sha256(entropy.as_bytes());
                    (hex::encode(rng_bytes.as_bytes()), true)
                } else {
                    tracing::error!("Faucet keystore exists but node has no stored passphrase. Delete faucet-keystore to re-generate.");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                tracing::error!("Cannot reach node RPC to get faucet secret: {e}");
                std::process::exit(1);
            }
        }
    };

    // Get chain_id from node for correct signing message computation.
    let chain_id = rpc.get_node_info().await
        .map(|info| info.chain_id as u32)
        .unwrap_or(0);
    if chain_id != 0 {
        tracing::info!("Chain ID from node: {:#010X}", chain_id);
    }

    // Initialize independent faucet wallet (local signing).
    let faucet_wallet = if !passphrase.is_empty() {
        match wallet::FaucetWallet::open_or_create(&keystore_dir, &passphrase, chain_id) {
            Ok(w) => {
                tracing::info!("Faucet wallet address: {}", w.address());

                // Always report the faucet address to the node so the GUI can display it.
                // On first boot, also store the passphrase (MUST succeed or the keystore is orphaned).
                if is_first_boot {
                    tracing::info!("First boot — storing faucet passphrase + address in node keystore via RPC");
                    let mut stored = false;
                    for attempt in 1..=3 {
                        match rpc.store_faucet_secret(&passphrase, Some(&w.address())).await {
                            Ok(()) => {
                                tracing::info!("Faucet passphrase + address stored in node keystore");
                                stored = true;
                                break;
                            }
                            Err(e) => {
                                tracing::warn!("Attempt {attempt}/3 — failed to store faucet secret: {e}");
                                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                            }
                        }
                    }
                    if !stored {
                        tracing::error!("FATAL: Could not store faucet passphrase after 3 attempts. Exiting to prevent orphaned keystore.");
                        std::process::exit(1);
                    }
                } else {
                    // Subsequent boot: passphrase already stored, just update the address.
                    if let Err(e) = rpc.store_faucet_secret(&passphrase, Some(&w.address())).await {
                        tracing::warn!("Failed to update faucet address on node: {e}");
                    }
                }

                Some(w)
            }
            Err(e) => {
                tracing::warn!("Could not initialize faucet wallet: {e}");
                None
            }
        }
    } else {
        None
    };

    // Resolve faucet address: --faucet-address > wallet auto-detect
    let faucet_address = cli
        .faucet_address
        .or_else(|| faucet_wallet.as_ref().map(|w| w.address()))
        .expect("Must provide --faucet-address or a valid --keystore-dir with --passphrase/--auto-unlock");

    let config = FaucetConfig {
        faucet_address,
        drip_amount: cli.drip_amount,
        ip_cooldown_secs: cli.ip_cooldown,
        address_cooldown_secs: cli.address_cooldown,
        daily_cap: cli.daily_cap,
    };

    // Detect connected network at startup.
    let network = match rpc.get_node_info().await {
        Ok(info) => {
            let label = if info.network_label.is_empty() {
                network_label_from_chain_id(info.chain_id)
            } else {
                info.network_label
            };
            tracing::info!(network = %label, chain_id = info.chain_id, "Connected to NOBLE node");
            label
        }
        Err(e) => {
            tracing::warn!("Could not detect network (node may be offline): {e}");
            "unknown".to_string()
        }
    };

    let state = Arc::new(FaucetState {
        db: Arc::new(db),
        rpc,
        config,
        network,
        wallet: faucet_wallet,
    });

    // CORS: allow any origin for the faucet (public service).
    let cors = tower_http::cors::CorsLayer::permissive();

    // Gatekeeper: require `Gatekeeper: noble` header on all requests.
    // Drops drive-by scanners before they touch application logic.
    let gatekeeper = axum::middleware::from_fn(gatekeeper_middleware);

    // Layer order: outermost runs first.
    // 1. Gatekeeper (reject scanners) — but allows OPTIONS preflight through
    // 2. CORS (add Access-Control headers for browser clients)
    // 3. Router (handlers)
    let mut app = Router::new()
        .route("/api/faucet", post(handlers::handle_faucet))
        .route("/api/faucet/status", get(handlers::handle_status))
        .with_state(state)
        .layer(gatekeeper)
        .layer(cors);

    // Optionally serve static web files.
    if let Some(web_dir) = &cli.web_dir {
        if web_dir.is_dir() {
            app = app.fallback_service(tower_http::services::ServeDir::new(web_dir));
            tracing::info!("Serving static files from {:?}", web_dir);
        } else {
            tracing::warn!(
                "Web directory {:?} not found — skipping static file serving",
                web_dir
            );
        }
    }

    let listener = tokio::net::TcpListener::bind(&cli.listen)
        .await
        .expect("Failed to bind listener");

    if let (Some(cert_path), Some(key_path)) = (&cli.tls_cert, &cli.tls_key) {
        // Serve HTTPS using the provided TLS certificate and key.
        let cert_pem = std::fs::read(cert_path).expect("Failed to read TLS cert");
        let key_raw = std::fs::read(key_path).expect("Failed to read TLS key");

        // Decrypt the key if it's a Noble-encrypted envelope (never write plaintext to disk).
        let key_pem = if noble_crypto::file_encrypt::is_noble_envelope(&key_raw) {
            let cm_hex = rpc_chain_meta.as_deref()
                .or(cli.chain_meta.as_deref())
                .expect("chain_meta required to decrypt Noble-envelope TLS key (from RPC or --chain-meta)");
            let cm_bytes: [u8; 32] = hex::decode(cm_hex)
                .expect("chain_meta must be 64 hex chars")
                .try_into()
                .expect("chain_meta must be exactly 32 bytes");
            let (decrypted, _) = noble_crypto::file_encrypt::decrypt_file_data_with_migration(&key_raw, &cm_bytes)
                .expect("Failed to decrypt TLS key envelope");
            decrypted
        } else {
            key_raw
        };

        let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
            rustls_pemfile::certs(&mut &cert_pem[..])
                .filter_map(|r| r.ok())
                .collect();
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .expect("Failed to parse TLS key PEM")
            .expect("No private key found in PEM");
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("Failed to build TLS ServerConfig");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));

        tracing::info!("Faucet server listening on {} (HTTPS)", cli.listen);

        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => { tracing::debug!("accept error: {e}"); continue; }
            };
            let acceptor = acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = hyper_util::rt::TokioIo::new(tls_stream);
                        // Inject ConnectInfo as an Extension so handlers can extract the client IP.
                        let app_with_ci = app.layer(axum::Extension(axum::extract::ConnectInfo(addr)));
                        let svc = hyper_util::service::TowerToHyperService::new(app_with_ci);
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, svc)
                        .await
                        {
                            tracing::debug!("faucet connection error: {e}");
                        }
                    }
                    Err(e) => tracing::debug!("TLS handshake failed: {e}"),
                }
            });
        }
    } else {
        tracing::error!("Faucet requires TLS. Provide --tls-cert and --tls-key. Plain HTTP is forbidden.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_label_detection() {
        // Chain IDs are now genesis-derived; the label is always hex-formatted.
        assert_eq!(
            network_label_from_chain_id(0x4E4F424C),
            "0x4E4F424C"
        );
        assert_eq!(
            network_label_from_chain_id(0x12345678),
            "0x12345678"
        );
    }

    #[test]
    fn faucet_config_defaults() {
        let cfg = FaucetConfig::default();
        assert_eq!(cfg.drip_amount, 100_000_000);
        assert_eq!(cfg.ip_cooldown_secs, 86400);
        assert_eq!(cfg.address_cooldown_secs, 86400);
        assert_eq!(cfg.daily_cap, 5_000_000_000);
    }

    #[test]
    fn cli_parse_defaults() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["noble-faucet", "--faucet-address", "abcd1234"]).unwrap();
        assert_eq!(cli.listen, "0.0.0.0:8786");
        assert_eq!(cli.rpc_url, "http://127.0.0.1:8783");
        assert_eq!(cli.faucet_address, Some("abcd1234".to_string()));
        assert_eq!(cli.drip_amount, 100_000_000);
        assert!(cli.totp_code.is_none());
        assert!(!cli.auto_unlock);
    }

    #[test]
    fn cli_parse_auto_unlock() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "noble-faucet",
            "--auto-unlock",
            "--keystore-dir",
            "/tmp/ks",
        ])
        .unwrap();
        assert!(cli.auto_unlock);
        assert!(cli.faucet_address.is_none());
    }

    #[test]
    fn rpc_client_accepts_https() {
        // F7: https:// is now supported via the NoCertVerifier TLS client.
        let result = NodeRpcClient::new("https://127.0.0.1:8783", None);
        assert!(result.is_ok(), "https:// should be accepted: {result:?}");
    }

    #[test]
    fn rpc_client_rejects_unknown_scheme() {
        let result = NodeRpcClient::new("ftp://127.0.0.1:8783", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unsupported URL scheme"),
            "error should mention unsupported scheme: {err}"
        );
    }

    #[test]
    fn rpc_client_accepts_http() {
        let result = NodeRpcClient::new("http://127.0.0.1:8783", None);
        assert!(result.is_ok());
    }

    #[test]
    fn db_rate_limiting() {
        let db = FaucetDb::open_memory().unwrap();
        // Fresh — no rate limits.
        assert!(!db.ip_recent_distribution("1.2.3.4", 86400).unwrap());
        assert!(!db.address_recent_distribution("addr1", 604800).unwrap());

        // After distribution — rate limited.
        db.record_distribution("addr1", "1.2.3.4", 10_000_000, Some("tx1"))
            .unwrap();
        assert!(db.ip_recent_distribution("1.2.3.4", 86400).unwrap());
        assert!(db.address_recent_distribution("addr1", 604800).unwrap());

        // Different IP/address — not rate limited.
        assert!(!db.ip_recent_distribution("5.6.7.8", 86400).unwrap());
        assert!(!db.address_recent_distribution("addr2", 604800).unwrap());
    }

    #[test]
    fn db_daily_cap_tracking() {
        let db = FaucetDb::open_memory().unwrap();
        db.record_distribution("a", "1.1.1.1", 50_000_000, None)
            .unwrap();
        db.record_distribution("b", "2.2.2.2", 30_000_000, None)
            .unwrap();
        let today = db.today_distributed().unwrap();
        assert_eq!(today, 80_000_000);
        let total = db.total_distributed().unwrap();
        assert_eq!(total, 80_000_000);
    }
}
