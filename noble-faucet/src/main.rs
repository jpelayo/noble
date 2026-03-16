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
    /// Amount to send per drip (in atomic units; 1 NOBLE = 1,000,000 atomic).
    pub drip_amount: u64,
    /// Per-IP cooldown in seconds (default: 24h = 86400).
    pub ip_cooldown_secs: u64,
    /// Per-address cooldown in seconds (default: 7d = 604800).
    pub address_cooldown_secs: u64,
    /// Daily cap in atomic units (default: 100 NOBLE = 100,000,000).
    pub daily_cap: u64,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            faucet_address: String::new(),
            drip_amount: 10_000_000, // 10 NOBLE
            ip_cooldown_secs: 86400,
            address_cooldown_secs: 604800,
            daily_cap: 100_000_000, // 100 NOBLE
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

/// NOBLE Faucet — token dispenser for chain onboarding.
#[derive(Parser)]
#[command(
    name = "noble-faucet",
    version,
    about = "NOBLE faucet server"
)]
struct Cli {
    /// Listen address (e.g. "0.0.0.0:8786").
    #[arg(long, default_value = "127.0.0.1:8786")]
    listen: String,

    /// NOBLE node JSON-RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:8783")]
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

    /// Amount per drip in atomic units (default: 10,000,000 = 10 NOBLE).
    #[arg(long, default_value = "10000000")]
    drip_amount: u64,

    /// Per-IP cooldown in seconds (default: 86400 = 24h).
    #[arg(long, default_value = "86400")]
    ip_cooldown: u64,

    /// Per-address cooldown in seconds (default: 604800 = 7d).
    #[arg(long, default_value = "604800")]
    address_cooldown: u64,

    /// Daily distribution cap in atomic units (default: 100,000,000 = 100 NOBLE).
    #[arg(long, default_value = "100000000")]
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Resolve paths using the canonical directory resolver (noble.toml → platform default).
    let base_dir = noble_core::paths::resolve_data_dir(std::path::Path::new(""));
    let db_path = cli.db_path.unwrap_or_else(|| base_dir.join("faucet.db"));
    let keystore_dir = cli.keystore_dir.unwrap_or_else(|| base_dir.join("faucet-keystore"));

    let db = FaucetDb::open(&db_path).expect("Failed to open faucet database");
    let rpc = NodeRpcClient::new(&cli.rpc_url, cli.totp_code)
        .expect("Failed to create RPC client (check URL scheme)");

    // Resolve passphrase: --passphrase > NOBLE_FAUCET_PASSPHRASE env > --auto-unlock (first boot)
    let keystore_is_empty = !keystore_dir.exists()
        || std::fs::read_dir(&keystore_dir).map(|mut d| d.next().is_none()).unwrap_or(true);

    let (passphrase, is_first_boot) = if let Some(p) = cli.passphrase.clone() {
        (p, false)
    } else if let Ok(p) = std::env::var("NOBLE_FAUCET_PASSPHRASE") {
        (p, false)
    } else if cli.auto_unlock && keystore_is_empty {
        // First boot: generate a real random passphrase (not the hardcoded one).
        let mut rng_bytes = [0u8; 32];
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = f.read_exact(&mut rng_bytes);
        }
        (hex::encode(rng_bytes), true)
    } else if cli.auto_unlock {
        // Keystore exists but no passphrase provided — this shouldn't happen
        // after the first boot (the node should pass --passphrase).
        // Fall back to legacy hardcoded passphrase for backward compat.
        ("noble-faucet-auto".to_string(), false)
    } else {
        (String::new(), false)
    };

    // Initialize independent faucet wallet (local signing).
    let faucet_wallet = if !passphrase.is_empty() || cli.auto_unlock {
        match wallet::FaucetWallet::open_or_create(&keystore_dir, &passphrase, 0) {
            Ok(w) => {
                tracing::info!("Faucet wallet address: {}", w.address());

                // First boot: store the passphrase in the node's keystore via RPC.
                if is_first_boot {
                    tracing::info!("First boot — storing faucet passphrase in node keystore via RPC");
                    match rpc.store_faucet_secret(&passphrase).await {
                        Ok(()) => tracing::info!("Faucet passphrase stored in node keystore"),
                        Err(e) => tracing::warn!("Failed to store faucet passphrase: {e}"),
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

    let mut app = Router::new()
        .route("/api/faucet", post(handlers::handle_faucet))
        .route("/api/faucet/status", get(handlers::handle_status))
        .with_state(state)
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

    tracing::info!("Faucet server listening on {}", cli.listen);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("Server error");
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
        assert_eq!(cfg.drip_amount, 10_000_000);
        assert_eq!(cfg.ip_cooldown_secs, 86400);
        assert_eq!(cfg.address_cooldown_secs, 604800);
        assert_eq!(cfg.daily_cap, 100_000_000);
    }

    #[test]
    fn cli_parse_defaults() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["noble-faucet", "--faucet-address", "abcd1234"]).unwrap();
        assert_eq!(cli.listen, "127.0.0.1:8786");
        assert_eq!(cli.rpc_url, "http://127.0.0.1:8783");
        assert_eq!(cli.faucet_address, Some("abcd1234".to_string()));
        assert_eq!(cli.drip_amount, 10_000_000);
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
