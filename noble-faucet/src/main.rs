// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE faucet server (mainnet + testnet).
//!
//! Serves two HTTP endpoints:
//!   - `POST /api/faucet` — request NOBLE tokens
//!   - `GET  /api/faucet/status` — faucet balance, network, and distribution stats
//!
//! Auto-detects the connected network (mainnet/testnet) via `noble_getNodeInfo`.
//! Rate limits: 1 request per IP per 24h, 1 request per address per 7d, daily cap.

pub mod db;
pub mod handlers;
pub mod rpc_client;

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

/// Known chain IDs.
pub const MAINNET_CHAIN_ID: u64 = 0x4E4F424C;

/// Derive a human-readable network label from the chain ID.
pub fn network_label_from_chain_id(chain_id: u64) -> String {
    match chain_id {
        MAINNET_CHAIN_ID => "mainnet".to_string(),
        0x4E4F4254 => "testnet".to_string(),
        0x4E4F4252 => "regtest".to_string(),
        other => format!("unknown (0x{other:X})"),
    }
}

/// Shared application state.
pub struct FaucetState {
    pub db: Arc<FaucetDb>,
    pub rpc: NodeRpcClient,
    pub config: FaucetConfig,
    /// Detected network label (e.g. "mainnet", "testnet").
    pub network: String,
}

/// NOBLE Faucet — token dispenser for mainnet onboarding and testnet usage.
#[derive(Parser)]
#[command(
    name = "noble-faucet",
    version,
    about = "NOBLE faucet server (mainnet + testnet)"
)]
struct Cli {
    /// Listen address (e.g. "0.0.0.0:8786").
    #[arg(long, default_value = "127.0.0.1:8786")]
    listen: String,

    /// NOBLE node JSON-RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:8783")]
    rpc_url: String,

    /// Faucet wallet address (hex public key on the node).
    #[arg(long)]
    faucet_address: String,

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
    #[arg(long, default_value = "faucet.db")]
    db_path: PathBuf,

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

    let db = FaucetDb::open(&cli.db_path).expect("Failed to open faucet database");
    let rpc = NodeRpcClient::new(&cli.rpc_url, cli.totp_code)
        .expect("Failed to create RPC client (check URL scheme)");
    let config = FaucetConfig {
        faucet_address: cli.faucet_address,
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
        assert_eq!(network_label_from_chain_id(0x4E4F424C), "mainnet");
        assert_eq!(network_label_from_chain_id(0x4E4F4254), "testnet");
        assert_eq!(network_label_from_chain_id(0x4E4F4252), "regtest");
        assert_eq!(
            network_label_from_chain_id(0x12345678),
            "unknown (0x12345678)"
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
        assert_eq!(cli.faucet_address, "abcd1234");
        assert_eq!(cli.drip_amount, 10_000_000);
        assert!(cli.totp_code.is_none());
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
