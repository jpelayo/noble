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

pub mod admin_auth;
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

    /// Path to the noble-node's data directory for local-FS secret bootstrap.
    /// When set, the faucet reads chain_meta + faucet passphrase + admin token
    /// directly from the node's on-disk keystore instead of fetching them over
    /// JSON-RPC. Eliminates the cross-process secret boundary that goes over
    /// loopback HTTPS today.
    ///
    /// Requires the faucet process to have read access to:
    ///   <node_data_dir>/.chain_meta
    ///   <node_data_dir>/keystore.noble
    ///
    /// Hard-fails at startup if either file is missing or unreadable — no
    /// silent fallback to RPC.
    ///
    /// Also reads `NOBLE_NODE_DATA_DIR` env var (CLI flag takes precedence).
    #[arg(long)]
    node_data_dir: Option<PathBuf>,

    /// Explicit path to the node's single-file keystore (keystore.noble).
    /// The node passes its RESOLVED `wallet.keystore_path` here so nonstandard
    /// layouts (absolute keystore_path outside data_dir — e.g. migrated legacy
    /// installs) bootstrap correctly. Defaults to
    /// `<node_data_dir>/keystore.noble` when omitted.
    #[arg(long)]
    node_keystore: Option<PathBuf>,

    /// Explicitly create a NEW faucet wallet even when a previous faucet
    /// address is on record (faucet-address.txt). This ABANDONS any funds
    /// held by the recorded address — the old key is unrecoverable unless its
    /// keystore file is restored from backup. Without this flag the faucet
    /// hard-fails instead of silently rotating its identity.
    #[arg(long)]
    force_new_wallet: bool,
}

/// Read the previously-recorded faucet address — the evidence that a wallet
/// existed before (and may hold funds).
fn read_marker_address(node_data_dir: Option<&std::path::Path>) -> Option<String> {
    let p = node_data_dir?.join("faucet-address.txt");
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Custody rule: wallet creation is refused when a prior address is on
/// record and the operator did not explicitly opt into abandoning it.
fn should_refuse_creation(recorded_address: Option<&str>, force_new_wallet: bool) -> bool {
    recorded_address.is_some() && !force_new_wallet
}

/// Custody rule: the recorded address may only be replaced by a DIFFERENT
/// one under --force-new-wallet. (Same address, or no record, is always fine.)
fn address_rotation_allowed(recorded: Option<&str>, current: &str, force_new_wallet: bool) -> bool {
    match recorded {
        None => true,
        Some(r) if r == current => true,
        Some(_) => force_new_wallet,
    }
}

/// Resolve the node's single-file keystore for local-FS bootstrap: the
/// explicit --node-keystore path when given, else the standard location
/// inside the node's data dir. ONE resolver for every consumer (bootstrap,
/// admin-token refresh, mtime watcher) so they can never disagree.
fn node_keystore_path(
    node_data_dir: &std::path::Path,
    explicit: Option<&std::path::Path>,
) -> PathBuf {
    explicit
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| node_data_dir.join("keystore.noble"))
}

/// Secrets fetched from the node's on-disk keystore (Group A local-FS bootstrap).
struct LocalSecrets {
    passphrase: String,
    chain_meta_hex: String,
    admin_token_hex: Option<String>,
}

/// Read faucet passphrase + admin token directly from the node's keystore.
/// Replaces RPC-based handoff in noble_getFaucetSecret / noble_getFaucetAdminToken.
///
/// Reuses the same noble-wallet + noble-crypto helpers the node uses, so the
/// decrypt path is bit-identical. Hard-fails on any error — caller should
/// `eprintln + std::process::exit(1)` on Err.
fn bootstrap_via_local_fs(
    node_data_dir: &std::path::Path,
    node_keystore: Option<&std::path::Path>,
) -> Result<LocalSecrets, String> {
    use noble_wallet::KeyStore;

    if !node_data_dir.is_dir() {
        return Err(format!(
            "--node-data-dir {} is not an existing directory",
            node_data_dir.display()
        ));
    }

    // 1. Read chain_meta. Use "automatic" encryption mode — manual mode is
    //    explicitly out of scope for the local-FS path (see plan, Open
    //    Question §). Operators on manual mode get a clear hint to use the
    //    RPC fallback instead.
    let chain_meta = noble_crypto::file_encrypt::load_chain_meta(
        node_data_dir,
        "automatic",
        None,
    )
    .map_err(|e| format!(
        "failed to read chain_meta from {}: {e}. \
         If encryption_mode=\"manual\" is set on the node, omit --node-data-dir \
         and use the legacy RPC bootstrap path instead.",
        node_data_dir.display()
    ))?;

    // 2. Open the node's keystore (explicit --node-keystore path when the
    //    node supplied one; standard <node_data_dir>/keystore.noble otherwise).
    let keystore_path = node_keystore_path(node_data_dir, node_keystore);
    let mut ks = KeyStore::open(&keystore_path, &chain_meta).map_err(|e| {
        format!("failed to open node keystore at {}: {e}", keystore_path.display())
    })?;
    let wallet_pass = hex::encode(
        noble_crypto::file_encrypt::derive_wallet_key(&chain_meta),
    );
    ks.unlock(&wallet_pass)
        .map_err(|e| format!("failed to unlock node keystore: {e}"))?;

    // 3. Extract the faucet passphrase (must be present — node-side has
    //    already bootstrapped it via the prior --passphrase / RPC path).
    let passphrase_bytes = ks
        .get_raw(noble_crypto::SCHEME_FAUCET_PASSPHRASE)
        .map_err(|e| format!(
            "faucet passphrase not present in node keystore ({e}). \
             Has the faucet been bootstrapped on this node before? \
             Run once with the legacy RPC path to generate it, then switch back."
        ))?;
    let passphrase = String::from_utf8(passphrase_bytes)
        .map_err(|e| format!("faucet passphrase in keystore is not valid UTF-8: {e}"))?;

    // 4. Extract the admin token if present. Format is
    //    [8-byte LE u64 timestamp][32 raw token bytes] (Tier 2 plan §1).
    //    Returns None if not yet provisioned (node lazily generates on first
    //    getFaucetAdminToken call); the AdminAuthLayer will refuse with 503
    //    until the node generates and the next refresh tick picks it up.
    let admin_token_hex = match ks.get_raw(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN) {
        Ok(bytes) if bytes.len() == 40 => Some(hex::encode(&bytes[8..])),
        Ok(other) => {
            tracing::warn!(
                "admin token in keystore has unexpected length ({} bytes) — \
                 ignoring; node will regenerate on next getFaucetAdminToken call",
                other.len()
            );
            None
        }
        Err(_) => None,
    };

    Ok(LocalSecrets {
        passphrase,
        chain_meta_hex: hex::encode(chain_meta),
        admin_token_hex,
    })
}

/// SHA-256-based fingerprint used to identify a token in logs without
/// leaking the token itself. Matches the node-side fingerprint
/// computation in `noble-api/src/methods/node.rs::faucet_admin_token_fingerprint`.
fn admin_auth_fingerprint(token_hex: &str) -> String {
    let digest = noble_crypto::sha256(token_hex.as_bytes());
    hex::encode(&digest.as_bytes()[..4])
}

/// Re-read the admin token from the node's on-disk keystore. Used by the
/// local-FS refresh path when the keystore.noble file mtime changes.
/// Returns `Ok(Some(token_hex))` when the token is present, `Ok(None)` when
/// the keystore parsed cleanly but the token entry is absent (node hasn't
/// bootstrapped it yet), and `Err` on any I/O / decrypt failure.
fn refresh_admin_token_from_disk(
    node_data_dir: &std::path::Path,
    node_keystore: Option<&std::path::Path>,
    chain_meta_hex: &str,
) -> Result<Option<String>, String> {
    use noble_wallet::KeyStore;

    let chain_meta_bytes = hex::decode(chain_meta_hex)
        .map_err(|e| format!("cached chain_meta is not valid hex: {e}"))?;
    let chain_meta: [u8; 32] = chain_meta_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "cached chain_meta is not 32 bytes".to_string())?;

    let keystore_path = node_keystore_path(node_data_dir, node_keystore);
    let mut ks = KeyStore::open(&keystore_path, &chain_meta)
        .map_err(|e| format!("open keystore: {e}"))?;
    let wallet_pass = hex::encode(
        noble_crypto::file_encrypt::derive_wallet_key(&chain_meta),
    );
    ks.unlock(&wallet_pass)
        .map_err(|e| format!("unlock keystore: {e}"))?;

    match ks.get_raw(noble_crypto::SCHEME_FAUCET_ADMIN_TOKEN) {
        Ok(bytes) if bytes.len() == 40 => Ok(Some(hex::encode(&bytes[8..]))),
        Ok(_) => Ok(None),
        Err(_) => Ok(None),
    }
}

#[tokio::main]
async fn main() {
    // Install rustls crypto provider before any TLS usage.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt::init();

    let mut cli = Cli::parse();
    // CLI flag takes precedence over env var. Only resolve env when flag absent.
    if cli.node_data_dir.is_none() {
        if let Ok(s) = std::env::var("NOBLE_NODE_DATA_DIR") {
            if !s.is_empty() {
                cli.node_data_dir = Some(PathBuf::from(s));
            }
        }
    }

    // Resolve paths using the canonical directory resolver (noble.toml → platform default).
    let base_dir = noble_core::paths::resolve_data_dir(std::path::Path::new(""));
    let db_path = cli.db_path.unwrap_or_else(|| base_dir.join("faucet.db"));
    let keystore_dir = cli.keystore_dir.unwrap_or_else(|| base_dir.join("faucet-keystore"));

    let db = FaucetDb::open(&db_path).expect("Failed to open faucet database");
    let rpc = NodeRpcClient::new(&cli.rpc_url, cli.totp_code)
        .expect("Failed to create RPC client (check URL scheme)");

    // Resolve passphrase via RPC or CLI fallback.
    // Faucet keystore existence: retained for legacy diagnostics. The
    // legacy `keystore_is_empty` branch was removed alongside the
    // getFaucetSecret RPC.
    let _ks_noble_file = keystore_dir.with_extension("noble");

    // ── Local-FS bootstrap (Group A) ─────────────────────────────────
    // If --node-data-dir is set, read all secrets directly from the node's
    // on-disk keystore. Eliminates the RPC handoff for chain_meta + passphrase
    // + admin token — narrows the cross-process boundary to local filesystem
    // permissions, which already chmod 0600 the relevant files.
    let local_secrets: Option<LocalSecrets> = if let Some(dir) = &cli.node_data_dir {
        match bootstrap_via_local_fs(dir, cli.node_keystore.as_deref()) {
            Ok(s) => {
                tracing::info!(
                    node_data_dir = %dir.display(),
                    "Local-FS bootstrap: chain_meta + passphrase{} loaded from disk; RPC handoff bypassed",
                    if s.admin_token_hex.is_some() { " + admin token" } else { "" }
                );
                Some(s)
            }
            Err(e) => {
                tracing::error!("Local-FS bootstrap failed: {e}");
                std::process::exit(1);
            }
        }
    } else {
        tracing::warn!(
            task = "faucet_secrets",
            "Bootstrapping via RPC — co-deploy with --node-data-dir (or set \
             NOBLE_NODE_DATA_DIR) for a tighter cross-process secret boundary. \
             This RPC handoff path will be removed in a future release."
        );
        None
    };

    // Priority: local-FS > --passphrase CLI > env var > error (legacy RPC path deleted)
    // Also capture chain_meta from local-FS for TLS key decryption.
    let rpc_chain_meta: Option<String> = local_secrets
        .as_ref()
        .map(|s| s.chain_meta_hex.clone());

    let (passphrase, is_first_boot) = if let Some(s) = &local_secrets {
        (s.passphrase.clone(), false)
    } else if let Some(p) = cli.passphrase.clone() {
        (p, false)
    } else if let Ok(p) = std::env::var("NOBLE_FAUCET_PASSPHRASE") {
        (p, false)
    } else {
        // Try to retrieve passphrase + chain_meta from node via RPC.
        // Legacy `getFaucetSecret` was deleted (open-node hardening). The
        // faucet now bootstraps via `--node-data-dir` and reads chain_meta +
        // passphrase + admin token directly from the node's keystore on disk.
        // Operators without `--node-data-dir` must either pass `--passphrase`
        // explicitly or set NOBLE_FAUCET_PASSPHRASE.
        tracing::error!(
            "Cannot bootstrap faucet without --node-data-dir, --passphrase, or NOBLE_FAUCET_PASSPHRASE.\n\
             Default deploy: ensure noble-node starts the faucet with --node-data-dir set\n\
             (this happens automatically when faucet.server_enabled = true in noble.toml).\n\
             Manual deploy: pass --node-data-dir=<path-to-node-data> to noble-faucet."
        );
        std::process::exit(1);
    };
    // chain_meta retained for backwards compat with TLS key decryption below.
    let _ = &rpc_chain_meta;

    // Get chain_id from node for correct signing message computation.
    let chain_id = rpc.get_node_info().await
        .map(|info| info.chain_id as u32)
        .unwrap_or(0);
    if chain_id != 0 {
        tracing::info!("Chain ID from node: {:#010X}", chain_id);
    }

    // Initialize independent faucet wallet (local signing).
    //
    // CUSTODY RULES — faucet funds can never be silently lost:
    //   • open() never creates. Creation happens only on a true first run
    //     (no faucet-address.txt on record) or under --force-new-wallet.
    //   • New wallets are passphrase-DERIVED: losing the keystore file no
    //     longer rotates the faucet identity (same passphrase ⇒ same address).
    //   • Every custody violation is a hard exit(1) — the node's supervisor
    //     raises a critical faucet_down alarm. The faucet never runs
    //     walletless or on a silently-rotated identity.
    let faucet_wallet = if !passphrase.is_empty() {
        let marker_addr = read_marker_address(cli.node_data_dir.as_deref());

        let w = match wallet::FaucetWallet::open(&keystore_dir, &passphrase, chain_id) {
            Ok(w) => w,
            Err(open_err @ (wallet::OpenError::Missing(_) | wallet::OpenError::NoKey(_))) => {
                if should_refuse_creation(marker_addr.as_deref(), cli.force_new_wallet) {
                    let recorded = marker_addr.as_deref().unwrap_or("<unknown>");
                    let would = wallet::FaucetWallet::derived_address(&passphrase)
                        .unwrap_or_else(|e| format!("<derivation failed: {e}>"));
                    tracing::error!(
                        "CUSTODY: {open_err}, but a previous faucet address is on record: {recorded}. \
                         Refusing to mint a new wallet (it would use {would} and strand any funds at \
                         the recorded address). Restore the faucet keystore from backup, or start with \
                         --force-new-wallet to explicitly abandon the recorded address."
                    );
                    std::process::exit(1);
                }
                match wallet::FaucetWallet::create_derived(&keystore_dir, &passphrase, chain_id) {
                    Ok(w) => w,
                    Err(e) => {
                        tracing::error!("Could not create faucet wallet: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(other) => {
                // Corrupt keystore / wrong passphrase / I/O. Creating a new
                // wallet over an unreadable one would be destructive — stop.
                tracing::error!(
                    "Could not open faucet wallet: {other}. NOT creating a new wallet over it — \
                     investigate the keystore (or restore it from backup) and restart."
                );
                std::process::exit(1);
            }
        };

        tracing::info!("Faucet wallet address: {}", w.address());

        // Address propagation to the node:
        //   • Local-FS mode (--node-data-dir set): write the address to
        //     <node_data_dir>/faucet-address.txt for the node to read.
        //     No RPC call, no secret on the wire — the address isn't
        //     secret anyway (it's where coins go).
        //   • Legacy mode (RPC bootstrap): fall back to storeFaucetSecret
        //     which sends BOTH passphrase and address. Retained only for
        //     pre-Group 4 faucet binaries; will be removed in a future PR.
        if let Some(ref node_dir) = cli.node_data_dir {
            // Rotation guard: the recorded (possibly funded) address is never
            // silently replaced by a different one.
            if !address_rotation_allowed(marker_addr.as_deref(), &w.address(), cli.force_new_wallet) {
                tracing::error!(
                    "CUSTODY: recorded faucet address {} differs from this wallet's address {}. \
                     Refusing to overwrite faucet-address.txt. Restore the matching keystore, or \
                     start with --force-new-wallet to explicitly abandon the recorded address.",
                    marker_addr.as_deref().unwrap_or(""),
                    w.address()
                );
                std::process::exit(1);
            }
            if let Some(prev) = marker_addr.as_deref() {
                if prev != w.address() {
                    tracing::warn!(
                        "--force-new-wallet: abandoning recorded faucet address {prev} in favor of {}",
                        w.address()
                    );
                }
            }
            let addr_path = node_dir.join("faucet-address.txt");
            let tmp_path = node_dir.join("faucet-address.txt.tmp");
            let addr_text = format!("{}\n", w.address());
            match std::fs::write(&tmp_path, addr_text.as_bytes()) {
                Ok(_) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &tmp_path,
                            std::fs::Permissions::from_mode(0o644),
                        );
                    }
                    match std::fs::rename(&tmp_path, &addr_path) {
                        Ok(_) => tracing::info!(
                            "Faucet address written to {} (local-FS mode)",
                            addr_path.display()
                        ),
                        Err(e) => tracing::warn!(
                            "Failed to rename faucet-address.txt: {e} — node will not see updated address until next boot"
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    "Failed to write faucet-address.txt at {}: {e}",
                    tmp_path.display()
                ),
            }
        } else {
            // Legacy mode (no --node-data-dir) lost its address-propagation
            // path with the deletion of storeFaucetSecret. Address visible
            // in the dashboard requires the file-write path above.
            tracing::warn!(
                "No --node-data-dir set — faucet address will not propagate to node \
                 dashboard. Address: {}",
                w.address()
            );
            let _ = is_first_boot;
        }

        Some(w)
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

    // ── Admin token: cache + refresh ──
    // Token is owned by the node (keystore scheme 0x86), visible/rotatable in
    // the node GUI's Faucet settings panel. The faucet binary just consumes
    // it. Cache starts empty; admin endpoint returns 503 until populated
    // (secure-by-default: refuse rather than serve unauthenticated).
    //
    // Two refresh sources, chosen at boot:
    //   • Local-FS  (--node-data-dir set) — watch keystore.noble mtime, re-read
    //     on change. Zero RPC traffic, no secret on the wire.
    //   • RPC       (legacy)              — poll noble_getFaucetAdminToken every
    //     60 s. Kept for back-compat during the Group A migration window.
    let admin_token_cache: admin_auth::AdminTokenCache =
        std::sync::Arc::new(std::sync::RwLock::new(None));

    // Initial seed: local-FS bootstrap may have grabbed the token already.
    if let Some(s) = &local_secrets {
        if let Some(tok) = &s.admin_token_hex {
            tracing::info!(
                task = "faucet_admin",
                fingerprint = %admin_auth_fingerprint(tok),
                "admin token loaded from node keystore (local-FS)"
            );
            if let Ok(mut w) = admin_token_cache.write() {
                *w = Some(tok.clone());
            }
        } else {
            tracing::info!(
                task = "faucet_admin",
                "admin token not yet present in node keystore — will appear after \
                 first noble_getFaucetAdminToken call on the node side; refresh \
                 task will pick it up"
            );
        }
    } else {
        // Legacy RPC fetch at boot.
        match state.rpc.get_faucet_admin_token().await {
            Ok(resp) => {
                tracing::info!(
                    task = "faucet_admin",
                    fingerprint = %resp.fingerprint,
                    "admin token loaded from node (RPC)"
                );
                if let Ok(mut w) = admin_token_cache.write() {
                    *w = Some(resp.token);
                }
            }
            Err(e) => {
                tracing::warn!(
                    task = "faucet_admin",
                    "could not fetch admin token from node at boot ({e}) — admin endpoints will return 503 until refresh succeeds"
                );
            }
        }
    }

    // Refresh task: source depends on bootstrap mode.
    {
        let cache_clone = admin_token_cache.clone();
        let state_clone = state.clone();
        let node_data_dir = cli.node_data_dir.clone();
        let node_keystore_for_refresh = cli.node_keystore.clone();
        let chain_meta_for_refresh = local_secrets
            .as_ref()
            .map(|s| s.chain_meta_hex.clone());
        tokio::spawn(async move {
            let mut last_fp = String::new();
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.tick().await; // discard the immediate first tick

            if let (Some(dir), Some(chain_meta_hex)) = (node_data_dir, chain_meta_for_refresh) {
                // ── Local-FS refresh: check mtime, re-read on change ──
                // Watch the REAL keystore file (--node-keystore override) —
                // watching a guessed path silently kills the hot-reload on
                // layouts where the keystore lives outside data_dir.
                let keystore_path =
                    node_keystore_path(&dir, node_keystore_for_refresh.as_deref());
                let mut last_mtime: Option<std::time::SystemTime> = None;
                loop {
                    tick.tick().await;
                    let mtime = std::fs::metadata(&keystore_path)
                        .ok()
                        .and_then(|m| m.modified().ok());
                    if mtime == last_mtime {
                        continue; // no change, skip the re-read
                    }
                    last_mtime = mtime;
                    match refresh_admin_token_from_disk(
                        &dir,
                        node_keystore_for_refresh.as_deref(),
                        &chain_meta_hex,
                    ) {
                        Ok(Some(tok)) => {
                            let fp = admin_auth_fingerprint(&tok);
                            if fp != last_fp {
                                tracing::info!(
                                    task = "faucet_admin",
                                    fingerprint = %fp,
                                    "admin token refreshed (local-FS, keystore mtime changed)"
                                );
                                last_fp = fp;
                            }
                            if let Ok(mut w) = cache_clone.write() {
                                *w = Some(tok);
                            }
                        }
                        Ok(None) => {
                            tracing::debug!(
                                task = "faucet_admin",
                                "keystore changed but admin token absent — node has not bootstrapped it yet"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(
                                task = "faucet_admin",
                                "local-FS admin token refresh failed ({e}) — keeping last good value"
                            );
                        }
                    }
                }
            }

            // ── Legacy RPC refresh: 60s poll ──
            loop {
                tick.tick().await;
                match state_clone.rpc.get_faucet_admin_token().await {
                    Ok(resp) => {
                        if resp.fingerprint != last_fp {
                            tracing::info!(
                                task = "faucet_admin",
                                fingerprint = %resp.fingerprint,
                                "admin token refreshed (RPC)"
                            );
                            last_fp = resp.fingerprint;
                        }
                        if let Ok(mut w) = cache_clone.write() {
                            *w = Some(resp.token);
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            task = "faucet_admin",
                            "admin token refresh failed ({e}) — keeping last good value"
                        );
                    }
                }
            }
        });
    }

    // Public faucet CORS — unchanged (token form must work cross-origin).
    let public_cors = tower_http::cors::CorsLayer::permissive();
    // Admin endpoint: same-origin only, no permissive CORS.
    let admin_cors = tower_http::cors::CorsLayer::new()
        .allow_methods([axum::http::Method::POST, axum::http::Method::OPTIONS]);
    let admin_auth_layer = admin_auth::AdminAuthLayer::new(admin_token_cache.clone());

    // Gatekeeper: require `Gatekeeper: noble` header on all requests.
    // Drops drive-by scanners before they touch application logic.
    let gatekeeper = axum::middleware::from_fn(gatekeeper_middleware);

    // Split routes:
    //   public  → permissive CORS, no auth (token-distribution form must work
    //             from any origin)
    //   admin   → tight CORS + AdminAuthLayer bearer check
    let public_routes = Router::new()
        .route("/api/faucet", post(handlers::handle_faucet))
        .route("/api/faucet/status", get(handlers::handle_status))
        .with_state(state.clone())
        .layer(public_cors);
    let admin_routes = Router::new()
        .route("/api/faucet/reset-limits", post(handlers::handle_reset_limits))
        .with_state(state)
        .layer(admin_cors)
        .layer(admin_auth_layer);

    let mut app = Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .layer(gatekeeper);

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
    fn creation_refusal_rules() {
        // (recorded_address, force) → refuse?
        assert!(!should_refuse_creation(None, false), "true first run: create freely");
        assert!(!should_refuse_creation(None, true));
        assert!(
            should_refuse_creation(Some("nbl1recorded"), false),
            "prior address on record without --force-new-wallet MUST refuse"
        );
        assert!(!should_refuse_creation(Some("nbl1recorded"), true), "force overrides");
    }

    #[test]
    fn rotation_guard_rules() {
        // (recorded, current, force) → allowed?
        assert!(address_rotation_allowed(None, "nbl1a", false), "no record: allowed");
        assert!(address_rotation_allowed(Some("nbl1a"), "nbl1a", false), "same address: allowed");
        assert!(
            !address_rotation_allowed(Some("nbl1a"), "nbl1b", false),
            "DIFFERENT address without force MUST be refused"
        );
        assert!(address_rotation_allowed(Some("nbl1a"), "nbl1b", true), "force overrides");
    }

    #[test]
    fn marker_address_read() {
        let dir = tempfile::tempdir().unwrap();
        // Absent dir / absent file / empty file → None.
        assert_eq!(read_marker_address(None), None);
        assert_eq!(read_marker_address(Some(dir.path())), None);
        std::fs::write(dir.path().join("faucet-address.txt"), "  \n").unwrap();
        assert_eq!(read_marker_address(Some(dir.path())), None);
        // Real content → trimmed address.
        std::fs::write(dir.path().join("faucet-address.txt"), "nbl1abc\n").unwrap();
        assert_eq!(read_marker_address(Some(dir.path())).as_deref(), Some("nbl1abc"));
    }

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
        assert_eq!(cli.rpc_url, "https://127.0.0.1:8783");
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
