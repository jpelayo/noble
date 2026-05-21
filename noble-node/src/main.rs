// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE protocol node binary — orchestrates all subsystems.

mod bridge;
pub mod ca_store;
mod config;
pub mod faucet_probe;
mod gui_server;
pub mod healing;
mod tls_cert;
#[allow(unused)]
mod lock_order;
pub mod metrics;
mod node;
mod pidfile;
pub mod pkcs12;
mod providers;
mod setup;
pub mod startup;
mod status;
pub mod trace;

use std::sync::Arc;

use clap::{CommandFactory, Parser};
use noble_api::trace_types::TraceHandle;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "noble-node", about = "NOBLE blockchain node", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start the node daemon
    Run {
        /// Path to TOML configuration file
        #[arg(default_value_t = default_config())]
        config: String,
        /// Use in-memory storage instead of RocksDB
        #[arg(long)]
        memory: bool,
        /// Write PID to this file for stop/restart
        #[arg(long, default_value = "noble.pid")]
        pid_file: String,
        /// Run in background (daemonize)
        #[arg(short, long)]
        daemon: bool,
    },
    /// Stop a running node
    Stop {
        /// PID file path
        #[arg(long, default_value = "noble.pid")]
        pid_file: String,
    },
    /// Stop then start the node
    Restart {
        /// Path to TOML configuration file
        #[arg(default_value_t = default_config())]
        config: String,
        /// PID file path
        #[arg(long, default_value = "noble.pid")]
        pid_file: String,
        /// Use in-memory storage instead of RocksDB
        #[arg(long)]
        memory: bool,
    },
    /// Show node status (running/stopped, chain height, peers, etc.)
    Status {
        /// RPC endpoint to query
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc: String,
        /// PID file to check process state
        #[arg(long, default_value = "noble.pid")]
        pid_file: String,
        /// TOTP code (if auth enabled)
        #[arg(long)]
        totp: Option<String>,
    },
    /// Interactive setup wizard — create or edit noble.toml
    Setup {
        /// Output configuration file path
        #[arg(short, long, default_value_t = default_config())]
        config: String,
    },
    /// Show connected peers
    Peers {
        /// RPC endpoint to query
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc: String,
        /// TOTP code (if auth enabled)
        #[arg(long)]
        totp: Option<String>,
    },
    /// Show consensus cycle status and validator list
    Consensus {
        /// RPC endpoint to query
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc: String,
        /// TOTP code (if auth enabled)
        #[arg(long)]
        totp: Option<String>,
    },
    /// Validate a configuration file without starting the node
    #[command(name = "config")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Generate shell completions for bash, zsh, fish, or PowerShell
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Print the SHA-256 fingerprint of the TLS certificate
    TlsFingerprint {
        /// Path to TOML configuration file (to locate the data directory)
        #[arg(default_value_t = default_config())]
        config: String,
    },
}

#[derive(clap::Subcommand)]
enum ConfigAction {
    /// Validate a TOML configuration file
    Validate {
        /// Path to configuration file
        #[arg(default_value = "noble.toml")]
        config: String,
    },
}

// ---------------------------------------------------------------------------
// Platform-aware config path helper
// ---------------------------------------------------------------------------

fn default_config() -> String {
    noble_core::paths::platform_config_path()
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Legacy backward-compat arg rewriting
// ---------------------------------------------------------------------------

/// Rewrite legacy invocations to the new subcommand format.
///
/// - `noble-node` → unchanged (Option<Commands> = None → default Run)
/// - `noble-node noble.toml` → `noble-node run noble.toml`
/// - `noble-node noble.toml --memory` → `noble-node run noble.toml --memory`
fn rewrite_legacy_args() -> Vec<String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        return args;
    }

    let known = [
        "run",
        "stop",
        "restart",
        "status",
        "setup",
        "peers",
        "consensus",
        "config",
        "completions",
        "tls-fingerprint",
        "help",
    ];
    let first = args[1].to_lowercase();

    // Already using new CLI format or built-in flags
    if known.contains(&first.as_str())
        || first.starts_with("--help")
        || first == "-h"
        || first.starts_with("--version")
        || first == "-v"
    {
        return args;
    }

    // Legacy invocation: prepend "run" subcommand
    let mut rewritten = vec![args[0].clone(), "run".into()];
    rewritten.extend(args[1..].iter().cloned());
    rewritten
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Ensure rustls has a CryptoProvider (ring) before any TLS usage.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse_from(rewrite_legacy_args());

    let command = cli.command.unwrap_or(Commands::Run {
        config: default_config(),
        memory: false,
        pid_file: "noble.pid".into(),
        daemon: false,
    });

    match command {
        Commands::Run {
            config,
            memory,
            pid_file,
            daemon,
        } => {
            run_node(&config, memory, &pid_file, daemon).await;
        }
        Commands::Stop { pid_file } => {
            pidfile::stop_node(&pid_file);
        }
        Commands::Restart {
            config,
            pid_file,
            memory,
        } => {
            pidfile::stop_node(&pid_file);
            run_node(&config, memory, &pid_file, false).await;
        }
        Commands::Status {
            rpc,
            pid_file,
            totp,
        } => {
            status::show_status(&rpc, &pid_file, totp.as_deref());
        }
        Commands::Setup { config } => {
            if let Err(e) = setup::run_setup(&config) {
                eprintln!("Setup failed: {e}");
                std::process::exit(1);
            }
        }
        Commands::Peers { rpc, totp } => {
            status::show_peers(&rpc, totp.as_deref());
        }
        Commands::Consensus { rpc, totp } => {
            status::show_consensus(&rpc, totp.as_deref());
        }
        Commands::Config { action } => match action {
            ConfigAction::Validate { config } => {
                config::validate_config_file(&config);
            }
        },
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "noble-node", &mut std::io::stdout());
        }
        Commands::TlsFingerprint { config } => {
            let cfg = match config::NodeConfig::from_file(std::path::Path::new(&config)) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Failed to load config from {config}: {e}");
                    std::process::exit(1);
                }
            };
            match tls_cert::certificate_fingerprint(&cfg.storage.data_dir) {
                Some(fp) => println!("SHA-256: {fp}"),
                None => {
                    eprintln!(
                        "No TLS certificate found in {} (run the node once with tls_enabled = true to generate it)",
                        cfg.storage.data_dir.display()
                    );
                    std::process::exit(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap config for headless (no-TTY) first start
// ---------------------------------------------------------------------------

/// Generate a minimal `noble.toml` so the node can boot into GUI setup mode.
///
/// Called when no config file exists and the process has no terminal (e.g.
/// launched by launchd / systemd / `brew services`). The config uses all
/// defaults with `remote_setup = true` so the operator can complete setup
/// via the web GUI at https://<host>:8785.
fn generate_bootstrap_config(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut cfg = config::NodeConfig::default();
    // Allow remote access to the setup wizard (operator may not be on localhost).
    cfg.api.remote_setup = true;
    // Use platform-aware absolute data directory (not the relative "data" default).
    cfg.storage.data_dir = noble_core::paths::platform_data_dir();

    let toml_str = toml::to_string_pretty(&cfg)?;

    // Ensure parent directory exists.
    if let Some(parent) = std::path::Path::new(config_path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    std::fs::write(config_path, toml_str)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Run command implementation
// ---------------------------------------------------------------------------

async fn run_node(config_path: &str, use_memory: bool, pid_file: &str, _daemon: bool) {
    // --- Setup gate ---------------------------------------------------------
    // If no config file exists, decide how to handle based on terminal availability.
    if !std::path::Path::new(config_path).exists() {
        use std::io::IsTerminal;
        if std::io::stdin().is_terminal() {
            // Interactive terminal — offer the CLI setup wizard.
            if !setup::prompt_missing_config(config_path) {
                return; // User chose Exit, or setup failed.
            }
            // Setup completed — config file now exists; fall through to load it.
        } else {
            // No terminal (launched by launchd/systemd/brew services).
            // Generate a minimal bootstrap config and start in GUI setup mode.
            eprintln!("No configuration found at {config_path}");
            eprintln!("No terminal detected — generating bootstrap config for GUI setup...");
            if let Err(e) = generate_bootstrap_config(config_path) {
                eprintln!("Failed to generate bootstrap config: {e}");
                std::process::exit(1);
            }
            eprintln!("Bootstrap config written to {config_path}");
            eprintln!("Complete setup at https://127.0.0.1:8785 (or https://<this-host>:8785 if remote)");
        }
    }

    // Load config first (before tracing init, so we can read [trace] config).
    let config = match config::NodeConfig::from_file(std::path::Path::new(config_path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config from {config_path}: {e}");
            std::process::exit(1);
        }
    };

    // Initialize tracing from config (replaces tracing_subscriber::fmt()).
    let trace_config = trace::TraceConfig {
        buffer_capacity: config.trace.buffer_capacity,
        initial_filter: config.trace.initial_filter.clone(),
        stderr_enabled: config.trace.stderr_enabled,
    };
    let trace_handle = trace::init_tracing(&trace_config);

    tracing::info!("NOBLE node v{}", noble_core::SOFTWARE_VERSION);
    tracing::info!("Loading config from {config_path}");
    tracing::info!("Config loaded successfully");

    // Write PID file for stop/restart/status
    if let Err(e) = pidfile::write_pid(pid_file) {
        tracing::warn!("Failed to write PID file: {e}");
    }

    let cfg_path = Some(std::path::PathBuf::from(config_path));

    // Prompt for encryption password if manual mode is configured.
    let encryption_password: Option<String> = if config.security.encryption_mode == "manual" {
        tracing::info!("Manual encryption mode — password required to unlock key files");
        eprintln!();
        eprintln!("  Encryption mode: manual");
        eprintln!("  Enter the encryption password to unlock key files.");
        eprintln!();
        match dialoguer::Password::new()
            .with_prompt("  Encryption password")
            .interact()
        {
            Ok(pw) if !pw.is_empty() => Some(pw),
            Ok(_) => {
                eprintln!("  Empty password not allowed in manual mode.");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("  Failed to read password: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let exit_code = if use_memory {
        tracing::info!("Using in-memory storage (--memory flag)");
        run_with_memory(&config, trace_handle, cfg_path).await
    } else {
        tracing::info!(
            "RocksDB mode — data_dir: {}",
            config.storage.data_dir.display()
        );
        run_with_rocksdb(&config, trace_handle, cfg_path, encryption_password.as_deref()).await
    };

    // Cleanup PID file on exit
    let _ = pidfile::remove_pid(pid_file);

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

/// Create Prometheus metrics if enabled in the configuration.
fn init_metrics(config: &config::NodeConfig) -> Option<metrics::NobleMetrics> {
    if config.metrics.enabled {
        Some(metrics::NobleMetrics::new())
    } else {
        tracing::info!("Prometheus metrics disabled by config");
        None
    }
}

async fn run_with_memory(config: &config::NodeConfig, trace_handle: Arc<TraceHandle>, config_path: Option<std::path::PathBuf>) -> i32 {
    match node::Node::init_memory(config) {
        Ok(n) => {
            tracing::info!("Node initialized — chain height: {}", n.chain_height());
            let metrics = init_metrics(config);
            if let Err(e) = n.run(config, Some(trace_handle), metrics, config_path).await {
                tracing::error!("Node exited with error: {e}");
                eprintln!("FATAL: Node exited with error: {e}");
                return 1;
            }
            0
        }
        Err(e) => {
            tracing::error!("Failed to initialize node: {e}");
            eprintln!("FATAL: Failed to initialize node: {e}");
            1
        }
    }
}

async fn run_with_rocksdb(config: &config::NodeConfig, trace_handle: Arc<TraceHandle>, config_path: Option<std::path::PathBuf>, encryption_password: Option<&str>) -> i32 {
    // Ensure data directory exists before opening storage.
    if !config.storage.data_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(&config.storage.data_dir) {
            tracing::error!("Failed to create data directory {}: {e}", config.storage.data_dir.display());
            eprintln!("FATAL: Failed to create data directory {}: {e}", config.storage.data_dir.display());
            return 1;
        }
    }

    // --- Multi-path sharding wiring ---
    // 1) Validate `[storage]` sharding config (absolute paths, no
    //    duplicates, no clash with data_dir). Catches operator mistakes
    //    BEFORE RocksDB ever touches the extra tiers.
    if let Err(e) = config.validate_storage_paths() {
        tracing::error!("storage config invalid: {e}");
        eprintln!("FATAL: storage config invalid: {e}");
        return 1;
    }
    // 2) Resolve the tier list: mkdir each, chmod 0700, compute
    //    target_bytes (auto from free space for Shape A, explicit for
    //    Shape B).
    let extras = match startup::compute_db_paths(&config.storage) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("storage tier resolution failed: {e}");
            eprintln!("FATAL: storage tier resolution failed: {e}");
            return 1;
        }
    };
    startup::log_storage_paths(&config.storage.data_dir, &extras);

    // 3) Pre-open discovery + reconciliation (skipped when
    //    reconcile_mode == Off, or no tiers AND no catalog at primary).
    let reconcile_mode = config.storage.reconcile_mode;
    if reconcile_mode != config::ReconcileMode::Off {
        // Audit Fix #4: discovery must hash discovered SSTs so the
        // move-detection in `decide()` can verify identity (size +
        // hash match) rather than just filename. Hashing N SSTs at
        // boot is O(total bytes / SSD bandwidth) — a few seconds for
        // a multi-TB archive node, paid once per startup as the cost
        // of safe RocksDB repair.
        let report = match noble_storage::discover_shards(
            &config.storage.data_dir,
            &extras,
            None, // chain_id check happens AFTER open; pre-open we don't have it
            /* with_hash */ true,
        ) {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("storage discovery failed: {e}");
                eprintln!("FATAL: storage discovery failed: {e}");
                return 1;
            }
        };
        startup::log_discovery_summary(&report);
        let decision = noble_storage::decide(&report);
        startup::log_decision(&decision);
        match decision {
            noble_storage::ReconcileDecision::OpenNormally => {}
            noble_storage::ReconcileDecision::RepairThenOpen { reason } => {
                if reconcile_mode == config::ReconcileMode::Verify {
                    tracing::error!(
                        "reconcile_mode = \"verify\" and catalog/disk diverged: {reason}"
                    );
                    eprintln!(
                        "FATAL: reconcile_mode = verify and catalog/disk diverged: {reason}"
                    );
                    return 1;
                }
                tracing::warn!("running multi-path repair: {reason}");
                let repair_cfg = noble_storage::RocksDbConfig {
                    db_paths: extras.clone(),
                    ..Default::default()
                };
                if let Err(e) = noble_storage::RocksDbStorage::repair_multi_path(
                    &config.storage.data_dir,
                    &repair_cfg,
                ) {
                    tracing::error!("multi-path repair failed: {e}");
                    eprintln!("FATAL: multi-path repair failed: {e}");
                    return 1;
                }
                tracing::info!(task = "shard_discovery", "repair complete; opening DB");
            }
            noble_storage::ReconcileDecision::Fail { reason, suggestion } => {
                eprintln!("FATAL: storage reconciliation failed: {reason}");
                eprintln!("Suggestion: {suggestion}");
                return 1;
            }
        }
    } else {
        tracing::info!(
            task = "shard_discovery",
            "reconcile_mode = off — skipping discovery"
        );
    }

    // 4) Open the DB with the resolved tiers.
    let rocks_cfg = noble_storage::RocksDbConfig {
        block_cache_size: (config.storage.cache_size_mb as usize) * 1024 * 1024,
        bloom_filter_bits: 10,
        enable_compression: config.storage.compression,
        db_paths: extras.clone(),
    };
    match noble_storage::RocksDbStorage::open_with_config_and_repair(
        &config.storage.data_dir,
        &rocks_cfg,
    ) {
        Ok(storage) => match node::Node::init_with_storage(config, storage, encryption_password, extras.clone()) {
            Ok(n) => {
                tracing::info!("Node initialized — chain height: {}", n.chain_height());

                // Run initial integrity check on recent blocks
                let report = n.verify_recent_blocks(100);
                if report.is_clean() {
                    tracing::info!(
                        "Integrity check passed ({} blocks verified)",
                        report.heights_checked
                    );
                } else {
                    tracing::warn!(
                        "Integrity issues found: {} findings, first at height {:?}",
                        report.findings.len(),
                        report.first_corrupt_height
                    );
                }

                let metrics = init_metrics(config);
                if let Err(e) = n.run(config, Some(trace_handle), metrics, config_path).await {
                    tracing::error!("Node exited with error: {e}");
                    eprintln!("FATAL: Node exited with error: {e}");
                    return 1;
                }
                0
            }
            Err(e) => {
                tracing::error!("Failed to initialize node: {e}");
                eprintln!("FATAL: Failed to initialize node: {e}");
                1
            }
        },
        Err(e) => {
            tracing::error!("Failed to open storage: {e}");
            eprintln!("FATAL: Failed to open storage: {e}");
            1
        }
    }
}
