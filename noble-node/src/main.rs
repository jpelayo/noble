// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE protocol node binary — orchestrates all subsystems.

mod bridge;
pub mod ca_store;
mod config;
mod gui_server;
mod tls_cert;
#[allow(unused)]
mod lock_order;
pub mod metrics;
mod node;
mod pidfile;
pub mod pkcs12;
mod providers;
mod setup;
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
// Run command implementation
// ---------------------------------------------------------------------------

async fn run_node(config_path: &str, use_memory: bool, pid_file: &str, _daemon: bool) {
    // --- Setup gate ---------------------------------------------------------
    // If no config file exists, offer the setup wizard before doing anything.
    if !std::path::Path::new(config_path).exists() {
        if !setup::prompt_missing_config(config_path) {
            return; // User chose Exit, or setup failed.
        }
        // Setup completed — config file now exists; fall through to load it.
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
    match noble_storage::RocksDbStorage::open_with_repair(&config.storage.data_dir) {
        Ok(storage) => match node::Node::init_with_storage(config, storage, encryption_password) {
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
