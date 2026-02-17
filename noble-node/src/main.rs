// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE protocol node binary — orchestrates all subsystems.

mod bridge;
pub mod ca_store;
#[allow(dead_code)]
mod config;
mod node;
pub mod pkcs12;
mod providers;
pub mod trace;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("noble.toml");
    let use_memory = args.iter().any(|a| a == "--memory");

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

    if use_memory {
        tracing::info!("Using in-memory storage (--memory flag)");
        match node::Node::init_memory(&config) {
            Ok(n) => {
                tracing::info!("Node initialized — chain height: {}", n.chain_height());
                if let Err(e) = n.run(&config, Some(trace_handle)).await {
                    tracing::error!("Node exited with error: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                tracing::error!("Failed to initialize node: {e}");
                std::process::exit(1);
            }
        }
    } else {
        tracing::info!(
            "RocksDB mode — data_dir: {}",
            config.storage.data_dir.display()
        );
        match noble_storage::RocksDbStorage::open_with_repair(&config.storage.data_dir) {
            Ok(storage) => match node::Node::init_with_storage(&config, storage) {
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

                    if let Err(e) = n.run(&config, Some(trace_handle)).await {
                        tracing::error!("Node exited with error: {e}");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to initialize node: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                tracing::error!("Failed to open storage: {e}");
                std::process::exit(1);
            }
        }
    }
}
