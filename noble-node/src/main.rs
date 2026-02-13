// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE protocol node binary — orchestrates all subsystems.

// Modules are fully wired once the event loop is complete;
// suppress dead_code warnings until then.
#[allow(dead_code)]
mod bridge;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod node;
#[allow(dead_code)]
mod providers;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Initialize tracing (log output).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).map(|s| s.as_str()).unwrap_or("noble.toml");
    let use_memory = args.iter().any(|a| a == "--memory");

    tracing::info!("NOBLE node v{}", noble_core::PROTOCOL_VERSION);
    tracing::info!("Loading config from {config_path}");

    match config::NodeConfig::from_file(std::path::Path::new(config_path)) {
        Ok(config) => {
            tracing::info!("Config loaded successfully");
            if use_memory {
                tracing::info!("Using in-memory storage (--memory flag)");
                match node::Node::init_memory(&config) {
                    Ok(n) => {
                        tracing::info!("Node initialized — chain height: {}", n.chain_height());
                        // TODO: Node event loop (network + consensus + API) in next sprint.
                        tracing::info!(
                            "Node event loop placeholder — full wiring in next iteration"
                        );
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
                    Ok(storage) => {
                        match node::Node::init_with_storage(&config, storage) {
                            Ok(n) => {
                                tracing::info!(
                                    "Node initialized — chain height: {}",
                                    n.chain_height()
                                );
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
                                tracing::info!(
                                    "Node event loop placeholder — full wiring in next iteration"
                                );
                            }
                            Err(e) => {
                                tracing::error!("Failed to initialize node: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to open storage: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to load config: {e}");
            std::process::exit(1);
        }
    }
}
