// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE node configuration schema.
//!
//! Deserialized from `noble.toml`. Each section maps to a subsystem.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level node configuration.
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub consensus: ConsensusConfig,
    pub api: ApiConfig,
    pub wallet: WalletConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
}

/// P2P networking configuration.
#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub seeds: Vec<String>,
    pub max_peers: u32,
    pub ban_threshold: u32,
}

/// RocksDB storage configuration.
#[derive(Debug, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub cache_size_mb: u32,
    pub compression: bool,
}

/// PoR consensus configuration.
#[derive(Debug, Deserialize)]
pub struct ConsensusConfig {
    pub validator_key_path: String,
    pub validator_list_path: PathBuf,
}

/// JSON-RPC and WebSocket API configuration.
#[derive(Debug, Deserialize)]
pub struct ApiConfig {
    pub rpc_addr: String,
    pub ws_addr: String,
    pub max_connections: u32,
    pub rate_limit: u32,
}

/// Wallet keystore configuration.
#[derive(Debug, Deserialize)]
pub struct WalletConfig {
    pub keystore_path: PathBuf,
}

/// Logging configuration.
#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
    pub rotation: String,
}

/// Prometheus metrics configuration.
#[derive(Debug, Deserialize)]
pub struct MetricsConfig {
    pub prometheus_addr: String,
    pub enabled: bool,
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_config() {
        let toml_str = include_str!("../../noble.toml");
        let config: NodeConfig = toml::from_str(toml_str).expect("default noble.toml must parse");
        assert_eq!(config.network.max_peers, 50);
        assert_eq!(config.storage.cache_size_mb, 256);
        assert!(config.storage.compression);
        assert_eq!(config.api.rpc_addr, "127.0.0.1:9933");
        assert_eq!(config.api.ws_addr, "127.0.0.1:9944");
        assert_eq!(config.logging.level, "info");
        assert!(config.metrics.enabled);
    }
}
