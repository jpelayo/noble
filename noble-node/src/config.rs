// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE node configuration schema.
//!
//! Deserialized from `noble.toml`. Each section maps to a subsystem.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level node configuration.
#[derive(Debug, Default, Deserialize)]
pub struct NodeConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub consensus: ConsensusConfig,
    pub api: ApiConfig,
    pub wallet: WalletConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub identity: IdentityConfig,
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
    /// Enable TOTP-based authentication for all RPC methods.
    #[serde(default)]
    pub totp_enabled: bool,
    /// Path to the file storing the TOTP shared secret (base32).
    /// If empty and totp_enabled is true, a secret is auto-generated and written here.
    #[serde(default)]
    pub totp_secret_file: String,
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

/// Node identity configuration for PoR self-identification broadcasts.
#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    pub node_name: String,
    pub org_type: String,
    pub org_name: String,
    pub node_role: String,
    /// Optional contact email. WARNING: broadcast publicly to all peers via GossipSub.
    pub contact_email: String,
    pub website: String,
    pub host_address: String,
    /// Whether this node wants to produce blocks.
    #[serde(default)]
    pub wants_to_validate: bool,
    /// Whether this node wants to cast consensus votes.
    #[serde(default)]
    pub wants_to_vote: bool,
}

impl NodeConfig {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/30333".to_string(),
            seeds: Vec::new(),
            max_peers: 50,
            ban_threshold: 100,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("data"),
            cache_size_mb: 256,
            compression: true,
        }
    }
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            validator_key_path: String::new(),
            validator_list_path: PathBuf::from("validators.txt"),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            rpc_addr: "127.0.0.1:9933".to_string(),
            ws_addr: "127.0.0.1:9944".to_string(),
            max_connections: 100,
            rate_limit: 30,
            totp_enabled: false,
            totp_secret_file: String::new(),
        }
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            keystore_path: PathBuf::from("keystore"),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: String::new(),
            rotation: "daily".to_string(),
        }
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus_addr: "127.0.0.1:9615".to_string(),
            enabled: true,
        }
    }
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            node_name: String::new(),
            org_type: "Individual".to_string(),
            org_name: String::new(),
            node_role: "FullNode".to_string(),
            contact_email: String::new(),
            website: String::new(),
            host_address: String::new(),
            wants_to_validate: false,
            wants_to_vote: false,
        }
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
        assert_eq!(config.identity.org_type, "Individual");
        assert_eq!(config.identity.node_role, "FullNode");
        assert!(config.identity.node_name.is_empty());
    }
}
