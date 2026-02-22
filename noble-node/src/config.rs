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
    /// Node operational mode and network selection.
    #[serde(default)]
    pub node: NodeSectionConfig,
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub consensus: ConsensusConfig,
    pub api: ApiConfig,
    pub wallet: WalletConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub identity: IdentityConfig,
    /// Runtime tracing configuration.
    #[serde(default)]
    pub trace: TraceConfig,
}

/// Operational role of the node binary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperationalRole {
    /// Full validating node that produces blocks and casts votes.
    Validator,
    /// Full node that does not produce blocks (default).
    #[default]
    Observer,
    /// Light client (headers only, no full block storage).
    Light,
}

/// Network the node connects to.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    #[default]
    Mainnet,
    Testnet,
    Regtest,
}

/// `[node]` section — operational mode and network selection.
#[derive(Debug, Default, Deserialize)]
pub struct NodeSectionConfig {
    /// Operational role: validator, observer, or light.
    #[serde(default)]
    pub role: OperationalRole,
    /// Target network: mainnet, testnet, or regtest.
    #[serde(default)]
    pub network: NetworkId,
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
#[derive(Deserialize)]
pub struct ConsensusConfig {
    pub validator_key_path: String,
    pub validator_list_path: PathBuf,
    /// Voting strategy for Round 1 (Reflection phase).
    /// Values: first_valid, fixed_validator, round_robin, subset_rotation,
    ///         random, weighted_reputation, follow_majority, manual
    #[serde(default = "default_voting_strategy")]
    pub voting_strategy: String,
    /// Voting strategy for Round 2 (Confirmation phase).
    #[serde(default = "default_confirmation_strategy")]
    pub confirmation_strategy: String,
    /// For fixed_validator strategy: hex pubkey of preferred validator.
    #[serde(default)]
    pub voting_preferred_validator: String,
    /// For subset_rotation strategy: hex pubkeys of preferred validators.
    #[serde(default)]
    pub voting_subset: Vec<String>,
}

fn default_voting_strategy() -> String {
    "first_valid".to_string()
}

fn default_confirmation_strategy() -> String {
    "follow_majority".to_string()
}

impl std::fmt::Debug for ConsensusConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusConfig")
            .field(
                "validator_key_path",
                if self.validator_key_path.is_empty() {
                    &"<not set>"
                } else {
                    &"[REDACTED]"
                },
            )
            .field("validator_list_path", &self.validator_list_path)
            .field("voting_strategy", &self.voting_strategy)
            .field("confirmation_strategy", &self.confirmation_strategy)
            .finish()
    }
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
    /// Dashboard GUI HTTP server bind address.
    #[serde(default = "default_gui_addr")]
    pub gui_addr: String,
    /// Path to the GUI static files directory.
    /// If empty, auto-detected relative to the binary.
    #[serde(default)]
    pub gui_dir: String,
    /// Allowed remote IPs or CIDR blocks for RPC/GUI access.
    /// 127.0.0.1 is always allowed. Empty = localhost-only (default).
    /// Example: ["192.168.1.0/24", "10.0.0.5"]
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

fn default_gui_addr() -> String {
    "127.0.0.1:8785".to_string()
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

/// Runtime tracing configuration.
#[derive(Debug, Deserialize)]
pub struct TraceConfig {
    /// Maximum number of entries in the RAM ring buffer.
    #[serde(default = "default_buffer_capacity")]
    pub buffer_capacity: usize,
    /// Initial filter directive (e.g. "info", "noble_core=trace").
    #[serde(default = "default_initial_filter")]
    pub initial_filter: String,
    /// Whether to also output traces to stderr (for development).
    #[serde(default)]
    pub stderr_enabled: bool,
}

fn default_buffer_capacity() -> usize {
    50_000
}
fn default_initial_filter() -> String {
    "info".to_string()
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: default_buffer_capacity(),
            initial_filter: default_initial_filter(),
            stderr_enabled: false,
        }
    }
}

/// Node identity configuration for PoR self-identification broadcasts.
#[derive(Deserialize)]
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
    /// Path to a PKCS#12 (.p12/.pfx) file for one-time PKI identity binding.
    /// The private key is used once to create a CMS signature binding the NOBLE
    /// identity key to the X.509 certificate, then can be removed.
    #[serde(default)]
    pub pkcs12_path: String,
    /// Password for the PKCS#12 file. Redacted in Debug output.
    #[serde(default)]
    pub pkcs12_password: String,
    /// Directory containing trusted CA certificates (PEM/DER) for verifying
    /// PKI attestations from other nodes. Each node maintains its own trust store.
    #[serde(default)]
    pub ca_store_path: String,
}

impl std::fmt::Debug for IdentityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityConfig")
            .field("node_name", &self.node_name)
            .field("org_type", &self.org_type)
            .field("org_name", &self.org_name)
            .field("node_role", &self.node_role)
            .field("contact_email", &self.contact_email)
            .field("website", &self.website)
            .field("host_address", &self.host_address)
            .field("wants_to_validate", &self.wants_to_validate)
            .field("wants_to_vote", &self.wants_to_vote)
            .field("pkcs12_path", &self.pkcs12_path)
            .field(
                "pkcs12_password",
                if self.pkcs12_password.is_empty() {
                    &"<not set>"
                } else {
                    &"[REDACTED]"
                },
            )
            .field("ca_store_path", &self.ca_store_path)
            .finish()
    }
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
            listen_addr: "/ip4/0.0.0.0/tcp/8780".to_string(),
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
            voting_strategy: default_voting_strategy(),
            confirmation_strategy: default_confirmation_strategy(),
            voting_preferred_validator: String::new(),
            voting_subset: Vec::new(),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            rpc_addr: "127.0.0.1:8783".to_string(),
            ws_addr: "127.0.0.1:8784".to_string(),
            max_connections: 100,
            rate_limit: 30,
            totp_enabled: false,
            totp_secret_file: String::new(),
            gui_addr: default_gui_addr(),
            gui_dir: String::new(),
            allowed_ips: Vec::new(),
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
            pkcs12_path: String::new(),
            pkcs12_password: String::new(),
            ca_store_path: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_config_debug_redacts_key_path() {
        let config = ConsensusConfig {
            validator_key_path: "/secret/validator.key".to_string(),
            validator_list_path: std::path::PathBuf::from("validators.txt"),
            voting_strategy: default_voting_strategy(),
            confirmation_strategy: default_confirmation_strategy(),
            voting_preferred_validator: String::new(),
            voting_subset: Vec::new(),
        };
        let debug_str = format!("{config:?}");
        assert!(
            debug_str.contains("[REDACTED]"),
            "Debug output should contain [REDACTED], got: {debug_str}"
        );
        assert!(
            !debug_str.contains("/secret/validator.key"),
            "Debug output should not contain actual key path"
        );
    }

    #[test]
    fn consensus_config_debug_shows_not_set_when_empty() {
        let config = ConsensusConfig::default();
        let debug_str = format!("{config:?}");
        assert!(
            debug_str.contains("<not set>"),
            "Debug output should show <not set> for empty path, got: {debug_str}"
        );
    }

    #[test]
    fn parse_default_config() {
        let toml_str = include_str!("../../noble.toml");
        let config: NodeConfig = toml::from_str(toml_str).expect("default noble.toml must parse");
        assert_eq!(config.node.role, OperationalRole::Observer);
        assert_eq!(config.node.network, NetworkId::Mainnet);
        assert_eq!(config.network.max_peers, 50);
        assert_eq!(config.storage.cache_size_mb, 256);
        assert!(config.storage.compression);
        assert_eq!(config.api.rpc_addr, "127.0.0.1:8783");
        assert_eq!(config.api.ws_addr, "127.0.0.1:8784");
        assert_eq!(config.api.gui_addr, "127.0.0.1:8785");
        assert_eq!(config.logging.level, "info");
        assert!(config.metrics.enabled);
        assert_eq!(config.identity.org_type, "Individual");
        assert_eq!(config.identity.node_role, "FullNode");
        assert!(config.identity.node_name.is_empty());
    }

    #[test]
    fn node_section_defaults_when_missing() {
        // Config without [node] section should use defaults
        let toml_str = r#"
            [network]
            listen_addr = "/ip4/0.0.0.0/tcp/8780"
            seeds = []
            max_peers = 50
            ban_threshold = 100

            [storage]
            data_dir = "data"
            cache_size_mb = 256
            compression = true

            [consensus]
            validator_key_path = ""
            validator_list_path = "validators.txt"

            [api]
            rpc_addr = "127.0.0.1:8783"
            ws_addr = "127.0.0.1:8784"
            max_connections = 100
            rate_limit = 30

            [wallet]
            keystore_path = "keystore"

            [logging]
            level = "info"
            file = ""
            rotation = "daily"

            [metrics]
            prometheus_addr = "127.0.0.1:9615"
            enabled = true

            [identity]
            node_name = ""
            org_type = "Individual"
            org_name = ""
            node_role = "FullNode"
            contact_email = ""
            website = ""
            host_address = ""
        "#;
        let config: NodeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.node.role, OperationalRole::Observer);
        assert_eq!(config.node.network, NetworkId::Mainnet);
    }

    #[test]
    fn all_default_ports_correct() {
        let config = ApiConfig::default();
        assert_eq!(config.rpc_addr, "127.0.0.1:8783");
        assert_eq!(config.ws_addr, "127.0.0.1:8784");
        assert_eq!(config.gui_addr, "127.0.0.1:8785");

        let net = NetworkConfig::default();
        assert_eq!(net.listen_addr, "/ip4/0.0.0.0/tcp/8780");
    }

    // T10: Default allowed_ips is empty vec
    #[test]
    fn default_allowed_ips_empty() {
        let config = ApiConfig::default();
        assert!(config.allowed_ips.is_empty());
    }

    // T11: Config with allowed_ips parses correctly
    #[test]
    fn config_allowed_ips_parses() {
        let toml_str = r#"
            [node]
            [network]
            listen_addr = "/ip4/0.0.0.0/tcp/8780"
            seeds = []
            max_peers = 50
            ban_threshold = 100

            [storage]
            data_dir = "data"
            cache_size_mb = 256
            compression = true

            [consensus]
            validator_key_path = ""
            validator_list_path = "validators.txt"

            [api]
            rpc_addr = "127.0.0.1:8783"
            ws_addr = "127.0.0.1:8784"
            max_connections = 100
            rate_limit = 30
            allowed_ips = ["192.168.1.0/24", "10.0.0.5"]

            [wallet]
            keystore_path = "keystore"

            [logging]
            level = "info"
            file = ""
            rotation = "daily"

            [metrics]
            prometheus_addr = "127.0.0.1:9615"
            enabled = true

            [identity]
            node_name = ""
            org_type = "Individual"
            org_name = ""
            node_role = "FullNode"
            contact_email = ""
            website = ""
            host_address = ""
        "#;
        let config: NodeConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.api.allowed_ips.len(), 2);
        assert_eq!(config.api.allowed_ips[0], "192.168.1.0/24");
        assert_eq!(config.api.allowed_ips[1], "10.0.0.5");
    }

    #[test]
    fn node_section_parses_all_variants() {
        for (role_str, expected_role) in [
            ("validator", OperationalRole::Validator),
            ("observer", OperationalRole::Observer),
            ("light", OperationalRole::Light),
        ] {
            let toml_str = format!(
                r#"[node]
                role = "{role_str}"
                network = "testnet"
                "#
            );
            // Parse just the node section
            #[derive(Deserialize)]
            struct Partial {
                node: NodeSectionConfig,
            }
            let p: Partial = toml::from_str(&toml_str).unwrap();
            assert_eq!(p.node.role, expected_role, "role={role_str}");
            assert_eq!(p.node.network, NetworkId::Testnet);
        }
    }
}
