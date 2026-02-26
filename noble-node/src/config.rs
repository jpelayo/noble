// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! NOBLE node configuration schema.
//!
//! Deserialized from `noble.toml`. Each section maps to a subsystem.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level node configuration.
#[derive(Debug, Default, Deserialize, Serialize)]
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
    /// Gateway fee-split configuration.
    #[serde(default)]
    pub gateway: GatewayConfig,
}

/// Operational role of the node binary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    #[default]
    Mainnet,
    Testnet,
    Regtest,
}

impl NetworkId {
    /// Return the chain ID constant for this network.
    pub fn chain_id(self) -> u32 {
        match self {
            Self::Mainnet => noble_core::MAINNET_CHAIN_ID,
            Self::Testnet => noble_core::TESTNET_CHAIN_ID,
            Self::Regtest => noble_core::REGTEST_CHAIN_ID,
        }
    }

    /// Construct the genesis block for this network.
    pub fn genesis_block(self) -> noble_core::Block {
        match self {
            Self::Mainnet => noble_core::genesis_block(),
            Self::Testnet => noble_core::testnet_genesis_block(),
            Self::Regtest => noble_core::regtest_genesis_block(),
        }
    }
}

/// `[node]` section — operational mode and network selection.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct NodeSectionConfig {
    /// Operational role: validator, observer, or light.
    #[serde(default)]
    pub role: OperationalRole,
    /// Target network: mainnet, testnet, or regtest.
    #[serde(default)]
    pub network: NetworkId,
}

/// P2P networking configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub seeds: Vec<String>,
    pub max_peers: u32,
    pub ban_threshold: u32,
}

/// RocksDB storage configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub cache_size_mb: u32,
    pub compression: bool,
}

/// PoR consensus configuration.
#[derive(Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
pub struct ApiConfig {
    pub rpc_addr: String,
    pub ws_addr: String,
    pub max_connections: u32,
    pub rate_limit: u32,
    /// Enable TOTP-based authentication for all RPC methods.
    #[serde(default)]
    pub totp_enabled: bool,
    /// TOTP enforcement scope: "all" (every request), "write_only" (only mutations),
    /// or "none" (disabled, same as totp_enabled=false).
    /// Defaults to "all" when totp_enabled=true.
    #[serde(default = "default_totp_scope")]
    pub totp_scope: String,
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

fn default_totp_scope() -> String {
    "all".to_string()
}

fn default_gui_addr() -> String {
    "127.0.0.1:8785".to_string()
}

/// Wallet keystore configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct WalletConfig {
    pub keystore_path: PathBuf,
}

/// Logging configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: String,
    pub rotation: String,
}

/// Prometheus metrics configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub prometheus_addr: String,
    pub enabled: bool,
}

/// Runtime tracing configuration.
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Deserialize, Serialize)]
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

/// `[gateway]` section — fee-split gateway key configuration.
#[derive(Debug, Deserialize, Serialize)]
pub struct GatewayConfig {
    /// Path to a file containing the gateway public key (hex-encoded wire bytes).
    /// If set, the key is loaded from this file instead of being auto-derived
    /// from the first wallet key.
    #[serde(default)]
    pub key_path: String,
    /// Enable gateway fee split. When true and a key is available (from key_path
    /// or auto-derived from the first wallet key), outgoing transactions include
    /// the gateway address for 50/50 fee splitting.
    #[serde(default = "default_gateway_enabled")]
    pub enabled: bool,
}

fn default_gateway_enabled() -> bool {
    true
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            key_path: String::new(),
            enabled: default_gateway_enabled(),
        }
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

/// Validate a configuration file and print the result.
///
/// Returns exit code 0 on success, 1 on error.
pub fn validate_config_file(path: &str) {
    let p = std::path::Path::new(path);
    if !p.exists() {
        eprintln!("Error: configuration file not found: {path}");
        std::process::exit(1);
    }
    match NodeConfig::from_file(p) {
        Ok(config) => {
            println!("Configuration file is valid: {path}");
            println!();
            println!("  Network:       {:?}", config.node.network);
            println!("  Role:          {:?}", config.node.role);
            println!("  P2P listen:    {}", config.network.listen_addr);
            println!("  RPC addr:      {}", config.api.rpc_addr);
            println!("  WS addr:       {}", config.api.ws_addr);
            println!("  GUI addr:      {}", config.api.gui_addr);
            println!("  Data dir:      {}", config.storage.data_dir.display());
            println!(
                "  Metrics:       {}",
                if config.metrics.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!(
                "  TOTP auth:     {}",
                if config.api.totp_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
        }
        Err(e) => {
            eprintln!("Error: invalid configuration file: {path}");
            eprintln!("  {e}");
            std::process::exit(1);
        }
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
            totp_scope: default_totp_scope(),
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
    fn network_id_chain_id_and_genesis() {
        assert_eq!(NetworkId::Mainnet.chain_id(), noble_core::MAINNET_CHAIN_ID);
        assert_eq!(NetworkId::Testnet.chain_id(), noble_core::TESTNET_CHAIN_ID);
        assert_eq!(NetworkId::Regtest.chain_id(), noble_core::REGTEST_CHAIN_ID);

        // Each network produces a distinct genesis block
        let m = NetworkId::Mainnet.genesis_block();
        let t = NetworkId::Testnet.genesis_block();
        let r = NetworkId::Regtest.genesis_block();
        assert_ne!(m.header.validator_id, t.header.validator_id);
        assert_ne!(t.header.validator_id, r.header.validator_id);
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

    // ── TOML round-trip tests (Part E5) ──

    #[test]
    fn node_config_default_round_trips_through_toml() {
        let original = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&original).expect("serialize default config");
        let parsed: NodeConfig =
            toml::from_str(&toml_str).expect("deserialize round-tripped config");

        assert_eq!(parsed.node.role, original.node.role);
        assert_eq!(parsed.node.network, original.node.network);
        assert_eq!(parsed.network.listen_addr, original.network.listen_addr);
        assert_eq!(parsed.network.max_peers, original.network.max_peers);
        assert_eq!(parsed.storage.cache_size_mb, original.storage.cache_size_mb);
        assert_eq!(parsed.storage.compression, original.storage.compression);
        assert_eq!(parsed.api.rpc_addr, original.api.rpc_addr);
        assert_eq!(parsed.api.ws_addr, original.api.ws_addr);
        assert_eq!(parsed.api.gui_addr, original.api.gui_addr);
        assert_eq!(parsed.api.totp_enabled, original.api.totp_enabled);
        assert_eq!(parsed.logging.level, original.logging.level);
        assert_eq!(parsed.metrics.enabled, original.metrics.enabled);
        assert_eq!(parsed.identity.org_type, original.identity.org_type);
        assert_eq!(parsed.identity.node_role, original.identity.node_role);
        assert_eq!(parsed.trace.buffer_capacity, original.trace.buffer_capacity);
        assert_eq!(parsed.trace.initial_filter, original.trace.initial_filter);
    }

    #[test]
    fn node_config_with_values_round_trips() {
        let mut config = NodeConfig::default();
        config.node.role = OperationalRole::Validator;
        config.node.network = NetworkId::Testnet;
        config.network.listen_addr = "/ip4/0.0.0.0/tcp/9999".to_string();
        config.network.max_peers = 100;
        config.network.seeds = vec![
            "/ip4/1.2.3.4/tcp/8780".to_string(),
            "/ip4/5.6.7.8/tcp/8780".to_string(),
        ];
        config.storage.data_dir = PathBuf::from("/var/noble/data");
        config.storage.cache_size_mb = 512;
        config.storage.compression = false;
        config.consensus.validator_key_path = "validator.key".to_string();
        config.consensus.voting_strategy = "round_robin".to_string();
        config.api.totp_enabled = true;
        config.api.totp_secret_file = "totp.secret".to_string();
        config.api.allowed_ips = vec!["192.168.1.0/24".to_string()];
        config.identity.node_name = "test-node".to_string();
        config.identity.org_type = "PrivateCorporation".to_string();
        config.identity.wants_to_validate = true;
        config.identity.wants_to_vote = true;
        config.trace.buffer_capacity = 100_000;
        config.trace.stderr_enabled = true;

        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let parsed: NodeConfig = toml::from_str(&toml_str).expect("deserialize");

        assert_eq!(parsed.node.role, OperationalRole::Validator);
        assert_eq!(parsed.node.network, NetworkId::Testnet);
        assert_eq!(parsed.network.listen_addr, "/ip4/0.0.0.0/tcp/9999");
        assert_eq!(parsed.network.max_peers, 100);
        assert_eq!(parsed.network.seeds.len(), 2);
        assert_eq!(parsed.storage.data_dir, PathBuf::from("/var/noble/data"));
        assert_eq!(parsed.storage.cache_size_mb, 512);
        assert!(!parsed.storage.compression);
        assert_eq!(parsed.consensus.validator_key_path, "validator.key");
        assert_eq!(parsed.consensus.voting_strategy, "round_robin");
        assert!(parsed.api.totp_enabled);
        assert_eq!(parsed.api.totp_secret_file, "totp.secret");
        assert_eq!(parsed.api.allowed_ips, vec!["192.168.1.0/24"]);
        assert_eq!(parsed.identity.node_name, "test-node");
        assert!(parsed.identity.wants_to_validate);
        assert!(parsed.identity.wants_to_vote);
        assert_eq!(parsed.trace.buffer_capacity, 100_000);
        assert!(parsed.trace.stderr_enabled);
    }

    #[test]
    fn serialized_config_contains_all_sections() {
        let config = NodeConfig::default();
        let toml_str = toml::to_string_pretty(&config).expect("serialize");

        assert!(toml_str.contains("[node]"), "missing [node]");
        assert!(toml_str.contains("[network]"), "missing [network]");
        assert!(toml_str.contains("[storage]"), "missing [storage]");
        assert!(toml_str.contains("[consensus]"), "missing [consensus]");
        assert!(toml_str.contains("[api]"), "missing [api]");
        assert!(toml_str.contains("[wallet]"), "missing [wallet]");
        assert!(toml_str.contains("[logging]"), "missing [logging]");
        assert!(toml_str.contains("[metrics]"), "missing [metrics]");
        assert!(toml_str.contains("[identity]"), "missing [identity]");
        assert!(toml_str.contains("[trace]"), "missing [trace]");
    }

    #[test]
    fn all_network_variants_round_trip() {
        for (variant, expected_str) in [
            (NetworkId::Mainnet, "mainnet"),
            (NetworkId::Testnet, "testnet"),
            (NetworkId::Regtest, "regtest"),
        ] {
            let mut config = NodeConfig::default();
            config.node.network = variant;
            let toml_str = toml::to_string_pretty(&config).expect("serialize");
            assert!(toml_str.contains(expected_str), "expected '{expected_str}'");
            let parsed: NodeConfig = toml::from_str(&toml_str).expect("deserialize");
            assert_eq!(parsed.node.network, variant);
        }
    }

    #[test]
    fn all_role_variants_round_trip() {
        for (variant, expected_str) in [
            (OperationalRole::Validator, "validator"),
            (OperationalRole::Observer, "observer"),
            (OperationalRole::Light, "light"),
        ] {
            let mut config = NodeConfig::default();
            config.node.role = variant;
            let toml_str = toml::to_string_pretty(&config).expect("serialize");
            assert!(toml_str.contains(expected_str), "expected '{expected_str}'");
            let parsed: NodeConfig = toml::from_str(&toml_str).expect("deserialize");
            assert_eq!(parsed.node.role, variant);
        }
    }
}
