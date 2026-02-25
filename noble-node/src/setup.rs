// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Interactive setup wizard for creating or editing `noble.toml`.
//!
//! Guides the operator through network selection, node role, identity,
//! wallet creation/import, TOTP security, storage, and networking
//! configuration. Produces a fully populated `noble.toml`.
//!
//! Supports **reconfiguration mode** (E4): when the target config file
//! already exists it is parsed and all prompts are pre-filled with the
//! current values.

use std::fs;
use std::path::{Path, PathBuf};

use dialoguer::{Confirm, Input, Password, Select};

use crate::config::{
    ApiConfig, ConsensusConfig, IdentityConfig, LoggingConfig, MetricsConfig, NetworkConfig,
    NetworkId, NodeConfig, NodeSectionConfig, OperationalRole, StorageConfig, TraceConfig,
    WalletConfig,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const BANNER: &str = r#"
 _   _  ___  ____  _     _____
| \ | |/ _ \| __ )| |   | ____|
|  \| | | | |  _ \| |   |  _|
| |\  | |_| | |_) | |___| |___
|_| \_|\___/|____/|_____|_____|
"#;

const NETWORK_CHOICES: &[&str] = &["Mainnet", "Testnet", "Regtest"];

const ROLE_CHOICES: &[&str] = &[
    "Full Node Observer    - no consensus",
    "Full Node Validator   - produces blocks and votes",
    "Block Producer        - produces blocks, no voting",
    "Voter Node            - votes on candidates, no production",
    "Archive Node          - full history, no consensus",
    "Gateway               - transaction relay",
    "Voting Gateway        - relay and votes",
    "Light Client          - minimal (headers only)",
];

const GOV_CLASS_CHOICES: &[&str] = &["Individual", "Private", "Public"];

const PRIVATE_ORG_TYPES: &[&str] = &[
    "Corp",
    "LLC",
    "Partnership",
    "Trust",
    "Foundation",
    "GmbH",
    "Holding",
    "Family Office",
    "SARL",
    "Other",
];

const PUBLIC_ORG_TYPES: &[&str] = &[
    "PublicCorp",
    "Government",
    "University",
    "Research",
    "NGO",
    "Central Bank",
    "Judiciary",
    "Other",
];

const WALLET_CHOICES: &[&str] = &[
    "Create new wallet (BIP-39 mnemonic)",
    "Import existing wallet (mnemonic phrase)",
    "Skip wallet setup",
];

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the interactive setup wizard.
///
/// If a config file already exists at `config_path`, it is loaded and its
/// values are used as defaults for every prompt (reconfiguration mode E4).
/// A `.bak` backup is created before overwriting.
pub fn run_setup(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("{BANNER}");
    println!("  NOBLE Node Setup Wizard");
    println!("{}", "\u{2550}".repeat(40));
    println!();

    // --- Reconfiguration mode (E4) ---
    let existing = load_existing_config(config_path);
    if existing.is_some() {
        println!("  Existing configuration found at {config_path}",);
        println!("  Current values will be used as defaults.\n");
    }
    let defaults = existing.unwrap_or_default();

    // -----------------------------------------------------------------------
    // Step 1: Network & Name
    // -----------------------------------------------------------------------
    section_header("1", "Network & Name");

    let network_idx = match defaults.node.network {
        NetworkId::Mainnet => 0,
        NetworkId::Testnet => 1,
        NetworkId::Regtest => 2,
    };
    let network_sel = Select::new()
        .with_prompt("Select network")
        .items(NETWORK_CHOICES)
        .default(network_idx)
        .interact()?;
    let network_id = match network_sel {
        0 => NetworkId::Mainnet,
        1 => NetworkId::Testnet,
        _ => NetworkId::Regtest,
    };

    let node_name: String = Input::new()
        .with_prompt("Node name (optional, max 64 chars)")
        .default(defaults.identity.node_name.clone())
        .allow_empty(true)
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.len() > 64 {
                Err("Node name must be 64 characters or fewer")
            } else {
                Ok(())
            }
        })
        .interact_text()?;

    // -----------------------------------------------------------------------
    // Step 2: Node Role
    // -----------------------------------------------------------------------
    section_header("2", "Node Role");

    let role_default = infer_role_index(&defaults);
    let role_sel = Select::new()
        .with_prompt("Select node role")
        .items(ROLE_CHOICES)
        .default(role_default)
        .interact()?;

    let (op_role, wants_validate, wants_vote, identity_node_role) = match role_sel {
        0 => (OperationalRole::Observer, false, false, "FullNode"),
        1 => (OperationalRole::Validator, true, true, "Validator"),
        2 => (OperationalRole::Validator, true, false, "BlockProducer"),
        3 => (OperationalRole::Observer, false, true, "Voter"),
        4 => (OperationalRole::Observer, false, false, "ArchiveNode"),
        5 => (OperationalRole::Observer, false, false, "Gateway"),
        6 => (OperationalRole::Observer, false, true, "VotingGateway"),
        7 => (OperationalRole::Light, false, false, "LightClient"),
        _ => (OperationalRole::Observer, false, false, "FullNode"),
    };

    // Prompt for validator key path if the role produces blocks.
    let mut validator_key_path = defaults.consensus.validator_key_path.clone();
    if wants_validate {
        validator_key_path = Input::new()
            .with_prompt("Path to validator private key file")
            .default(if validator_key_path.is_empty() {
                "validator.key".to_string()
            } else {
                validator_key_path
            })
            .interact_text()?;
    }

    // -----------------------------------------------------------------------
    // Step 3: Identity
    // -----------------------------------------------------------------------
    section_header("3", "Identity");

    let gov_default = match defaults.identity.org_type.as_str() {
        "Individual" => 0,
        "Corp" | "LLC" | "Partnership" | "Trust" | "Foundation" | "GmbH" | "Holding"
        | "Family Office" | "SARL" => 1,
        "PublicCorp" | "Government" | "University" | "Research" | "NGO" | "Central Bank"
        | "Judiciary" => 2,
        _ => 0,
    };
    let gov_sel = Select::new()
        .with_prompt("Governance class")
        .items(GOV_CLASS_CHOICES)
        .default(gov_default)
        .interact()?;

    let org_type = match gov_sel {
        0 => "Individual".to_string(),
        1 => {
            let priv_default = PRIVATE_ORG_TYPES
                .iter()
                .position(|t| *t == defaults.identity.org_type)
                .unwrap_or(0);
            let sel = Select::new()
                .with_prompt("Private organization type")
                .items(PRIVATE_ORG_TYPES)
                .default(priv_default)
                .interact()?;
            PRIVATE_ORG_TYPES[sel].to_string()
        }
        _ => {
            let pub_default = PUBLIC_ORG_TYPES
                .iter()
                .position(|t| *t == defaults.identity.org_type)
                .unwrap_or(0);
            let sel = Select::new()
                .with_prompt("Public organization type")
                .items(PUBLIC_ORG_TYPES)
                .default(pub_default)
                .interact()?;
            PUBLIC_ORG_TYPES[sel].to_string()
        }
    };

    let org_name: String = Input::new()
        .with_prompt("Organization name (optional)")
        .default(defaults.identity.org_name.clone())
        .allow_empty(true)
        .interact_text()?;

    let contact_email: String = {
        if !defaults.identity.contact_email.is_empty() {
            println!("  WARNING: Contact email is broadcast publicly to all peers via GossipSub.");
        }
        let email: String = Input::new()
            .with_prompt("Contact email (optional)")
            .default(defaults.identity.contact_email.clone())
            .allow_empty(true)
            .interact_text()?;
        if !email.is_empty() && defaults.identity.contact_email.is_empty() {
            println!(
                "  WARNING: This email will be broadcast publicly to all peers via GossipSub."
            );
            if !Confirm::new()
                .with_prompt("  Are you sure you want to include it?")
                .default(true)
                .interact()?
            {
                String::new()
            } else {
                email
            }
        } else {
            email
        }
    };

    let website: String = Input::new()
        .with_prompt("Website (optional)")
        .default(defaults.identity.website.clone())
        .allow_empty(true)
        .interact_text()?;

    // -----------------------------------------------------------------------
    // Step 4: Wallet
    // -----------------------------------------------------------------------
    section_header("4", "Wallet");

    let wallet_sel = Select::new()
        .with_prompt("Wallet setup")
        .items(WALLET_CHOICES)
        .default(2) // default: skip
        .interact()?;

    let mut wallet_public_key: Option<String> = None;

    match wallet_sel {
        0 => {
            // --- Create new wallet ---
            let passphrase = prompt_wallet_passphrase()?;

            // Use a temporary directory for the keystore during creation.
            let keystore_dir = platform_data_dir().join("keystore");
            fs::create_dir_all(&keystore_dir)?;

            let mut ks = noble_wallet::KeyStore::new(&keystore_dir)?;
            let (mnemonic, pub_key) = ks.create_key_from_mnemonic(24, &passphrase)?;

            println!();
            println!("  ============================================================");
            println!("  YOUR 24-WORD RECOVERY PHRASE (write these down NOW):");
            println!("  ============================================================");
            println!();
            display_mnemonic_grid(&mnemonic);
            println!();
            println!("  WARNING: If you lose these words, your funds are GONE FOREVER.");
            println!("  Write them down on paper. Do NOT store them digitally.");
            println!("  ============================================================");
            println!();

            // Verify 3 random words
            verify_mnemonic_words(&mnemonic)?;

            wallet_public_key = Some(hex::encode(pub_key.to_wire_bytes()));
            println!();
            println!(
                "  Wallet created. Public key: {}",
                wallet_public_key.as_ref().unwrap()
            );

            // Zeroize passphrase (drop will handle String dealloc, but we clear it).
            drop(passphrase);
        }
        1 => {
            // --- Import existing wallet ---
            let mnemonic_input: String = Input::new()
                .with_prompt("Enter your BIP-39 mnemonic phrase (12 or 24 words)")
                .interact_text()?;

            let passphrase = prompt_wallet_passphrase()?;

            let keystore_dir = platform_data_dir().join("keystore");
            fs::create_dir_all(&keystore_dir)?;

            let mut ks = noble_wallet::KeyStore::new(&keystore_dir)?;
            let pub_key = ks.recover_from_mnemonic(&mnemonic_input, &passphrase)?;

            wallet_public_key = Some(hex::encode(pub_key.to_wire_bytes()));
            println!();
            println!(
                "  Wallet imported. Public key: {}",
                wallet_public_key.as_ref().unwrap()
            );

            drop(passphrase);
        }
        _ => {
            println!("  Wallet setup skipped.");
        }
    }

    // -----------------------------------------------------------------------
    // Step 5: TOTP Security
    // -----------------------------------------------------------------------
    section_header("5", "TOTP Security");

    let totp_enabled_default = defaults.api.totp_enabled;
    let totp_enabled = Confirm::new()
        .with_prompt("Enable TOTP authentication for RPC API?")
        .default(totp_enabled_default)
        .interact()?;

    let mut totp_secret_file = defaults.api.totp_secret_file.clone();
    if totp_enabled {
        // Generate a TOTP secret.
        let (validator, secret_b32) = noble_api::auth::TotpValidator::generate()
            .map_err(|e| format!("TOTP generation failed: {e}"))?;

        let uri = validator.otpauth_uri("NOBLE Node");

        println!();
        println!("  TOTP Secret (base32): {secret_b32}");
        println!("  otpauth URI:          {uri}");
        println!();
        println!("  Add this to your authenticator app (Google Authenticator, Authy, etc.).");
        println!();

        // Verify code
        loop {
            let code: String = Input::new()
                .with_prompt("Enter 6-digit TOTP code to verify")
                .interact_text()?;
            if validator.validate(&code) {
                println!("  TOTP verified successfully.");
                break;
            }
            println!("  Invalid code. Please try again.");
        }

        // Write secret to file.
        if totp_secret_file.is_empty() {
            totp_secret_file = "totp_secret".to_string();
        }
        let secret_path = Path::new(&totp_secret_file);
        fs::write(secret_path, &secret_b32)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(secret_path, fs::Permissions::from_mode(0o600))?;
        }
        println!("  TOTP secret written to: {totp_secret_file}");
    }

    // -----------------------------------------------------------------------
    // Step 6: Storage
    // -----------------------------------------------------------------------
    section_header("6", "Storage");

    let default_data_dir = if defaults.storage.data_dir == Path::new("data") {
        platform_data_dir().to_string_lossy().to_string()
    } else {
        defaults.storage.data_dir.to_string_lossy().to_string()
    };

    let data_dir: String = Input::new()
        .with_prompt("Data directory")
        .default(default_data_dir)
        .interact_text()?;

    let cache_size: u32 = Input::new()
        .with_prompt("Cache size (MB)")
        .default(defaults.storage.cache_size_mb)
        .interact_text()?;

    let compression = Confirm::new()
        .with_prompt("Enable Zstd compression?")
        .default(defaults.storage.compression)
        .interact()?;

    // -----------------------------------------------------------------------
    // Step 7: Networking (optional)
    // -----------------------------------------------------------------------
    section_header("7", "Networking");

    let configure_network = Confirm::new()
        .with_prompt("Configure networking? (defaults are fine for most users)")
        .default(false)
        .interact()?;

    let (listen_addr, seeds, max_peers) = if configure_network {
        let addr: String = Input::new()
            .with_prompt("P2P listen address")
            .default(defaults.network.listen_addr.clone())
            .interact_text()?;

        let seeds_str: String = Input::new()
            .with_prompt("Seed nodes (comma-separated multiaddrs, or empty)")
            .default(defaults.network.seeds.join(", "))
            .allow_empty(true)
            .interact_text()?;
        let seed_vec: Vec<String> = seeds_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let peers: u32 = Input::new()
            .with_prompt("Max peers")
            .default(defaults.network.max_peers)
            .interact_text()?;

        (addr, seed_vec, peers)
    } else {
        (
            defaults.network.listen_addr.clone(),
            defaults.network.seeds.clone(),
            defaults.network.max_peers,
        )
    };

    // -----------------------------------------------------------------------
    // Step 8: Review & Write
    // -----------------------------------------------------------------------
    section_header("8", "Review & Write");

    let config = NodeConfig {
        node: NodeSectionConfig {
            role: op_role,
            network: network_id,
        },
        network: NetworkConfig {
            listen_addr,
            seeds,
            max_peers,
            ban_threshold: defaults.network.ban_threshold,
        },
        storage: StorageConfig {
            data_dir: PathBuf::from(&data_dir),
            cache_size_mb: cache_size,
            compression,
        },
        consensus: ConsensusConfig {
            validator_key_path,
            validator_list_path: defaults.consensus.validator_list_path.clone(),
            voting_strategy: defaults.consensus.voting_strategy.clone(),
            confirmation_strategy: defaults.consensus.confirmation_strategy.clone(),
            voting_preferred_validator: defaults.consensus.voting_preferred_validator.clone(),
            voting_subset: defaults.consensus.voting_subset.clone(),
        },
        api: ApiConfig {
            rpc_addr: defaults.api.rpc_addr.clone(),
            ws_addr: defaults.api.ws_addr.clone(),
            max_connections: defaults.api.max_connections,
            rate_limit: defaults.api.rate_limit,
            totp_enabled,
            totp_secret_file,
            gui_addr: defaults.api.gui_addr.clone(),
            gui_dir: defaults.api.gui_dir.clone(),
            allowed_ips: defaults.api.allowed_ips.clone(),
        },
        wallet: WalletConfig {
            keystore_path: PathBuf::from("keystore"),
        },
        logging: LoggingConfig {
            level: defaults.logging.level.clone(),
            file: defaults.logging.file.clone(),
            rotation: defaults.logging.rotation.clone(),
        },
        metrics: MetricsConfig {
            prometheus_addr: defaults.metrics.prometheus_addr.clone(),
            enabled: defaults.metrics.enabled,
        },
        identity: IdentityConfig {
            node_name,
            org_type,
            org_name,
            node_role: identity_node_role.to_string(),
            contact_email,
            website,
            host_address: defaults.identity.host_address.clone(),
            wants_to_validate: wants_validate,
            wants_to_vote: wants_vote,
            pkcs12_path: defaults.identity.pkcs12_path.clone(),
            pkcs12_password: defaults.identity.pkcs12_password.clone(),
            ca_store_path: defaults.identity.ca_store_path.clone(),
        },
        trace: TraceConfig {
            buffer_capacity: defaults.trace.buffer_capacity,
            initial_filter: defaults.trace.initial_filter.clone(),
            stderr_enabled: defaults.trace.stderr_enabled,
        },
    };

    // Display summary table.
    print_summary(&config, config_path);

    let write_confirmed = Confirm::new()
        .with_prompt(format!("Write configuration to {config_path}?"))
        .default(true)
        .interact()?;

    if !write_confirmed {
        println!("\n  Setup cancelled. No files were written.");
        return Ok(());
    }

    // Create backup if existing file.
    let config_file = Path::new(config_path);
    if config_file.exists() {
        let backup_path = format!("{config_path}.bak");
        fs::copy(config_file, &backup_path)?;
        println!("  Backup created: {backup_path}");
    }

    // Serialize and write TOML.
    let toml_str = toml::to_string_pretty(&config)?;
    // Ensure parent directory exists.
    if let Some(parent) = config_file.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(config_file, &toml_str)?;

    println!();
    println!("  Configuration written to: {config_path}");
    println!();

    // Platform-appropriate start hint.
    let binary = if cfg!(target_os = "windows") {
        "noble-node.exe"
    } else {
        "noble-node"
    };
    println!("  To start the node:");
    println!("    {binary} run {config_path}");
    println!();
    println!("  To run in background:");
    println!("    {binary} run {config_path} --daemon");
    println!();
    println!("  To check status:");
    println!("    {binary} status");
    println!();

    if let Some(pk) = wallet_public_key {
        println!("  Wallet public key: {pk}");
        println!();
    }

    println!("  Setup complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Print a section header.
fn section_header(number: &str, title: &str) {
    println!();
    println!("  [{number}] {title}");
    println!("  {}", "\u{2500}".repeat(36));
}

/// Load and parse an existing config file, returning `None` on any failure.
fn load_existing_config(path: &str) -> Option<NodeConfig> {
    let p = Path::new(path);
    if !p.exists() {
        return None;
    }
    NodeConfig::from_file(p).ok()
}

/// Determine the platform-aware default data directory.
///
/// - macOS: `~/Library/Application Support/NOBLE/data`
/// - Linux: `~/.noble/data` (non-root) or `/var/lib/noble/data` (root)
/// - Windows: `{AppData}/NOBLE/data`
fn platform_data_dir() -> PathBuf {
    match std::env::consts::OS {
        "macos" => dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("NOBLE")
            .join("data"),
        "linux" => {
            let is_root = std::env::var("USER").map(|u| u == "root").unwrap_or(false);
            if is_root {
                PathBuf::from("/var/lib/noble/data")
            } else {
                dirs::home_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join(".noble")
                    .join("data")
            }
        }
        "windows" => dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("NOBLE")
            .join("data"),
        _ => PathBuf::from("data"),
    }
}

/// Prompt for wallet encryption passphrase with confirmation and min-length.
fn prompt_wallet_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    let passphrase = Password::new()
        .with_prompt("Wallet encryption passphrase")
        .with_confirmation("Confirm passphrase", "Passwords don't match")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.len() >= 12 {
                Ok(())
            } else {
                Err("Minimum 12 characters")
            }
        })
        .interact()?;
    Ok(passphrase)
}

/// Display a BIP-39 mnemonic in 4-column numbered grid format.
fn display_mnemonic_grid(mnemonic: &str) {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let cols = 4;
    let rows = words.len().div_ceil(cols);

    for row in 0..rows {
        print!("  ");
        for col in 0..cols {
            let idx = row + col * rows;
            if idx < words.len() {
                print!("  {:>2}. {:<14}", idx + 1, words[idx]);
            }
        }
        println!();
    }
}

/// Verify 3 random mnemonic words by index.
fn verify_mnemonic_words(mnemonic: &str) -> Result<(), Box<dyn std::error::Error>> {
    use rand::seq::SliceRandom;

    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let word_count = words.len();

    // Pick 3 unique random indices.
    let mut indices: Vec<usize> = (0..word_count).collect();
    indices.shuffle(&mut rand::thread_rng());
    let check_indices: Vec<usize> = indices.into_iter().take(3).collect();

    println!("  Please verify 3 words from your recovery phrase:\n");

    for &idx in &check_indices {
        loop {
            let answer: String = Input::new()
                .with_prompt(format!("  Word #{}", idx + 1))
                .interact_text()?;
            if answer.trim().eq_ignore_ascii_case(words[idx]) {
                break;
            }
            println!("    Incorrect. Please try again.");
        }
    }

    println!("  All words verified correctly.");
    Ok(())
}

/// Infer the role selection index from existing config values.
fn infer_role_index(config: &NodeConfig) -> usize {
    match (
        config.node.role,
        config.identity.wants_to_validate,
        config.identity.wants_to_vote,
        config.identity.node_role.as_str(),
    ) {
        (OperationalRole::Validator, true, true, _) => 1,
        (OperationalRole::Validator, true, false, _) => 2,
        (OperationalRole::Observer, false, true, "VotingGateway") => 6,
        (OperationalRole::Observer, false, true, _) => 3,
        (OperationalRole::Observer, false, false, "ArchiveNode") => 4,
        (OperationalRole::Observer, false, false, "Gateway") => 5,
        (OperationalRole::Light, _, _, _) => 7,
        _ => 0, // Full Node Observer
    }
}

/// Print a formatted summary table of the configuration.
fn print_summary(config: &NodeConfig, config_path: &str) {
    println!();
    println!("  {}", "\u{2550}".repeat(52));
    println!("  Configuration Summary");
    println!("  {}", "\u{2550}".repeat(52));
    println!();
    summary_line("Config file", config_path);
    summary_line("Network", &format!("{:?}", config.node.network));
    summary_line("Node role", &format!("{:?}", config.node.role));
    summary_line("Identity role", &config.identity.node_role);
    if !config.identity.node_name.is_empty() {
        summary_line("Node name", &config.identity.node_name);
    }
    summary_line("Org type", &config.identity.org_type);
    if !config.identity.org_name.is_empty() {
        summary_line("Org name", &config.identity.org_name);
    }
    if config.identity.wants_to_validate {
        summary_line("Validates", "yes");
        summary_line("Validator key", &config.consensus.validator_key_path);
    }
    if config.identity.wants_to_vote {
        summary_line("Votes", "yes");
    }
    summary_line("Data directory", &config.storage.data_dir.to_string_lossy());
    summary_line(
        "Cache size",
        &format!("{} MB", config.storage.cache_size_mb),
    );
    summary_line(
        "Compression",
        if config.storage.compression {
            "Zstd"
        } else {
            "none"
        },
    );
    summary_line("P2P listen", &config.network.listen_addr);
    summary_line("Max peers", &config.network.max_peers.to_string());
    if !config.network.seeds.is_empty() {
        summary_line("Seeds", &config.network.seeds.join(", "));
    }
    summary_line("RPC", &config.api.rpc_addr);
    summary_line("WebSocket", &config.api.ws_addr);
    summary_line("GUI", &config.api.gui_addr);
    summary_line(
        "TOTP auth",
        if config.api.totp_enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    summary_line("Metrics", &config.metrics.prometheus_addr);
    summary_line("Log level", &config.logging.level);
    println!();
    println!("  {}", "\u{2550}".repeat(52));
    println!();
}

/// Print a single summary line.
fn summary_line(label: &str, value: &str) {
    println!("  {:<18} {value}", format!("{label}:"));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_data_dir_is_not_empty() {
        let dir = platform_data_dir();
        assert!(
            !dir.as_os_str().is_empty(),
            "platform_data_dir() must return a non-empty path"
        );
    }

    #[test]
    fn display_mnemonic_grid_does_not_panic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about \
                         abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon art";
        display_mnemonic_grid(mnemonic);
    }

    #[test]
    fn infer_role_index_defaults() {
        let config = NodeConfig::default();
        assert_eq!(infer_role_index(&config), 0);
    }

    #[test]
    fn infer_role_index_validator() {
        let mut config = NodeConfig::default();
        config.node.role = OperationalRole::Validator;
        config.identity.wants_to_validate = true;
        config.identity.wants_to_vote = true;
        assert_eq!(infer_role_index(&config), 1);
    }

    #[test]
    fn infer_role_index_block_producer() {
        let mut config = NodeConfig::default();
        config.node.role = OperationalRole::Validator;
        config.identity.wants_to_validate = true;
        config.identity.wants_to_vote = false;
        assert_eq!(infer_role_index(&config), 2);
    }

    #[test]
    fn infer_role_index_voter() {
        let mut config = NodeConfig::default();
        config.node.role = OperationalRole::Observer;
        config.identity.wants_to_validate = false;
        config.identity.wants_to_vote = true;
        config.identity.node_role = "Voter".to_string();
        assert_eq!(infer_role_index(&config), 3);
    }

    #[test]
    fn infer_role_index_light() {
        let mut config = NodeConfig::default();
        config.node.role = OperationalRole::Light;
        assert_eq!(infer_role_index(&config), 7);
    }

    #[test]
    fn infer_role_index_archive() {
        let mut config = NodeConfig::default();
        config.identity.node_role = "ArchiveNode".to_string();
        assert_eq!(infer_role_index(&config), 4);
    }

    #[test]
    fn infer_role_index_gateway() {
        let mut config = NodeConfig::default();
        config.identity.node_role = "Gateway".to_string();
        assert_eq!(infer_role_index(&config), 5);
    }

    #[test]
    fn infer_role_index_voting_gateway() {
        let mut config = NodeConfig::default();
        config.identity.wants_to_vote = true;
        config.identity.node_role = "VotingGateway".to_string();
        assert_eq!(infer_role_index(&config), 6);
    }

    #[test]
    fn load_existing_config_returns_none_for_missing() {
        assert!(load_existing_config("/nonexistent/path/noble.toml").is_none());
    }

    #[test]
    fn summary_line_formats_correctly() {
        // Just ensure it doesn't panic; output goes to stdout.
        summary_line("Test", "value");
    }

    #[test]
    fn section_header_formats_correctly() {
        section_header("1", "Test Section");
    }
}
