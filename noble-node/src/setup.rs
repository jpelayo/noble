// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Interactive setup wizard for creating or editing `noble.toml`.
//!
//! Guides the operator through network selection, node role, identity,
//! wallet creation/import, TOTP security, storage, encryption, and
//! networking configuration. Produces a fully populated `noble.toml`.
//!
//! Supports **reconfiguration mode** (E4): when the target config file
//! already exists it is parsed and all prompts are pre-filled with the
//! current values.

use std::fs;
use std::path::{Path, PathBuf};

use dialoguer::{Confirm, Input, Select};
use noble_crypto::{
    bitcoin_addr::{pubkey_to_p2pkh, pubkey_to_p2wpkh, pubkey_to_p2tr},
    NoblePrivateKey, SCHEME_SECP256K1,
};
use zeroize::Zeroize;

use crate::config::{
    ApiConfig, ConsensusConfig, GatewayConfig, IdentityConfig, LoggingConfig, MetricsConfig,
    NetworkConfig, NodeConfig, NodeSectionConfig, OperationalRole, SecurityConfig,
    StorageConfig, TraceConfig, WalletConfig,
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

const ORG_TYPE_LABELS: &[&str] = &[
    "Individual",
    "Fully privately funded non-profit institution or NGO",
    "Fully privately funded for-profit corporation",
    "Fully privately funded for-profit startup",
    "Fully privately funded for-profit academic institution",
    "Fully privately funded for-profit institution",
    "National public administration entity",
    "Regional or municipal public administration entity",
    "Publicly funded supranational organization",
    "Publicly funded corporation or startup",
    "Publicly funded academic institution",
    "Publicly funded institution or NGO",
];

const ORG_TYPE_IDS: &[&str] = &[
    "Individual",
    "PrivateNonProfit",
    "PrivateCorporation",
    "PrivateStartup",
    "PrivateAcademic",
    "PrivateInstitution",
    "PublicNational",
    "PublicRegional",
    "PublicSupranational",
    "PublicCorporation",
    "PublicAcademic",
    "PublicInstitution",
];

const REWARD_ADDR_HELP: &str = "\
  Paste your Bitcoin address (bc1q..., 1..., bc1p...) or hex NOBLE public key.\n\
  This address receives 50% of transaction fees processed by your node.\n\
  Leave empty to skip (you can configure this later in Settings).";

// Validator keys are always derived from a BIP-39 mnemonic via SLIP-0010.
// No random generation option — all keys must be recoverable from 24 words.

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Called by `run_node()` when the config file is absent.
///
/// Prints a warning and offers:
///   [1] Run setup wizard
///   [2] Exit
///
/// Returns `true` if setup completed and the node should proceed to start.
/// Returns `false` if the user chose to exit or setup failed.
pub fn prompt_missing_config(config_path: &str) -> bool {
    println!("{BANNER}");
    println!("  ─────────────────────────────────────────");
    println!("  WARNING: Node not configured");
    println!("  ─────────────────────────────────────────");
    println!();
    println!("  Configuration file not found:");
    println!("    {config_path}");
    println!();
    println!("  NOBLE requires a valid noble.toml before it can start.");
    println!("  The setup wizard takes about 2 minutes.");
    println!();

    let choices = &["Run setup wizard", "Exit"];
    let sel = Select::new()
        .with_prompt("What would you like to do?")
        .items(choices)
        .default(0)
        .interact()
        .unwrap_or(1);

    println!();

    if sel == 0 {
        match run_setup(config_path) {
            Ok(()) => {
                println!("  Starting node...");
                println!();
                true
            }
            Err(e) => {
                eprintln!("  Setup failed: {e}");
                false
            }
        }
    } else {
        println!("  Exiting. Run `noble-node setup` when you are ready to configure.");
        false
    }
}

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
    // Remote Access (preamble — asked before numbered steps)
    // -----------------------------------------------------------------------
    section_header("◆", "Remote Access");

    println!("  Allow remote connections to the Dashboard GUI and JSON-RPC API.");
    println!("  Enter IP addresses or CIDR blocks (127.0.0.1 is always allowed).");
    println!("  Leave empty for localhost-only access.");
    println!();

    let allowed_ips_str: String = Input::new()
        .with_prompt("Allowed IPs (comma-separated, e.g. 10.0.0.0/8)")
        .default(defaults.api.allowed_ips.join(", "))
        .allow_empty(true)
        .interact_text()?;

    let mut allowed_ips: Vec<String> = allowed_ips_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Validate using the same parser the node uses at runtime.
    if !allowed_ips.is_empty() {
        if let Err(e) = noble_api::ip_filter::IpFilter::new(&allowed_ips) {
            println!("  Warning: {e}");
            println!("  Continuing with localhost-only access.");
            allowed_ips.clear();
        } else {
            println!();
            println!("  Remote access enabled. After setup, the dashboard GUI will");
            let scheme = if defaults.api.tls_enabled { "https" } else { "http" };
            println!("  be available at {scheme}://<this-host>:8785");
        }
    }

    // -----------------------------------------------------------------------
    // Step 1: Node Name
    // -----------------------------------------------------------------------
    section_header("1", "Node Name");

    let node_name: String = Input::new()
        .with_prompt("Node name (required, max 64 chars)")
        .default(if defaults.identity.node_name.is_empty() {
            String::new()
        } else {
            defaults.identity.node_name.clone()
        })
        .allow_empty(false)
        .validate_with(|input: &String| -> Result<(), &str> {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                Err("Node name is required")
            } else if trimmed.len() > 64 {
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

    // Prompt for validator key path if the role produces blocks,
    // then offer to generate the key inline if the file doesn't exist.
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

        maybe_generate_validator_key(&validator_key_path)?;
    }

    // -----------------------------------------------------------------------
    // Step 3: Identity
    // -----------------------------------------------------------------------
    section_header("3", "Identity");

    let org_default = ORG_TYPE_IDS
        .iter()
        .position(|id| *id == defaults.identity.org_type)
        .unwrap_or(0);
    let org_sel = Select::new()
        .with_prompt("Organization type")
        .items(ORG_TYPE_LABELS)
        .default(org_default)
        .interact()?;
    let org_type = ORG_TYPE_IDS[org_sel].to_string();

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
    // Step 4: Wallet (offline generate / recover)
    // -----------------------------------------------------------------------
    section_header("4", "Wallet (optional)");

    println!("  Generate or recover a Noble wallet offline.");
    println!("  This does NOT persist anything to the node — it displays keys");
    println!("  so you can record them before configuring the reward address.");
    println!();

    let wallet_choices = &[
        "Generate new wallet (BIP-39 mnemonic)",
        "Recover wallet from existing mnemonic",
        "Skip — I already have a wallet",
    ];
    let wallet_sel = Select::new()
        .with_prompt("Wallet action")
        .items(wallet_choices)
        .default(2)
        .interact()?;

    let wallet_address = match wallet_sel {
        0 => run_wallet_generate()?,
        1 => run_wallet_recover()?,
        _ => {
            println!("  Skipped.");
            None
        }
    };

    // -----------------------------------------------------------------------
    // Step 5: Reward Address
    // -----------------------------------------------------------------------
    section_header("5", "Reward Address");

    println!("{REWARD_ADDR_HELP}");
    println!();

    // Pre-fill with the wallet address if one was just generated/recovered
    let reward_default = if let Some(ref addr) = wallet_address {
        println!("  (Pre-filled with the wallet address generated above.)");
        println!();
        addr.clone()
    } else {
        defaults.rewards.reward_address.clone()
    };

    let reward_address: String = Input::new()
        .with_prompt("Reward address")
        .default(reward_default)
        .allow_empty(true)
        .interact_text()?;

    let reward_address = reward_address.trim().to_string();
    if !reward_address.is_empty() {
        // Validate the address
        match noble_crypto::bitcoin_addr::parse_bitcoin_address(&reward_address) {
            Ok(addr) => {
                let addr_type = &addr.address_type;
                println!("  Valid {addr_type:?} address.");
            }
            Err(e) => {
                println!("  Warning: Could not validate address: {e}");
                println!("  Continuing anyway — you can fix this in Settings.");
            }
        }
    } else {
        println!("  Reward address skipped. Configure later in Settings.");
    }

    // -----------------------------------------------------------------------
    // Step 6: TOTP Security
    // -----------------------------------------------------------------------
    section_header("6", "TOTP Security");

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
    // Step 7: Storage
    // -----------------------------------------------------------------------
    section_header("7", "Storage");

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

    let pruning_choices = &[
        "Archive      — full history, no pruning (recommended for validators)",
        "Moderate     — keep recent blocks, prune old state",
        "Aggressive   — minimal storage, headers + recent blocks only",
    ];
    let pruning_default = match defaults.storage.pruning_mode.as_str() {
        "moderate" => 1,
        "aggressive" => 2,
        _ => 0,
    };
    let pruning_sel = Select::new()
        .with_prompt("Pruning mode")
        .items(pruning_choices)
        .default(pruning_default)
        .interact()?;
    let pruning_mode = match pruning_sel {
        1 => "moderate".to_string(),
        2 => "aggressive".to_string(),
        _ => "archive".to_string(),
    };

    let keep_blocks: u64 = if pruning_mode != "archive" {
        let default_keep = if defaults.storage.keep_blocks > 0 {
            defaults.storage.keep_blocks
        } else {
            100_000
        };
        Input::new()
            .with_prompt("Number of recent blocks to keep")
            .default(default_keep)
            .interact_text()?
    } else {
        0
    };

    // -----------------------------------------------------------------------
    // Step 8: Security (Encryption Mode)
    // -----------------------------------------------------------------------
    section_header("8", "Encryption");

    println!("  All private keys (validator, TLS, P2P, TOTP) are encrypted at rest.");
    println!("  Choose how the encryption key is managed:");
    println!();

    let enc_choices = &[
        "Automatic  — machine-specific key, no password on startup (recommended)",
        "Manual     — password required every startup (stronger protection)",
    ];
    let enc_default = match defaults.security.encryption_mode.as_str() {
        "manual" => 1,
        _ => 0,
    };
    let enc_sel = Select::new()
        .with_prompt("Encryption mode")
        .items(enc_choices)
        .default(enc_default)
        .interact()?;
    let encryption_mode = match enc_sel {
        1 => {
            println!();
            println!("  The password will be required every time the node starts.");
            println!("  If lost, encrypted key files cannot be recovered.");
            "manual".to_string()
        }
        _ => "automatic".to_string(),
    };

    // -----------------------------------------------------------------------
    // Step 9: Networking (optional)
    // -----------------------------------------------------------------------
    section_header("9", "Networking");

    let configure_network = Confirm::new()
        .with_prompt("Configure networking? (defaults are fine for most users)")
        .default(false)
        .interact()?;

    let (listen_addr, seeds, max_peers) = if configure_network {
        let port_options = ["8780 (default)", "8781", "8782"];
        let current_port = extract_port_from_listen_addr(&defaults.network.listen_addr);
        let default_idx = match current_port {
            8781 => 1,
            8782 => 2,
            _ => 0,
        };
        let port_idx = Select::new()
            .with_prompt("P2P port (open this port to the internet)")
            .items(&port_options)
            .default(default_idx)
            .interact()?;
        let port: u16 = match port_idx {
            1 => 8781,
            2 => 8782,
            _ => 8780,
        };
        let addr = format!("/ip4/0.0.0.0/tcp/{port}");

        let seed_default = if defaults.network.seeds.is_empty() {
            noble_network::config::DEFAULT_GENESIS_NODE.to_string()
        } else {
            defaults.network.seeds.join(", ")
        };
        let seeds_str: String = Input::new()
            .with_prompt("Seed nodes (comma-separated, Enter to accept default)")
            .default(seed_default)
            .allow_empty(true)
            .interact_text()?;
        let seed_vec: Vec<String> = seeds_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| normalize_seed_addr(&s))
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
    // Step 10: Review & Write
    // -----------------------------------------------------------------------
    section_header("10", "Review & Write");

    let config = NodeConfig {
        node: NodeSectionConfig {
            role: op_role,
            ..Default::default()
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
            pruning_mode: pruning_mode.clone(),
            keep_blocks,
            max_db_size_gb: 0,
        },
        security: SecurityConfig {
            encryption_mode: encryption_mode.clone(),
        },
        consensus: ConsensusConfig {
            validator_key_path,
            validator_list_path: defaults.consensus.validator_list_path.clone(),
            voting_strategy: defaults.consensus.voting_strategy.clone(),
            confirmation_strategy: defaults.consensus.confirmation_strategy.clone(),
            voting_preferred_validator: defaults.consensus.voting_preferred_validator.clone(),
            voting_subset: defaults.consensus.voting_subset.clone(),
            fork_resolution_strategy: defaults.consensus.fork_resolution_strategy.clone(),
            fork_resolution_delay_cycles: defaults.consensus.fork_resolution_delay_cycles,
        },
        api: ApiConfig {
            rpc_addr: defaults.api.rpc_addr.clone(),
            ws_addr: defaults.api.ws_addr.clone(),
            max_connections: defaults.api.max_connections,
            rate_limit: defaults.api.rate_limit,
            totp_enabled,
            totp_scope: defaults.api.totp_scope.clone(),
            totp_secret_file,
            gui_addr: defaults.api.gui_addr.clone(),
            gui_dir: defaults.api.gui_dir.clone(),
            allowed_ips: allowed_ips.clone(),
            tls_enabled: defaults.api.tls_enabled,
            tls_san: defaults.api.tls_san.clone(),
            tls_allow_plaintext_fallback: defaults.api.tls_allow_plaintext_fallback,
            remote_setup: defaults.api.remote_setup,
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
            country_code: defaults.identity.country_code.clone(),
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
        gateway: GatewayConfig::default(),
        rewards: crate::config::RewardsConfig {
            reward_address: reward_address.clone(),
        },
        faucet: crate::config::FaucetConfig::default(),
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

    // Also persist identity.json to data_dir so the node's canonical identity
    // source is up-to-date from the first boot (same file used by noble_setNodeIdentity).
    let data_dir_path = std::path::PathBuf::from(&data_dir);
    if let Ok(identity_json) = serde_json::to_string_pretty(&noble_api::state::NodeIdentityData {
        node_name: config.identity.node_name.clone(),
        org_type: config.identity.org_type.clone(),
        org_name: config.identity.org_name.clone(),
        node_role: config.identity.node_role.clone(),
        contact_email: config.identity.contact_email.clone(),
        website: config.identity.website.clone(),
        host_address: config.identity.host_address.clone(),
        country_code: config.identity.country_code.clone(),
        wants_to_validate: config.identity.wants_to_validate,
        wants_to_vote: config.identity.wants_to_vote,
        p2p_port: extract_port_from_listen_addr(&config.network.listen_addr),
        setup_complete: true,
    }) {
        fs::create_dir_all(&data_dir_path)?;
        let identity_path = data_dir_path.join("identity.json");
        fs::write(&identity_path, &identity_json)?;
        println!("  Identity written to: {}", identity_path.display());
    }

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

    if !reward_address.is_empty() {
        println!("  Reward address: {reward_address}");
        println!();
    }

    println!("  Setup complete.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run inline wallet generation during setup (no persistence).
fn run_wallet_generate() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let word_choices = &["24 words (recommended)", "12 words"];
    let word_sel = Select::new()
        .with_prompt("Mnemonic length")
        .items(word_choices)
        .default(0)
        .interact()?;
    let word_count: usize = if word_sel == 0 { 24 } else { 12 };

    let mnemonic = bip39::Mnemonic::generate(word_count)
        .map_err(|e| format!("mnemonic generation failed: {e}"))?;

    let address_hex = print_wallet_info(&mnemonic, "");
    Ok(Some(address_hex))
}

/// Run inline wallet recovery during setup (no persistence).
fn run_wallet_recover() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let mnemonic_str: String = Input::new()
        .with_prompt("Enter mnemonic phrase (12 or 24 words)")
        .interact_text()?;

    let mnemonic: bip39::Mnemonic = mnemonic_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid mnemonic: {e}"))?;

    let address_hex = print_wallet_info(&mnemonic, "");
    Ok(Some(address_hex))
}

/// Derive and display full wallet info from a mnemonic (same as noble-tool).
/// Returns the hex-encoded wire address for reward address prefill.
fn print_wallet_info(mnemonic: &bip39::Mnemonic, passphrase: &str) -> String {
    let mut seed = mnemonic.to_seed(passphrase);

    let xprv = bip32::XPrv::derive_from_path(
        &seed,
        &"m/44'/9999'/0'/0/0".parse().expect("valid derivation path"),
    )
    .expect("BIP-32 derivation failed");

    seed.zeroize();

    let mut sk_bytes = xprv.private_key().to_bytes().to_vec();
    let private_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
    let public_key = private_key.public_key();
    let wire_bytes = public_key.to_wire_bytes();
    let pk_bytes = public_key.key_bytes();

    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(pk_bytes);

    let p2pkh = pubkey_to_p2pkh(&compressed, true);
    let p2wpkh = pubkey_to_p2wpkh(&compressed, true);
    let p2tr = pubkey_to_p2tr(&compressed, true);

    let words: Vec<&str> = mnemonic.to_string().leak().split_whitespace().collect();

    eprintln!();
    eprintln!("  \x1b[33mWARNING: The private key and mnemonic below grant full\x1b[0m");
    eprintln!("  \x1b[33mcontrol of this wallet. Store them securely and NEVER\x1b[0m");
    eprintln!("  \x1b[33mshare them. This output is NOT saved anywhere.\x1b[0m");
    println!();
    println!("  === Noble Wallet ===");
    println!();
    println!("  Mnemonic ({} words):", words.len());
    for (i, word) in words.iter().enumerate() {
        print!("  {:>3}. {:<14}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();
    println!("  Derivation Path: m/44'/9999'/0'/0/0");
    println!("  Private Key:     {}", hex::encode(&sk_bytes));
    println!("  Public Key:      {}", hex::encode(pk_bytes));
    println!("  Wire Hex:        {}", hex::encode(&wire_bytes));
    println!();
    println!("  Bitcoin Addresses:");
    println!("    P2PKH  (1...):   {p2pkh}");
    println!("    P2WPKH (bc1q):   {p2wpkh}");
    println!("    P2TR   (bc1p):   {p2tr}");
    println!();

    let address_hex = hex::encode(&wire_bytes);
    sk_bytes.zeroize();
    address_hex
}

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
fn platform_data_dir() -> PathBuf {
    noble_core::paths::platform_data_dir()
}


/// If the key file exists, display its public key.
/// If it doesn't exist, offer to generate it inline.
fn maybe_generate_validator_key(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_path = Path::new(path);

    if key_path.exists() {
        // Key already present — show its public key so the operator can add it to validators.txt.
        println!();
        match read_validator_pubkey(key_path) {
            Some(pk_hex) => {
                println!("  Key file found: {path}");
                println!("  Public key:");
                println!("    {pk_hex}");
            }
            None => {
                println!("  WARNING: Key file found but could not be parsed: {path}");
                println!("  Delete it and re-run setup to generate a fresh key.");
            }
        }
        println!();
        return Ok(());
    }

    println!();
    println!("  No key file at '{path}'.");
    println!();

    let generate = Confirm::new()
        .with_prompt("Generate a new validator key now?")
        .default(true)
        .interact()?;

    if !generate {
        println!();
        println!("  Skipped. Generate later with:");
        println!("    noble-tool generate-key --output {path}");
        println!();
        return Ok(());
    }

    // BIP-39 mnemonic → BIP-32 secp256k1 key at m/44'/9999'/0'/0/0
    // Same key for wallet transactions AND block validation.
    let mnemonic = bip39::Mnemonic::generate(24)
        .map_err(|e| format!("mnemonic generation failed: {e}"))?;
    let mnemonic_words = mnemonic.words().collect::<Vec<_>>().join(" ");
    let mut seed = mnemonic.to_seed("");
    let child = bip32::XPrv::derive_from_path(
        seed,
        &"m/44'/9999'/0'/0/0"
            .parse()
            .map_err(|e: bip32::Error| format!("derivation path: {e}"))?,
    )
    .map_err(|e| {
        seed.zeroize();
        format!("BIP-32 derivation failed: {e}")
    })?;
    seed.zeroize();
    let mut sk_bytes = child.to_bytes().to_vec();
    let private_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
    sk_bytes.zeroize();
    let scheme_id = SCHEME_SECP256K1;

    // Build 33-byte key file: [scheme_id || private_key_bytes].
    let key_bytes = match &private_key {
        NoblePrivateKey::Ed25519(b) | NoblePrivateKey::Secp256k1(b) => b.clone(),
        _ => unreachable!("generate_validator_key only produces Ed25519 or Secp256k1"),
    };
    let mut raw = Vec::with_capacity(33);
    raw.push(scheme_id);
    raw.extend_from_slice(&key_bytes);

    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(key_path)?;
        file.write_all(&raw)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(key_path, &raw)?;
    }

    let pubkey_hex = private_key.public_key().to_address();

    println!();
    println!("  Validator key written to: {path}  (permissions: 0600)");
    println!();
    println!("  Public key — add this line to validators.txt on every node:");
    println!();
    println!("    {pubkey_hex}");
    println!();

    println!("  ┌─────────────────────────────────────────────────────────────┐");
    println!("  │  RECOVERY PHRASE — write these 24 words down and store      │");
    println!("  │  them safely. This is the ONLY way to recover your key.     │");
    println!("  └─────────────────────────────────────────────────────────────┘");
    println!();
    for (i, word) in mnemonic_words.split_whitespace().enumerate() {
        print!("  {:>2}. {:<12}", i + 1, word);
        if (i + 1) % 4 == 0 { println!(); }
    }
    println!();
    println!("  Derivation path: m/44'/9999'/0'/0/0 (BIP-32 secp256k1)");
    println!();

    Ok(())
}

/// Read a 33-byte validator key file and derive its public key hex.
/// Returns `None` if the file is malformed or the scheme is unrecognised.
fn read_validator_pubkey(key_path: &Path) -> Option<String> {
    let raw = fs::read(key_path).ok()?;
    if raw.len() != 33 {
        return None;
    }
    let private_key = match raw[0] {
        0x01 => NoblePrivateKey::Ed25519(raw[1..].to_vec()),
        0x02 => NoblePrivateKey::Secp256k1(raw[1..].to_vec()),
        _ => return None,
    };
    Some(private_key.public_key().to_address())
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
    summary_line("Pruning", &config.storage.pruning_mode);
    if config.storage.pruning_mode != "archive" && config.storage.keep_blocks > 0 {
        summary_line("Keep blocks", &config.storage.keep_blocks.to_string());
    }
    summary_line("Encryption", &config.security.encryption_mode);
    summary_line("P2P listen", &config.network.listen_addr);
    summary_line("Max peers", &config.network.max_peers.to_string());
    if !config.network.seeds.is_empty() {
        summary_line("Seeds", &config.network.seeds.join(", "));
    }
    summary_line("RPC", &config.api.rpc_addr);
    summary_line("WebSocket", &config.api.ws_addr);
    summary_line("GUI", &config.api.gui_addr);
    if !config.api.allowed_ips.is_empty() {
        summary_line("Remote access", &config.api.allowed_ips.join(", "));
    } else {
        summary_line("Remote access", "localhost only");
    }
    summary_line(
        "TOTP auth",
        if config.api.totp_enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    if !config.rewards.reward_address.is_empty() {
        summary_line("Reward address", &config.rewards.reward_address);
    }
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

/// Extract the TCP port number from a `/ip4/.../tcp/PORT` multiaddr string.
///
/// Normalize a single seed address from user input into multiaddr form.
///
/// Handles bare IP, hostname, host:port, URL, and bracketed IPv6.
fn normalize_seed_addr(input: &str) -> String {
    let input = input.trim();
    if input.starts_with('/') { return input.to_string(); }
    let stripped = input
        .strip_prefix("https://").or_else(|| input.strip_prefix("http://"))
        .unwrap_or(input);
    let stripped = stripped.split('/').next().unwrap_or(stripped);
    let stripped = stripped.split('?').next().unwrap_or(stripped);
    if stripped.starts_with('[') {
        if let Some(end) = stripped.find(']') {
            let ip6 = &stripped[1..end];
            let rest = &stripped[end + 1..];
            let port = rest.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(8780);
            return format!("/ip6/{ip6}/tcp/{port}");
        }
    }
    let has_alpha = stripped.chars().any(|c| c.is_ascii_alphabetic());
    let colons = stripped.chars().filter(|&c| c == ':').count();
    if colons > 1 { return format!("/ip6/{stripped}/tcp/8780"); }
    if colons == 1 {
        if let Some((host, port_str)) = stripped.rsplit_once(':') {
            let port = port_str.parse::<u16>().unwrap_or(8780);
            return if has_alpha { format!("/dns4/{host}/tcp/{port}") } else { format!("/ip4/{host}/tcp/{port}") };
        }
    }
    if has_alpha { format!("/dns4/{stripped}/tcp/8780") } else { format!("/ip4/{stripped}/tcp/8780") }
}

/// Returns 8780 if the port cannot be parsed.
fn extract_port_from_listen_addr(addr: &str) -> u16 {
    addr.rsplit("/tcp/")
        .next()
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(8780)
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
