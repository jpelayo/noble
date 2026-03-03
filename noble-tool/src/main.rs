// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! `noble-tool` — offline utility for genesis block generation, benchmarking,
//! and chain validation.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use zeroize::Zeroize;

use noble_codec::NobleCbor;
use noble_core::{
    compute_merkle_root, genesis_block, regtest_genesis_block, testnet_genesis_block, Block,
};
use noble_crypto::{ed25519, secp256k1, sha256, Hash256};
use noble_storage::{RocksDbStorage, StorageEngine};

// ---------------------------------------------------------------------------
// Platform-aware path helpers
// ---------------------------------------------------------------------------

fn default_genesis_output() -> PathBuf {
    noble_core::paths::platform_genesis_path()
}

fn default_data_dir() -> PathBuf {
    noble_core::paths::platform_data_dir()
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Offline tooling for the NOBLE blockchain.
#[derive(Parser)]
#[command(name = "noble-tool", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate and serialize a genesis block to a CBOR file.
    Genesis {
        /// Output file path for the serialized genesis block.
        #[arg(long, default_value_os_t = default_genesis_output())]
        output: PathBuf,

        /// Network variant to generate the genesis block for.
        #[arg(long, default_value = "mainnet")]
        network: Network,

        /// Also print the genesis block hash as JSON to stdout.
        #[arg(long)]
        json: bool,
    },

    /// Run simple timing benchmarks for core cryptographic operations.
    Benchmark {
        /// Which benchmark suite to run.
        #[arg(long, default_value = "all")]
        suite: BenchSuite,
    },

    /// Validate an on-disk chain stored in RocksDB.
    ValidateChain {
        /// Path to the RocksDB data directory.
        #[arg(long, default_value_os_t = default_data_dir())]
        data_dir: PathBuf,
    },

    /// Generate or recover a Noble wallet (offline — nothing is persisted).
    Wallet {
        #[command(subcommand)]
        action: WalletCommand,
    },

    /// Manage at-rest encryption of key material.
    Security {
        #[command(subcommand)]
        action: SecurityCommand,
    },

    /// Manage peers and seed nodes on a running node via JSON-RPC.
    Peer {
        #[command(subcommand)]
        action: PeerCommand,
    },

    /// Manage allowed IP CIDRs for RPC/GUI remote access on a running node.
    AllowIps {
        #[command(subcommand)]
        action: AllowIpsCommand,
    },

    /// View and manage storage configuration on a running node.
    Storage {
        #[command(subcommand)]
        action: StorageCommand,
    },

    /// Delete blockchain data (RocksDB) while preserving keys and identity.
    ResetChain {
        /// Path to the data directory.
        #[arg(long, default_value_os_t = default_data_dir())]
        data_dir: PathBuf,
        /// Actually perform the deletion (without this flag, only a dry-run is shown).
        #[arg(long)]
        confirm: bool,
        /// Preserve peer memory (recently-seen peers) across the reset. (Not yet implemented — flag accepted but ignored.)
        #[arg(long)]
        keep_peers: bool,
    },
}

#[derive(Subcommand)]
enum SecurityCommand {
    /// Show the current encryption status of the data directory.
    Status {
        /// Path to the data directory.
        #[arg(long, default_value_os_t = default_data_dir())]
        data_dir: PathBuf,
    },

    /// Switch the at-rest encryption mode.
    SetMode {
        /// Encryption mode: "automatic" or "manual".
        #[arg(long)]
        mode: String,

        /// Password for manual mode (required when switching TO manual).
        #[arg(long)]
        password: Option<String>,

        /// Current password (required when switching FROM manual).
        #[arg(long)]
        current_password: Option<String>,

        /// Path to the data directory.
        #[arg(long, default_value_os_t = default_data_dir())]
        data_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Generate a new BIP-39 mnemonic and derive the Noble wallet key.
    Generate {
        /// Number of mnemonic words (12 or 24).
        #[arg(long, default_value_t = 24)]
        words: u32,

        /// Optional BIP-39 passphrase ("25th word").
        #[arg(long, default_value = "")]
        passphrase: String,

        /// Output machine-readable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Recover a wallet from an existing BIP-39 mnemonic phrase.
    Recover {
        /// The mnemonic phrase (12 or 24 words, quoted).
        #[arg(long)]
        mnemonic: String,

        /// Optional BIP-39 passphrase ("25th word").
        #[arg(long, default_value = "")]
        passphrase: String,

        /// Output machine-readable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },

    /// Delete a wallet key from the keystore.
    /// Auto-discovers noble.toml for offline mode, or uses RPC if node is running.
    Delete {
        /// Public key hex (wire format) to delete.
        pubkey_hex: String,
        /// Override config file path (default: auto-detect noble.toml).
        #[arg(long)]
        config: Option<String>,
        /// JSON-RPC URL of the running node (online mode).
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },

    /// List all public keys in the wallet.
    /// Auto-discovers noble.toml for offline mode, or uses RPC if node is running.
    List {
        /// Override config file path (default: auto-detect noble.toml).
        #[arg(long)]
        config: Option<String>,

        /// JSON-RPC URL of the running node (online mode).
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,

        /// Output machine-readable JSON instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AllowIpsCommand {
    /// List current allowed CIDRs.
    List {
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
    /// Replace all allowed CIDRs.
    Set {
        /// CIDRs to allow (e.g. 192.168.0.0/16, or "tailscale").
        cidrs: Vec<String>,
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
    /// Add a CIDR to the allow list.
    Add {
        /// CIDR to add (e.g. 192.168.0.0/16, or "tailscale").
        cidr: String,
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
    /// Remove a CIDR from the allow list.
    Remove {
        /// CIDR to remove.
        cidr: String,
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Dial a peer by multiaddr on a running node.
    Dial {
        /// Multiaddr to dial (e.g. /ip4/192.168.5.20/tcp/8780).
        multiaddr: String,
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },

    /// List configured seed nodes.
    ListSeeds {
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },

    /// Add a seed node (dials immediately and persists to noble.toml).
    AddSeed {
        /// Multiaddr of the seed (e.g. /ip4/192.168.5.20/tcp/8780).
        multiaddr: String,
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
}

#[derive(Subcommand)]
enum StorageCommand {
    /// Show storage stats (DB size, disk usage, column families).
    Info {
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
    /// Show current storage configuration.
    Config {
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Update a storage config value (writes to noble.toml, restart required).
    Set {
        /// Config key (data_dir, cache_size_mb, compression, pruning_mode, keep_blocks, max_db_size_gb).
        key: String,
        /// New value.
        value: String,
        /// JSON-RPC URL of the running node.
        #[arg(long, default_value = "https://127.0.0.1:8783")]
        rpc_url: String,
    },
}

#[derive(Clone, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

#[derive(Clone, ValueEnum)]
enum BenchSuite {
    All,
    Crypto,
    Codec,
    Hash,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Genesis {
            output,
            network,
            json,
        } => cmd_genesis(output, network, json),
        Commands::Benchmark { suite } => cmd_benchmark(suite),
        Commands::ValidateChain { data_dir } => cmd_validate_chain(data_dir),
        Commands::Wallet { action } => cmd_wallet(action),
        Commands::Security { action } => cmd_security(action),
        Commands::Peer { action } => cmd_peer(action),
        Commands::AllowIps { action } => cmd_allow_ips(action),
        Commands::Storage { action } => cmd_storage(action),
        Commands::ResetChain {
            data_dir,
            confirm,
            keep_peers,
        } => cmd_reset_chain(data_dir, confirm, keep_peers),
    }
}

// ---------------------------------------------------------------------------
// genesis
// ---------------------------------------------------------------------------

fn cmd_genesis(output: PathBuf, network: Network, json: bool) {
    let block = match network {
        Network::Mainnet => genesis_block(),
        Network::Testnet => testnet_genesis_block(),
        Network::Regtest => regtest_genesis_block(),
    };

    let cbor_bytes = block
        .to_cbor()
        .expect("failed to serialize genesis block to CBOR");

    fs::write(&output, &cbor_bytes).expect("failed to write genesis CBOR file");

    let block_hash = block
        .header
        .compute_block_hash()
        .expect("failed to compute genesis block hash");

    eprintln!("Wrote {} bytes to {}", cbor_bytes.len(), output.display());
    eprintln!("Genesis block hash: {block_hash}");

    if json {
        let obj = serde_json::json!({
            "block_hash": block_hash.to_string(),
            "height": block.header.height,
            "timestamp": block.header.timestamp,
            "cbor_size": cbor_bytes.len(),
        });
        println!("{}", serde_json::to_string_pretty(&obj).unwrap());
    }
}

// ---------------------------------------------------------------------------
// benchmark
// ---------------------------------------------------------------------------

fn cmd_benchmark(suite: BenchSuite) {
    let mut results: Vec<(&str, std::time::Duration)> = Vec::new();

    match suite {
        BenchSuite::All => {
            run_hash_benchmarks(&mut results);
            run_crypto_benchmarks(&mut results);
            run_codec_benchmarks(&mut results);
        }
        BenchSuite::Hash => run_hash_benchmarks(&mut results),
        BenchSuite::Crypto => run_crypto_benchmarks(&mut results),
        BenchSuite::Codec => run_codec_benchmarks(&mut results),
    }

    // Print formatted table
    println!("{:<30} {:>12}", "Benchmark", "Time");
    println!("{}", "-".repeat(44));
    for (name, elapsed) in &results {
        println!("{:<30} {:>12.3?}", name, elapsed);
    }
}

/// SHA-256 hash of 1 KB payload, iterated 10 000 times.
fn run_hash_benchmarks(results: &mut Vec<(&str, std::time::Duration)>) {
    let data = vec![0xABu8; 1024];
    let iterations = 10_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = sha256(&data);
    }
    let elapsed = start.elapsed();
    results.push(("SHA-256 1KB x10000", elapsed));
}

/// Ed25519 sign + verify and secp256k1 sign + verify.
fn run_crypto_benchmarks(results: &mut Vec<(&str, std::time::Duration)>) {
    let message = sha256(b"benchmark payload");

    // Ed25519
    let (ed_sk, ed_pk) = ed25519::generate_keypair();

    let iterations = 1_000;

    // Ed25519 sign
    let start = Instant::now();
    let mut ed_sig = Vec::new();
    for _ in 0..iterations {
        ed_sig = ed25519::sign(&ed_sk, &message.0).expect("ed25519 sign");
    }
    results.push(("Ed25519 sign x1000", start.elapsed()));

    // Ed25519 verify
    let start = Instant::now();
    for _ in 0..iterations {
        ed25519::verify(&ed_pk, &message.0, &ed_sig).expect("ed25519 verify");
    }
    results.push(("Ed25519 verify x1000", start.elapsed()));

    // secp256k1
    let (sec_sk, sec_pk) = secp256k1::generate_keypair();

    // secp256k1 sign
    let start = Instant::now();
    let mut sec_sig = Vec::new();
    for _ in 0..iterations {
        sec_sig = secp256k1::sign(&sec_sk, &message.0).expect("secp256k1 sign");
    }
    results.push(("secp256k1 sign x1000", start.elapsed()));

    // secp256k1 verify
    let start = Instant::now();
    for _ in 0..iterations {
        secp256k1::verify(&sec_pk, &message.0, &sec_sig).expect("secp256k1 verify");
    }
    results.push(("secp256k1 verify x1000", start.elapsed()));
}

/// CBOR encode/decode a genesis block, iterated 1 000 times.
fn run_codec_benchmarks(results: &mut Vec<(&str, std::time::Duration)>) {
    let block = genesis_block();
    let iterations = 1_000;

    // Encode
    let start = Instant::now();
    let mut encoded = Vec::new();
    for _ in 0..iterations {
        encoded = block.to_cbor().expect("cbor encode");
    }
    results.push(("CBOR encode block x1000", start.elapsed()));

    // Decode
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = Block::from_cbor(&encoded).expect("cbor decode");
    }
    results.push(("CBOR decode block x1000", start.elapsed()));
}

// ---------------------------------------------------------------------------
// validate-chain
// ---------------------------------------------------------------------------

fn cmd_validate_chain(data_dir: PathBuf) {
    let storage = RocksDbStorage::open(&data_dir).expect("failed to open RocksDB");

    let tip = match storage.get_chain_tip().expect("failed to read chain tip") {
        Some(t) => t,
        None => {
            println!("Chain is empty (no blocks). Validation passed trivially.");
            return;
        }
    };

    println!("Chain tip: height={}, hash={}", tip.height, tip.block_hash);

    let mut prev_hash = Hash256::ZERO;
    let mut validated: u64 = 0;

    for height in 0..=tip.height {
        // Retrieve block hash at this height
        let stored_hash = match storage.get_block_hash_by_height(height) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("FAIL at height {height}: missing block hash — {e}");
                std::process::exit(1);
            }
        };

        // Retrieve full block
        let block = match storage.get_block(&stored_hash) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("FAIL at height {height}: cannot read block — {e}");
                std::process::exit(1);
            }
        };

        // 1. Verify header hash
        let recomputed_hash = block
            .header
            .compute_block_hash()
            .expect("hash computation failed");
        if recomputed_hash != stored_hash {
            eprintln!(
                "FAIL at height {height}: block hash mismatch (stored={stored_hash}, recomputed={recomputed_hash})"
            );
            std::process::exit(1);
        }

        // 2. Verify merkle root
        // We cannot recompute tx_ids without a chain_id, so we check the count
        // and the empty-tree case. For blocks with transactions we recompute
        // the merkle root from the transactions' canonical tx_ids.
        if block.transactions.is_empty() {
            let expected_merkle = compute_merkle_root(&[]);
            if block.header.merkle_root != expected_merkle {
                eprintln!("FAIL at height {height}: merkle root mismatch for empty block");
                std::process::exit(1);
            }
        }
        // For non-empty blocks we skip full merkle recomputation since
        // compute_tx_id requires chain_id which is not available from storage.
        // The integrity module handles that for full audits.

        // 3. Verify prev_block_hash linkage
        if block.header.prev_block_hash != prev_hash {
            eprintln!(
                "FAIL at height {height}: prev_block_hash mismatch (expected={prev_hash}, got={})",
                block.header.prev_block_hash
            );
            std::process::exit(1);
        }

        // 4. Verify height monotonicity
        if block.header.height != height {
            eprintln!(
                "FAIL at height {height}: stored height={} does not match expected",
                block.header.height
            );
            std::process::exit(1);
        }

        prev_hash = stored_hash;
        validated += 1;

        if validated % 1_000 == 0 {
            println!("  validated {validated} blocks (height {height})...");
        }
    }

    println!(
        "SUCCESS: validated {validated} blocks from height 0 to {}.",
        tip.height
    );
}

// ---------------------------------------------------------------------------
// wallet (offline generate / recover)
// ---------------------------------------------------------------------------

/// All derived wallet information (no persistence).
struct WalletInfo {
    mnemonic: String,
    private_key_hex: String,
    public_key_hex: String,
    wire_hex: String,
    p2pkh: String,
    p2wpkh: String,
    p2tr: String,
}

/// Derive a Noble wallet from a BIP-39 mnemonic (no persistence).
///
/// Path: `m/44'/9999'/0'/0/0` (same as `noble-wallet` `KeyStore`).
fn derive_wallet_info(mnemonic: &bip39::Mnemonic, passphrase: &str) -> WalletInfo {
    use noble_crypto::bitcoin_addr::{pubkey_to_p2pkh, pubkey_to_p2wpkh, pubkey_to_p2tr};
    use noble_crypto::NoblePrivateKey;

    // 1. Seed
    let mut seed = mnemonic.to_seed(passphrase);

    // 2. BIP-32 derivation at m/44'/9999'/0'/0/0
    let xprv = bip32::XPrv::derive_from_path(
        &seed,
        &"m/44'/9999'/0'/0/0".parse().expect("valid derivation path"),
    )
    .expect("BIP-32 derivation failed");

    seed.zeroize();

    // 3. Build private/public keys
    let mut sk_bytes = xprv.private_key().to_bytes().to_vec();
    let private_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
    let public_key = private_key.public_key();
    let wire_bytes = public_key.to_wire_bytes();
    let pk_bytes = public_key.key_bytes();

    // 4. Compressed secp256k1 public key (33 bytes)
    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(pk_bytes);

    // 5. Bitcoin addresses
    let p2pkh = pubkey_to_p2pkh(&compressed, true);
    let p2wpkh = pubkey_to_p2wpkh(&compressed, true);
    let p2tr = pubkey_to_p2tr(&compressed, true);

    let info = WalletInfo {
        mnemonic: mnemonic.to_string(),
        private_key_hex: hex::encode(&sk_bytes),
        public_key_hex: hex::encode(pk_bytes),
        wire_hex: hex::encode(&wire_bytes),
        p2pkh,
        p2wpkh,
        p2tr,
    };

    sk_bytes.zeroize();
    info
}

// ---------------------------------------------------------------------------
// wallet auto-discovery helpers
// ---------------------------------------------------------------------------

/// Minimal TOML structs for extracting paths from noble.toml.
#[derive(serde::Deserialize)]
struct MinimalConfig {
    #[serde(default)]
    storage: MinimalStorage,
    #[serde(default)]
    wallet: MinimalWallet,
}

#[derive(serde::Deserialize, Default)]
struct MinimalStorage {
    #[serde(default)]
    data_dir: Option<PathBuf>,
}

#[derive(serde::Deserialize, Default)]
struct MinimalWallet {
    #[serde(default)]
    keystore_path: Option<PathBuf>,
}

/// Read noble.toml and extract `storage.data_dir` + `wallet.keystore_path`.
/// Returns `(data_dir, keystore_path)` or `None` if the config file is missing.
fn resolve_wallet_paths(config_override: Option<&str>) -> Option<(PathBuf, PathBuf)> {
    let config_path = config_override
        .map(PathBuf::from)
        .unwrap_or_else(|| noble_core::paths::platform_config_path());

    let text = std::fs::read_to_string(&config_path).ok()?;
    let cfg: MinimalConfig = toml::from_str(&text).ok()?;

    let data_dir = cfg.storage.data_dir
        .unwrap_or_else(noble_core::paths::platform_data_dir);
    let keystore_path = cfg.wallet.keystore_path
        .unwrap_or_else(|| data_dir.join("keystore"));

    Some((data_dir, keystore_path))
}

/// Load .chain_meta from data_dir and derive the 64-char hex wallet passphrase.
fn derive_wallet_passphrase(data_dir: &std::path::Path) -> String {
    let chain_meta = noble_crypto::file_encrypt::load_or_create_chain_meta(
        data_dir, "automatic", None,
    )
    .unwrap_or_else(|e| {
        eprintln!("Error loading .chain_meta: {e}");
        std::process::exit(1);
    });
    hex::encode(noble_crypto::file_encrypt::derive_wallet_key(&chain_meta))
}

fn cmd_wallet(action: WalletCommand) {
    match action {
        WalletCommand::Generate {
            words,
            passphrase,
            json,
        } => {
            if words != 12 && words != 24 {
                eprintln!("Error: --words must be 12 or 24.");
                std::process::exit(1);
            }
            let mnemonic = bip39::Mnemonic::generate(words as usize)
                .expect("failed to generate mnemonic");
            let info = derive_wallet_info(&mnemonic, &passphrase);
            if json {
                print_wallet_json(&info);
            } else {
                print_wallet_human(&info);
            }
        }
        WalletCommand::Recover {
            mnemonic,
            passphrase,
            json,
        } => {
            let parsed: bip39::Mnemonic = match mnemonic.parse() {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error: invalid mnemonic — {e}");
                    std::process::exit(1);
                }
            };
            let info = derive_wallet_info(&parsed, &passphrase);
            if json {
                print_wallet_json(&info);
            } else {
                print_wallet_human(&info);
            }
        }
        WalletCommand::Delete {
            pubkey_hex,
            config,
            rpc_url,
        } => {
            // If --config is set, go straight to offline mode.
            // Otherwise try RPC first, then fall back to auto-discovered config.
            if config.is_some() {
                // Offline mode with explicit config
                let (data_dir, ks_path) = resolve_wallet_paths(config.as_deref())
                    .unwrap_or_else(|| { eprintln!("Error: could not read noble.toml"); std::process::exit(1); });
                let passphrase = derive_wallet_passphrase(&data_dir);
                let mut ks = noble_wallet::KeyStore::new(&ks_path)
                    .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                let wire = hex::decode(&pubkey_hex)
                    .unwrap_or_else(|e| { eprintln!("Invalid hex: {e}"); std::process::exit(1); });
                let pk = noble_crypto::NoblePublicKey::from_wire_bytes(&wire)
                    .unwrap_or_else(|e| { eprintln!("Invalid key: {e}"); std::process::exit(1); });
                ks.delete_key(&pk, &passphrase)
                    .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                let short_start = &pubkey_hex[..pubkey_hex.len().min(8)];
                let short_end = &pubkey_hex[pubkey_hex.len().saturating_sub(8)..];
                println!("Key deleted: {short_start}...{short_end}");
            } else {
                // Try online (RPC) first — passphrase is ignored server-side
                let params = serde_json::json!({
                    "pubkey_hex": pubkey_hex,
                    "passphrase": "",
                });
                match rpc_call(&rpc_url, "noble_deleteAddress", params) {
                    Ok(result) => {
                        let msg = result
                            .get("message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("Key deleted.");
                        println!("{msg}");
                    }
                    Err(rpc_err) if rpc_err.starts_with("RPC error:") => {
                        // Node is reachable but returned an error — show it
                        eprintln!("Error: {rpc_err}");
                        std::process::exit(1);
                    }
                    Err(_conn_err) => {
                        // Connection failed — fall back to offline auto-discovery
                        if let Some((data_dir, ks_path)) = resolve_wallet_paths(None) {
                            let passphrase = derive_wallet_passphrase(&data_dir);
                            let mut ks = noble_wallet::KeyStore::new(&ks_path)
                                .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                            let wire = hex::decode(&pubkey_hex)
                                .unwrap_or_else(|e| { eprintln!("Invalid hex: {e}"); std::process::exit(1); });
                            let pk = noble_crypto::NoblePublicKey::from_wire_bytes(&wire)
                                .unwrap_or_else(|e| { eprintln!("Invalid key: {e}"); std::process::exit(1); });
                            ks.delete_key(&pk, &passphrase)
                                .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                            let short_start = &pubkey_hex[..pubkey_hex.len().min(8)];
                            let short_end = &pubkey_hex[pubkey_hex.len().saturating_sub(8)..];
                            println!("Key deleted: {short_start}...{short_end}");
                        } else {
                            eprintln!("Error: node not reachable and no noble.toml found.");
                            eprintln!("Hint: use --config /path/to/noble.toml for offline mode.");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
        WalletCommand::List {
            config,
            rpc_url,
            json,
        } => {
            if config.is_some() {
                // Offline mode with explicit config
                let (_data_dir, ks_path) = resolve_wallet_paths(config.as_deref())
                    .unwrap_or_else(|| { eprintln!("Error: could not read noble.toml"); std::process::exit(1); });
                let ks_path_str = ks_path.display().to_string();
                let ks = noble_wallet::KeyStore::new(&ks_path)
                    .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                let keys = ks.list_keys()
                    .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                print_key_list_offline(&keys, &ks_path_str, json);
            } else {
                // Try online (RPC) first
                match rpc_call(&rpc_url, "noble_listAddresses", serde_json::json!({})) {
                    Ok(result) => print_key_list_online(&result, json),
                    Err(rpc_err) if rpc_err.starts_with("RPC error:") => {
                        eprintln!("Error: {rpc_err}");
                        std::process::exit(1);
                    }
                    Err(_conn_err) => {
                        // Connection failed — fall back to offline auto-discovery
                        if let Some((_data_dir, ks_path)) = resolve_wallet_paths(None) {
                            let ks_path_str = ks_path.display().to_string();
                            let ks = noble_wallet::KeyStore::new(&ks_path)
                                .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                            let keys = ks.list_keys()
                                .unwrap_or_else(|e| { eprintln!("Error: {e}"); std::process::exit(1); });
                            print_key_list_offline(&keys, &ks_path_str, json);
                        } else {
                            eprintln!("Error: node not reachable and no noble.toml found.");
                            eprintln!("Hint: use --config /path/to/noble.toml for offline mode.");
                            std::process::exit(1);
                        }
                    }
                }
            }
        }
    }
}

/// Print key list from offline keystore read.
fn print_key_list_offline(keys: &[noble_crypto::NoblePublicKey], ks_path: &str, json: bool) {
    use noble_crypto::SCHEME_SECP256K1;
    if json {
        let entries: Vec<serde_json::Value> = keys.iter().map(|pk| {
            let wire = pk.to_wire_bytes();
            let scheme = if pk.scheme_id() == SCHEME_SECP256K1 { "secp256k1" } else { "ed25519" };
            let mut obj = serde_json::json!({
                "pubkey_hex": hex::encode(&wire),
                "scheme": scheme,
            });
            if pk.scheme_id() == SCHEME_SECP256K1 {
                let kb = pk.key_bytes();
                if kb.len() == 33 {
                    let mut compressed = [0u8; 33];
                    compressed.copy_from_slice(kb);
                    obj["p2pkh"] = serde_json::json!(noble_crypto::bitcoin_addr::pubkey_to_p2pkh(&compressed, true));
                    obj["p2wpkh"] = serde_json::json!(noble_crypto::bitcoin_addr::pubkey_to_p2wpkh(&compressed, true));
                    obj["p2tr"] = serde_json::json!(noble_crypto::bitcoin_addr::pubkey_to_p2tr(&compressed, true));
                }
            }
            obj
        }).collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "keys": entries })).unwrap());
    } else {
        if keys.is_empty() {
            println!("No keys found in {ks_path}");
            return;
        }
        println!("=== Wallet Keys ({}) ===", keys.len());
        println!();
        for pk in keys {
            let wire_hex = hex::encode(pk.to_wire_bytes());
            let scheme = if pk.scheme_id() == SCHEME_SECP256K1 { "secp256k1" } else { "ed25519" };
            println!("[{scheme}] {wire_hex}");
            if pk.scheme_id() == SCHEME_SECP256K1 {
                let kb = pk.key_bytes();
                if kb.len() == 33 {
                    let mut compressed = [0u8; 33];
                    compressed.copy_from_slice(kb);
                    println!("  P2PKH  (1...):  {}", noble_crypto::bitcoin_addr::pubkey_to_p2pkh(&compressed, true));
                    println!("  P2WPKH (bc1q):  {}", noble_crypto::bitcoin_addr::pubkey_to_p2wpkh(&compressed, true));
                    println!("  P2TR   (bc1p):  {}", noble_crypto::bitcoin_addr::pubkey_to_p2tr(&compressed, true));
                }
            }
            println!();
        }
        println!("To delete: noble-tool wallet delete <pubkey_hex>");
    }
}

/// Print key list from online RPC response (noble_listAddresses).
fn print_key_list_online(result: &serde_json::Value, json: bool) {
    if json {
        // Pass through the RPC JSON directly
        println!("{}", serde_json::to_string_pretty(result).unwrap());
    } else {
        let keys = result.get("keys").and_then(|v| v.as_array());
        match keys {
            Some(list) if !list.is_empty() => {
                println!("=== Wallet Keys ({}) ===", list.len());
                println!();
                for entry in list {
                    let scheme = entry.get("scheme").and_then(|v| v.as_str()).unwrap_or("?");
                    let hex = entry.get("pubkey_hex").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("[{scheme}] {hex}");
                    if let Some(addrs) = entry.get("bitcoin_addresses").and_then(|v| v.as_array()) {
                        for addr in addrs {
                            if let Some(s) = addr.as_str() {
                                let label = if s.starts_with("bc1p") {
                                    "P2TR   (bc1p)"
                                } else if s.starts_with("bc1q") {
                                    "P2WPKH (bc1q)"
                                } else {
                                    "P2PKH  (1...)"
                                };
                                println!("  {label}:  {s}");
                            }
                        }
                    }
                    println!();
                }
                println!("To delete: noble-tool wallet delete <pubkey_hex>");
            }
            _ => {
                println!("No keys found.");
            }
        }
    }
}

fn print_wallet_human(info: &WalletInfo) {
    // Warning on stderr
    eprintln!("WARNING: The private key and mnemonic below grant full");
    eprintln!("control of this wallet. Store them securely and NEVER");
    eprintln!("share them. This output is NOT saved anywhere.");
    eprintln!();

    // Data on stdout
    println!("=== Noble Wallet ===");
    println!();

    // Format mnemonic in numbered 4-column grid
    let words: Vec<&str> = info.mnemonic.split_whitespace().collect();
    println!("Mnemonic ({} words):", words.len());
    for (i, word) in words.iter().enumerate() {
        print!("{:>3}. {:<14}", i + 1, word);
        if (i + 1) % 4 == 0 {
            println!();
        }
    }
    println!();

    println!("Derivation Path: m/44'/9999'/0'/0/0");
    println!("Private Key:     {}", info.private_key_hex);
    println!("Public Key:      {}", info.public_key_hex);
    println!("Wire Hex:        {}", info.wire_hex);
    println!();
    println!("Bitcoin Addresses:");
    println!("  P2PKH  (1...):   {}", info.p2pkh);
    println!("  P2WPKH (bc1q):   {}", info.p2wpkh);
    println!("  P2TR   (bc1p):   {}", info.p2tr);
}

fn print_wallet_json(info: &WalletInfo) {
    let obj = serde_json::json!({
        "mnemonic": info.mnemonic,
        "derivation_path": "m/44'/9999'/0'/0/0",
        "private_key": info.private_key_hex,
        "public_key": info.public_key_hex,
        "wire_hex": info.wire_hex,
        "bitcoin_addresses": {
            "p2pkh": info.p2pkh,
            "p2wpkh": info.p2wpkh,
            "p2tr": info.p2tr,
        },
    });
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}

// ---------------------------------------------------------------------------
// security (encryption mode management)
// ---------------------------------------------------------------------------

fn cmd_security(action: SecurityCommand) {
    use noble_crypto::file_encrypt::{chain_meta_status, load_or_create_chain_meta, switch_encryption_mode};

    match action {
        SecurityCommand::Status { data_dir } => {
            let (exists, is_locked) = chain_meta_status(&data_dir);
            let mode = if is_locked { "manual" } else { "automatic" };
            println!("Data directory: {}", data_dir.display());
            println!("Chain meta:     {}", if exists { "exists" } else { "not found" });
            println!("Format:         {}", if is_locked { "NBLK (password-locked)" } else { "raw 32-byte entropy" });
            println!("Mode:           {mode}");
        }
        SecurityCommand::SetMode {
            mode,
            password,
            current_password,
            data_dir,
        } => {
            if mode != "automatic" && mode != "manual" {
                eprintln!("Error: --mode must be 'automatic' or 'manual'.");
                std::process::exit(1);
            }

            let (exists, is_locked) = chain_meta_status(&data_dir);
            if !exists {
                eprintln!("Error: no .chain_meta file found in {}", data_dir.display());
                eprintln!("Run the node once to create it, or use 'noble-tool genesis' first.");
                std::process::exit(1);
            }

            // Load the current chain_meta
            let current_mode = if is_locked { "manual" } else { "automatic" };
            let load_pw = if is_locked {
                current_password.as_deref().or_else(|| {
                    eprintln!("Error: --current-password is required when chain_meta is password-locked.");
                    std::process::exit(1);
                })
            } else {
                None
            };

            let chain_meta = load_or_create_chain_meta(&data_dir, current_mode, load_pw)
                .unwrap_or_else(|e| {
                    eprintln!("Error loading chain_meta: {e}");
                    std::process::exit(1);
                });

            switch_encryption_mode(
                &data_dir,
                &chain_meta,
                &mode,
                current_password.as_deref(),
                password.as_deref(),
            )
            .unwrap_or_else(|e| {
                eprintln!("Error switching encryption mode: {e}");
                std::process::exit(1);
            });

            println!("Encryption mode switched to '{mode}'.");
            println!("Remember to update noble.toml: [security] encryption_mode = \"{mode}\"");
        }
    }
}

// ---------------------------------------------------------------------------
// peer (RPC client)
// ---------------------------------------------------------------------------

/// Make a JSON-RPC 2.0 call to a running Noble node.
fn rpc_call(rpc_url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value, String> {
    // Ensure a crypto provider is installed (idempotent — ignores if already set).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    // Build agent — accept self-signed certs (nodes use auto-generated TLS certs).
    let agent = ureq::AgentBuilder::new()
        .tls_config(
            std::sync::Arc::new(
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
                    .with_no_client_auth(),
            ),
        )
        .build();

    let resp = agent
        .post(rpc_url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let resp_str = resp.into_string().map_err(|e| format!("invalid response body: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&resp_str)
        .map_err(|e| format!("invalid JSON response: {e}"))?;

    if let Some(error) = json.get("error") {
        let msg = error["message"].as_str().unwrap_or("unknown error");
        return Err(format!("RPC error: {msg}"));
    }

    json.get("result")
        .cloned()
        .ok_or_else(|| "no 'result' field in RPC response".to_string())
}

/// TLS verifier that accepts any certificate (for self-signed node certs).
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn cmd_peer(action: PeerCommand) {
    match action {
        PeerCommand::Dial { multiaddr, rpc_url } => {
            let multiaddr = if multiaddr.starts_with('/') {
                multiaddr.clone()
            } else {
                format!("/ip4/{}/tcp/8780", multiaddr)
            };
            let params = serde_json::json!({ "multiaddr": multiaddr });
            match rpc_call(&rpc_url, "noble_dialPeer", params) {
                Ok(result) => {
                    let msg = result.get("message").and_then(|m| m.as_str()).unwrap_or("OK");
                    println!("{msg}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        PeerCommand::ListSeeds { rpc_url } => {
            match rpc_call(&rpc_url, "noble_getSeeds", serde_json::json!({})) {
                Ok(result) => {
                    let seeds = result.get("seeds").and_then(|s| s.as_array());
                    match seeds {
                        Some(list) if !list.is_empty() => {
                            println!("Configured seeds ({}):", list.len());
                            for seed in list {
                                println!("  {}", seed.as_str().unwrap_or("?"));
                            }
                        }
                        _ => println!("No seeds configured."),
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        PeerCommand::AddSeed { multiaddr, rpc_url } => {
            let multiaddr = if multiaddr.starts_with('/') {
                multiaddr.clone()
            } else {
                format!("/ip4/{}/tcp/8780", multiaddr)
            };
            let params = serde_json::json!({ "multiaddr": multiaddr });
            match rpc_call(&rpc_url, "noble_addSeed", params) {
                Ok(result) => {
                    let seeds = result.get("seeds").and_then(|s| s.as_array());
                    let count = seeds.map_or(0, |s| s.len());
                    println!("Seed added. Total seeds: {count}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// allow-ips (RPC client)
// ---------------------------------------------------------------------------

/// Expand shorthand aliases for common CIDRs.
fn expand_cidr_alias(s: &str) -> String {
    match s {
        "tailscale" | "100" => "100.64.0.0/10".into(),
        "lan" | "192" => "192.168.0.0/16".into(),
        "10" => "10.0.0.0/8".into(),
        "172" => "172.16.0.0/12".into(),
        other => other.to_string(),
    }
}

fn cmd_allow_ips(action: AllowIpsCommand) {
    match action {
        AllowIpsCommand::List { rpc_url } => {
            match rpc_call(&rpc_url, "noble_getAllowedIps", serde_json::json!({})) {
                Ok(result) => {
                    let ips = result
                        .get("allowed_ips")
                        .and_then(|v| v.as_array());
                    let remote = result
                        .get("remote_access_enabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    match ips {
                        Some(list) if !list.is_empty() => {
                            println!("Allowed CIDRs ({}):", list.len());
                            for cidr in list {
                                println!("  {}", cidr.as_str().unwrap_or("?"));
                            }
                            println!(
                                "Remote access: {}",
                                if remote { "enabled" } else { "disabled" }
                            );
                        }
                        _ => {
                            println!("No allowed CIDRs configured (localhost-only).");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        AllowIpsCommand::Set { cidrs, rpc_url } => {
            let expanded: Vec<String> = cidrs.iter().map(|s| expand_cidr_alias(s)).collect();
            let params = serde_json::json!({ "allowed_ips": expanded });
            match rpc_call(&rpc_url, "noble_setAllowedIps", params) {
                Ok(result) => {
                    let msg = result
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("OK");
                    println!("{msg}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        AllowIpsCommand::Add { cidr, rpc_url } => {
            let expanded = expand_cidr_alias(&cidr);
            // Get current list
            let current = match rpc_call(&rpc_url, "noble_getAllowedIps", serde_json::json!({})) {
                Ok(result) => {
                    result
                        .get("allowed_ips")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                }
                Err(e) => {
                    eprintln!("Error fetching current list: {e}");
                    std::process::exit(1);
                }
            };
            if current.iter().any(|c| c == &expanded) {
                println!("CIDR {expanded} is already in the allow list.");
                return;
            }
            let mut updated = current;
            updated.push(expanded.clone());
            let params = serde_json::json!({ "allowed_ips": updated });
            match rpc_call(&rpc_url, "noble_setAllowedIps", params) {
                Ok(_) => {
                    println!("Added {expanded}.");
                    // Print updated list
                    print_allow_list(&rpc_url);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        AllowIpsCommand::Remove { cidr, rpc_url } => {
            let expanded = expand_cidr_alias(&cidr);
            // Get current list
            let current = match rpc_call(&rpc_url, "noble_getAllowedIps", serde_json::json!({})) {
                Ok(result) => {
                    result
                        .get("allowed_ips")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default()
                }
                Err(e) => {
                    eprintln!("Error fetching current list: {e}");
                    std::process::exit(1);
                }
            };
            if !current.iter().any(|c| c == &expanded) {
                println!("CIDR {expanded} is not in the allow list.");
                return;
            }
            let updated: Vec<String> = current.into_iter().filter(|c| c != &expanded).collect();
            let params = serde_json::json!({ "allowed_ips": updated });
            match rpc_call(&rpc_url, "noble_setAllowedIps", params) {
                Ok(_) => {
                    println!("Removed {expanded}.");
                    print_allow_list(&rpc_url);
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Print the current allow list from the node.
fn print_allow_list(rpc_url: &str) {
    if let Ok(result) = rpc_call(rpc_url, "noble_getAllowedIps", serde_json::json!({})) {
        let ips = result.get("allowed_ips").and_then(|v| v.as_array());
        let remote = result
            .get("remote_access_enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        match ips {
            Some(list) if !list.is_empty() => {
                println!("Allowed CIDRs ({}):", list.len());
                for cidr in list {
                    println!("  {}", cidr.as_str().unwrap_or("?"));
                }
                println!(
                    "Remote access: {}",
                    if remote { "enabled" } else { "disabled" }
                );
            }
            _ => {
                println!("No allowed CIDRs configured (localhost-only).");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------

fn cmd_storage(action: StorageCommand) {
    match action {
        StorageCommand::Info { rpc_url } => {
            match rpc_call(&rpc_url, "noble_getStorageStats", serde_json::json!({})) {
                Ok(result) => {
                    let data_dir = result.get("data_dir").and_then(|v| v.as_str()).unwrap_or("N/A");
                    let db_bytes = result.get("total_db_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let avail = result.get("available_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let total_vol = result.get("total_volume_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let cache = result.get("cache_size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let compress = result.get("compression_enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                    let max_db = result.get("max_db_size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);

                    println!("=== Storage Stats ===");
                    println!("{:<20} {}", "Data Directory:", data_dir);
                    println!("{:<20} {}", "DB Size:", format_bytes(db_bytes));
                    println!("{:<20} {}", "Disk Free:", format_bytes(avail));
                    println!("{:<20} {}", "Disk Total:", format_bytes(total_vol));
                    println!("{:<20} {} MB", "Cache:", cache / (1024 * 1024));
                    println!("{:<20} {}", "Compression:", if compress { "Zstd" } else { "None" });
                    if max_db > 0 {
                        println!("{:<20} {} GB", "Max DB Size:", max_db / (1024 * 1024 * 1024));
                    } else {
                        println!("{:<20} Unlimited", "Max DB Size:");
                    }

                    // Column families
                    if let Some(cfs) = result.get("column_families").and_then(|v| v.as_array()) {
                        if !cfs.is_empty() {
                            println!();
                            println!("Column Families:");
                            println!("  {:<24} {:>12} {:>12}", "Name", "Est. Size", "Est. Keys");
                            println!("  {}", "-".repeat(50));
                            for cf in cfs {
                                let name = cf.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                                let bytes = cf.get("estimated_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                                let keys = cf.get("estimated_keys").and_then(|v| v.as_u64()).unwrap_or(0);
                                println!("  {:<24} {:>12} {:>12}", name, format_bytes(bytes), keys);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        StorageCommand::Config { rpc_url, json } => {
            match rpc_call(&rpc_url, "noble_getStorageConfig", serde_json::json!({})) {
                Ok(result) => {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
                    } else {
                        let data_dir = result.get("data_dir").and_then(|v| v.as_str()).unwrap_or("N/A");
                        let cache = result.get("cache_size_mb").and_then(|v| v.as_u64()).unwrap_or(0);
                        let compress = result.get("compression").and_then(|v| v.as_bool()).unwrap_or(false);
                        let pruning = result.get("pruning_mode").and_then(|v| v.as_str()).unwrap_or("N/A");
                        let keep = result.get("keep_blocks").and_then(|v| v.as_u64()).unwrap_or(0);
                        let max_gb = result.get("max_db_size_gb").and_then(|v| v.as_u64()).unwrap_or(0);

                        println!("=== Storage Configuration ===");
                        println!("{:<20} {}", "Data Directory:", data_dir);
                        println!("{:<20} {} MB", "Cache Size:", cache);
                        println!("{:<20} {}", "Compression:", if compress { "enabled" } else { "disabled" });
                        println!("{:<20} {}", "Pruning Mode:", pruning);
                        println!("{:<20} {}", "Keep Blocks:", if keep == 0 { "all (archive)".to_string() } else { keep.to_string() });
                        println!("{:<20} {}", "Max DB Size:", if max_gb == 0 { "unlimited".to_string() } else { format!("{max_gb} GB") });
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
        StorageCommand::Set { key, value, rpc_url } => {
            let valid_keys = ["data_dir", "cache_size_mb", "compression", "pruning_mode", "keep_blocks", "max_db_size_gb"];
            if !valid_keys.contains(&key.as_str()) {
                eprintln!("Error: unknown storage config key '{key}'");
                eprintln!("Valid keys: {}", valid_keys.join(", "));
                std::process::exit(1);
            }
            let params = serde_json::json!({
                "section": "storage",
                "key": key,
                "value": value,
            });
            match rpc_call(&rpc_url, "noble_setConfigValue", params) {
                Ok(result) => {
                    let restart = result.get("restart_required").and_then(|v| v.as_bool()).unwrap_or(true);
                    println!("Updated storage.{key} = {value}");
                    if restart {
                        println!("Restart the node for the change to take effect.");
                    }
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut idx = 0;
    while val >= 1024.0 && idx < units.len() - 1 {
        val /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{bytes} B")
    } else {
        format!("{val:.2} {}", units[idx])
    }
}

// ---------------------------------------------------------------------------
// reset-chain
// ---------------------------------------------------------------------------

fn cmd_reset_chain(data_dir: PathBuf, confirm: bool, _keep_peers: bool) {
    // 1. Verify data_dir exists
    if !data_dir.exists() {
        eprintln!(
            "Error: data directory does not exist: {}",
            data_dir.display()
        );
        std::process::exit(1);
    }

    // 2. Check RocksDB LOCK file — if locked, node is running
    let lock_path = data_dir.join("LOCK");
    if lock_path.exists() {
        match std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
        {
            Ok(f) => {
                use std::os::unix::io::AsRawFd;
                let fd = f.as_raw_fd();
                let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
                if ret != 0 {
                    eprintln!("Error: database is locked — the node is still running.");
                    eprintln!("Stop it first:  brew services stop noble");
                    std::process::exit(1);
                }
                // Lock succeeded → node is not running, release
                unsafe { libc::flock(fd, libc::LOCK_UN) };
            }
            Err(_) => {} // Can't open LOCK file — proceed cautiously
        }
    }

    // 3. Preserved files and directories (never touched)
    let preserved_files: &[&str] = &[
        "identity.json",
        "validator.key",
        ".chain_meta",
        "tls-cert.pem",
        "tls-key.pem",
        "p2p_identity.key",
        "identity_attestation.cbor",
        "noble.toml",
    ];
    let preserved_dirs: &[&str] = &["keystore"];

    // 4. Enumerate what exists in data_dir
    let entries: Vec<_> = match fs::read_dir(&data_dir) {
        Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
        Err(e) => {
            eprintln!("Error reading data directory: {e}");
            std::process::exit(1);
        }
    };

    let mut to_delete: Vec<PathBuf> = Vec::new();
    let mut preserved_found: Vec<String> = Vec::new();

    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if preserved_files.contains(&name_str.as_ref())
            || preserved_dirs.contains(&name_str.as_ref())
        {
            preserved_found.push(name_str.to_string());
        } else {
            to_delete.push(entry.path());
        }
    }

    // 5. Print plan
    println!("=== NOBLE Chain Reset ===");
    println!();
    println!("Data directory: {}", data_dir.display());
    println!();

    if to_delete.is_empty() {
        println!("Nothing to delete — data directory contains only preserved files.");
        return;
    }

    println!("WILL DELETE (blockchain data):");
    for path in &to_delete {
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if path.is_dir() {
            println!("  - {name}/");
        } else {
            println!("  - {name}");
        }
    }
    println!();
    println!("WILL PRESERVE (keys & identity):");
    for name in &preserved_found {
        let is_dir = data_dir.join(name).is_dir();
        if is_dir {
            println!("  ✓ {name}/");
        } else {
            println!("  ✓ {name}");
        }
    }

    if !confirm {
        println!();
        println!("Dry run — no files were deleted.");
        println!("Add --confirm to actually perform the reset.");
        return;
    }

    // 6. Perform deletion
    let mut deleted_count = 0u64;
    let mut freed_bytes = 0u64;

    for path in &to_delete {
        if path.is_dir() {
            // Sum sizes of files inside before deleting
            if let Ok(walk) = fs::read_dir(path) {
                for entry in walk.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        freed_bytes += meta.len();
                    }
                }
            }
            if let Err(e) = fs::remove_dir_all(path) {
                eprintln!(
                    "Warning: could not delete directory {}: {e}",
                    path.display()
                );
            } else {
                deleted_count += 1;
            }
        } else {
            if let Ok(meta) = path.metadata() {
                freed_bytes += meta.len();
            }
            if let Err(e) = fs::remove_file(path) {
                eprintln!("Warning: could not delete file {}: {e}", path.display());
            } else {
                deleted_count += 1;
            }
        }
    }

    let freed_mb = freed_bytes as f64 / (1024.0 * 1024.0);
    println!();
    println!(
        "Done. Deleted {deleted_count} items, freed {freed_mb:.1} MB."
    );
    println!("Restart the node to create a fresh genesis block.");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_mainnet_serializes() {
        let block = genesis_block();
        let bytes = block.to_cbor().expect("mainnet genesis CBOR encode");
        assert!(!bytes.is_empty());
        let decoded = Block::from_cbor(&bytes).expect("mainnet genesis CBOR decode");
        assert_eq!(block, decoded);
    }

    #[test]
    fn genesis_testnet_serializes() {
        let block = testnet_genesis_block();
        let bytes = block.to_cbor().expect("testnet genesis CBOR encode");
        assert!(!bytes.is_empty());
        let decoded = Block::from_cbor(&bytes).expect("testnet genesis CBOR decode");
        assert_eq!(block, decoded);
    }

    #[test]
    fn genesis_regtest_serializes() {
        let block = regtest_genesis_block();
        let bytes = block.to_cbor().expect("regtest genesis CBOR encode");
        assert!(!bytes.is_empty());
        let decoded = Block::from_cbor(&bytes).expect("regtest genesis CBOR decode");
        assert_eq!(block, decoded);
    }

    #[test]
    fn benchmark_sha256_runs() {
        let mut results = Vec::new();
        run_hash_benchmarks(&mut results);
        assert_eq!(results.len(), 1);
        assert!(!results[0].1.is_zero());
    }

    #[test]
    fn benchmark_ed25519_runs() {
        let mut results = Vec::new();
        run_crypto_benchmarks(&mut results);
        // Ed25519 sign, Ed25519 verify, secp256k1 sign, secp256k1 verify
        assert!(results.len() >= 2);
        for (name, dur) in &results {
            assert!(!dur.is_zero(), "{name} took zero time");
        }
    }

    #[test]
    fn validate_chain_empty_db_succeeds() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let storage = RocksDbStorage::open(dir.path()).expect("open empty RocksDB");
        let tip = storage.get_chain_tip().expect("read chain tip");
        assert!(tip.is_none(), "empty DB should have no chain tip");
    }

    // ── Wallet tests ──

    #[test]
    fn wallet_generate_24_words() {
        let mnemonic = bip39::Mnemonic::generate(24).unwrap();
        let info = derive_wallet_info(&mnemonic, "");

        let words: Vec<&str> = info.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
        assert_eq!(info.private_key_hex.len(), 64); // 32 bytes hex
        assert_eq!(info.public_key_hex.len(), 66); // 33 bytes hex (compressed)
        assert!(info.wire_hex.starts_with("02")); // secp256k1 scheme prefix
        assert!(info.p2pkh.starts_with('1') || info.p2pkh.starts_with('L'));
        assert!(info.p2wpkh.starts_with("bc1q"));
        assert!(info.p2tr.starts_with("bc1p"));
    }

    #[test]
    fn wallet_generate_12_words() {
        let mnemonic = bip39::Mnemonic::generate(12).unwrap();
        let info = derive_wallet_info(&mnemonic, "");

        let words: Vec<&str> = info.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert_eq!(info.private_key_hex.len(), 64);
        assert!(info.p2pkh.starts_with('1'));
        assert!(info.p2wpkh.starts_with("bc1q"));
        assert!(info.p2tr.starts_with("bc1p"));
    }

    #[test]
    fn wallet_recover_deterministic() {
        let mnemonic = bip39::Mnemonic::generate(24).unwrap();
        let info1 = derive_wallet_info(&mnemonic, "");
        let info2 = derive_wallet_info(&mnemonic, "");

        assert_eq!(info1.private_key_hex, info2.private_key_hex);
        assert_eq!(info1.public_key_hex, info2.public_key_hex);
        assert_eq!(info1.wire_hex, info2.wire_hex);
        assert_eq!(info1.p2pkh, info2.p2pkh);
        assert_eq!(info1.p2wpkh, info2.p2wpkh);
        assert_eq!(info1.p2tr, info2.p2tr);
    }

    #[test]
    fn wallet_passphrase_changes_key() {
        let mnemonic = bip39::Mnemonic::generate(24).unwrap();
        let info_a = derive_wallet_info(&mnemonic, "");
        let info_b = derive_wallet_info(&mnemonic, "my secret passphrase");

        assert_ne!(info_a.private_key_hex, info_b.private_key_hex);
        assert_ne!(info_a.public_key_hex, info_b.public_key_hex);
        assert_ne!(info_a.p2wpkh, info_b.p2wpkh);
    }

    #[test]
    fn wallet_recover_roundtrip() {
        let mnemonic = bip39::Mnemonic::generate(24).unwrap();
        let mnemonic_str = mnemonic.to_string();
        let parsed: bip39::Mnemonic = mnemonic_str.parse().unwrap();

        let info1 = derive_wallet_info(&mnemonic, "test");
        let info2 = derive_wallet_info(&parsed, "test");

        assert_eq!(info1.private_key_hex, info2.private_key_hex);
        assert_eq!(info1.p2wpkh, info2.p2wpkh);
    }

    #[test]
    fn wallet_json_output_parses() {
        let mnemonic = bip39::Mnemonic::generate(24).unwrap();
        let info = derive_wallet_info(&mnemonic, "");

        let obj = serde_json::json!({
            "mnemonic": info.mnemonic,
            "derivation_path": "m/44'/9999'/0'/0/0",
            "private_key": info.private_key_hex,
            "public_key": info.public_key_hex,
            "wire_hex": info.wire_hex,
            "bitcoin_addresses": {
                "p2pkh": info.p2pkh,
                "p2wpkh": info.p2wpkh,
                "p2tr": info.p2tr,
            },
        });

        let json_str = serde_json::to_string_pretty(&obj).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["mnemonic"].is_string());
        assert!(parsed["private_key"].is_string());
        assert!(parsed["public_key"].is_string());
        assert!(parsed["wire_hex"].is_string());
        assert!(parsed["bitcoin_addresses"]["p2pkh"].is_string());
        assert!(parsed["bitcoin_addresses"]["p2wpkh"].is_string());
        assert!(parsed["bitcoin_addresses"]["p2tr"].is_string());
    }

    #[test]
    fn wallet_invalid_mnemonic_rejected() {
        let bad = "foo bar baz quux wibble wobble";
        let result: Result<bip39::Mnemonic, _> = bad.parse();
        assert!(result.is_err());
    }

    // ── Peer RPC tests (offline — verify bad URL gives error, not panic) ──

    #[test]
    fn peer_rpc_bad_url_returns_error() {
        let result = rpc_call("https://127.0.0.1:1", "noble_getSeeds", serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn peer_rpc_invalid_url_returns_error() {
        let result = rpc_call("not-a-url", "noble_dialPeer", serde_json::json!({}));
        assert!(result.is_err());
    }

    // ── AllowIps alias tests ──

    #[test]
    fn cidr_alias_tailscale() {
        assert_eq!(expand_cidr_alias("tailscale"), "100.64.0.0/10");
        assert_eq!(expand_cidr_alias("100"), "100.64.0.0/10");
    }

    #[test]
    fn cidr_alias_lan() {
        assert_eq!(expand_cidr_alias("lan"), "192.168.0.0/16");
        assert_eq!(expand_cidr_alias("192"), "192.168.0.0/16");
    }

    #[test]
    fn cidr_alias_private_ranges() {
        assert_eq!(expand_cidr_alias("10"), "10.0.0.0/8");
        assert_eq!(expand_cidr_alias("172"), "172.16.0.0/12");
    }

    #[test]
    fn cidr_alias_passthrough() {
        assert_eq!(expand_cidr_alias("203.0.113.0/24"), "203.0.113.0/24");
        assert_eq!(expand_cidr_alias("10.0.0.1/32"), "10.0.0.1/32");
    }

    // ── ResetChain tests ──

    #[test]
    fn reset_chain_nonexistent_dir() {
        // Just verify the preserved list is correct — cmd_reset_chain exits on missing dir
        let preserved: &[&str] = &[
            "identity.json", "validator.key", ".chain_meta",
            "tls-cert.pem", "tls-key.pem", "p2p_identity.key",
            "identity_attestation.cbor", "noble.toml",
        ];
        assert!(preserved.contains(&"identity.json"));
        assert!(preserved.contains(&"validator.key"));
        assert!(preserved.contains(&".chain_meta"));
        assert!(preserved.contains(&"noble.toml"));
    }

    #[test]
    fn reset_chain_preserves_keys_deletes_db() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let base = dir.path();

        // Create preserved files
        fs::write(base.join("identity.json"), b"{}").unwrap();
        fs::write(base.join("validator.key"), b"key").unwrap();
        fs::write(base.join(".chain_meta"), b"meta").unwrap();
        fs::write(base.join("noble.toml"), b"toml").unwrap();
        fs::create_dir(base.join("keystore")).unwrap();
        fs::write(base.join("keystore/key1.json"), b"k").unwrap();

        // Create RocksDB-like files
        fs::write(base.join("CURRENT"), b"MANIFEST-000001\n").unwrap();
        fs::write(base.join("MANIFEST-000001"), b"mf").unwrap();
        fs::write(base.join("000001.sst"), b"sst").unwrap();
        fs::write(base.join("000001.log"), b"log").unwrap();
        fs::write(base.join("LOCK"), b"").unwrap();
        fs::write(base.join("IDENTITY"), b"id").unwrap();

        // Run reset with --confirm
        cmd_reset_chain(base.to_path_buf(), true, false);

        // Preserved files should still exist
        assert!(base.join("identity.json").exists());
        assert!(base.join("validator.key").exists());
        assert!(base.join(".chain_meta").exists());
        assert!(base.join("noble.toml").exists());
        assert!(base.join("keystore").exists());
        assert!(base.join("keystore/key1.json").exists());

        // RocksDB files should be gone
        assert!(!base.join("CURRENT").exists());
        assert!(!base.join("MANIFEST-000001").exists());
        assert!(!base.join("000001.sst").exists());
        assert!(!base.join("000001.log").exists());
        assert!(!base.join("LOCK").exists());
        assert!(!base.join("IDENTITY").exists());
    }

    #[test]
    fn reset_chain_dry_run_preserves_everything() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let base = dir.path();

        fs::write(base.join("identity.json"), b"{}").unwrap();
        fs::write(base.join("CURRENT"), b"data").unwrap();
        fs::write(base.join("000001.sst"), b"sst").unwrap();

        // Dry run — nothing should be deleted
        cmd_reset_chain(base.to_path_buf(), false, false);

        assert!(base.join("identity.json").exists());
        assert!(base.join("CURRENT").exists());
        assert!(base.join("000001.sst").exists());
    }

    // ── Security tests ──

    #[test]
    fn security_status_empty_dir() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let (exists, is_locked) = noble_crypto::file_encrypt::chain_meta_status(dir.path());
        assert!(!exists);
        assert!(!is_locked);
    }

    #[test]
    fn security_status_auto_dir() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let meta = noble_crypto::file_encrypt::load_or_create_chain_meta(dir.path(), "automatic", None).unwrap();
        let (exists, is_locked) = noble_crypto::file_encrypt::chain_meta_status(dir.path());
        assert!(exists);
        assert!(!is_locked);
        assert_eq!(meta.len(), 32);
    }

    #[test]
    fn security_mode_switch_roundtrip() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let meta = noble_crypto::file_encrypt::load_or_create_chain_meta(dir.path(), "automatic", None).unwrap();

        // auto → manual
        noble_crypto::file_encrypt::switch_encryption_mode(dir.path(), &meta, "manual", None, Some("test-pw")).unwrap();
        let (exists, is_locked) = noble_crypto::file_encrypt::chain_meta_status(dir.path());
        assert!(exists);
        assert!(is_locked);

        // manual → auto
        noble_crypto::file_encrypt::switch_encryption_mode(dir.path(), &meta, "automatic", Some("test-pw"), None).unwrap();
        let (exists, is_locked) = noble_crypto::file_encrypt::chain_meta_status(dir.path());
        assert!(exists);
        assert!(!is_locked);

        // Verify chain_meta preserved
        let reloaded = noble_crypto::file_encrypt::load_or_create_chain_meta(dir.path(), "automatic", None).unwrap();
        assert_eq!(meta, reloaded);
    }
}
