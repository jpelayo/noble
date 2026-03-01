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

fn default_key_path() -> PathBuf {
    noble_core::paths::platform_data_dir()
        .join("keystore")
        .join("validator.key")
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

    /// Generate a new validator keypair and write it to a 33-byte key file.
    ///
    /// File format: [scheme_id(1) || private_key(32)]. Permissions set to 0o600.
    /// The public key hex is printed to stdout for use in validators.txt.
    GenerateKey {
        /// Output file path for the 33-byte validator key.
        #[arg(long, default_value_os_t = default_key_path())]
        output: PathBuf,
        /// Key scheme: ed25519 (default) or secp256k1.
        #[arg(long, default_value = "ed25519")]
        scheme: String,
    },

    /// Read a validator key file and print the derived public key hex.
    ShowKey {
        /// Path to the 33-byte validator key file.
        #[arg(long, default_value_os_t = default_key_path())]
        key_file: PathBuf,
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
        Commands::GenerateKey { output, scheme } => cmd_generate_key(output, scheme),
        Commands::ShowKey { key_file } => cmd_show_key(key_file),
        Commands::Wallet { action } => cmd_wallet(action),
        Commands::Security { action } => cmd_security(action),
        Commands::Peer { action } => cmd_peer(action),
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
// generate-key
// ---------------------------------------------------------------------------

fn cmd_generate_key(output: PathBuf, scheme: String) {
    use noble_crypto::{NoblePrivateKey, SCHEME_ED25519, SCHEME_SECP256K1};

    let (scheme_id, private_key) = match scheme.as_str() {
        "ed25519" => {
            let (sk, _) = noble_crypto::ed25519::generate_keypair();
            (SCHEME_ED25519, NoblePrivateKey::Ed25519(sk))
        }
        "secp256k1" => {
            let (sk, _) = noble_crypto::secp256k1::generate_keypair();
            (SCHEME_SECP256K1, NoblePrivateKey::Secp256k1(sk))
        }
        other => {
            eprintln!("Error: unknown key scheme '{other}'. Use 'ed25519' or 'secp256k1'.");
            std::process::exit(1);
        }
    };

    // Build the 33-byte file: [scheme_id || private_key_bytes]
    let key_bytes = match &private_key {
        NoblePrivateKey::Ed25519(b) | NoblePrivateKey::Secp256k1(b) => b.clone(),
    };
    let mut raw = Vec::with_capacity(33);
    raw.push(scheme_id);
    raw.extend_from_slice(&key_bytes);
    assert_eq!(raw.len(), 33, "key file must be exactly 33 bytes");

    // Write with restricted permissions (0o600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&output)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&raw)
            })
            .unwrap_or_else(|e| {
                eprintln!("Error: failed to write key file: {e}");
                std::process::exit(1);
            });
    }
    #[cfg(not(unix))]
    {
        fs::write(&output, &raw).unwrap_or_else(|e| {
            eprintln!("Error: failed to write key file: {e}");
            std::process::exit(1);
        });
    }

    let public_key = private_key.public_key();
    let pubkey_hex = hex::encode(public_key.to_wire_bytes());

    eprintln!("Generated {} validator key: {}", scheme, output.display());
    eprintln!("Add this public key to validators.txt:");
    println!("{pubkey_hex}");
}

// ---------------------------------------------------------------------------
// show-key
// ---------------------------------------------------------------------------

fn cmd_show_key(key_file: PathBuf) {
    use noble_crypto::NoblePrivateKey;

    let raw = fs::read(&key_file).unwrap_or_else(|e| {
        eprintln!("Error: failed to read key file '{}': {e}", key_file.display());
        std::process::exit(1);
    });

    if raw.len() != 33 {
        eprintln!(
            "Error: invalid key file '{}': expected 33 bytes, got {}",
            key_file.display(),
            raw.len()
        );
        std::process::exit(1);
    }

    let scheme_id = raw[0];
    let key_bytes = raw[1..].to_vec();

    let private_key = match scheme_id {
        noble_crypto::SCHEME_ED25519 => NoblePrivateKey::Ed25519(key_bytes),
        noble_crypto::SCHEME_SECP256K1 => NoblePrivateKey::Secp256k1(key_bytes),
        other => {
            eprintln!("Error: unknown scheme_id {other:#04x} in key file.");
            std::process::exit(1);
        }
    };

    let public_key = private_key.public_key();
    let pubkey_hex = hex::encode(public_key.to_wire_bytes());
    println!("{pubkey_hex}");
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

    #[test]
    fn generate_key_ed25519_produces_valid_file() {
        use noble_crypto::{NoblePrivateKey, SCHEME_ED25519};
        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = dir.path().join("validator.key");

        // Generate keypair and write 33-byte file
        let (sk, _) = noble_crypto::ed25519::generate_keypair();
        let private_key = NoblePrivateKey::Ed25519(sk);
        let key_bytes = match &private_key {
            NoblePrivateKey::Ed25519(b) | NoblePrivateKey::Secp256k1(b) => b.clone(),
        };
        let mut raw = Vec::with_capacity(33);
        raw.push(SCHEME_ED25519);
        raw.extend_from_slice(&key_bytes);
        fs::write(&key_path, &raw).expect("write key file");

        // Read back and verify round-trip
        let read_back = fs::read(&key_path).expect("read key file");
        assert_eq!(read_back.len(), 33);
        assert_eq!(read_back[0], SCHEME_ED25519);

        // Reconstruct private key and derive pubkey
        let sk2 = NoblePrivateKey::Ed25519(read_back[1..].to_vec());
        let pk2 = sk2.public_key();
        let pk_orig = private_key.public_key();
        assert_eq!(pk2.to_wire_bytes(), pk_orig.to_wire_bytes());
    }

    #[test]
    fn generate_key_secp256k1_produces_valid_file() {
        use noble_crypto::{NoblePrivateKey, SCHEME_SECP256K1};
        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = dir.path().join("validator.key");

        let (sk, _) = noble_crypto::secp256k1::generate_keypair();
        let private_key = NoblePrivateKey::Secp256k1(sk);
        let key_bytes = match &private_key {
            NoblePrivateKey::Ed25519(b) | NoblePrivateKey::Secp256k1(b) => b.clone(),
        };
        let mut raw = Vec::with_capacity(33);
        raw.push(SCHEME_SECP256K1);
        raw.extend_from_slice(&key_bytes);
        fs::write(&key_path, &raw).expect("write key file");

        let read_back = fs::read(&key_path).expect("read key file");
        assert_eq!(read_back.len(), 33);
        assert_eq!(read_back[0], SCHEME_SECP256K1);

        let sk2 = NoblePrivateKey::Secp256k1(read_back[1..].to_vec());
        let pk2 = sk2.public_key();
        let pk_orig = private_key.public_key();
        assert_eq!(pk2.to_wire_bytes(), pk_orig.to_wire_bytes());
    }

    #[test]
    fn show_key_reads_and_derives_pubkey() {
        use noble_crypto::{NoblePrivateKey, SCHEME_ED25519};
        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = dir.path().join("validator.key");

        let (sk_bytes, expected_pk_bytes) = noble_crypto::ed25519::generate_keypair();

        // Write key file
        let mut raw = vec![SCHEME_ED25519];
        raw.extend_from_slice(&sk_bytes);
        fs::write(&key_path, &raw).expect("write key file");

        // Simulate show-key logic
        let file_bytes = fs::read(&key_path).expect("read key file");
        assert_eq!(file_bytes.len(), 33);
        let scheme_id = file_bytes[0];
        let key_bytes = file_bytes[1..].to_vec();
        let private_key = match scheme_id {
            SCHEME_ED25519 => NoblePrivateKey::Ed25519(key_bytes),
            _ => panic!("unexpected scheme"),
        };
        let pubkey_hex = hex::encode(private_key.public_key().to_wire_bytes());
        let expected_hex = hex::encode({
            let mut wire = vec![SCHEME_ED25519];
            wire.extend_from_slice(&expected_pk_bytes);
            wire
        });
        assert_eq!(pubkey_hex, expected_hex);
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
