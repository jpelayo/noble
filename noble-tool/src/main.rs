// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! `noble-tool` — offline utility for genesis block generation, benchmarking,
//! and chain validation.

use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};

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
}
