// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Wallet cryptography: BIP-39, BIP-32, secp256k1 signing, and CBOR transaction building.
//!
//! Replicates `NobleClientCrypto` from the Swift packages exactly:
//! - `LiveMnemonicProvider.swift`  → BIP-39/BIP-32 key derivation
//! - `Secp256k1Helper.swift`      → ECDSA signing
//! - `TransactionBuilder.swift`   → CBOR transaction construction
//!
//! CBOR parity is critical — the signing payload must produce byte-identical
//! output to SwiftCBOR so signatures are valid on-chain.

use crate::models::{NobleProtocol, UtxoOutpoint};
use hmac::{Hmac, Mac};
use k256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};
use serde_json::Value;

// ============================================================================
// BIP-39: Mnemonic Generation & Validation
// ============================================================================

/// Generate a BIP-39 mnemonic of the given word count.
pub fn generate_mnemonic(word_count: usize) -> Result<Vec<String>, String> {
    let mnemonic = bip39::Mnemonic::generate(word_count)
        .map_err(|e| format!("Failed to generate mnemonic: {e}"))?;
    Ok(mnemonic
        .words()
        .map(|w| w.to_string())
        .collect())
}

/// Validate a BIP-39 mnemonic.
pub fn validate_mnemonic(words: &[String]) -> bool {
    let phrase = words.join(" ");
    bip39::Mnemonic::parse(&phrase).is_ok()
}

// ============================================================================
// BIP-32: HD Key Derivation at m/44'/9999'/0'/0/0
// ============================================================================

/// Derive a secp256k1 private key from a BIP-39 mnemonic.
///
/// Path: `m/44'/9999'/0'/0/0` (Noble's coin type).
/// Returns the 32-byte private key.
pub fn derive_private_key(words: &[String]) -> Result<Vec<u8>, String> {
    let phrase = words.join(" ");
    let mnemonic =
        bip39::Mnemonic::parse(&phrase).map_err(|e| format!("Invalid mnemonic: {e}"))?;

    // BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048 iterations, 64 bytes)
    let seed = mnemonic.to_seed("");

    // BIP-32 master key: HMAC-SHA512("Bitcoin seed", seed)
    let master = derive_hd_master_key(&seed)?;

    // Derive at m/44'/9999'/0'/0/0
    let path: [u32; 5] = [
        0x8000_002C, // 44'
        0x8000_270F, // 9999'
        0x8000_0000, // 0'
        0,           // 0
        0,           // 0
    ];

    let mut current = master;
    for &index in &path {
        current = derive_hd_child(&current, index)?;
    }

    Ok(current.key)
}

/// Derive the Noble address (wire hex) from a private key.
///
/// Format: `0x02` (secp256k1 scheme) + 33-byte compressed public key = 34 bytes hex.
pub fn derive_address(private_key: &[u8]) -> Result<String, String> {
    let pubkey = compressed_public_key(private_key)?;
    let mut wire = vec![NobleProtocol::SCHEME_SECP256K1]; // 0x02
    wire.extend_from_slice(&pubkey);
    Ok(hex::encode(wire))
}

struct ExtendedKey {
    key: Vec<u8>,        // 32 bytes
    chain_code: Vec<u8>, // 32 bytes
}

fn derive_hd_master_key(seed: &[u8]) -> Result<ExtendedKey, String> {
    let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed")
        .map_err(|e| format!("HMAC init failed: {e}"))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let key = result[..32].to_vec();
    let chain_code = result[32..].to_vec();

    if key.iter().all(|&b| b == 0) {
        return Err("Invalid master key (zero)".to_string());
    }

    Ok(ExtendedKey { key, chain_code })
}

fn derive_hd_child(parent: &ExtendedKey, index: u32) -> Result<ExtendedKey, String> {
    let mut mac = Hmac::<Sha512>::new_from_slice(&parent.chain_code)
        .map_err(|e| format!("HMAC init failed: {e}"))?;

    if index >= 0x8000_0000 {
        // Hardened: 0x00 || parent_key || index_be
        mac.update(&[0x00]);
        mac.update(&parent.key);
    } else {
        // Normal: compressed_pubkey || index_be
        let pubkey = compressed_public_key(&parent.key)?;
        mac.update(&pubkey);
    }
    mac.update(&index.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let il = &result[..32];
    let ir = &result[32..];

    // child_key = (IL + parent_key) mod n
    let child_key = add_mod_n(il, &parent.key);

    Ok(ExtendedKey {
        key: child_key,
        chain_code: ir.to_vec(),
    })
}

/// secp256k1 curve order n.
const SECP256K1_ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36,
    0x41, 0x41,
];

fn add_mod_n(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        result[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    if carry > 0 || compare_256(&result, &SECP256K1_ORDER) >= 0 {
        let mut borrow: i16 = 0;
        for i in (0..32).rev() {
            let diff = i16::from(result[i]) - i16::from(SECP256K1_ORDER[i]) - borrow;
            if diff < 0 {
                result[i] = ((diff + 256) & 0xFF) as u8;
                borrow = 1;
            } else {
                result[i] = diff as u8;
                borrow = 0;
            }
        }
    }
    result
}

fn compare_256(a: &[u8], b: &[u8]) -> i32 {
    for i in 0..32 {
        if a[i] != b[i] {
            return i32::from(a[i]) - i32::from(b[i]);
        }
    }
    0
}

// ============================================================================
// secp256k1 Signing
// ============================================================================

/// Get the compressed (33-byte) public key from a 32-byte private key.
pub fn compressed_public_key(private_key: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_slice(private_key)
        .map_err(|e| format!("Invalid private key: {e}"))?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(verifying_key.to_encoded_point(true).as_bytes().to_vec())
}

/// Sign a message with secp256k1 ECDSA.
///
/// Following the Swift/NOBLE convention:
/// 1. Caller passes `signing_message = SHA-256(canonical_cbor(payload))`
/// 2. k256 internally hashes again: `SHA-256(signing_message)` before ECDSA
/// This matches P256K's behavior and the NOBLE node's verification.
///
/// Returns 64-byte compact signature (r || s).
pub fn sign(signing_message: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    let signing_key = SigningKey::from_slice(private_key)
        .map_err(|e| format!("Invalid private key: {e}"))?;

    let signature: k256::ecdsa::Signature = signing_key.sign(signing_message);
    Ok(signature.to_bytes().to_vec())
}

// ============================================================================
// CBOR Transaction Building
// ============================================================================

/// Build and sign a notarization transaction (type 0x00).
///
/// Matches `TransactionBuilder.buildNotarization()` in Swift.

pub fn handle_crypto_action(
    action: &str,
    params: &Value,
    private_key: &[u8],
    wallet_address: &str,
    chain_id_str: &str,
) -> Result<Value, String> {
    let chain_id = parse_chain_id(chain_id_str);

    match action {
        "signNotarization" => {
            let checksum_hex = params
                .get("checksum")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: checksum")?;
            let checksum =
                hex::decode(checksum_hex).map_err(|e| format!("Invalid checksum hex: {e}"))?;

            let fee = params
                .get("fee")
                .and_then(|v| v.as_u64())
                .ok_or("Missing parameter: fee")?;

            // Use noble-tx-core shared C library.
            let metadata_arr: Vec<serde_json::Value> = parse_metadata(params)
                .iter()
                .map(|(k, v)| serde_json::json!({"key": k, "value": v}))
                .collect();
            let input_json = serde_json::json!({
                "checksum": hex::encode(&checksum),
                "metadata": metadata_arr,
                "fee": fee,
                "utxos": params.get("utxos").cloned().unwrap_or(serde_json::json!([])),
                "change_address": wallet_address,
                "private_key": hex::encode(private_key),
                "chain_id": chain_id,
            });
            let result_json = noble_tx_core::sign_notarization(&input_json.to_string())
                .map_err(|e| format!("sign_notarization: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(serde_json::json!({ "txHex": result["tx_hex"], "txId": result["tx_id"] }))
        }

        "signTransfer" => {
            // Use noble-tx-core shared C library.
            let input_json = serde_json::json!({
                "recipient": params.get("recipient").and_then(|v| v.as_str()).unwrap_or(""),
                "amount": params.get("amount").and_then(|v| v.as_u64()).unwrap_or(0),
                "fee": params.get("fee").and_then(|v| v.as_u64()).unwrap_or(0),
                "utxos": params.get("utxos").cloned().unwrap_or(serde_json::json!([])),
                "change_address": wallet_address,
                "private_key": hex::encode(private_key),
                "chain_id": chain_id,
            });
            let result_json = noble_tx_core::sign_transfer(&input_json.to_string())
                .map_err(|e| format!("sign_transfer: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(serde_json::json!({ "txHex": result["tx_hex"], "txId": result["tx_id"] }))
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}


pub fn hash_file(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?;
    let hash = sha256_hash(&data);
    Ok(hex::encode(hash))
}
