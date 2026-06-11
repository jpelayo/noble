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

            let fee = params.get("fee").and_then(|v| v.as_u64()).unwrap_or(0);
            let fee_rate = params.get("fee_rate").and_then(|v| v.as_u64()).unwrap_or(0);

            // Use noble-tx-core shared C library.
            // Extract metadata with ECIES encryption for encrypted fields.
            let metadata_arr: Vec<serde_json::Value> = parse_metadata_with_ecies(params, private_key)?;
            let mut input_json = serde_json::json!({
                "checksum": hex::encode(&checksum),
                "metadata": metadata_arr,
                "fee": fee,
                "utxos": params.get("utxos").cloned().unwrap_or(serde_json::json!([])),
                "change_address": wallet_address,
                "private_key": hex::encode(private_key),
                "chain_id": chain_id,
            });
            if fee_rate > 0 {
                input_json["fee_rate"] = serde_json::json!(fee_rate);
            }
            let result_json = noble_tx_core::sign_notarization(&input_json.to_string())
                .map_err(|e| format!("sign_notarization: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(serde_json::json!({ "txHex": result["tx_hex"], "txId": result["tx_id"] }))
        }

        "encryptField" => {
            let value = params.get("value").and_then(|v| v.as_str())
                .ok_or("Missing parameter: value")?;
            let mode = params.get("mode").and_then(|v| v.as_str())
                .ok_or("Missing parameter: mode")?;
            if mode == "encrypted" {
                let recipient_pubkey = params.get("recipient_pubkey").and_then(|v| v.as_str())
                    .ok_or("Missing parameter: recipient_pubkey")?;
                let plaintext_hex = hex::encode(value.as_bytes());
                let payload_hex = noble_tx_core::ecies_encrypt_field(&plaintext_hex, recipient_pubkey)
                    .map_err(|e| format!("ECIES encrypt: {e}"))?;
                Ok(serde_json::json!({ "encrypted_hex": payload_hex }))
            } else {
                Err("mode must be 'encrypted' (protected fields use client-side Web Crypto)".to_string())
            }
        }

        "decryptField" | "decryptEciesField" => {
            let payload_hex = params.get("payload_hex")
                .or_else(|| params.get("encrypted_hex"))
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: payload_hex or encrypted_hex")?;
            let private_key_hex = hex::encode(private_key);
            let plaintext_hex = noble_tx_core::ecies_decrypt_field(payload_hex, &private_key_hex)
                .map_err(|e| format!("ECIES decrypt: {e}"))?;
            let plaintext_bytes = hex::decode(&plaintext_hex).unwrap_or_default();
            let plaintext = String::from_utf8(plaintext_bytes).unwrap_or(plaintext_hex.clone());
            Ok(serde_json::json!({ "plaintext": plaintext, "value": plaintext }))
        }

        "signTransfer" => {
            // Use noble-tx-core shared C library.
            let fee_rate = params.get("fee_rate").and_then(|v| v.as_u64()).unwrap_or(0);
            let mut input_json = serde_json::json!({
                "recipient": params.get("recipient").and_then(|v| v.as_str()).unwrap_or(""),
                "amount": params.get("amount").and_then(|v| v.as_u64()).unwrap_or(0),
                "fee": params.get("fee").and_then(|v| v.as_u64()).unwrap_or(0),
                "utxos": params.get("utxos").cloned().unwrap_or(serde_json::json!([])),
                "change_address": wallet_address,
                "private_key": hex::encode(private_key),
                "chain_id": chain_id,
            });
            if fee_rate > 0 {
                input_json["fee_rate"] = serde_json::json!(fee_rate);
            }
            let result_json = noble_tx_core::sign_transfer(&input_json.to_string())
                .map_err(|e| format!("sign_transfer: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(serde_json::json!({ "txHex": result["tx_hex"], "txId": result["tx_id"] }))
        }

        "signSplitTransfer" => {
            let outputs = params.get("outputs").filter(|v| v.is_array()).cloned()
                .ok_or_else(|| "signSplitTransfer: missing 'outputs'".to_string())?;
            let utxos = params.get("utxos").filter(|v| v.is_array()).cloned()
                .ok_or_else(|| "signSplitTransfer: missing 'utxos'".to_string())?;
            let fee_rate = params.get("fee_rate").and_then(|v| v.as_u64()).unwrap_or(0);
            let input_json = serde_json::json!({
                "outputs": outputs,
                "fee": params.get("fee").and_then(|v| v.as_u64()).unwrap_or(0),
                "fee_rate": fee_rate,
                "utxos": utxos,
                "change_address": wallet_address,
                "private_key": hex::encode(private_key),
                "chain_id": chain_id,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
            });
            let result_json = noble_tx_core::sign_split_transfer(&input_json.to_string())
                .map_err(|e| format!("sign_split_transfer: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(serde_json::json!({ "txHex": result["tx_hex"], "txId": result["tx_id"] }))
        }

        "buildTransaction" => {
            let mut input_json = params.clone();
            input_json["private_key"] = serde_json::json!(hex::encode(private_key));
            input_json["change_address"] = serde_json::json!(wallet_address);
            input_json["chain_id"] = serde_json::json!(chain_id);
            input_json["timestamp"] = serde_json::json!(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
            );
            let result_json = noble_tx_core::build_transaction(&input_json.to_string())
                .map_err(|e| format!("build_transaction: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(serde_json::json!({
                "txHex": result["tx_hex"], "txId": result["tx_id"],
                "fee": result["fee"], "size": result["size"]
            }))
        }

        "decryptLockedTx" => {
            let result_json = noble_tx_core::decode_locked_tx(&serde_json::json!(params).to_string())
                .map_err(|e| format!("decode_locked_tx: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(result)
        }

        "estimateTxSize" => {
            let estimate_json = serde_json::json!({
                "tx_type": params.get("tx_type").and_then(|v| v.as_str()).unwrap_or("notarization"),
                "checksum": params.get("checksum").and_then(|v| v.as_str()).unwrap_or(&"00".repeat(32)),
                "metadata": params.get("metadata").cloned().unwrap_or(serde_json::json!([])),
                "recipient": params.get("recipient").and_then(|v| v.as_str()).unwrap_or(""),
                "change_address": wallet_address,
                "private_key": hex::encode(private_key),
                "chain_id": chain_id,
            });
            let result_json = noble_tx_core::estimate_tx_size(&estimate_json.to_string())
                .map_err(|e| format!("estimate_tx_size: {e}"))?;
            let result: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| format!("parse result: {e}"))?;
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                return Err(err.to_string());
            }
            Ok(result)
        }

        "signMetadataField" => {
            // CMS detached signature over a metadata field value, using a
            // per-key signing identity (NOT the wallet key). Mirrors the
            // Mac client: key + certificate both required.
            let key_id = params
                .get("keyId")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: keyId")?;
            let field_value = params
                .get("fieldValue")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: fieldValue")?;

            // Algorithm comes from the My Card signing-key entry.
            let contacts = crate::storage::load_contacts();
            let key_entry = contacts
                .iter()
                .find(|c| c.is_my_card)
                .and_then(|c| c.signing_keys.iter().find(|sk| sk.id == key_id))
                .ok_or("Signing key not found")?;

            let priv_bytes =
                crate::security::load_credential(&crate::security::signing_key_credential(key_id))?
                    .ok_or("Private key not found in keyring")?;
            let cert_bytes =
                crate::security::load_credential(&crate::security::signing_cert_credential(key_id))?
                    .ok_or("Certificate not found in keyring")?;

            let cms_params = serde_json::json!({
                "private_key_hex": hex::encode(&priv_bytes),
                "certificate_der_b64": base64_encode(&cert_bytes),
                "field_value": field_value,
                "algorithm": key_entry.algorithm,
            });
            let result = noble_cms_core::cms::sign_cms(&cms_params.to_string())
                .map_err(|e| format!("CMS signing failed: {e}"))?;
            Ok(serde_json::json!({
                "signatureHex": result.cms_hex,
                "size": result.size,
            }))
        }

        "verifyMetadataField" => {
            let sig_hex = params
                .get("signatureHex")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: signatureHex")?;
            let field_value = params
                .get("fieldValue")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: fieldValue")?;

            // Step 1: parse the CMS to extract the signer SKI (no cert yet).
            let parse_params = serde_json::json!({
                "cms_hex": sig_hex,
                "field_value": field_value,
            });
            let parsed = noble_cms_core::cms::verify_cms(&parse_params.to_string())
                .map_err(|e| format!("CMS parse failed: {e}"))?;
            let signer_ski = parsed.signer_ski_hex;
            let algorithm = parsed.algorithm;

            // Step 2: find the signer's certificate by SKI across contacts.
            let contacts = crate::storage::load_contacts();
            let mut cert_b64: Option<String> = None;
            let mut signer_name: Option<String> = None;
            'outer: for contact in &contacts {
                for sk in &contact.signing_keys {
                    if sk.subject_key_identifier.as_deref() == Some(signer_ski.as_str()) {
                        cert_b64 = sk.certificate_der.clone();
                        let key_label = if sk.label.is_empty() {
                            String::new()
                        } else {
                            format!(" ({})", sk.label)
                        };
                        signer_name = Some(format!("{}{}", contact.display_name(), key_label));
                        break 'outer;
                    }
                }
            }

            // Step 3: verify the signature if we have the certificate.
            let (valid, error) = match &cert_b64 {
                Some(cert) => {
                    let verify_params = serde_json::json!({
                        "cms_hex": sig_hex,
                        "field_value": field_value,
                        "certificate_der_b64": cert,
                    });
                    match noble_cms_core::cms::verify_cms(&verify_params.to_string()) {
                        Ok(v) => (v.valid, v.error),
                        Err(e) => (false, Some(e)),
                    }
                }
                None => {
                    let prefix: String = signer_ski.chars().take(12).collect();
                    (false, Some(format!("no certificate found for signer (SKI: {prefix}...)")))
                }
            };

            Ok(serde_json::json!({
                "valid": valid,
                "signerSKI": signer_ski,
                "signerName": signer_name,
                "hasCertificate": cert_b64.is_some(),
                "algorithm": algorithm,
                "error": error,
            }))
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}

/// Minimal base64 encoder (standard alphabet, padded) — avoids adding a
/// dependency for one call site.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}


/// SHA-256 hash of raw bytes.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Parse chain ID hex string (e.g. "0x4E4F424C") to u32.
pub fn parse_chain_id(s: &str) -> u32 {
    let hex_str = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    u32::from_str_radix(hex_str, 16).unwrap_or(0)
}

/// Extract metadata with ECIES encryption for encrypted fields.
/// Returns JSON array of {key, value} objects ready for the C library.
fn parse_metadata_with_ecies(params: &Value, _private_key: &[u8]) -> Result<Vec<serde_json::Value>, String> {
    let entries = params.get("metadata").and_then(|v| v.as_array());
    let Some(entries) = entries else { return Ok(vec![]); };
    let mut result = Vec::new();
    for entry in entries {
        let key = entry.get("key").and_then(|v| v.as_str()).unwrap_or("");
        let mut value = entry.get("value").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mode = entry.get("mode").and_then(|v| v.as_str()).unwrap_or("plaintext");
        let recipient = entry.get("recipient").and_then(|v| v.as_str()).unwrap_or("");
        if mode == "encrypted" && !recipient.is_empty() {
            let plaintext_hex = hex::encode(value.as_bytes());
            let payload_hex = noble_tx_core::ecies_encrypt_field(&plaintext_hex, recipient)
                .map_err(|e| format!("ECIES encrypt for field '{}': {}", key, e))?;
            value = payload_hex;
        }
        result.push(serde_json::json!({"key": key, "value": value}));
    }
    Ok(result)
}

/// Extract metadata key-value pairs from bridge params.
pub fn parse_metadata(params: &Value) -> Vec<(String, String)> {
    params.get("metadata")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter().filter_map(|entry| {
                let key = entry.get("key").and_then(|v| v.as_str())?;
                let value = entry.get("value").and_then(|v| v.as_str())?;
                Some((key.to_string(), value.to_string()))
            }).collect()
        })
        .unwrap_or_default()
}

pub fn hash_file(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?;
    let hash = sha256_hash(&data);
    Ok(hex::encode(hash))
}
