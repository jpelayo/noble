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
pub fn sign_notarization(
    checksum: &[u8],       // 32-byte SHA-256 hash
    metadata: &[(String, String)], // (key, value) pairs
    fee: u64,
    utxos: &[UtxoOutpoint],
    change_address: &[u8], // Wire bytes
    private_key: &[u8],    // 32-byte key
    chain_id: u32,
) -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Clock error: {e}"))?
        .as_secs();
    let public_key = compressed_public_key(private_key)?;

    // Build inputs from UTXOs
    let inputs: Vec<CborInput> = utxos
        .iter()
        .map(|u| CborInput {
            txid: u.txid.clone(),
            vout: u.vout,
        })
        .collect();

    // Build outputs: change = sum(inputs) - fee
    let total_input: u64 = utxos.iter().map(|u| u.value).sum();
    let change = total_input.saturating_sub(fee);
    let mut outputs = Vec::new();
    if change > 0 {
        outputs.push(CborOutput {
            value: change,
            address_wire: change_address.to_vec(),
        });
    }

    // Sort metadata by key (matching Swift)
    let mut sorted_meta: Vec<(String, String)> = metadata.to_vec();
    sorted_meta.sort_by(|a, b| a.0.cmp(&b.0));

    // Build signing payload
    let payload = build_signing_payload(
        NobleProtocol::PROTOCOL_VERSION,
        NobleProtocol::TX_TYPE_NOTARIZATION,
        &inputs,
        &outputs,
        checksum,
        timestamp,
        &sorted_meta,
        None,
        chain_id,
    );

    let payload_bytes = payload;
    let signing_message = sha256_hash(&payload_bytes);
    let signature = sign(&signing_message, private_key)?;

    // Build full transaction
    let tx_cbor = build_transaction_cbor(
        NobleProtocol::PROTOCOL_VERSION,
        NobleProtocol::TX_TYPE_NOTARIZATION,
        &inputs,
        &outputs,
        checksum,
        timestamp,
        &public_key,
        &signature,
        &sorted_meta,
        None,
    );

    let tx_bytes = tx_cbor;
    Ok(hex::encode(tx_bytes))
}

/// Build and sign a transfer transaction (type 0x01).
///
/// Matches `TransactionBuilder.buildTransfer()` in Swift.
pub fn sign_transfer(
    recipient_wire: &[u8],
    amount: u64,
    fee: u64,
    utxos: &[UtxoOutpoint],
    change_address: &[u8],
    private_key: &[u8],
    chain_id: u32,
) -> Result<String, String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("Clock error: {e}"))?
        .as_secs();
    let public_key = compressed_public_key(private_key)?;

    let inputs: Vec<CborInput> = utxos
        .iter()
        .map(|u| CborInput {
            txid: u.txid.clone(),
            vout: u.vout,
        })
        .collect();

    // Outputs: [0] recipient, [1] change (if any)
    let mut outputs = vec![CborOutput {
        value: amount,
        address_wire: recipient_wire.to_vec(),
    }];

    let total_input: u64 = utxos.iter().map(|u| u.value).sum();
    let change = total_input.saturating_sub(amount).saturating_sub(fee);
    if change > 0 {
        outputs.push(CborOutput {
            value: change,
            address_wire: change_address.to_vec(),
        });
    }

    // Dummy checksum (32 zero bytes) for transfers
    let dummy_checksum = vec![0u8; 32];

    let payload = build_signing_payload(
        NobleProtocol::PROTOCOL_VERSION,
        NobleProtocol::TX_TYPE_TRANSFER,
        &inputs,
        &outputs,
        &dummy_checksum,
        timestamp,
        &[],
        None,
        chain_id,
    );

    let payload_bytes = payload;
    let signing_message = sha256_hash(&payload_bytes);
    let signature = sign(&signing_message, private_key)?;

    let tx_cbor = build_transaction_cbor(
        NobleProtocol::PROTOCOL_VERSION,
        NobleProtocol::TX_TYPE_TRANSFER,
        &inputs,
        &outputs,
        &dummy_checksum,
        timestamp,
        &public_key,
        &signature,
        &[],
        None,
    );

    let tx_bytes = tx_cbor;
    Ok(hex::encode(tx_bytes))
}

// ============================================================================
// CBOR Internal Types & Building
// ============================================================================

struct CborInput {
    txid: Vec<u8>,
    vout: u32,
}

struct CborOutput {
    value: u64,
    address_wire: Vec<u8>,
}

/// Build the signing payload as raw CBOR bytes using frozen wire format V1.
///
/// Must produce byte-identical output to noble-core::wire::v1::tx_signing_payload_bytes().
/// Keys are sorted alphabetically (NOT RFC 8949 length-first).
fn build_signing_payload(
    version: u16,
    tx_type: u8,
    inputs: &[CborInput],
    outputs: &[CborOutput],
    checksum: &[u8],
    timestamp: u64,
    metadata: &[(String, String)],
    gateway_address: Option<&[u8]>,
    chain_id: u32,
) -> Vec<u8> {
    use crate::cbor;

    // Sort metadata by key for order-independent signing
    let mut sorted_meta: Vec<&(String, String)> = metadata.iter().collect();
    sorted_meta.sort_by(|a, b| a.0.cmp(&b.0));

    let mut field_count = 8usize; // always-present fields
    if gateway_address.is_some() { field_count += 1; }

    let mut buf = Vec::with_capacity(256);
    cbor::write_map(&mut buf, field_count);

    // Alphabetical order: chain_id, checksum, gateway_address(?),
    // input_outpoints, metadata, outputs, timestamp, tx_type, version

    cbor::write_text(&mut buf, "chain_id");
    cbor::write_uint(&mut buf, chain_id as u64);

    cbor::write_text(&mut buf, "checksum");
    cbor::write_bytes(&mut buf, checksum);

    if let Some(gw) = gateway_address {
        cbor::write_text(&mut buf, "gateway_address");
        cbor::write_bytes(&mut buf, gw);
    }

    cbor::write_text(&mut buf, "input_outpoints");
    cbor::write_array(&mut buf, inputs.len());
    for inp in inputs {
        cbor::write_map(&mut buf, 2);
        cbor::write_text(&mut buf, "txid");
        cbor::write_bytes(&mut buf, &inp.txid);
        cbor::write_text(&mut buf, "vout");
        cbor::write_uint(&mut buf, inp.vout as u64);
    }

    cbor::write_text(&mut buf, "metadata");
    cbor::write_array(&mut buf, sorted_meta.len());
    for (k, v) in &sorted_meta {
        cbor::write_map(&mut buf, 2);
        cbor::write_text(&mut buf, "key");
        cbor::write_text(&mut buf, k);
        cbor::write_text(&mut buf, "value");
        cbor::write_bytes(&mut buf, v.as_bytes());
    }

    cbor::write_text(&mut buf, "outputs");
    cbor::write_array(&mut buf, outputs.len());
    for out in outputs {
        cbor::write_map(&mut buf, 2);
        cbor::write_text(&mut buf, "address");
        cbor::write_bytes(&mut buf, &out.address_wire);
        cbor::write_text(&mut buf, "value");
        cbor::write_uint(&mut buf, out.value);
    }

    cbor::write_text(&mut buf, "timestamp");
    cbor::write_uint(&mut buf, timestamp);

    cbor::write_text(&mut buf, "tx_type");
    cbor::write_uint(&mut buf, tx_type as u64);

    cbor::write_text(&mut buf, "version");
    cbor::write_uint(&mut buf, version as u64);

    buf
}

/// Build the full transaction CBOR bytes using frozen wire format V1.
///
/// Must match noble-core::wire::v1::Transaction::encode_wire().
fn build_transaction_cbor(
    version: u16,
    tx_type: u8,
    inputs: &[CborInput],
    outputs: &[CborOutput],
    checksum: &[u8],
    timestamp: u64,
    public_key: &[u8],
    signature: &[u8],
    metadata: &[(String, String)],
    gateway_address: Option<&[u8]>,
) -> Vec<u8> {
    use crate::cbor;

    let mut field_count = 9usize;
    if gateway_address.is_some() { field_count += 1; }

    let mut buf = Vec::with_capacity(512);
    cbor::write_map(&mut buf, field_count);

    // Alphabetical order: additional_sigs, checksum, gateway_address(?),
    // inputs, metadata, outputs, issuer_sig, timestamp, tx_type, version

    cbor::write_text(&mut buf, "additional_sigs");
    cbor::write_array(&mut buf, 0);

    cbor::write_text(&mut buf, "checksum");
    cbor::write_bytes(&mut buf, checksum);

    if let Some(gw) = gateway_address {
        cbor::write_text(&mut buf, "gateway_address");
        cbor::write_bytes(&mut buf, gw);
    }

    cbor::write_text(&mut buf, "inputs");
    cbor::write_array(&mut buf, inputs.len());
    for inp in inputs {
        cbor::write_map(&mut buf, 1);
        cbor::write_text(&mut buf, "prev_output");
        cbor::write_map(&mut buf, 2);
        cbor::write_text(&mut buf, "txid");
        cbor::write_bytes(&mut buf, &inp.txid);
        cbor::write_text(&mut buf, "vout");
        cbor::write_uint(&mut buf, inp.vout as u64);
    }

    cbor::write_text(&mut buf, "metadata");
    cbor::write_array(&mut buf, metadata.len());
    for (k, v) in metadata {
        cbor::write_map(&mut buf, 2);
        cbor::write_text(&mut buf, "key");
        cbor::write_text(&mut buf, k);
        cbor::write_text(&mut buf, "value");
        cbor::write_bytes(&mut buf, v.as_bytes());
    }

    cbor::write_text(&mut buf, "outputs");
    cbor::write_array(&mut buf, outputs.len());
    for out in outputs {
        cbor::write_map(&mut buf, 2);
        cbor::write_text(&mut buf, "address");
        cbor::write_bytes(&mut buf, &out.address_wire);
        cbor::write_text(&mut buf, "value");
        cbor::write_uint(&mut buf, out.value);
    }

    // issuer_sig as wire bytes: [scheme_id(1) || pubkey_len(1) || pubkey || sig]
    cbor::write_text(&mut buf, "issuer_sig");
    let mut sig_wire = Vec::with_capacity(2 + public_key.len() + signature.len());
    sig_wire.push(NobleProtocol::SCHEME_SECP256K1);
    sig_wire.push(public_key.len() as u8);
    sig_wire.extend_from_slice(public_key);
    sig_wire.extend_from_slice(signature);
    cbor::write_bytes(&mut buf, &sig_wire);

    cbor::write_text(&mut buf, "timestamp");
    cbor::write_uint(&mut buf, timestamp);

    cbor::write_text(&mut buf, "tx_type");
    cbor::write_uint(&mut buf, tx_type as u64);

    cbor::write_text(&mut buf, "version");
    cbor::write_uint(&mut buf, version as u64);

    buf
}

/// SHA-256 hash.
fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ============================================================================
// Bridge Handler: noble_crypto
// ============================================================================

/// Handle `noble_crypto` bridge actions (signNotarization, signTransfer).
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

            let metadata = parse_metadata(params);
            let all_utxos = parse_utxos(params)?;
            let selected = select_utxos(&all_utxos, fee)?;
            let change_address = wallet_wire_bytes(wallet_address);

            let tx_hex = sign_notarization(
                &checksum,
                &metadata,
                fee,
                &selected,
                &change_address,
                private_key,
                chain_id,
            )?;

            Ok(serde_json::json!({ "txHex": tx_hex }))
        }

        "signTransfer" => {
            let recipient_hex = params
                .get("recipient")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: recipient")?;
            let recipient_wire =
                hex::decode(recipient_hex).map_err(|e| format!("Invalid recipient hex: {e}"))?;

            let amount = params
                .get("amount")
                .and_then(|v| v.as_u64())
                .ok_or("Missing parameter: amount")?;

            let fee = params
                .get("fee")
                .and_then(|v| v.as_u64())
                .ok_or("Missing parameter: fee")?;

            let all_utxos = parse_utxos(params)?;
            let target = amount + fee;
            let selected = select_utxos(&all_utxos, target)?;
            let change_address = wallet_wire_bytes(wallet_address);

            let tx_hex = sign_transfer(
                &recipient_wire,
                amount,
                fee,
                &selected,
                &change_address,
                private_key,
                chain_id,
            )?;

            Ok(serde_json::json!({ "txHex": tx_hex }))
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}

/// Parse chain ID from hex string (e.g. "0x4E4F424C" or "4E4F424C").
fn parse_chain_id(s: &str) -> u32 {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(hex, 16).unwrap_or(NobleProtocol::PRIMARY_CHAIN_ID)
}

/// Parse metadata from bridge params.
fn parse_metadata(params: &Value) -> Vec<(String, String)> {
    params
        .get("metadata")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let key = item.get("key")?.as_str()?.to_string();
                    let value = item.get("value")?.as_str()?.to_string();
                    Some((key, value))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parse UTXO array from bridge params.
fn parse_utxos(params: &Value) -> Result<Vec<UtxoOutpoint>, String> {
    let utxo_arr = params
        .get("utxos")
        .and_then(|v| v.as_array())
        .ok_or("Missing parameter: utxos")?;

    let mut result = Vec::new();
    for item in utxo_arr {
        let txid_hex = item
            .get("txid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let vout = item.get("vout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let value = item.get("value").and_then(|v| v.as_u64()).unwrap_or(0);

        if let Ok(txid) = hex::decode(txid_hex) {
            result.push(UtxoOutpoint { txid, vout, value });
        }
    }

    if result.is_empty() {
        return Err("Missing parameter: utxos (all entries malformed)".to_string());
    }

    Ok(result)
}

// ── Coin Selection ──
// Three-pass algorithm: changeless → smallest-first → largest-first.

/// Dust threshold: change below this value is not worth creating.
const DUST_THRESHOLD: u64 = 5_000; // 0.005 NOBLE

/// Select UTXOs to cover `target` (amount + fee).
pub fn select_utxos(available: &[UtxoOutpoint], target: u64) -> Result<Vec<UtxoOutpoint>, String> {
    let total: u64 = available.iter().map(|u| u.value).sum();
    if total < target {
        return Err(format!(
            "Insufficient funds: have {total} atomic, need {target}"
        ));
    }

    // Pass 1: Changeless — exact match with 1, 2, or 3 UTXOs.
    if let Some(exact) = find_exact_match(available, target, 0) {
        return Ok(exact);
    }

    // Pass 1b: Near-changeless — change < dust threshold.
    if let Some(near) = find_exact_match(available, target, DUST_THRESHOLD) {
        return Ok(near);
    }

    // Pass 2: Single best fit — smallest single UTXO that covers the target.
    if let Some(best) = available.iter().filter(|u| u.value >= target).min_by_key(|u| u.value) {
        return Ok(vec![best.clone()]);
    }

    // Pass 3: Smallest-first — spend dust to reduce UTXO bloat.
    let mut ascending: Vec<&UtxoOutpoint> = available.iter().collect();
    ascending.sort_by_key(|u| u.value);
    if let Some(result) = accumulate(&ascending, target) {
        return Ok(result);
    }

    // Pass 3: Largest-first — guaranteed if total >= target.
    ascending.reverse();
    if let Some(result) = accumulate(&ascending, target) {
        return Ok(result);
    }

    Err(format!(
        "Insufficient funds: have {total} atomic, need {target}"
    ))
}

fn find_exact_match(
    utxos: &[UtxoOutpoint],
    target: u64,
    tolerance: u64,
) -> Option<Vec<UtxoOutpoint>> {
    let n = utxos.len();

    // Single UTXO.
    for i in 0..n {
        let sum = utxos[i].value;
        if sum >= target && sum <= target + tolerance {
            return Some(vec![utxos[i].clone()]);
        }
    }

    // Pair.
    if n >= 2 {
        for i in 0..(n - 1) {
            for j in (i + 1)..n {
                let sum = utxos[i].value + utxos[j].value;
                if sum >= target && sum <= target + tolerance {
                    return Some(vec![utxos[i].clone(), utxos[j].clone()]);
                }
            }
        }
    }

    // Triple.
    if n >= 3 {
        for i in 0..(n - 2) {
            for j in (i + 1)..(n - 1) {
                for k in (j + 1)..n {
                    let sum = utxos[i].value + utxos[j].value + utxos[k].value;
                    if sum >= target && sum <= target + tolerance {
                        return Some(vec![
                            utxos[i].clone(),
                            utxos[j].clone(),
                            utxos[k].clone(),
                        ]);
                    }
                }
            }
        }
    }

    None
}

fn accumulate(sorted: &[&UtxoOutpoint], target: u64) -> Option<Vec<UtxoOutpoint>> {
    let mut selected = Vec::new();
    let mut sum: u64 = 0;
    for utxo in sorted {
        selected.push((*utxo).clone());
        sum += utxo.value;
        if sum >= target {
            return Some(selected);
        }
    }
    None
}

/// Convert wallet address (hex wire format) to raw bytes.
fn wallet_wire_bytes(address: &str) -> Vec<u8> {
    hex::decode(address).unwrap_or_default()
}

/// SHA-256 hash of file contents (for noble_security.hashFile).
pub fn hash_file(path: &str) -> Result<String, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?;
    let hash = sha256_hash(&data);
    Ok(hex::encode(hash))
}
