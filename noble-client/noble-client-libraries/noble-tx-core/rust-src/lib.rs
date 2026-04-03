// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Rust wrapper for the noble-tx-core C library.
// The C library is the SINGLE source of truth for transaction CBOR encoding.
// Used by all clients (iOS, macOS, Windows, Linux) and the node itself.
//
use std::ffi::{CStr, CString};
use std::os::raw::c_char;



extern "C" {
    fn noble_sign_transfer(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_split_transfer(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_notarization(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_key_rotation(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_badge_proposal(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_badge_vote(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_badge_revocation(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_locked(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_unlocking(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_dao_create(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_dao_vote(params_json: *const c_char) -> *mut c_char;
    fn noble_build_coinbase(params_json: *const c_char) -> *mut c_char;
    fn noble_build_fee_distribution(params_json: *const c_char) -> *mut c_char;
    fn noble_build_transaction(params_json: *const c_char) -> *mut c_char;
    fn noble_select_utxos(params_json: *const c_char) -> *mut c_char;
    fn noble_estimate_tx_size(params_json: *const c_char) -> *mut c_char;
    fn noble_tx_decode(params_json: *const c_char) -> *mut c_char;
    fn noble_tx_decode_locked(params_json: *const c_char) -> *mut c_char;
    fn noble_verify_tx(params_json: *const c_char) -> *mut c_char;
    fn noble_free(ptr: *mut c_char);
}

/// Call a C FFI function with a JSON string, returning the result string.
fn call_ffi(
    f: unsafe extern "C" fn(*const c_char) -> *mut c_char,
    params_json: &str,
) -> Result<String, String> {
    let c_input = CString::new(params_json).map_err(|e| format!("invalid input: {e}"))?;
    let result_ptr = unsafe { f(c_input.as_ptr()) };
    if result_ptr.is_null() {
        return Err("FFI returned null".to_string());
    }
    let result_str = unsafe { CStr::from_ptr(result_ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { noble_free(result_ptr) };
    Ok(result_str)
}

/// Unified transaction builder — handles transfer, split, join, notarize.
pub fn build_transaction(params_json: &str) -> Result<String, String> {
    call_ffi(noble_build_transaction, params_json)
}

/// Build, sign, and CBOR-encode a transfer transaction.
pub fn sign_transfer(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_transfer, params_json)
}

/// Build, sign, and CBOR-encode a multi-output transfer (UTXO split/join).
pub fn sign_split_transfer(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_split_transfer, params_json)
}

/// Build, sign, and CBOR-encode a notarization transaction.
pub fn sign_notarization(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_notarization, params_json)
}

/// Build, sign, and CBOR-encode a key rotation transaction (0x02).
pub fn sign_key_rotation(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_key_rotation, params_json)
}

/// Build, sign, and CBOR-encode a badge proposal transaction (0x03).
pub fn sign_badge_proposal(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_badge_proposal, params_json)
}

/// Build, sign, and CBOR-encode a badge vote transaction (0x04).
pub fn sign_badge_vote(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_badge_vote, params_json)
}

/// Build, sign, and CBOR-encode a badge revocation transaction (0x05).
pub fn sign_badge_revocation(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_badge_revocation, params_json)
}

/// Build, sign, and CBOR-encode a locked notarization transaction (0x06).
pub fn sign_locked(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_locked, params_json)
}

/// Build, sign, and CBOR-encode an unlocking transaction (0x07).
pub fn sign_unlocking(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_unlocking, params_json)
}

/// Build, sign, and CBOR-encode a DAO poll creation transaction (0x12).
pub fn sign_dao_create(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_dao_create, params_json)
}

/// Build, sign, and CBOR-encode a DAO poll vote transaction (0x12).
pub fn sign_dao_vote(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_dao_vote, params_json)
}

/// Build, sign, and CBOR-encode a coinbase (block reward) transaction (0x10).
pub fn build_coinbase(params_json: &str) -> Result<String, String> {
    call_ffi(noble_build_coinbase, params_json)
}

/// Build, sign, and CBOR-encode a fee distribution transaction (0x11).
pub fn build_fee_distribution(params_json: &str) -> Result<String, String> {
    call_ffi(noble_build_fee_distribution, params_json)
}

/// Run 5-pass coin selection on UTXOs.
pub fn select_utxos(params_json: &str) -> Result<String, String> {
    call_ffi(noble_select_utxos, params_json)
}

/// Estimate the CBOR byte size of a transaction without submitting.
pub fn estimate_tx_size(params_json: &str) -> Result<String, String> {
    call_ffi(noble_estimate_tx_size, params_json)
}

/// Decode a CBOR-encoded transaction back to JSON.
pub fn tx_decode(params_json: &str) -> Result<String, String> {
    call_ffi(noble_tx_decode, params_json)
}

/// Decode a locked transaction and decrypt metadata with password.
pub fn tx_decode_locked(params_json: &str) -> Result<String, String> {
    call_ffi(noble_tx_decode_locked, params_json)
}

/// Verify the issuer_sig on a CBOR-encoded transaction.
pub fn verify_tx(params_json: &str) -> Result<String, String> {
    call_ffi(noble_verify_tx, params_json)
}

// ── ECIES field encryption (pure Rust, no C FFI) ──

// NOTE: noble_ecies_encrypt / noble_ecies_decrypt are now implemented in C (ecies.c).
// The C implementations use the same compact binary format and HKDF info string.
// These Rust-native helpers remain for WRY apps that link noble-crypto directly.

/// Rust-native ECIES encrypt (for WRY apps that link noble-crypto directly).
pub fn ecies_encrypt_field(plaintext_hex: &str, recipient_pubkey_hex: &str) -> Result<String, String> {
    let plaintext = hex::decode(plaintext_hex).map_err(|e| format!("bad plaintext hex: {e}"))?;
    let pubkey_bytes = hex::decode(recipient_pubkey_hex).map_err(|e| format!("bad pubkey hex: {e}"))?;
    if pubkey_bytes.len() != 33 {
        return Err(format!("pubkey must be 33 bytes, got {}", pubkey_bytes.len()));
    }
    let recipient = noble_crypto::keys::NoblePublicKey::Secp256k1(pubkey_bytes);
    let payload = noble_crypto::ecies::encrypt_single(&plaintext, &recipient)
        .map_err(|e| format!("ECIES encrypt: {e}"))?;
    Ok(hex::encode(&payload))
}

/// Rust-native ECIES decrypt (for WRY apps that link noble-crypto directly).
pub fn ecies_decrypt_field(payload_hex: &str, private_key_hex: &str) -> Result<String, String> {
    let payload = hex::decode(payload_hex).map_err(|e| format!("bad payload hex: {e}"))?;
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| format!("bad privkey hex: {e}"))?;
    if sk_bytes.len() != 32 {
        return Err(format!("private key must be 32 bytes, got {}", sk_bytes.len()));
    }
    let private_key = noble_crypto::keys::NoblePrivateKey::Secp256k1(sk_bytes);
    let plaintext = noble_crypto::ecies::decrypt_single(&payload, &private_key)
        .map_err(|e| format!("ECIES decrypt: {e}"))?;
    Ok(hex::encode(&plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Generate a test keypair and return (private_key_hex, wire_address_hex).
    /// Wire address = 0x02 (scheme_id secp256k1) + 33-byte compressed pubkey.
    fn test_keypair() -> (String, String) {
        let (sk, pk) = noble_crypto::secp256k1::generate_keypair();
        let sk_hex = hex::encode(&sk);
        let wire_hex = format!("02{}", hex::encode(&pk));
        (sk_hex, wire_hex)
    }

    fn fake_utxo(value: u64, index: u8) -> String {
        let txid = hex::encode([index; 32]);
        format!(r#"{{"txid":"{}","vout":0,"value":{}}}"#, txid, value)
    }

    fn parse_result(json_str: &str) -> Value {
        serde_json::from_str(json_str).expect("FFI returned invalid JSON")
    }

    // ═══════════════════════════════════════════════════════════════
    // Suite 1: Transfer tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn transfer_valid_roundtrip() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0x11);
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["tx_hex"].is_string(), "expected tx_hex");
        assert!(v["tx_id"].is_string(), "expected tx_id");
        let tx_hex = v["tx_hex"].as_str().unwrap();
        assert!(tx_hex.len() > 20, "tx_hex too short");
        let tx_id = v["tx_id"].as_str().unwrap();
        assert_eq!(tx_id.len(), 64, "tx_id must be 64 hex chars");
    }

    #[test]
    fn transfer_recipient_preserved() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0x22);
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        // Decode the tx to verify recipient
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        let outputs = dv["outputs"].as_array().unwrap();
        // First output should be the recipient
        let first_addr = outputs[0]["address"].as_str().unwrap();
        assert_eq!(first_addr, recipient_addr, "recipient address mismatch");
    }

    #[test]
    fn transfer_amount_preserved() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0x33);
        let amount = 50_000_000u64;
        let params = format!(
            r#"{{"recipient":"{}","amount":{},"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, amount, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        let outputs = dv["outputs"].as_array().unwrap();
        let recipient_value = outputs[0]["value"].as_u64().unwrap();
        assert_eq!(recipient_value, amount, "amount mismatch");
    }

    #[test]
    fn transfer_change_correct() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let input_value = 200_000_000u64;
        let amount = 50_000_000u64;
        let fee = 1000u64;
        let utxo = fake_utxo(input_value, 0x44);
        let params = format!(
            r#"{{"recipient":"{}","amount":{},"fee":{},"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, amount, fee, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        let outputs = dv["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 2, "expected recipient + change outputs");
        let change_value = outputs[1]["value"].as_u64().unwrap();
        assert_eq!(change_value, input_value - amount - fee, "change = input - amount - fee");
    }

    #[test]
    fn transfer_fee_rate_computation() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0x55);
        let fee_rate = 2u64;
        let params = format!(
            r#"{{"recipient":"{}","amount":50000000,"fee_rate":{},"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, fee_rate, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        let actual_fee = v["fee"].as_u64().expect("fee_rate response must include fee");
        let size = v["size"].as_u64().expect("fee_rate response must include size");
        assert_eq!(actual_fee, size * fee_rate, "fee = size × fee_rate");
    }

    #[test]
    fn transfer_insufficient_funds_via_coin_select() {
        // C transfer builder doesn't validate total_input >= amount+fee (clients pre-select UTXOs).
        // But coin_select correctly rejects insufficient funds.
        let txid = hex::encode([0x66; 32]);
        let params = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":1000}}],"target":200000000}}"#, txid
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["error"].is_string(), "coin_select must reject insufficient funds: {result}");
    }

    #[test]
    fn transfer_no_utxos_builds_inputless_tx() {
        // C transfer builder allows empty UTXOs — produces a tx with 0 inputs.
        // Validation happens at node level, not at builder level.
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[]}}"#,
            recipient_addr, addr, sk
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        // C builder produces a valid tx (node validates inputs, not builder)
        assert!(v["tx_hex"].is_string(), "builder should produce tx even with no UTXOs");
    }

    #[test]
    fn transfer_single_utxo_no_change() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        // Exact match: amount + fee = UTXO value → no change output
        let fee = 1000u64;
        let amount = 100_000_000u64 - fee;
        let utxo = fake_utxo(100_000_000, 0x77);
        let params = format!(
            r#"{{"recipient":"{}","amount":{},"fee":{},"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, amount, fee, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(!v.get("error").is_some(), "unexpected error: {result}");
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        let outputs = dv["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 1, "exact match should produce 1 output (no change)");
    }

    #[test]
    fn transfer_invalid_recipient_hex() {
        let (sk, addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0x88);
        let params = format!(
            r#"{{"recipient":"ZZZZ","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["error"].is_string(), "expected error for invalid recipient: {result}");
    }

    #[test]
    fn transfer_self_transfer() {
        let (sk, addr) = test_keypair();
        // recipient == change_address → both outputs go to same address
        let utxo = fake_utxo(200_000_000, 0x99);
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(!v.get("error").is_some(), "unexpected error: {result}");
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        let outputs = dv["outputs"].as_array().unwrap();
        assert!(outputs.len() >= 1, "should have at least 1 output");
    }

    // ═══════════════════════════════════════════════════════════════
    // Suite 1: Notarization tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn notarization_valid_roundtrip() {
        let (sk, addr) = test_keypair();
        let checksum = hex::encode([0xAB; 32]);
        let utxo = fake_utxo(200_000_000, 0xAA);
        let params = format!(
            r#"{{"checksum":"{}","fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            checksum, addr, sk, utxo
        );
        let result = sign_notarization(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["tx_hex"].is_string(), "expected tx_hex");
        assert!(v["tx_id"].is_string(), "expected tx_id");
    }

    #[test]
    fn notarization_checksum_preserved() {
        let (sk, addr) = test_keypair();
        let checksum = hex::encode([0xCD; 32]);
        let utxo = fake_utxo(200_000_000, 0xBB);
        let params = format!(
            r#"{{"checksum":"{}","fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            checksum, addr, sk, utxo
        );
        let result = sign_notarization(&params).unwrap();
        let v = parse_result(&result);
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        assert_eq!(dv["checksum"].as_str().unwrap(), checksum, "checksum must survive encode/decode");
    }

    #[test]
    fn notarization_metadata_preserved() {
        let (sk, addr) = test_keypair();
        let checksum = hex::encode([0xEE; 32]);
        let utxo = fake_utxo(200_000_000, 0xCC);
        let params = format!(
            r#"{{"checksum":"{}","fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"metadata":[{{"key":"author","value":"Alice"}},{{"key":"doc_type","value":"invoice"}}],"utxos":[{}]}}"#,
            checksum, addr, sk, utxo
        );
        let result = sign_notarization(&params).unwrap();
        let v = parse_result(&result);
        let decode_params = format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap());
        let decoded = tx_decode(&decode_params).unwrap();
        let dv = parse_result(&decoded);
        let metadata = dv["metadata"].as_array().unwrap();
        assert_eq!(metadata.len(), 2, "expected 2 metadata entries");
        let keys: Vec<&str> = metadata.iter().map(|m| m["key"].as_str().unwrap()).collect();
        assert!(keys.contains(&"author"), "missing 'author' metadata");
        assert!(keys.contains(&"doc_type"), "missing 'doc_type' metadata");
    }

    #[test]
    fn notarization_fee_computation() {
        let (sk, addr) = test_keypair();
        let checksum = hex::encode([0xFF; 32]);
        let utxo = fake_utxo(200_000_000, 0xDD);
        let fee_rate = 3u64;
        let params = format!(
            r#"{{"checksum":"{}","fee_rate":{},"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            checksum, fee_rate, addr, sk, utxo
        );
        let result = sign_notarization(&params).unwrap();
        let v = parse_result(&result);
        let actual_fee = v["fee"].as_u64().expect("fee_rate response must include fee");
        let size = v["size"].as_u64().expect("fee_rate response must include size");
        assert_eq!(actual_fee, size * fee_rate, "fee = size × fee_rate");
    }

    #[test]
    fn notarization_empty_checksum_rejected() {
        let (sk, addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0xEE);
        // Missing checksum field
        let params = format!(
            r#"{{"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, sk, utxo
        );
        let result = sign_notarization(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["error"].is_string(), "expected error for missing checksum: {result}");
    }

    // ═══════════════════════════════════════════════════════════════
    // Suite 1: Coin selection tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn coin_selection_works() {
        let input = r#"{"utxos":[{"txid":"aabb","vout":0,"value":100000000}],"target":50000000}"#;
        let result = select_utxos(input).unwrap();
        assert!(result.contains("\"selected\""), "expected selected field: {result}");
        assert!(result.contains("\"total\""), "expected total field: {result}");
    }

    #[test]
    fn coin_select_single_utxo() {
        let txid = hex::encode([0x01; 32]);
        let params = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":100000000}}],"target":50000000}}"#, txid
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        let selected = v["selected"].as_array().unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(v["total"].as_u64().unwrap(), 100_000_000);
        assert_eq!(v["change"].as_u64().unwrap(), 50_000_000);
    }

    #[test]
    fn coin_select_exact_match() {
        let txid = hex::encode([0x02; 32]);
        let params = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":50000000}}],"target":50000000}}"#, txid
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        assert_eq!(v["total"].as_u64().unwrap(), 50_000_000);
        assert_eq!(v["change"].as_u64().unwrap(), 0, "exact match = no change");
    }

    #[test]
    fn coin_select_multiple_needed() {
        let txid1 = hex::encode([0x03; 32]);
        let txid2 = hex::encode([0x04; 32]);
        let params = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":30000000}},{{"txid":"{}","vout":0,"value":30000000}}],"target":50000000}}"#,
            txid1, txid2
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        let selected = v["selected"].as_array().unwrap();
        assert_eq!(selected.len(), 2, "both UTXOs needed");
        assert_eq!(v["total"].as_u64().unwrap(), 60_000_000);
    }

    #[test]
    fn coin_select_all_needed() {
        let utxos: Vec<String> = (0..4).map(|i| {
            let txid = hex::encode([i + 10; 32]);
            format!(r#"{{"txid":"{}","vout":0,"value":25000000}}"#, txid)
        }).collect();
        let params = format!(
            r#"{{"utxos":[{}],"target":99000000}}"#, utxos.join(",")
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        let selected = v["selected"].as_array().unwrap();
        assert_eq!(selected.len(), 4, "all 4 UTXOs needed");
        assert_eq!(v["total"].as_u64().unwrap(), 100_000_000);
    }

    #[test]
    fn coin_select_insufficient() {
        let txid = hex::encode([0x05; 32]);
        let params = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":1000}}],"target":50000000}}"#, txid
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["error"].is_string(), "expected error for insufficient funds: {result}");
    }

    #[test]
    fn coin_select_large_values() {
        let txid = hex::encode([0x06; 32]);
        // Use a large value that fits in JSON i64 range (JSON numbers may be parsed as i64)
        let large = 4_000_000_000_000_000u64; // 4 quadrillion groats
        let params = format!(
            r#"{{"utxos":[{{"txid":"{}","vout":0,"value":{}}}],"target":1000}}"#, txid, large
        );
        let result = select_utxos(&params).unwrap();
        let v = parse_result(&result);
        assert_eq!(v["total"].as_u64().unwrap(), large, "large value preserved");
    }

    // ═══════════════════════════════════════════════════════════════
    // Suite 3: Signing verification (through JSON FFI)
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn sign_encode_valid_produces_cbor() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0xF0);
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        let tx_hex = v["tx_hex"].as_str().unwrap();
        // tx_hex must be valid hex
        let tx_bytes = hex::decode(tx_hex).expect("tx_hex must be valid hex");
        // CBOR starts with a map marker (0xa0-0xbf for small maps, or 0xb9 for 2-byte count)
        assert!(!tx_bytes.is_empty(), "tx_bytes must not be empty");
    }

    #[test]
    fn sign_encode_tx_id_deterministic() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0xF1);
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        let tx_id = v["tx_id"].as_str().unwrap();
        // tx_id must be 64 hex chars (32 bytes SHA-256)
        assert_eq!(tx_id.len(), 64);
        assert!(hex::decode(tx_id).is_ok(), "tx_id must be valid hex");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0xF2);
        let params = format!(
            r#"{{"recipient":"{}","amount":100000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo
        );
        let result = sign_transfer(&params).unwrap();
        let v = parse_result(&result);
        // Use noble_verify_tx to verify the signature
        let verify_params = format!(
            r#"{{"tx_hex":"{}","chain_id":1315202980}}"#,
            v["tx_hex"].as_str().unwrap()
        );
        let verify_result = verify_tx(&verify_params).unwrap();
        let vr = parse_result(&verify_result);
        assert!(
            vr.get("error").is_none(),
            "signature verification should succeed: {verify_result}"
        );
    }

    #[test]
    fn derive_pubkey_deterministic() {
        // Two transfers with the same key should have the same signer pubkey
        let (sk, addr) = test_keypair();
        let (_, recipient_addr) = test_keypair();
        let utxo1 = fake_utxo(200_000_000, 0xF3);
        let utxo2 = fake_utxo(200_000_000, 0xF4);

        let params1 = format!(
            r#"{{"recipient":"{}","amount":50000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo1
        );
        let params2 = format!(
            r#"{{"recipient":"{}","amount":60000000,"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000001,"utxos":[{}]}}"#,
            recipient_addr, addr, sk, utxo2
        );

        let r1 = sign_transfer(&params1).unwrap();
        let r2 = sign_transfer(&params2).unwrap();
        let v1 = parse_result(&r1);
        let v2 = parse_result(&r2);

        let d1 = parse_result(&tx_decode(&format!(r#"{{"tx_hex":"{}"}}"#, v1["tx_hex"].as_str().unwrap())).unwrap());
        let d2 = parse_result(&tx_decode(&format!(r#"{{"tx_hex":"{}"}}"#, v2["tx_hex"].as_str().unwrap())).unwrap());

        assert_eq!(
            d1["issuer_sig"]["public_key"].as_str().unwrap(),
            d2["issuer_sig"]["public_key"].as_str().unwrap(),
            "same private key must derive same public key"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Split transfer tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn split_transfer_3_outputs() {
        let (sk, addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0xE0);
        let params = format!(
            r#"{{"outputs":[{{"address":"{}","amount":50000000}},{{"address":"{}","amount":50000000}},{{"address":"{}","amount":50000000}}],"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, addr, addr, addr, sk, utxo
        );
        let result = sign_split_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["tx_hex"].is_string(), "expected tx_hex: {result}");
        // Decode and verify 4 outputs (3 recipients + 1 change)
        let decoded = parse_result(&tx_decode(&format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap())).unwrap());
        let outputs = decoded["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 4, "expected 3 splits + 1 change");
        assert_eq!(outputs[0]["value"].as_u64().unwrap(), 50_000_000);
        assert_eq!(outputs[1]["value"].as_u64().unwrap(), 50_000_000);
        assert_eq!(outputs[2]["value"].as_u64().unwrap(), 50_000_000);
        // Change = 200M - 150M - 1000 = 49_999_000
        assert_eq!(outputs[3]["value"].as_u64().unwrap(), 49_999_000);
    }

    #[test]
    fn split_transfer_exact_no_change() {
        let (sk, addr) = test_keypair();
        let utxo = fake_utxo(100_001_000, 0xE1);
        let params = format!(
            r#"{{"outputs":[{{"address":"{}","amount":50000000}},{{"address":"{}","amount":50000000}}],"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, addr, addr, sk, utxo
        );
        let result = sign_split_transfer(&params).unwrap();
        let v = parse_result(&result);
        let decoded = parse_result(&tx_decode(&format!(r#"{{"tx_hex":"{}"}}"#, v["tx_hex"].as_str().unwrap())).unwrap());
        let outputs = decoded["outputs"].as_array().unwrap();
        assert_eq!(outputs.len(), 2, "exact amount = no change output");
    }

    #[test]
    fn split_transfer_insufficient_funds() {
        let (sk, addr) = test_keypair();
        let utxo = fake_utxo(1000, 0xE2);
        let params = format!(
            r#"{{"outputs":[{{"address":"{}","amount":50000000}},{{"address":"{}","amount":50000000}}],"fee":1000,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, addr, addr, sk, utxo
        );
        let result = sign_split_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["error"].is_string(), "expected error for insufficient funds: {result}");
    }

    #[test]
    fn split_transfer_with_fee_rate() {
        let (sk, addr) = test_keypair();
        let utxo = fake_utxo(200_000_000, 0xE3);
        let params = format!(
            r#"{{"outputs":[{{"address":"{}","amount":50000000}},{{"address":"{}","amount":50000000}}],"fee_rate":2,"change_address":"{}","private_key":"{}","chain_id":1315202980,"timestamp":1700000000,"utxos":[{}]}}"#,
            addr, addr, addr, sk, utxo
        );
        let result = sign_split_transfer(&params).unwrap();
        let v = parse_result(&result);
        assert!(v["fee"].is_number(), "fee_rate response must include fee");
        assert!(v["size"].is_number(), "fee_rate response must include size");
        let fee = v["fee"].as_u64().unwrap();
        let size = v["size"].as_u64().unwrap();
        assert_eq!(fee, size * 2, "fee = size × fee_rate");
    }
}
