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

/// Build, sign, and CBOR-encode a transfer transaction.
pub fn sign_transfer(params_json: &str) -> Result<String, String> {
    call_ffi(noble_sign_transfer, params_json)
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

    #[test]
    fn coin_selection_works() {
        let input = r#"{"utxos":[{"txid":"aabb","vout":0,"value":100000000}],"target":50000000}"#;
        let result = select_utxos(input).unwrap();
        assert!(result.contains("\"selected\""), "expected selected field: {result}");
        assert!(result.contains("\"total\""), "expected total field: {result}");
    }
}
