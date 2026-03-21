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
    fn noble_select_utxos(params_json: *const c_char) -> *mut c_char;
    fn noble_tx_encode(tx_json: *const c_char) -> *mut c_char;
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

/// Encode a Transaction to CBOR bytes using the canonical C encoder.
///
/// This is the ONLY transaction encoder in the protocol. Both clients and
/// the node use this function (directly or indirectly) to produce transaction
/// CBOR. The mempool validates fees against the byte count of this encoding.
pub fn encode_transaction(tx: &noble_core::Transaction) -> Result<Vec<u8>, String> {
    let json = tx_to_json(tx);
    let result_str = call_ffi(noble_tx_encode, &json)?;
    let result: serde_json::Value = serde_json::from_str(&result_str)
        .map_err(|e| format!("parse C result: {e}"))?;
    if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }
    let tx_hex = result
        .get("tx_hex")
        .and_then(|v| v.as_str())
        .ok_or("missing tx_hex in C result")?;
    hex::decode(tx_hex).map_err(|e| format!("hex decode: {e}"))
}

/// Return the CBOR byte size of a transaction as encoded by the C library.
pub fn transaction_cbor_size(tx: &noble_core::Transaction) -> Result<usize, String> {
    let json = tx_to_json(tx);
    let result_str = call_ffi(noble_tx_encode, &json)?;
    let result: serde_json::Value = serde_json::from_str(&result_str)
        .map_err(|e| format!("parse C result: {e}"))?;
    if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
        return Err(err.to_string());
    }
    result
        .get("size")
        .and_then(|v| v.as_u64())
        .map(|v| v as usize)
        .ok_or_else(|| "missing size in C result".to_string())
}

/// Convert a noble_core::Transaction to the JSON format expected by the C library.
fn tx_to_json(tx: &noble_core::Transaction) -> String {
    let inputs: Vec<serde_json::Value> = tx
        .inputs
        .iter()
        .map(|inp| {
            serde_json::json!({
                "prev_output": {
                    "txid": hex::encode(inp.prev_output.txid.as_bytes()),
                    "vout": inp.prev_output.vout,
                }
            })
        })
        .collect();

    let outputs: Vec<serde_json::Value> = tx
        .outputs
        .iter()
        .map(|out| {
            let addr_hex = hex::encode(out.address.to_wire_bytes());
            serde_json::json!({
                "value": out.value,
                "address": addr_hex,
            })
        })
        .collect();

    let metadata: Vec<serde_json::Value> = tx
        .metadata
        .iter()
        .map(|m| {
            // UTF-8 metadata → string as-is; binary (e.g. encrypted) → hex fallback
            let value_str = match String::from_utf8(m.value.clone()) {
                Ok(s) => s,
                Err(_) => hex::encode(&m.value),
            };
            serde_json::json!({
                "key": m.key,
                "value": value_str,
            })
        })
        .collect();

    let sig = &tx.issuer_sig;
    let issuer_sig = serde_json::json!({
        "scheme_id": sig.scheme_id,
        "public_key": hex::encode(&sig.public_key),
        "signature": hex::encode(&sig.signature),
    });

    let additional_sigs: Vec<serde_json::Value> = tx
        .additional_sigs
        .iter()
        .map(|s| {
            serde_json::json!({
                "scheme_id": s.scheme_id,
                "public_key": hex::encode(&s.public_key),
                "signature": hex::encode(&s.signature),
            })
        })
        .collect();

    let mut json = serde_json::json!({
        "version": tx.version,
        "tx_type": tx.tx_type,
        "inputs": inputs,
        "outputs": outputs,
        "checksum": hex::encode(tx.checksum.as_bytes()),
        "timestamp": tx.timestamp,
        "issuer_sig": issuer_sig,
        "additional_sigs": additional_sigs,
        "metadata": metadata,
    });

    // Optional fields — only include when present
    if let Some(ref gw) = tx.gateway_address {
        json["gateway_address"] = serde_json::json!(hex::encode(gw));
    }
    if let Some(exp) = tx.expires_at {
        json["expires_at"] = serde_json::json!(exp);
    }

    json.to_string()
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
