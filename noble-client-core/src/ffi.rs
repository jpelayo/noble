// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! C FFI exports for client apps (Swift via xcframework, WRY via direct linking).
//!
//! All functions take a JSON string input and return a JSON string output.
//! Caller must free returned strings via `noble_client_free()`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn json_call<F: FnOnce(&str) -> Result<String, String>>(input: *const c_char, f: F) -> *mut c_char {
    let input_str = if input.is_null() {
        "{}"
    } else {
        match unsafe { CStr::from_ptr(input) }.to_str() {
            Ok(s) => s,
            Err(_) => return error_json("invalid UTF-8 input"),
        }
    };

    match f(input_str) {
        Ok(json) => CString::new(json).unwrap_or_default().into_raw(),
        Err(e) => error_json(&e),
    }
}

fn error_json(msg: &str) -> *mut c_char {
    let json = serde_json::json!({ "error": msg }).to_string();
    CString::new(json).unwrap_or_default().into_raw()
}

/// Build and sign a transfer transaction.
/// Input: JSON with `recipient`, `amount`, `fee`, `utxos`, `change_address`, `private_key`, `chain_id`.
/// Output: JSON with `tx_hex` and `tx_id`, or `error`.
#[no_mangle]
pub extern "C" fn noble_client_sign_transfer(params_json: *const c_char) -> *mut c_char {
    json_call(params_json, |input| {
        let params: crate::transaction::TransferParams =
            serde_json::from_str(input).map_err(|e| format!("JSON parse error: {e}"))?;
        let result = crate::transaction::sign_transfer(params)?;
        serde_json::to_string(&result).map_err(|e| format!("JSON encode error: {e}"))
    })
}

/// Build and sign a notarization transaction.
/// Input: JSON with `checksum`, `metadata`, `fee`, `utxos`, `change_address`, `private_key`, `chain_id`.
/// Output: JSON with `tx_hex` and `tx_id`, or `error`.
#[no_mangle]
pub extern "C" fn noble_client_sign_notarization(params_json: *const c_char) -> *mut c_char {
    json_call(params_json, |input| {
        let params: crate::transaction::NotarizationParams =
            serde_json::from_str(input).map_err(|e| format!("JSON parse error: {e}"))?;
        let result = crate::transaction::sign_notarization(params)?;
        serde_json::to_string(&result).map_err(|e| format!("JSON encode error: {e}"))
    })
}

/// Run coin selection on available UTXOs.
/// Input: JSON with `utxos` and `target`.
/// Output: JSON with `selected` array, or `error`.
#[no_mangle]
pub extern "C" fn noble_client_select_utxos(params_json: *const c_char) -> *mut c_char {
    json_call(params_json, |input| {
        #[derive(serde::Deserialize)]
        struct Params { utxos: Vec<crate::coin_selection::Utxo>, target: u64 }
        let p: Params = serde_json::from_str(input).map_err(|e| format!("JSON parse error: {e}"))?;
        let selected = crate::coin_selection::select(&p.utxos, p.target)?;
        serde_json::to_string(&serde_json::json!({ "selected": selected }))
            .map_err(|e| format!("JSON encode error: {e}"))
    })
}

/// Generate a BIP-39 mnemonic.
/// Input: JSON with `word_count` (12 or 24).
/// Output: JSON with `words` array, or `error`.
#[no_mangle]
pub extern "C" fn noble_client_generate_mnemonic(params_json: *const c_char) -> *mut c_char {
    json_call(params_json, |input| {
        #[derive(serde::Deserialize)]
        struct Params { word_count: usize }
        let p: Params = serde_json::from_str(input).map_err(|e| format!("JSON parse error: {e}"))?;
        let words = crate::transaction::generate_mnemonic(p.word_count)?;
        serde_json::to_string(&serde_json::json!({ "words": words }))
            .map_err(|e| format!("JSON encode error: {e}"))
    })
}

/// Derive a secp256k1 keypair from a BIP-39 mnemonic.
/// Input: JSON with `words` array.
/// Output: JSON with `private_key` (hex) and `public_key` (hex wire), or `error`.
#[no_mangle]
pub extern "C" fn noble_client_derive_keypair(params_json: *const c_char) -> *mut c_char {
    json_call(params_json, |input| {
        #[derive(serde::Deserialize)]
        struct Params { words: Vec<String> }
        let p: Params = serde_json::from_str(input).map_err(|e| format!("JSON parse error: {e}"))?;
        let (sk_hex, pk_hex) = crate::transaction::derive_keypair(&p.words)?;
        serde_json::to_string(&serde_json::json!({ "private_key": sk_hex, "public_key": pk_hex }))
            .map_err(|e| format!("JSON encode error: {e}"))
    })
}

/// Free a string returned by any noble_client_* function.
#[no_mangle]
pub extern "C" fn noble_client_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { let _ = CString::from_raw(ptr); }
    }
}
