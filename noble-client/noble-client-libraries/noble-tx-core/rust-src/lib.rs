// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Rust wrapper for the noble-tx-core C library.
// Used by NobleWin (Windows) and NobleDoc (Linux).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn noble_sign_transfer(params_json: *const c_char) -> *mut c_char;
    fn noble_sign_notarization(params_json: *const c_char) -> *mut c_char;
    fn noble_select_utxos(params_json: *const c_char) -> *mut c_char;
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

/// Run 5-pass coin selection on UTXOs.
pub fn select_utxos(params_json: &str) -> Result<String, String> {
    call_ffi(noble_select_utxos, params_json)
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
