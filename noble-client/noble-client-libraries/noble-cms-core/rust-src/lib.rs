// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// noble-cms-core: CMS/PKCS#7 per-field metadata signing for NOBLE.
//
// Single Rust implementation exposed as a stable C ABI.
// Used by all platforms: Apple (via XCFramework), WRY (via Cargo), node (via Cargo).

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub mod cms;

// ── C ABI Exports ──

fn call_cms(
    f: impl FnOnce(&str) -> Result<String, String>,
    params_json: &str,
) -> *mut c_char {
    let json_result = match f(params_json) {
        Ok(val) => val,
        Err(e) => format!("{{\"error\":\"{}\"}}", e.replace('\"', "\\\"").replace('\n', " ")),
    };
    CString::new(json_result)
        .map(|cs| cs.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn parse_input(ptr: *const c_char) -> Option<&'static str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Create a CMS/PKCS#7 detached signature over a metadata field value.
#[no_mangle]
pub extern "C" fn noble_sign_cms(params_json: *const c_char) -> *mut c_char {
    let Some(input) = parse_input(params_json) else {
        return std::ptr::null_mut();
    };
    call_cms(
        |json| {
            let r = cms::sign_cms(json)?;
            serde_json::to_string(&r).map_err(|e| format!("serialize: {e}"))
        },
        input,
    )
}

/// Verify a CMS/PKCS#7 detached signature.
#[no_mangle]
pub extern "C" fn noble_verify_cms(params_json: *const c_char) -> *mut c_char {
    let Some(input) = parse_input(params_json) else {
        return std::ptr::null_mut();
    };
    call_cms(
        |json| {
            let r = cms::verify_cms(json)?;
            serde_json::to_string(&r).map_err(|e| format!("serialize: {e}"))
        },
        input,
    )
}

/// Parse a PKCS#12 container and extract the EC key + certificate.
#[no_mangle]
pub extern "C" fn noble_import_pkcs12(params_json: *const c_char) -> *mut c_char {
    let Some(input) = parse_input(params_json) else {
        return std::ptr::null_mut();
    };
    call_cms(
        |json| {
            let r = cms::import_pkcs12(json)?;
            serde_json::to_string(&r).map_err(|e| format!("serialize: {e}"))
        },
        input,
    )
}

/// Free a string returned by any noble_cms_* function.
#[no_mangle]
pub extern "C" fn noble_cms_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)) };
    }
}
