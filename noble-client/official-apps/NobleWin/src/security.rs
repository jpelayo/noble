// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Credential storage (Windows Credential Manager via `keyring`) and SHA-256 file hashing.
//!
//! Replaces macOS Keychain access from `LiveKeychainService.swift`.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tao::event_loop::EventLoopProxy;

use crate::bridge::UserEvent;

const SERVICE_NAME: &str = "com.infinitecontext.noblewin";

pub const KEY_PRIVATE_KEY: &str = "noblewin.wallet.privatekey";
pub const KEY_MNEMONIC: &str = "noblewin.wallet.mnemonic";
pub const KEY_NODE_URL: &str = "noblewin.settings.nodeurl";

/// Store a value in the OS credential store.
pub fn store_credential(key: &str, value: &[u8]) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE_NAME, key)
        .map_err(|e| format!("Keyring error: {e} [{}]", crate::errors::NE_KEYCHAIN_STORE))?;
    let hex_value = hex::encode(value);
    entry
        .set_password(&hex_value)
        .map_err(|e| format!("Failed to store credential: {e} [{}]", crate::errors::NE_KEYCHAIN_STORE))
}

/// Load a value from the OS credential store.
pub fn load_credential(key: &str) -> Result<Option<Vec<u8>>, String> {
    let entry = keyring::Entry::new(SERVICE_NAME, key)
        .map_err(|e| format!("Keyring error: {e} [{}]", crate::errors::NE_KEYCHAIN_LOAD))?;
    match entry.get_password() {
        Ok(hex_value) => {
            let bytes = hex::decode(&hex_value)
                .map_err(|e| format!("Invalid stored credential: {e} [{}]", crate::errors::NE_INVALID_KEY_DATA))?;
            Ok(Some(bytes))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to load credential: {e} [{}]", crate::errors::NE_KEYCHAIN_LOAD)),
    }
}

/// Delete a value from the OS credential store.
pub fn delete_credential(key: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE_NAME, key)
        .map_err(|e| format!("Keyring error: {e}"))?;
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Already gone
        Err(e) => Err(format!("Failed to delete credential: {e}")),
    }
}

/// Check if a credential exists.
pub fn has_credential(key: &str) -> bool {
    load_credential(key)
        .map(|v| v.is_some())
        .unwrap_or(false)
}

/// Handle `noble_security` bridge actions.
pub fn handle_security_action(action: &str, params: &Value) -> Result<Value, String> {
    match action {
        "hashFile" => {
            let file_path = params
                .get("filePath")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: filePath")?;
            let hash = crate::crypto::hash_file(file_path)?;
            Ok(serde_json::json!({ "hash": hash }))
        }

        "loadPrivateKey" => {
            // Security: never send the raw key to JS. Only report availability.
            let available = has_credential(KEY_PRIVATE_KEY);
            Ok(serde_json::json!({ "available": available }))
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}

/// Download a URL, stream-hash the body with SHA-256, and emit progress events
/// to the WebView while downloading. Enforces a byte cap; rejects non-HTTP(S)
/// schemes at the caller side (we double-check here too).
pub async fn download_and_hash(
    params: &Value,
    proxy: &EventLoopProxy<UserEvent>,
) -> Result<Value, String> {
    let url_str = params
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or("Missing parameter: url")?;

    let parsed = reqwest::Url::parse(url_str)
        .map_err(|e| format!("Invalid URL: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Ok(serde_json::json!({
            "ok": false,
            "errorCode": "UNSUPPORTED_SCHEME",
            "error": "Only http:// and https:// are allowed",
        }));
    }

    let max_bytes = params
        .get("maxBytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(64 * 1024 * 1024) as usize;
    let request_id = params
        .get("requestId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| format!("HTTP client init failed: {e}"))?;

    let started_at = Instant::now();
    let response = match client.get(parsed).send().await {
        Ok(r) => r,
        Err(e) => {
            let code = if e.is_timeout() { "TIMEOUT" } else { "NETWORK" };
            return Ok(serde_json::json!({
                "ok": false,
                "errorCode": code,
                "error": e.to_string(),
            }));
        }
    };

    if !response.status().is_success() {
        return Ok(serde_json::json!({
            "ok": false,
            "errorCode": format!("HTTP_{}", response.status().as_u16()),
            "error": format!("HTTP {}", response.status()),
        }));
    }

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let total_bytes: Option<u64> = response.content_length();
    if let Some(total) = total_bytes {
        if (total as usize) > max_bytes {
            return Ok(serde_json::json!({
                "ok": false,
                "errorCode": "SIZE_LIMIT_EXCEEDED",
                "error": "File is larger than the verify limit.",
            }));
        }
    }

    emit_progress(proxy, &request_id, 0, total_bytes);

    let mut hasher = Sha256::new();
    let mut received: usize = 0;
    let mut last_tick = Instant::now() - Duration::from_secs(1);
    let mut last_bytes: usize = 0;
    let mut response = response;

    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                received += chunk.len();
                if received > max_bytes {
                    return Ok(serde_json::json!({
                        "ok": false,
                        "errorCode": "SIZE_LIMIT_EXCEEDED",
                        "error": "File is larger than the verify limit.",
                    }));
                }
                hasher.update(&chunk);
                let now = Instant::now();
                if now.duration_since(last_tick) >= Duration::from_millis(100)
                    || (received - last_bytes) >= 256 * 1024
                {
                    last_tick = now;
                    last_bytes = received;
                    emit_progress(proxy, &request_id, received as u64, total_bytes);
                }
            }
            Ok(None) => break,
            Err(e) => {
                let code = if e.is_timeout() { "TIMEOUT" } else { "NETWORK" };
                return Ok(serde_json::json!({
                    "ok": false,
                    "errorCode": code,
                    "error": e.to_string(),
                }));
            }
        }
    }

    // Final tick so the UI shows 100% before we flip to hashing/result state.
    emit_progress(proxy, &request_id, received as u64, total_bytes.or(Some(received as u64)));

    let digest = hasher.finalize();
    let hash_hex = hex::encode(digest);
    let elapsed_ms = started_at.elapsed().as_millis() as u64;

    let mut out = serde_json::json!({
        "ok": true,
        "hash": hash_hex,
        "size": received,
        "elapsedMs": elapsed_ms,
    });
    if let Some(ct) = content_type {
        out["contentType"] = Value::String(ct);
    }
    Ok(out)
}

fn emit_progress(
    proxy: &EventLoopProxy<UserEvent>,
    request_id: &str,
    bytes_downloaded: u64,
    total_bytes: Option<u64>,
) {
    let total = match total_bytes {
        Some(t) => t.to_string(),
        None => "null".to_string(),
    };
    let rid = request_id.replace('\'', "\\'");
    let js = format!(
        "window.NobleBridge && window.NobleBridge._onDownloadProgress && window.NobleBridge._onDownloadProgress({{requestId:'{}',bytesDownloaded:{},totalBytes:{}}})",
        rid, bytes_downloaded, total
    );
    let _ = proxy.send_event(UserEvent::EvalScript(js));
}
