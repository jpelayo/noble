// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Credential storage (Linux Secret Service via `keyring`) and SHA-256 file hashing.
//!
//! Uses the system keyring (GNOME Keyring, KDE Wallet, or compatible
//! Secret Service provider) for secure credential storage on Linux.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tao::event_loop::EventLoopProxy;

use crate::bridge::UserEvent;

const SERVICE_NAME: &str = "com.infinitecontext.nobledoc";

pub const KEY_PRIVATE_KEY: &str = "nobledoc.wallet.privatekey";
pub const KEY_MNEMONIC: &str = "nobledoc.wallet.mnemonic";
pub const KEY_NODE_URL: &str = "nobledoc.settings.nodeurl";

/// Keyring key for a CMS signing private key (per-key UUID).
pub fn signing_key_credential(key_id: &str) -> String {
    format!("nobledoc.signing-key.{key_id}")
}

/// Keyring key for a CMS signing certificate (per-key UUID).
pub fn signing_cert_credential(key_id: &str) -> String {
    format!("nobledoc.signing-cert.{key_id}")
}

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

        "getMyCard" => {
            let contacts = crate::storage::load_contacts();
            match contacts.iter().find(|c| c.is_my_card) {
                Some(my_card) => Ok(crate::storage::contact_to_bridge_json(my_card)),
                None => Ok(serde_json::json!({ "signingKeys": [] })),
            }
        }

        "generateSigningKey" => {
            // Generate a secp256k1 keypair from the OS CSPRNG. Mirrors the
            // Mac client (SecRandomCopyBytes + derivePublicKey + SHA-1 SKI).
            let mut priv_bytes = [0u8; 32];
            let mut attempts = 0;
            let pub_bytes = loop {
                getrandom::getrandom(&mut priv_bytes)
                    .map_err(|e| format!("Failed to generate random key: {e}"))?;
                match crate::crypto::compressed_public_key(&priv_bytes) {
                    Ok(p) => break p,
                    // Astronomically unlikely (scalar out of range); retry.
                    Err(_) if attempts < 4 => attempts += 1,
                    Err(e) => return Err(format!("Failed to derive public key: {e}")),
                }
            };
            let compressed_hex = hex::encode(&pub_bytes);
            // X.509 SubjectKeyIdentifier convention: SHA-1 of the public key.
            let ski_hex = {
                use sha1::{Digest as Sha1Digest, Sha1};
                let mut h = Sha1::new();
                h.update(&pub_bytes);
                hex::encode(h.finalize())
            };

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let entry = crate::models::SigningKeyEntry {
                id: uuid::Uuid::new_v4().to_string(),
                label: "Noble Key".to_string(),
                algorithm: "secp256k1".to_string(),
                public_key_hex: compressed_hex,
                has_private_key: true,
                certificate_subject: None,
                certificate_der: None,
                subject_key_identifier: Some(ski_hex),
                imported_at: now,
            };

            store_credential(&signing_key_credential(&entry.id), &priv_bytes)?;

            let mut contacts = crate::storage::load_contacts();
            if let Some(my_card) = contacts.iter_mut().find(|c| c.is_my_card) {
                my_card.signing_keys.push(entry.clone());
                crate::storage::save_contacts(&contacts)?;
            }

            Ok(entry.to_bridge_json())
        }

        "removeSigningKey" => {
            let key_id = params
                .get("keyId")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: keyId")?;

            // Key material deletion must succeed (prevent key leak on a
            // card that no longer lists the key). Cert cleanup is
            // best-effort — the key is the critical secret.
            delete_credential(&signing_key_credential(key_id))?;
            if let Err(e) = delete_credential(&signing_cert_credential(key_id)) {
                eprintln!("[security] warning: cert cleanup failed (key removed): {e}");
            }

            let mut contacts = crate::storage::load_contacts();
            for c in contacts.iter_mut() {
                c.signing_keys.retain(|sk| sk.id != key_id);
            }
            crate::storage::save_contacts(&contacts)?;

            Ok(serde_json::json!({ "ok": true }))
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
