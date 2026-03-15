// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Credential storage (Linux Secret Service via `keyring`) and SHA-256 file hashing.
//!
//! Uses the system keyring (GNOME Keyring, KDE Wallet, or compatible
//! Secret Service provider) for secure credential storage on Linux.

use serde_json::Value;

const SERVICE_NAME: &str = "com.infinitecontext.nobledoc";

pub const KEY_PRIVATE_KEY: &str = "nobledoc.wallet.privatekey";
pub const KEY_MNEMONIC: &str = "nobledoc.wallet.mnemonic";
pub const KEY_NODE_URL: &str = "nobledoc.settings.nodeurl";

/// Store a value in the OS credential store.
pub fn store_credential(key: &str, value: &[u8]) -> Result<(), String> {
    let entry = keyring::Entry::new(SERVICE_NAME, key)
        .map_err(|e| format!("Keyring error: {e}"))?;
    let hex_value = hex::encode(value);
    entry
        .set_password(&hex_value)
        .map_err(|e| format!("Failed to store credential: {e}"))
}

/// Load a value from the OS credential store.
pub fn load_credential(key: &str) -> Result<Option<Vec<u8>>, String> {
    let entry = keyring::Entry::new(SERVICE_NAME, key)
        .map_err(|e| format!("Keyring error: {e}"))?;
    match entry.get_password() {
        Ok(hex_value) => {
            let bytes = hex::decode(&hex_value)
                .map_err(|e| format!("Invalid stored credential: {e}"))?;
            Ok(Some(bytes))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to load credential: {e}")),
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
