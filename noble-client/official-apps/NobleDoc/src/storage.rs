// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! File-based persistence for contacts, drafts, and settings.
//!
//! Replaces UserDefaults persistence from the Apple clients.
//! Data stored in `%APPDATA%/NobleDoc/` on Windows, `~/.local/share/NobleDoc/`
//! on Linux, `~/Library/Application Support/NobleDoc/` on macOS.

use crate::models::{Contact, Settings};
use serde_json::Value;
use std::path::PathBuf;

/// Get the data directory for NobleDoc storage files.
fn data_dir() -> PathBuf {
    let base = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    base.join("NobleDoc")
}

/// Ensure the data directory exists.
fn ensure_data_dir() -> std::io::Result<PathBuf> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

// ============================================================================
// Contacts
// ============================================================================

fn contacts_path() -> PathBuf {
    data_dir().join("contacts.json")
}

pub fn load_contacts() -> Vec<Contact> {
    let path = contacts_path();
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save_contacts(contacts: &[Contact]) -> Result<(), String> {
    let dir = ensure_data_dir().map_err(|e| format!("Failed to create data dir: {e}"))?;
    let path = dir.join("contacts.json");
    let json =
        serde_json::to_string_pretty(contacts).map_err(|e| format!("JSON serialize error: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("Failed to write contacts: {e}"))
}

// ============================================================================
// Drafts
// ============================================================================

fn drafts_path() -> PathBuf {
    data_dir().join("drafts.json")
}

pub fn load_drafts() -> Vec<Value> {
    let path = drafts_path();
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save_drafts(drafts: &[Value]) -> Result<(), String> {
    let dir = ensure_data_dir().map_err(|e| format!("Failed to create data dir: {e}"))?;
    let path = dir.join("drafts.json");
    let json =
        serde_json::to_string_pretty(drafts).map_err(|e| format!("JSON serialize error: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("Failed to write drafts: {e}"))
}

// ============================================================================
// Web preferences
// ============================================================================
// The WebUI persists preference keys (theme, thousands separator, auto-split,
// faucet cooldown) through the bridge because webview localStorage is not
// guaranteed to survive relaunch. Flat key->string map, hydrated back into
// localStorage at boot.

fn preferences_path() -> PathBuf {
    data_dir().join("preferences.json")
}

pub fn load_preferences() -> Value {
    match std::fs::read_to_string(preferences_path()) {
        Ok(json) => serde_json::from_str(&json)
            .unwrap_or_else(|_| Value::Object(serde_json::Map::new())),
        Err(_) => Value::Object(serde_json::Map::new()),
    }
}

pub fn save_preferences(prefs: &Value) -> Result<(), String> {
    let dir = ensure_data_dir().map_err(|e| format!("Failed to create data dir: {e}"))?;
    let json = serde_json::to_string_pretty(prefs)
        .map_err(|e| format!("JSON serialize error: {e}"))?;
    std::fs::write(dir.join("preferences.json"), json)
        .map_err(|e| format!("Failed to write preferences: {e}"))
}

// ============================================================================
// Settings
// ============================================================================

fn settings_path() -> PathBuf {
    data_dir().join("settings.json")
}

pub fn load_settings() -> Settings {
    let path = settings_path();
    match std::fs::read_to_string(&path) {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => Settings::default(),
    }
}

pub fn save_settings(settings: &Settings) -> Result<(), String> {
    let dir = ensure_data_dir().map_err(|e| format!("Failed to create data dir: {e}"))?;
    let path = dir.join("settings.json");
    let json = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("JSON serialize error: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("Failed to write settings: {e}"))
}

// ============================================================================
// VCF (VCard v3.0) Export/Import
// ============================================================================

/// Serialize contacts to VCard v3.0 format with custom Noble fields.
/// Matches `VCardFormat.swift`.
pub fn contacts_to_vcf(contacts: &[Contact]) -> String {
    let mut vcf = String::new();
    for c in contacts {
        vcf.push_str("BEGIN:VCARD\r\n");
        vcf.push_str("VERSION:3.0\r\n");
        vcf.push_str(&format!(
            "N:{};{};;;\r\n",
            c.last_name, c.first_name
        ));
        vcf.push_str(&format!(
            "FN:{}\r\n",
            c.display_name()
        ));
        if !c.company.is_empty() {
            vcf.push_str(&format!("ORG:{}\r\n", c.company));
        }
        if !c.email.is_empty() {
            vcf.push_str(&format!("EMAIL:{}\r\n", c.email));
        }
        if !c.noble_pubkey.is_empty() {
            vcf.push_str(&format!("X-NOBLE-PUBKEY:{}\r\n", c.noble_pubkey));
        }
        if !c.bitcoin_key.is_empty() {
            vcf.push_str(&format!("X-NOBLE-BTCKEY:{}\r\n", c.bitcoin_key));
        }
        if !c.notes.is_empty() {
            vcf.push_str(&format!("NOTE:{}\r\n", c.notes));
        }
        vcf.push_str("END:VCARD\r\n");
    }
    vcf
}

/// Parse VCard v3.0 data into contacts.
pub fn vcf_to_contacts(vcf: &str) -> Vec<Contact> {
    let mut contacts = Vec::new();
    let mut current: Option<ContactBuilder> = None;

    for line in vcf.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("BEGIN:VCARD") {
            current = Some(ContactBuilder::default());
        } else if trimmed.eq_ignore_ascii_case("END:VCARD") {
            if let Some(builder) = current.take() {
                contacts.push(builder.build());
            }
        } else if let Some(ref mut builder) = current {
            if let Some((key, value)) = trimmed.split_once(':') {
                match key.to_ascii_uppercase().as_str() {
                    "N" => {
                        let parts: Vec<&str> = value.split(';').collect();
                        builder.last_name = parts.first().unwrap_or(&"").to_string();
                        builder.first_name = parts.get(1).unwrap_or(&"").to_string();
                    }
                    "FN" => builder.display_name = value.to_string(),
                    "ORG" => builder.company = value.to_string(),
                    "EMAIL" => builder.email = value.to_string(),
                    "X-NOBLE-PUBKEY" => builder.noble_pubkey = value.to_string(),
                    "X-NOBLE-BTCKEY" => builder.bitcoin_key = value.to_string(),
                    "NOTE" => builder.notes = value.to_string(),
                    _ => {}
                }
            }
        }
    }

    contacts
}

#[derive(Default)]
struct ContactBuilder {
    first_name: String,
    last_name: String,
    display_name: String,
    company: String,
    email: String,
    noble_pubkey: String,
    bitcoin_key: String,
    notes: String,
}

impl ContactBuilder {
    fn build(self) -> Contact {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        Contact {
            id: uuid::Uuid::new_v4().to_string(),
            first_name: self.first_name,
            last_name: self.last_name,
            company: self.company,
            email: self.email,
            noble_pubkey: self.noble_pubkey,
            bitcoin_key: self.bitcoin_key,
            notes: self.notes,
            is_favorite: false,
            created_at: now,
            updated_at: now,
            is_my_card: false,
            signing_keys: Vec::new(),
        }
    }
}

// ============================================================================
// Bridge Handler: noble_storage
// ============================================================================

/// Contact → bridge-response dict. Matches the Mac client's contactToDict:
/// includes the computed displayName and isMyCard; signingKeys present only
/// when non-empty; certificateDER never crosses to JS.
pub fn contact_to_bridge_json(c: &Contact) -> Value {
    let mut dict = serde_json::json!({
        "id": c.id,
        "firstName": c.first_name,
        "lastName": c.last_name,
        "company": c.company,
        "email": c.email,
        "noblePubkey": c.noble_pubkey,
        "bitcoinKey": c.bitcoin_key,
        "notes": c.notes,
        "isFavorite": c.is_favorite,
        "isMyCard": c.is_my_card,
        "displayName": c.display_name(),
        "createdAt": c.created_at,
        "updatedAt": c.updated_at,
    });
    if !c.signing_keys.is_empty() {
        dict["signingKeys"] = Value::Array(
            c.signing_keys.iter().map(|sk| sk.to_bridge_json()).collect(),
        );
    }
    dict
}

/// Handle `noble_storage` bridge actions.
pub fn handle_storage_action(
    action: &str,
    params: &Value,
    wallet_address: &str,
) -> Result<Value, String> {
    match action {
        "getContacts" => {
            let mut contacts = load_contacts();
            // Sort: favorites first, then alphabetical by display name
            contacts.sort_by(|a, b| {
                b.is_favorite
                    .cmp(&a.is_favorite)
                    .then_with(|| {
                        a.display_name()
                            .to_lowercase()
                            .cmp(&b.display_name().to_lowercase())
                    })
            });

            let contact_dicts: Vec<Value> =
                contacts.iter().map(contact_to_bridge_json).collect();

            Ok(serde_json::json!({ "contacts": contact_dicts }))
        }

        "ensureMyCard" => {
            let mut contacts = load_contacts();
            if contacts.iter().any(|c| c.is_my_card) {
                return Ok(serde_json::json!({ "ok": true, "existed": true }));
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let my_card = Contact {
                id: uuid::Uuid::new_v4().to_string(),
                first_name: "My".to_string(),
                last_name: "Card".to_string(),
                company: String::new(),
                email: String::new(),
                noble_pubkey: wallet_address.to_string(),
                bitcoin_key: String::new(),
                notes: String::new(),
                is_favorite: false,
                created_at: now,
                updated_at: now,
                is_my_card: true,
                signing_keys: Vec::new(),
            };
            let id = my_card.id.clone();
            contacts.insert(0, my_card);
            save_contacts(&contacts)?;
            Ok(serde_json::json!({ "ok": true, "existed": false, "id": id }))
        }

        "saveContact" => {
            let contact_val = params
                .get("contact")
                .ok_or("Missing parameter: contact")?;

            let contact: Contact = serde_json::from_value(contact_val.clone())
                .map_err(|e| format!("Invalid contact: {e}"))?;

            let mut contacts = load_contacts();
            if let Some(idx) = contacts.iter().position(|c| c.id == contact.id) {
                contacts[idx] = contact.clone();
            } else {
                contacts.push(contact.clone());
            }
            save_contacts(&contacts)?;

            Ok(serde_json::json!({ "ok": true, "id": contact.id }))
        }

        "deleteContact" => {
            let id = params
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: id")?;

            let mut contacts = load_contacts();
            // My Card is undeletable (Swift client parity).
            if contacts.iter().any(|c| c.id == id && c.is_my_card) {
                return Err("Cannot delete My Card".to_string());
            }
            contacts.retain(|c| c.id != id);
            save_contacts(&contacts)?;

            Ok(serde_json::json!({ "ok": true }))
        }

        "exportContactsVCF" => {
            let contacts = load_contacts();
            let ids: Option<Vec<&str>> = params
                .get("ids")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect());

            let selected: Vec<&Contact> = if let Some(ids) = ids {
                contacts.iter().filter(|c| ids.contains(&c.id.as_str())).collect()
            } else {
                contacts.iter().collect()
            };

            let vcf = contacts_to_vcf(&selected.into_iter().cloned().collect::<Vec<_>>());
            Ok(serde_json::json!({ "vcf": vcf }))
        }

        "importContactsVCF" => {
            let vcf_string = params
                .get("vcf")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: vcf")?;

            let parsed = vcf_to_contacts(vcf_string);
            let contact_dicts: Vec<Value> =
                parsed.iter().map(contact_to_bridge_json).collect();

            Ok(serde_json::json!({
                "contacts": contact_dicts,
                "count": parsed.len(),
            }))
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}
