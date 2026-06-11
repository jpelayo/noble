// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Shared types for the NobleWin client application.

use serde::{Deserialize, Serialize};

/// Contact entry matching the Apple clients' Contact model.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Contact {
    pub id: String,
    pub first_name: String,
    pub last_name: String,
    pub company: String,
    pub email: String,
    pub noble_pubkey: String,
    pub bitcoin_key: String,
    pub notes: String,
    pub is_favorite: bool,
    pub created_at: f64,
    pub updated_at: f64,
    /// Whether this contact represents the user's own identity ("My Card").
    /// Only one contact should have this flag set. My Card is undeletable.
    #[serde(default)]
    pub is_my_card: bool,
    /// Signing keys for CMS per-field metadata signatures.
    #[serde(default)]
    pub signing_keys: Vec<SigningKeyEntry>,
}

/// A signing key entry stored on a contact card.
///
/// Private keys live in the system keyring (referenced by `id`), NOT in
/// this struct. `certificate_der` holds the full X.509 certificate for
/// CMS signature verification — persisted to contacts.json but stripped
/// from bridge responses (too large for JS; matches the Mac client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningKeyEntry {
    pub id: String,
    /// Human-readable label (e.g. "Noble Key", "Work Certificate").
    pub label: String,
    /// Key algorithm: "p256" (corporate PKI) or "secp256k1" (Noble native).
    pub algorithm: String,
    /// Compressed public key hex (33 bytes SEC1).
    pub public_key_hex: String,
    /// Whether the private key exists in the system keyring.
    pub has_private_key: bool,
    /// Certificate subject CN. None if no certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_subject: Option<String>,
    /// Base64-encoded DER X.509 certificate (verification + signer display).
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "certificateDER")]
    pub certificate_der: Option<String>,
    /// SubjectKeyIdentifier hex (20 bytes, SHA-1 of public key). Links
    /// on-chain CMS SignerInfo.sid to this certificate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key_identifier: Option<String>,
    pub imported_at: f64,
}

impl SigningKeyEntry {
    /// Bridge-response dict: everything except `certificate_der`
    /// (intentionally omitted from JS — too large; Swift parity).
    pub fn to_bridge_json(&self) -> serde_json::Value {
        let mut d = serde_json::json!({
            "id": self.id,
            "label": self.label,
            "algorithm": self.algorithm,
            "publicKeyHex": self.public_key_hex,
            "hasPrivateKey": self.has_private_key,
            "importedAt": self.imported_at,
        });
        if let Some(subj) = &self.certificate_subject {
            d["certificateSubject"] = serde_json::json!(subj);
        }
        if let Some(ski) = &self.subject_key_identifier {
            d["subjectKeyIdentifier"] = serde_json::json!(ski);
        }
        d
    }
}

impl Contact {
    pub fn display_name(&self) -> String {
        let full = format!("{} {}", self.first_name, self.last_name);
        let trimmed = full.trim();
        if trimmed.is_empty() {
            if !self.company.is_empty() {
                self.company.clone()
            } else {
                "Unknown".to_string()
            }
        } else {
            trimmed.to_string()
        }
    }
}

/// Application settings persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settings {
    #[serde(default = "default_node_url")]
    pub node_url: String,
    #[serde(default = "default_true")]
    pub auto_connect: bool,
    #[serde(default)]
    pub app_lock_enabled: bool,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u32,
    #[serde(default = "default_true")]
    pub re_auth_for_sends: bool,
    #[serde(default)]
    pub onboarding_complete: bool,
    #[serde(default)]
    pub rpc_api_enabled: Option<bool>,
    #[serde(default)]
    pub rpc_api_port: Option<u16>,
    #[serde(default)]
    pub mcp_server_enabled: Option<bool>,
    #[serde(default)]
    pub mcp_server_port: Option<u16>,
}

fn default_node_url() -> String {
    "https://node.infinitecontext.com:8783".to_string()
}

fn default_true() -> bool {
    true
}

fn default_lock_timeout() -> u32 {
    300
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            node_url: default_node_url(),
            auto_connect: true,
            app_lock_enabled: false,
            lock_timeout: 300,
            re_auth_for_sends: true,
            onboarding_complete: false,
            rpc_api_enabled: None,
            rpc_api_port: None,
            mcp_server_enabled: None,
            mcp_server_port: None,
        }
    }
}

/// Full application state snapshot sent to WebUI via getState.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateSnapshot {
    pub is_connected: bool,
    pub has_wallet: bool,
    pub wallet_address: String,
    pub chain_id: String,
    pub block_height: u64,
    pub selected_section: String,
}

/// NOBLE protocol constants matching TransactionBuilder.swift.
pub struct NobleProtocol;

impl NobleProtocol {
    pub const PROTOCOL_VERSION: u16 = 1;
    pub const TX_TYPE_NOTARIZATION: u8 = 0x00;
    pub const TX_TYPE_TRANSFER: u8 = 0x01;
    pub const PRIMARY_CHAIN_ID: u32 = 0x4E4F_424C; // "NOBL"
    pub const SCHEME_SECP256K1: u8 = 0x02;
    pub const MAX_METADATA_ENTRIES: usize = 16;
}

/// A UTXO outpoint reference for transaction building.
#[derive(Debug, Clone)]
pub struct UtxoOutpoint {
    pub txid: Vec<u8>, // 32 bytes
    pub vout: u32,
    pub value: u64,
}

/// A transaction output specification.
#[derive(Debug, Clone)]
pub struct TxOutputSpec {
    pub value: u64,
    pub address_wire: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pre-0.2.0 contacts.json entries (no isMyCard/signingKeys keys)
    /// must deserialize with defaults — upgrade must not lose contacts.
    #[test]
    fn legacy_contact_deserializes_with_defaults() {
        let legacy = r#"{
            "id":"abc","firstName":"Jane","lastName":"Doe","company":"",
            "email":"","noblePubkey":"02aa","bitcoinKey":"","notes":"",
            "isFavorite":false,"createdAt":1700000000.0,"updatedAt":1700000000.0
        }"#;
        let c: Contact = serde_json::from_str(legacy).expect("legacy contact must parse");
        assert!(!c.is_my_card);
        assert!(c.signing_keys.is_empty());
    }

    /// New-format entries round-trip, and certificate_der serializes
    /// under the exact key the Swift clients use ("certificateDER").
    #[test]
    fn signing_key_entry_round_trip_and_der_key() {
        let entry = SigningKeyEntry {
            id: "k1".into(),
            label: "Noble Key".into(),
            algorithm: "secp256k1".into(),
            public_key_hex: "02ab".into(),
            has_private_key: true,
            certificate_subject: None,
            certificate_der: Some("AAAA".into()),
            subject_key_identifier: Some("deadbeef".into()),
            imported_at: 1700000000.0,
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["certificateDER"], "AAAA");
        let back: SigningKeyEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.certificate_der.as_deref(), Some("AAAA"));
        // Bridge dict must NOT leak the certificate to JS.
        let bridge = entry.to_bridge_json();
        assert!(bridge.get("certificateDER").is_none());
        assert_eq!(bridge["subjectKeyIdentifier"], "deadbeef");
    }
}
