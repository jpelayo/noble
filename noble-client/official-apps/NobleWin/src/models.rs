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
