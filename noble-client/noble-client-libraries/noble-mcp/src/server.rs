// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! HTTP server for the embedded RPC and MCP endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tower_http::cors::CorsLayer;

/// Callback type: host app provides this to handle JSON-RPC requests.
/// Receives a JSON string, returns a JSON string.
pub type HandlerCallback = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// Shared state for the axum server.
#[derive(Clone)]
pub struct ServerState {
    pub handler: HandlerCallback,
    pub mode: ServerMode,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ServerMode {
    /// Plain JSON-RPC: method name maps directly to bridge action.
    Rpc,
    /// MCP protocol: handles initialize, tools/list, tools/call, resources, prompts.
    Mcp,
}

// ── JSON-RPC types ──

#[derive(Deserialize)]
#[allow(dead_code)]
struct JsonRpcRequest {
    jsonrpc: Option<String>,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl JsonRpcResponse {
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self { jsonrpc: "2.0", id, result: Some(result), error: None }
    }
    fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self { jsonrpc: "2.0", id, result: None, error: Some(JsonRpcError { code, message }) }
    }
}

// ── MCP protocol types ──

#[derive(Serialize)]
struct McpInitializeResult {
    #[serde(rename = "protocolVersion")]
    protocol_version: &'static str,
    capabilities: McpCapabilities,
    #[serde(rename = "serverInfo")]
    server_info: McpServerInfo,
    instructions: &'static str,
}

#[derive(Serialize)]
struct McpCapabilities {
    tools: McpToolsCapability,
    resources: McpResourcesCapability,
    prompts: McpPromptsCapability,
}

#[derive(Serialize)]
struct McpToolsCapability {
    #[serde(rename = "listChanged")]
    list_changed: bool,
}

#[derive(Serialize)]
struct McpResourcesCapability {
    subscribe: bool,
    #[serde(rename = "listChanged")]
    list_changed: bool,
}

#[derive(Serialize)]
struct McpPromptsCapability {
    #[serde(rename = "listChanged")]
    list_changed: bool,
}

#[derive(Serialize)]
struct McpServerInfo {
    name: &'static str,
    version: &'static str,
}

// ── Tool registry ──

/// Static tool definitions for all 57 bridge actions.
/// Each tool has name, description, inputSchema (JSON Schema), and annotations.
fn build_tool_list() -> serde_json::Value {
    serde_json::json!({
        "tools": TOOL_DEFINITIONS.iter().map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
                "annotations": t.annotations,
            })
        }).collect::<Vec<_>>()
    })
}

struct ToolDef {
    name: &'static str,
    handler: &'static str,
    action: &'static str,
    description: &'static str,
    input_schema: serde_json::Value,
    annotations: serde_json::Value,
}

// The full tool registry — 57 tools across 5 domains.
// Lazy-initialized on first tools/list call.
static TOOL_DEFINITIONS: std::sync::LazyLock<Vec<ToolDef>> = std::sync::LazyLock::new(|| {
    let ro = serde_json::json!({"readOnlyHint": true, "idempotentHint": true});
    let rw = serde_json::json!({"destructiveHint": true});
    let safe = serde_json::json!({"readOnlyHint": true});
    let obj = |props: serde_json::Value, req: &[&str]| -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": props, "required": req})
    };
    let s = || serde_json::json!({"type": "string"});
    let n = || serde_json::json!({"type": "number"});
    let b = || serde_json::json!({"type": "boolean"});
    let arr = |item: serde_json::Value| serde_json::json!({"type": "array", "items": item});
    let empty = serde_json::json!({"type": "object"});

    vec![
        // ── noble_api (23 tools) ──
        ToolDef { name: "getBalance", handler: "noble_api", action: "getBalance",
            description: "Get balance of a Noble address (available, pending, maturing).",
            input_schema: obj(serde_json::json!({"address": s()}), &["address"]),
            annotations: ro.clone() },
        ToolDef { name: "getSyncStatus", handler: "noble_api", action: "getSyncStatus",
            description: "Get node sync status (height, progress).",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getCycleStatus", handler: "noble_api", action: "getCycleStatus",
            description: "Get current consensus cycle status.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getWalletSnapshot", handler: "noble_api", action: "getWalletSnapshot",
            description: "Atomic wallet snapshot: balance + transactions under one chain height.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getWalletTransactions", handler: "noble_api", action: "getWalletTransactions",
            description: "Get wallet transaction history.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "estimateFee", handler: "noble_api", action: "estimateFee",
            description: "Estimate transaction fee rates.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "verifyDocument", handler: "noble_api", action: "verifyDocument",
            description: "Verify a document checksum is registered on-chain.",
            input_schema: obj(serde_json::json!({"checksum": s()}), &["checksum"]),
            annotations: ro.clone() },
        ToolDef { name: "getDocumentVersions", handler: "noble_api", action: "getDocumentVersions",
            description: "Get all versions of a registered document.",
            input_schema: obj(serde_json::json!({"checksum": s()}), &["checksum"]),
            annotations: ro.clone() },
        ToolDef { name: "submitTransaction", handler: "noble_api", action: "submitTransaction",
            description: "Submit a signed transaction to the network mempool.",
            input_schema: obj(serde_json::json!({"txHex": s()}), &["txHex"]),
            annotations: rw.clone() },
        ToolDef { name: "getNodeInfo", handler: "noble_api", action: "getNodeInfo",
            description: "Get connected node info (version, chain ID, height).",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getBlockCount", handler: "noble_api", action: "getBlockCount",
            description: "Get current block height.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getNetworkInfo", handler: "noble_api", action: "getNetworkInfo",
            description: "Get network info (peers, clock drift).",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getPeers", handler: "noble_api", action: "getPeers",
            description: "Get connected peer list.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getTransaction", handler: "noble_api", action: "getTransaction",
            description: "Get full transaction details by ID.",
            input_schema: obj(serde_json::json!({"txId": s()}), &["txId"]),
            annotations: ro.clone() },
        ToolDef { name: "getTransactionStatus", handler: "noble_api", action: "getTransactionStatus",
            description: "Get transaction status (pending/confirmed/unknown).",
            input_schema: obj(serde_json::json!({"txId": s()}), &["txId"]),
            annotations: ro.clone() },
        ToolDef { name: "lookupChecksum", handler: "noble_api", action: "lookupChecksum",
            description: "Look up a document checksum on-chain.",
            input_schema: obj(serde_json::json!({"checksum": s()}), &["checksum"]),
            annotations: ro.clone() },
        ToolDef { name: "validateAddress", handler: "noble_api", action: "validateAddress",
            description: "Validate a Noble address format.",
            input_schema: obj(serde_json::json!({"address": s()}), &["address"]),
            annotations: ro.clone() },
        ToolDef { name: "getAddressUtxos", handler: "noble_api", action: "getAddressUtxos",
            description: "Get UTXOs for an address with lifecycle status.",
            input_schema: obj(serde_json::json!({"address": s()}), &["address"]),
            annotations: ro.clone() },
        ToolDef { name: "faucetStatus", handler: "noble_api", action: "faucetStatus",
            description: "Get faucet availability and balance.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "faucetRequest", handler: "noble_api", action: "faucetRequest",
            description: "Request coins from the faucet.",
            input_schema: obj(serde_json::json!({"address": s()}), &["address"]),
            annotations: rw.clone() },
        ToolDef { name: "getAvailableFaucets", handler: "noble_api", action: "getAvailableFaucets",
            description: "List faucets discovered on the network.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "faucetHopRequest", handler: "noble_api", action: "faucetHopRequest",
            description: "Request coins from a peer faucet.",
            input_schema: obj(serde_json::json!({"url": s(), "address": s()}), &["url", "address"]),
            annotations: rw.clone() },

        // ── noble_crypto (5 tools) ──
        ToolDef { name: "signNotarization", handler: "noble_crypto", action: "signNotarization",
            description: "Sign a document notarization transaction.",
            input_schema: obj(serde_json::json!({"checksum": s(), "fee": n(), "fee_rate": n(), "metadata": arr(serde_json::json!({"type":"object"})), "utxos": arr(serde_json::json!({"type":"object"}))}), &["checksum", "fee", "utxos"]),
            annotations: rw.clone() },
        ToolDef { name: "signTransfer", handler: "noble_crypto", action: "signTransfer",
            description: "Sign a transfer transaction.",
            input_schema: obj(serde_json::json!({"recipient": s(), "amount": n(), "fee_rate": n(), "utxos": arr(serde_json::json!({"type":"object"}))}), &["recipient", "amount", "utxos"]),
            annotations: rw.clone() },
        ToolDef { name: "estimateTxSize", handler: "noble_crypto", action: "estimateTxSize",
            description: "Estimate transaction wire size.",
            input_schema: obj(serde_json::json!({"tx_type": s()}), &["tx_type"]),
            annotations: ro.clone() },
        ToolDef { name: "validateMetadata", handler: "noble_mcp", action: "validateMetadata",
            description: "Validate metadata fields before building a transaction. Checks slot budget (max 16), field pairing (doc:bridge+doc:relation), forced encryption (contact:email/phone), mode requirements, key/value size limits, and version chain rules.",
            input_schema: obj(serde_json::json!({
                "metadata": arr(serde_json::json!({"type": "object", "properties": {
                    "key": s(), "value": s(), "mode": s(),
                    "recipient": s(), "fieldPassword": s(), "signed": b()
                }})),
                "tx_type": s(),
                "batch": b()
            }), &["metadata"]),
            annotations: safe.clone() },
        ToolDef { name: "encryptField", handler: "noble_crypto", action: "encryptField",
            description: "Encrypt a metadata field value. For mode 'protected': AES-256-GCM with password. For mode 'encrypted': ECIES with recipient public key. Returns hex-encoded ciphertext to use as the field value in signNotarization.",
            input_schema: obj(serde_json::json!({
                "value": s(), "mode": s(),
                "password": s(), "recipient_pubkey": s()
            }), &["value", "mode"]),
            annotations: safe.clone() },
        ToolDef { name: "decryptField", handler: "noble_crypto", action: "decryptField",
            description: "Decrypt a metadata field value. For mode 'protected': AES-256-GCM with password. For mode 'encrypted': ECIES with user's private key (loaded from keystore).",
            input_schema: obj(serde_json::json!({
                "encrypted_hex": s(), "mode": s(),
                "password": s()
            }), &["encrypted_hex", "mode"]),
            annotations: safe.clone() },
        ToolDef { name: "signMetadataField", handler: "noble_crypto", action: "signMetadataField",
            description: "Create CMS detached signature for a metadata field.",
            input_schema: obj(serde_json::json!({"keyId": s(), "fieldValue": s()}), &["keyId", "fieldValue"]),
            annotations: safe.clone() },
        ToolDef { name: "verifyMetadataField", handler: "noble_crypto", action: "verifyMetadataField",
            description: "Verify a CMS signature on a metadata field.",
            input_schema: obj(serde_json::json!({"signatureHex": s(), "fieldValue": s()}), &["signatureHex", "fieldValue"]),
            annotations: ro.clone() },

        // ── noble_security (6 tools) ──
        ToolDef { name: "hashFile", handler: "noble_security", action: "hashFile",
            description: "Compute SHA-256 hash of a file.",
            input_schema: obj(serde_json::json!({"filePath": s()}), &["filePath"]),
            annotations: ro.clone() },
        ToolDef { name: "loadPrivateKey", handler: "noble_security", action: "loadPrivateKey",
            description: "Load a private key from the keychain.",
            input_schema: obj(serde_json::json!({"keyId": s()}), &["keyId"]),
            annotations: safe.clone() },
        ToolDef { name: "getMyCard", handler: "noble_security", action: "getMyCard",
            description: "Get the user's identity card with signing keys.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "importPKCS12", handler: "noble_security", action: "importPKCS12",
            description: "Import a PKCS#12 certificate container.",
            input_schema: obj(serde_json::json!({"filePath": s(), "password": s()}), &["filePath"]),
            annotations: rw.clone() },
        ToolDef { name: "generateSigningKey", handler: "noble_security", action: "generateSigningKey",
            description: "Generate a new signing key pair.",
            input_schema: obj(serde_json::json!({"label": s()}), &[]),
            annotations: rw.clone() },
        ToolDef { name: "removeSigningKey", handler: "noble_security", action: "removeSigningKey",
            description: "Remove a signing key from the keychain.",
            input_schema: obj(serde_json::json!({"keyId": s()}), &["keyId"]),
            annotations: rw.clone() },

        // ── noble_app (19 tools) ──
        ToolDef { name: "getState", handler: "noble_app", action: "getState",
            description: "Get current application state.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "getSettings", handler: "noble_app", action: "getSettings",
            description: "Get application settings.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "saveSettings", handler: "noble_app", action: "saveSettings",
            description: "Save application settings.",
            input_schema: obj(serde_json::json!({"settings": serde_json::json!({"type":"object"})}), &["settings"]),
            annotations: rw.clone() },
        ToolDef { name: "getSecuritySettings", handler: "noble_app", action: "getSecuritySettings",
            description: "Get security preferences.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "saveSecuritySettings", handler: "noble_app", action: "saveSecuritySettings",
            description: "Save security preferences.",
            input_schema: obj(serde_json::json!({"settings": serde_json::json!({"type":"object"})}), &["settings"]),
            annotations: rw.clone() },
        ToolDef { name: "testConnection", handler: "noble_app", action: "testConnection",
            description: "Test connection to a Noble node.",
            input_schema: obj(serde_json::json!({"url": s()}), &["url"]),
            annotations: ro.clone() },
        ToolDef { name: "connectToNode", handler: "noble_app", action: "connectToNode",
            description: "Connect to a Noble node.",
            input_schema: obj(serde_json::json!({"url": s()}), &["url"]),
            annotations: rw.clone() },
        ToolDef { name: "disconnectNode", handler: "noble_app", action: "disconnectNode",
            description: "Disconnect from the current node.",
            input_schema: empty.clone(), annotations: rw.clone() },
        ToolDef { name: "getDrafts", handler: "noble_app", action: "getDrafts",
            description: "Get saved document registration drafts.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "saveDraft", handler: "noble_app", action: "saveDraft",
            description: "Save a document registration draft.",
            input_schema: obj(serde_json::json!({"draft": serde_json::json!({"type":"object"})}), &["draft"]),
            annotations: rw.clone() },
        ToolDef { name: "deleteDraft", handler: "noble_app", action: "deleteDraft",
            description: "Delete a saved draft.",
            input_schema: obj(serde_json::json!({"id": s()}), &["id"]),
            annotations: rw.clone() },
        ToolDef { name: "copyToClipboard", handler: "noble_app", action: "copyToClipboard",
            description: "Copy text to the system clipboard.",
            input_schema: obj(serde_json::json!({"text": s()}), &["text"]),
            annotations: safe.clone() },
        ToolDef { name: "openFileDialog", handler: "noble_app", action: "openFileDialog",
            description: "Open a native file picker dialog.",
            input_schema: obj(serde_json::json!({"multiple": b()}), &[]),
            annotations: safe.clone() },
        ToolDef { name: "saveFileDialog", handler: "noble_app", action: "saveFileDialog",
            description: "Open a native save-file dialog.",
            input_schema: obj(serde_json::json!({"suggestedName": s(), "data": s()}), &["data"]),
            annotations: safe.clone() },
        ToolDef { name: "readFileText", handler: "noble_app", action: "readFileText",
            description: "Read text content of a file.",
            input_schema: obj(serde_json::json!({"filePath": s()}), &["filePath"]),
            annotations: ro.clone() },
        ToolDef { name: "navigateTo", handler: "noble_app", action: "navigateTo",
            description: "Navigate to a page in the app.",
            input_schema: obj(serde_json::json!({"page": s()}), &["page"]),
            annotations: safe.clone() },
        ToolDef { name: "share", handler: "noble_app", action: "share",
            description: "Open the system share sheet.",
            input_schema: obj(serde_json::json!({"text": s()}), &["text"]),
            annotations: safe.clone() },
        ToolDef { name: "shareText", handler: "noble_app", action: "shareText",
            description: "Share text via the system share sheet.",
            input_schema: obj(serde_json::json!({"text": s()}), &["text"]),
            annotations: safe.clone() },

        // ── noble_storage (6 tools) ──
        ToolDef { name: "getContacts", handler: "noble_storage", action: "getContacts",
            description: "Get address book contacts.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "saveContact", handler: "noble_storage", action: "saveContact",
            description: "Save or update a contact.",
            input_schema: obj(serde_json::json!({"contact": serde_json::json!({"type":"object"})}), &["contact"]),
            annotations: rw.clone() },
        ToolDef { name: "deleteContact", handler: "noble_storage", action: "deleteContact",
            description: "Delete a contact.",
            input_schema: obj(serde_json::json!({"id": s()}), &["id"]),
            annotations: rw.clone() },
        ToolDef { name: "ensureMyCard", handler: "noble_storage", action: "ensureMyCard",
            description: "Ensure the user's identity card exists.",
            input_schema: empty.clone(), annotations: safe.clone() },
        ToolDef { name: "exportContactsVCF", handler: "noble_storage", action: "exportContactsVCF",
            description: "Export contacts as VCF/vCard.",
            input_schema: empty.clone(), annotations: ro.clone() },
        ToolDef { name: "importContactsVCF", handler: "noble_storage", action: "importContactsVCF",
            description: "Import contacts from VCF/vCard.",
            input_schema: obj(serde_json::json!({"vcf": s()}), &["vcf"]),
            annotations: rw.clone() },
    ]
});

// ── MCP resource definitions ──

fn build_resource_list() -> serde_json::Value {
    serde_json::json!({
        "resources": [
            { "uri": "noble://wallet/balance", "name": "Wallet Balance", "description": "Current balance, available, pending, maturing", "mimeType": "application/json" },
            { "uri": "noble://wallet/transactions", "name": "Transaction History", "description": "Recent wallet transactions with direction and status", "mimeType": "application/json" },
            { "uri": "noble://wallet/utxos", "name": "Spendable UTXOs", "description": "Available UTXOs for coin selection", "mimeType": "application/json" },
            { "uri": "noble://contacts", "name": "Contacts", "description": "Address book entries", "mimeType": "application/json" },
            { "uri": "noble://drafts", "name": "Saved Drafts", "description": "Document registration drafts", "mimeType": "application/json" },
            { "uri": "noble://settings", "name": "App Settings", "description": "Current connection and configuration", "mimeType": "application/json" },
            { "uri": "noble://node/info", "name": "Node Info", "description": "Connected node version, chain ID, block height", "mimeType": "application/json" },
            { "uri": "noble://node/sync", "name": "Sync Status", "description": "Current sync progress", "mimeType": "application/json" },
            { "uri": "noble://node/peers", "name": "Network Peers", "description": "Connected peer list", "mimeType": "application/json" },
        ]
    })
}

// ── MCP prompt definitions ──

fn build_prompt_list() -> serde_json::Value {
    serde_json::json!({
        "prompts": [
            {
                "name": "register-document",
                "description": "Step-by-step document registration on the Noble blockchain",
                "arguments": [
                    { "name": "filePath", "description": "Path to the file to register", "required": true },
                    { "name": "metadata", "description": "Optional metadata key-value pairs", "required": false },
                ]
            },
            {
                "name": "register-document-batch",
                "description": "Register multiple documents as a linked batch on the Noble blockchain",
                "arguments": [
                    { "name": "filePaths", "description": "Comma-separated file paths to register", "required": true },
                    { "name": "batchName", "description": "Human-readable batch name", "required": false },
                ]
            },
            {
                "name": "send-payment",
                "description": "Guided Noble coin transfer",
                "arguments": [
                    { "name": "recipient", "description": "Recipient Noble address (nbl1...)", "required": true },
                    { "name": "amount", "description": "Amount in NOBLE", "required": true },
                ]
            },
            {
                "name": "verify-document",
                "description": "Check if a document is registered on-chain",
                "arguments": [
                    { "name": "checksum", "description": "SHA-256 checksum hex (64 chars)", "required": true },
                ]
            },
        ]
    })
}

// ── Handler mapping ──

/// Map a tool name to its bridge handler + action.
fn resolve_tool(name: &str) -> Option<(&'static str, &'static str)> {
    TOOL_DEFINITIONS.iter()
        .find(|t| t.name == name)
        .map(|t| (t.handler, t.action))
}

/// Map a resource URI to the bridge call that fetches it.
fn resolve_resource(uri: &str) -> Option<(&'static str, &'static str, serde_json::Value)> {
    match uri {
        "noble://wallet/balance" => Some(("noble_api", "getBalance", serde_json::json!({}))),
        "noble://wallet/transactions" => Some(("noble_api", "getWalletTransactions", serde_json::json!({}))),
        "noble://wallet/utxos" => Some(("noble_api", "getAddressUtxos", serde_json::json!({}))),
        "noble://contacts" => Some(("noble_storage", "getContacts", serde_json::json!({}))),
        "noble://drafts" => Some(("noble_app", "getDrafts", serde_json::json!({}))),
        "noble://settings" => Some(("noble_app", "getSettings", serde_json::json!({}))),
        "noble://node/info" => Some(("noble_api", "getNodeInfo", serde_json::json!({}))),
        "noble://node/sync" => Some(("noble_api", "getSyncStatus", serde_json::json!({}))),
        "noble://node/peers" => Some(("noble_api", "getPeers", serde_json::json!({}))),
        _ => None,
    }
}

// ── Server-side tool implementations ──

/// Validate metadata fields according to Noble protocol rules.
/// Returns { valid: true } or { valid: false, errors: [...] }.
fn validate_metadata_tool(
    arguments: Option<&serde_json::Value>,
) -> Result<serde_json::Value, (i32, String)> {
    let args = arguments.ok_or((-32602, "Missing arguments".to_string()))?;
    let entries = args.get("metadata").and_then(|v| v.as_array())
        .ok_or((-32602, "Missing metadata array".to_string()))?;

    let mut errors: Vec<String> = Vec::new();

    // Count slots: 1 schema + fields + signatures (signed fields = 2 slots)
    let mut slot_count = 1usize; // schema descriptor always occupies slot 0
    for entry in entries {
        slot_count += 1;
        if entry.get("signed").and_then(|v| v.as_bool()).unwrap_or(false) {
            slot_count += 1; // CMS signature consumes an additional slot
        }
    }
    if slot_count > 16 {
        errors.push(format!("Exceeds 16 slot limit ({slot_count} slots: 1 schema + {} fields/sigs)", slot_count - 1));
    }

    let mut has_bridge = false;
    let mut has_relation = false;
    let mut seen_keys: Vec<String> = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        let key = entry.get("key").and_then(|v| v.as_str()).unwrap_or("");
        let value = entry.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let mode = entry.get("mode").and_then(|v| v.as_str()).unwrap_or("plaintext");

        // Key/value size limits
        if key.is_empty() || key.len() > 64 {
            errors.push(format!("[{i}] Key must be 1-64 bytes, got {}", key.len()));
        }
        if value.is_empty() || value.len() > 256 {
            errors.push(format!("[{i}] Value must be 1-256 bytes, got {}", value.len()));
        }

        // Duplicate key check (encrypted fields with same key are allowed — auto-duplicated)
        if mode != "encrypted" && seen_keys.contains(&key.to_string()) {
            errors.push(format!("[{i}] Duplicate key '{key}' (only encrypted fields may share keys)"));
        }
        seen_keys.push(key.to_string());

        // Force-encrypt contact fields
        if (key == "contact:email" || key == "contact:phone") && mode != "encrypted" {
            errors.push(format!("[{i}] '{key}' must be mode 'encrypted' (forced encryption)"));
        }

        // doc:batch must be plaintext
        if key == "doc:batch" && mode != "plaintext" {
            errors.push(format!("[{i}] 'doc:batch' must be mode 'plaintext' (batch coordination)"));
        }

        // Protected requires password
        if mode == "protected" {
            let pw = entry.get("fieldPassword").and_then(|v| v.as_str()).unwrap_or("");
            if pw.is_empty() {
                errors.push(format!("[{i}] '{key}' mode 'protected' requires non-empty fieldPassword"));
            }
        }

        // Encrypted requires recipient
        if mode == "encrypted" {
            let recipient = entry.get("recipient").and_then(|v| v.as_str()).unwrap_or("");
            if recipient.is_empty() {
                errors.push(format!("[{i}] '{key}' mode 'encrypted' requires non-empty recipient pubkey"));
            } else if recipient.len() != 66 {
                errors.push(format!("[{i}] '{key}' recipient must be 33-byte hex (66 chars), got {}", recipient.len()));
            }
            // Check plaintext fits after ECIES encryption (121 overhead + plaintext ≤ 256)
            if value.len() > 134 {
                errors.push(format!("[{i}] '{key}' value too long for ECIES ({} bytes, max 134)", value.len()));
            }
        }

        // Track pairing
        if key == "doc:bridge" { has_bridge = true; }
        if key == "doc:relation" { has_relation = true; }

        // Version chain rules
        if key == "doc:version" {
            if value.parse::<u32>().is_err() || value == "0" {
                errors.push(format!("[{i}] 'doc:version' must be positive integer, got '{value}'"));
            }
        }
        if key == "doc:prev_checksum" {
            if value.len() != 64 || !value.chars().all(|c| c.is_ascii_hexdigit()) {
                errors.push(format!("[{i}] 'doc:prev_checksum' must be 64 hex chars"));
            }
            // Check doc:version exists and > 1
            let version_entry = entries.iter().find(|e| {
                e.get("key").and_then(|v| v.as_str()) == Some("doc:version")
            });
            match version_entry {
                None => errors.push(format!("[{i}] 'doc:prev_checksum' requires 'doc:version' field")),
                Some(ve) => {
                    let ver = ve.get("value").and_then(|v| v.as_str()).unwrap_or("0");
                    if ver.parse::<u32>().unwrap_or(0) <= 1 {
                        errors.push(format!("[{i}] 'doc:prev_checksum' requires doc:version > 1"));
                    }
                }
            }
        }
    }

    // Pairing check
    if has_bridge && !has_relation {
        errors.push("'doc:bridge' requires 'doc:relation' (fields must be paired)".to_string());
    }
    if has_relation && !has_bridge {
        errors.push("'doc:relation' requires 'doc:bridge' (fields must be paired)".to_string());
    }

    if errors.is_empty() {
        Ok(serde_json::json!({ "valid": true }))
    } else {
        Ok(serde_json::json!({ "valid": false, "errors": errors }))
    }
}

// ── Request handling ──

/// Handle an incoming HTTP POST (both RPC and MCP modes).
async fn handle_post(
    State(state): State<ServerState>,
    body: String,
) -> impl IntoResponse {
    let req: JsonRpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = JsonRpcResponse::error(
                serde_json::Value::Null, -32700,
                format!("Parse error: {e}"),
            );
            return (StatusCode::OK, Json(resp));
        }
    };

    let id = req.id.clone().unwrap_or(serde_json::Value::Null);

    let result = match state.mode {
        ServerMode::Rpc => handle_rpc_request(&state, &req).await,
        ServerMode::Mcp => handle_mcp_request(&state, &req).await,
    };

    match result {
        Ok(val) => (StatusCode::OK, Json(JsonRpcResponse::success(id, val))),
        Err((code, msg)) => (StatusCode::OK, Json(JsonRpcResponse::error(id, code, msg))),
    }
}

/// Plain RPC: method = "noble.{action}" → route to bridge handler.
async fn handle_rpc_request(
    state: &ServerState,
    req: &JsonRpcRequest,
) -> Result<serde_json::Value, (i32, String)> {
    // Strip "noble." prefix if present
    let action = req.method.strip_prefix("noble.").unwrap_or(&req.method);

    let (handler, bridge_action) = resolve_tool(action)
        .ok_or((-32601, format!("Method not found: {}", req.method)))?;

    call_bridge(state, handler, bridge_action, &req.params)
}

/// MCP: handles protocol methods (initialize, tools/list, tools/call, resources, prompts, ping).
async fn handle_mcp_request(
    state: &ServerState,
    req: &JsonRpcRequest,
) -> Result<serde_json::Value, (i32, String)> {
    match req.method.as_str() {
        "initialize" => Ok(serde_json::to_value(McpInitializeResult {
            protocol_version: "2025-03-26",
            capabilities: McpCapabilities {
                tools: McpToolsCapability { list_changed: false },
                resources: McpResourcesCapability { subscribe: false, list_changed: false },
                prompts: McpPromptsCapability { list_changed: false },
            },
            server_info: McpServerInfo { name: "Noble Client", version: "0.99.0" },
            instructions: "Noble blockchain client. Use tools to manage wallet, register documents, send payments, and query the blockchain.",
        }).unwrap()),

        "notifications/initialized" => Ok(serde_json::json!({})),

        "ping" => Ok(serde_json::json!({})),

        "tools/list" => Ok(build_tool_list()),

        "tools/call" => {
            let params = req.params.as_ref()
                .ok_or((-32602, "Missing params".to_string()))?;
            let name = params.get("name").and_then(|v| v.as_str())
                .ok_or((-32602, "Missing tool name".to_string()))?;
            let arguments = params.get("arguments");

            // Server-side tools (no bridge callback needed)
            if name == "validateMetadata" {
                let result = validate_metadata_tool(arguments)?;
                return Ok(serde_json::json!({
                    "content": [{ "type": "text", "text": serde_json::to_string(&result).unwrap_or_default() }],
                    "isError": false,
                }));
            }

            let (handler, action) = resolve_tool(name)
                .ok_or((-32601, format!("Unknown tool: {name}")))?;

            let result = call_bridge(state, handler, action, &arguments.cloned())?;

            Ok(serde_json::json!({
                "content": [{ "type": "text", "text": serde_json::to_string(&result).unwrap_or_default() }],
                "isError": false,
            }))
        }

        "resources/list" => Ok(build_resource_list()),

        "resources/read" => {
            let params = req.params.as_ref()
                .ok_or((-32602, "Missing params".to_string()))?;
            let uri = params.get("uri").and_then(|v| v.as_str())
                .ok_or((-32602, "Missing resource uri".to_string()))?;

            let (handler, action, default_params) = resolve_resource(uri)
                .ok_or((-32002, format!("Resource not found: {uri}")))?;

            let result = call_bridge(state, handler, action, &Some(default_params))?;

            Ok(serde_json::json!({
                "contents": [{ "uri": uri, "mimeType": "application/json", "text": serde_json::to_string(&result).unwrap_or_default() }]
            }))
        }

        "prompts/list" => Ok(build_prompt_list()),

        "prompts/get" => {
            let params = req.params.as_ref()
                .ok_or((-32602, "Missing params".to_string()))?;
            let name = params.get("name").and_then(|v| v.as_str())
                .ok_or((-32602, "Missing prompt name".to_string()))?;

            match name {
                "register-document" => Ok(serde_json::json!({
                    "description": "Register a document on the Noble blockchain with metadata",
                    "messages": [{
                        "role": "user",
                        "content": { "type": "text", "text": concat!(
                            "I want to register a document on the Noble blockchain.\n\n",
                            "Steps:\n",
                            "1. Hash the file with hashFile\n",
                            "2. Choose metadata fields. Available types:\n",
                            "   - doc:title (auto-populate from filename), doc:description, doc:url\n",
                            "   - author, publisher, signer:pubkey\n",
                            "   - contact:email (MUST be encrypted), contact:phone (MUST be encrypted)\n",
                            "   - doc:bridge + doc:relation (always paired)\n",
                            "   - custom fields (any key name)\n",
                            "3. For each field, choose mode: plaintext, protected (password), or encrypted (ECIES recipient)\n",
                            "4. Validate metadata with validateMetadata\n",
                            "5. Encrypt protected/encrypted fields with encryptField\n",
                            "6. Estimate fee with estimateTxSize\n",
                            "7. Build and sign with signNotarization (pass pre-encrypted values with mode 'plaintext')\n",
                            "8. Submit with submitTransaction\n\n",
                            "Rules:\n",
                            "- Max 16 metadata slots (1 schema + fields + signatures)\n",
                            "- Signed fields consume 2 slots (field + CMS signature)\n",
                            "- contact:email and contact:phone MUST be mode 'encrypted'\n",
                            "- doc:bridge requires doc:relation (and vice versa)\n",
                            "- Encrypted fields: max 134 bytes plaintext (ECIES overhead = 121 bytes)\n",
                            "- Multi-recipient encryption: create one entry per recipient (same key, different ciphertext)"
                        ) }
                    }]
                })),
                "register-document-batch" => Ok(serde_json::json!({
                    "description": "Register multiple documents as a linked batch",
                    "messages": [{
                        "role": "user",
                        "content": { "type": "text", "text": concat!(
                            "I want to register multiple documents as a linked batch.\n\n",
                            "Steps:\n",
                            "1. Generate a batch UUID (any unique identifier)\n",
                            "2. Hash all files with hashFile\n",
                            "3. Build shared batch metadata for ALL files:\n",
                            "   - doc:batch = UUID (plaintext)\n",
                            "   - doc:bridge = UUID (plaintext)\n",
                            "   - doc:relation = 'same batch' (plaintext)\n",
                            "4. Add per-file metadata (doc:title from filename, etc.)\n",
                            "5. For each file: merge batch + per-file metadata\n",
                            "6. Validate each file's metadata with validateMetadata\n",
                            "7. Encrypt fields as needed with encryptField\n",
                            "8. Estimate fees with estimateTxSize for each file\n",
                            "9. Sign + submit each file with signNotarization + submitTransaction\n",
                            "10. Report results (successes + failures)\n\n",
                            "The batch UUID links all documents together. Each file becomes a separate\n",
                            "transaction sharing the same doc:batch, doc:bridge, and doc:relation metadata."
                        ) }
                    }]
                })),
                "send-payment" => Ok(serde_json::json!({
                    "description": "Send a Noble coin transfer",
                    "messages": [{
                        "role": "user",
                        "content": { "type": "text", "text": "I want to send NOBLE coins. Please help me: 1) Validate the recipient address, 2) Check my balance, 3) Estimate the fee, 4) Build, sign, and submit the transfer." }
                    }]
                })),
                "verify-document" => Ok(serde_json::json!({
                    "description": "Verify a document registration",
                    "messages": [{
                        "role": "user",
                        "content": { "type": "text", "text": "I want to verify if a document is registered on-chain. Please check the checksum and show me the registration details." }
                    }]
                })),
                _ => Err((-32602, format!("Unknown prompt: {name}"))),
            }
        }

        _ => Err((-32601, format!("Method not found: {}", req.method))),
    }
}

/// Call the host app's bridge handler via the C callback.
fn call_bridge(
    state: &ServerState,
    handler: &str,
    action: &str,
    params: &Option<serde_json::Value>,
) -> Result<serde_json::Value, (i32, String)> {
    let request = serde_json::json!({
        "handler": handler,
        "action": action,
        "params": params.clone().unwrap_or(serde_json::json!({})),
    });

    let request_str = serde_json::to_string(&request).unwrap();
    let response_str = (state.handler)(&request_str);

    let response: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| (-32603, format!("Bridge response parse error: {e}")))?;

    if let Some(err) = response.get("error").and_then(|e| e.as_str()) {
        return Err((-32603, err.to_string()));
    }

    Ok(response.get("result").cloned().unwrap_or(response))
}

// ── Server lifecycle ──

pub struct ServerHandle {
    shutdown_tx: oneshot::Sender<()>,
    _runtime: tokio::runtime::Runtime,
}

impl ServerHandle {
    pub fn start(port: u16, handler: HandlerCallback, mode: ServerMode) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to create runtime: {e}"))?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let state = ServerState { handler, mode };
        let path = match mode {
            ServerMode::Rpc => "/",
            ServerMode::Mcp => "/mcp",
        };

        let app = Router::new()
            .route(path, post(handle_post))
            .layer(CorsLayer::permissive())
            .with_state(state);

        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        rt.spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[noble-client-api] Failed to bind port {port}: {e}");
                    return;
                }
            };
            eprintln!("[noble-client-api] {} server listening on http://127.0.0.1:{port}{path}",
                if mode == ServerMode::Rpc { "RPC" } else { "MCP" });

            axum::serve(listener, app)
                .with_graceful_shutdown(async { let _ = shutdown_rx.await; })
                .await
                .ok();
        });

        Ok(Self { shutdown_tx, _runtime: rt })
    }

    pub fn stop(self) {
        let _ = self.shutdown_tx.send(());
        // Runtime drops when ServerHandle drops, which shuts down the background thread.
    }
}
