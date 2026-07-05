// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Application state, polling loop, and `noble_app` bridge handler.
//!
//! Mirrors `AppState.swift` — manages connection lifecycle, wallet state,
//! settings persistence, and the 30-second poll timer that pushes live data
//! to the WebUI.

use crate::api::ApiClient;
use crate::bridge::UserEvent;
use crate::crypto;
use crate::models::Settings;
use crate::security;
use crate::storage;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tao::event_loop::EventLoopProxy;
use tokio::runtime::Handle;

/// Shared mutable application state, protected by a Mutex for cross-thread access.
pub struct AppState {
    pub is_connected: bool,
    pub chain_id: String,
    pub block_height: u64,
    pub node_url: String,
    pub node_state: String,
    pub has_wallet: bool,
    pub wallet_address: String,
    pub wallet_balance: String,
    pub selected_section: String,
    pub settings: Settings,
    pub api_client: Option<ApiClient>,
    poll_failure_count: u32,
    reconnect_handle: Option<tokio::task::JoinHandle<()>>,
    /// True after a deliberate disconnect — suppresses every automatic
    /// reconnection path until the user connects again. Without this the poll
    /// loop would silently re-connect right after "Disconnect".
    user_disconnected: bool,
    /// Monotonic token for the polling loop: each start_polling() bumps it and
    /// older loops exit on their next tick, so repeated connects never stack
    /// duplicate pollers.
    poll_generation: u64,
}

impl AppState {
    pub fn new() -> Self {
        let settings = storage::load_settings();
        let has_wallet = security::has_credential(security::KEY_PRIVATE_KEY);

        let wallet_address = if has_wallet {
            load_wallet_address().unwrap_or_default()
        } else {
            String::new()
        };

        let node_url = security::load_credential(security::KEY_NODE_URL)
            .ok()
            .flatten()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| settings.node_url.clone());

        Self {
            is_connected: false,
            chain_id: String::new(),
            block_height: 0,
            node_url,
            node_state: String::new(),
            has_wallet,
            wallet_address,
            wallet_balance: String::new(),
            selected_section: "home".to_string(),
            settings,
            api_client: None,
            poll_failure_count: 0,
            reconnect_handle: None,
            user_disconnected: false,
            poll_generation: 0,
        }
    }

    /// Get a state snapshot for the WebUI.
    pub fn snapshot(&self) -> Value {
        json!({
            "isConnected": self.is_connected,
            "hasWallet": self.has_wallet,
            "walletAddress": self.wallet_address,
            "chainId": self.chain_id,
            "blockHeight": self.block_height,
            "nodeState": self.node_state,
            "selectedSection": self.selected_section,
        })
    }
}

/// Load wallet address from stored private key.
fn load_wallet_address() -> Result<String, String> {
    let private_key = security::load_credential(security::KEY_PRIVATE_KEY)?
        .ok_or("No private key")?;
    crypto::derive_address(&private_key)
}

/// Thread-safe shared state handle.
pub type SharedState = Arc<Mutex<AppState>>;

/// Create initial shared state.
pub fn create_shared_state() -> SharedState {
    Arc::new(Mutex::new(AppState::new()))
}

// ============================================================================
// Polling Loop
// ============================================================================

/// Start the 30-second polling loop.
///
/// Runs as a tokio task. Fetches node info + balance and pushes updates
/// via `EventLoopProxy`. Auto-disconnects after 3 consecutive failures.
pub fn start_polling(
    state: SharedState,
    proxy: EventLoopProxy<UserEvent>,
    handle: Handle,
) {
    // Generation token: only the newest poll loop stays alive. Every
    // start_polling() bumps the counter; older loops notice on their next tick
    // and exit, so repeated connects never stack duplicate pollers.
    let my_generation = {
        let mut st = state.lock().expect("app state lock poisoned");
        st.poll_generation += 1;
        st.poll_generation
    };

    handle.spawn(async move {
        // 10s cadence matches the Mac client (AppState.pollTick) so the desktop
        // shell's balance/height/peer state feels equally live.
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        // Skip the first immediate tick — we poll right after connecting
        interval.tick().await;

        loop {
            interval.tick().await;

            let (node_url, wallet_address, is_connected, stale, user_disconnected) = {
                let st = state.lock().expect("app state lock poisoned");
                (
                    st.node_url.clone(),
                    st.wallet_address.clone(),
                    st.is_connected,
                    st.poll_generation != my_generation,
                    st.user_disconnected,
                )
            };
            if stale {
                return; // a newer poll loop owns polling now
            }

            // If disconnected, attempt silent reconnection with a fresh client —
            // unless the user disconnected on purpose (never override that).
            if !is_connected {
                if user_disconnected {
                    continue;
                }
                let reconnect_client = ApiClient::new(&node_url);
                if let Ok(info) = reconnect_client.call_rpc("noble_getNodeInfo", json!([])).await {
                    // chain_id is a hex STRING on the wire (e.g. "0F48C9C1") —
                    // same parse as every other call site.
                    let chain_id = info.get("chain_id").or(info.get("chainId"))
                        .and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let block_height = info.get("block_height").or(info.get("blockHeight"))
                        .and_then(|v| v.as_u64()).unwrap_or(0);
                    {
                        let mut st = state.lock().expect("app state lock poisoned");
                        st.is_connected = true;
                        st.chain_id = chain_id.clone();
                        st.block_height = block_height;
                        st.poll_failure_count = 0;
                    }
                    if let Err(e) = proxy.send_event(UserEvent::PollTick(json!({
                        "isConnected": true,
                        "blockHeight": block_height,
                        "chainId": chain_id,
                    }))) { eprintln!("event send failed: {e:?}"); }
                }
                continue;
            }

            let client = ApiClient::new(&node_url);

            // Fetch node info
            let node_info = client
                .call_rpc("noble_getNodeInfo", json!([]))
                .await;

            match node_info {
                Ok(info) => {
                    let chain_id = info
                        .get("chain_id")
                        .or(info.get("chainId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let block_height = info
                        .get("block_height")
                        .or(info.get("blockHeight"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let peer_count = info
                        .get("peer_count")
                        .or(info.get("peerCount"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let is_syncing = info
                        .get("is_syncing")
                        .or(info.get("isSyncing"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let mut state_update = json!({
                        "isConnected": true,
                        "blockHeight": block_height,
                        "chainId": chain_id,
                        "peerCount": peer_count,
                        "isSyncing": is_syncing,
                    });

                    // Fetch sync status
                    let mut node_state_value = String::new();
                    if let Ok(sync) = client.call_rpc("noble_getSyncStatus", json!([])).await {
                        let sync_state = sync.get("state")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        node_state_value = sync_state.clone();
                        state_update["syncStatus"] = json!({
                            "synced": sync.get("synced").and_then(|v| v.as_bool()).unwrap_or(false),
                            "currentHeight": sync.get("current_height")
                                .or(sync.get("currentHeight"))
                                .and_then(|v| v.as_u64()).unwrap_or(0),
                            "highestKnown": sync.get("highest_known")
                                .or(sync.get("highestKnown"))
                                .and_then(|v| v.as_u64()).unwrap_or(0),
                            // Mac includes state inside syncStatus (AppState.swift:519).
                            "state": sync_state.clone(),
                        });
                        state_update["nodeState"] = json!(sync_state);
                    }

                    // Fetch cycle status
                    if let Ok(cycle) = client.call_rpc("noble_getCycleStatus", json!([])).await {
                        state_update["cycleStatus"] = json!({
                            "cycleNumber": cycle.get("cycle_number")
                                .or(cycle.get("cycleNumber"))
                                .and_then(|v| v.as_u64()).unwrap_or(0),
                            "phase": cycle.get("phase").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                            "phaseRemainingSecs": cycle.get("phase_remaining_secs")
                                .or(cycle.get("phaseRemainingSecs"))
                                .and_then(|v| v.as_u64()).unwrap_or(0),
                        });
                    }

                    // Fetch balance if wallet exists
                    if !wallet_address.is_empty() {
                        if let Ok(balance) = client
                            .call_rpc("noble_getAddressBalance", json!([wallet_address]))
                            .await
                        {
                            let bal = balance
                                .get("balance")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            let available = balance
                                .get("available")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(bal);
                            // Mac pushes walletImmature too (AppState.swift:540);
                            // the node exposes it as immature_value / immature.
                            let immature = balance
                                .get("immature_value")
                                .or(balance.get("immature"))
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0);
                            state_update["walletBalance"] = json!(bal);
                            state_update["walletAvailable"] = json!(available);
                            state_update["walletImmature"] = json!(immature);
                        }
                    }

                    // Update local state
                    {
                        let mut st = state.lock().expect("app state lock poisoned");
                        st.block_height = block_height;
                        st.chain_id = chain_id;
                        st.node_state = node_state_value;
                        st.poll_failure_count = 0;
                    }

                    // Push to WebView
                    if let Err(e) = proxy.send_event(UserEvent::PollTick(state_update)) { eprintln!("event send failed: {e:?}"); }
                }
                Err(_) => {
                    let should_disconnect = {
                        let mut st = state.lock().expect("app state lock poisoned");
                        st.poll_failure_count += 1;
                        st.poll_failure_count >= 5
                    };

                    if should_disconnect {
                        {
                            let mut st = state.lock().expect("app state lock poisoned");
                            st.is_connected = false;
                            // Keep node_url and api_client alive for reconnection.
                        }
                        if let Err(e) = proxy.send_event(UserEvent::PollTick(json!({
                            "isConnected": false,
                        }))) { eprintln!("event send failed: {e:?}"); }
                    }
                }
            }
        }
    });
}

// ============================================================================
// Reconnect Loop
// ============================================================================

/// Spawn (or replace) the background reconnect loop: retries the saved node
/// URL every 10s until it connects, then starts polling and exits. Used by
/// `connectToNode` on failure AND by the launch auto-connect failure path, so
/// the WebUI's "Reconnecting…" banner is always backed by a real dialer.
/// Aborts any previous loop and stores its own handle in `reconnect_handle`
/// (cancelled by the next connect/disconnect). Exits permanently if the user
/// disconnected on purpose.
pub fn spawn_reconnect_loop(
    state: SharedState,
    proxy: EventLoopProxy<UserEvent>,
    tokio_handle: Handle,
) {
    // Cancel any previous loop before replacing it.
    {
        let mut st = state.lock().expect("app state lock poisoned");
        if let Some(old) = st.reconnect_handle.take() {
            old.abort();
        }
    }

    let reconnect_state = state.clone();
    let reconnect_proxy = proxy.clone();
    let reconnect_tokio = tokio_handle.clone();
    let handle = tokio_handle.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.tick().await; // skip immediate tick

        loop {
            interval.tick().await;

            let current_url = {
                let st = reconnect_state.lock().expect("app state lock poisoned");
                if st.is_connected || st.user_disconnected {
                    return; // connected elsewhere, or deliberate disconnect
                }
                st.node_url.clone()
            };

            let retry_client = ApiClient::new(&current_url);
            if let Ok(info) = retry_client
                .call_rpc("noble_getNodeInfo", json!([]))
                .await
            {
                let chain_id = info
                    .get("chain_id")
                    .or(info.get("chainId"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let block_height = info
                    .get("block_height")
                    .or(info.get("blockHeight"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                {
                    let mut st = reconnect_state.lock().expect("app state lock poisoned");
                    st.is_connected = true;
                    st.chain_id = chain_id.clone();
                    st.block_height = block_height;
                    st.api_client = Some(retry_client);
                    st.poll_failure_count = 0;
                    st.reconnect_handle = None;
                    if let Err(e) = security::store_credential(
                        security::KEY_NODE_URL,
                        st.node_url.as_bytes(),
                    ) { eprintln!("credential store failed: {e}"); }
                }

                // Push connected state to WebView.
                if let Err(e) = reconnect_proxy.send_event(UserEvent::PollTick(json!({
                    "isConnected": true,
                    "chainId": chain_id,
                    "blockHeight": block_height,
                }))) { eprintln!("event send failed: {e:?}"); }

                // Start polling loop.
                start_polling(
                    reconnect_state.clone(),
                    reconnect_proxy.clone(),
                    reconnect_tokio.clone(),
                );
                return;
            }
        }
    });

    let mut st = state.lock().expect("app state lock poisoned");
    st.reconnect_handle = Some(handle);
}

// ============================================================================
// Bridge Handler: noble_app
// ============================================================================

/// Handle `noble_app` bridge actions.
///
/// Some actions require async (testConnection, connectToNode) — they spawn
/// a tokio task and send the result via EventLoopProxy.
pub async fn handle_app_action(
    action: &str,
    params: &Value,
    state: &SharedState,
    proxy: &EventLoopProxy<UserEvent>,
    _callback_id: &str,
    tokio_handle: &Handle,
) -> Result<Value, String> {
    match action {
        "getState" => {
            let st = state.lock().expect("app state lock poisoned");
            Ok(st.snapshot())
        }

        "navigateTo" => {
            let section = params
                .get("section")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: section")?;
            {
                let mut st = state.lock().expect("app state lock poisoned");
                st.selected_section = section.to_string();
            }
            Ok(json!({ "ok": true }))
        }

        "copyToClipboard" => {
            let text = params
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: text")?;
            match arboard::Clipboard::new() {
                Ok(mut clipboard) => {
                    clipboard
                        .set_text(text)
                        .map_err(|e| format!("Clipboard error: {e}"))?;
                    Ok(json!({ "ok": true }))
                }
                Err(e) => Err(format!("Clipboard unavailable: {e}")),
            }
        }

        "openFileDialog" => {
            let multiple = params
                .get("multiple")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let dialog = rfd::FileDialog::new();
            let files = if multiple {
                dialog.pick_files()
            } else {
                dialog.pick_file().map(|f| vec![f])
            };

            let file_list: Vec<Value> = files
                .unwrap_or_default()
                .iter()
                .map(|path| {
                    let size = std::fs::metadata(path)
                        .map(|m| m.len())
                        .unwrap_or(0);
                    json!({
                        "path": path.to_string_lossy(),
                        "name": path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        "size": size,
                    })
                })
                .collect();

            Ok(json!({ "files": file_list }))
        }

        // `share` is the canonical WebUI action; `shareText` is the legacy
        // alias. Desktop has no native share sheet — both copy to clipboard.
        "share" | "shareText" => {
            let text = params
                .get("text")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: text")?;
            match arboard::Clipboard::new() {
                Ok(mut clipboard) => {
                    clipboard
                        .set_text(text)
                        .map_err(|e| format!("Clipboard error: {e}"))?;
                    Ok(json!({ "ok": true }))
                }
                Err(e) => Err(format!("Clipboard unavailable: {e}")),
            }
        }

        "reportBridgeTimeout" => {
            // The WebUI's slow-load watchdog detected a stalled bridge call.
            // Mirror the Mac client: weight it as 2 poll failures; after the
            // same ≥5 threshold the connection indicator flips off.
            let should_disconnect = {
                let mut st = state.lock().expect("app state lock poisoned");
                st.poll_failure_count += 2;
                let trigger = st.poll_failure_count >= 5 && st.is_connected;
                if trigger {
                    st.is_connected = false;
                }
                trigger
            };
            if should_disconnect {
                if let Err(e) = proxy.send_event(UserEvent::PollTick(json!({
                    "isConnected": false,
                }))) {
                    eprintln!("event send failed: {e:?}");
                }
            }
            Ok(json!({ "ok": true }))
        }

        "saveFileDialog" => {
            let suggested_name = params
                .get("filename")
                .and_then(|v| v.as_str())
                .unwrap_or("export.vcf");
            let content = params
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let path = rfd::FileDialog::new()
                .set_file_name(suggested_name)
                .save_file();

            if let Some(path) = path {
                std::fs::write(&path, content)
                    .map_err(|e| format!("Failed to save file: {e}"))?;
                Ok(json!({ "ok": true }))
            } else {
                Ok(json!({ "ok": false }))
            }
        }

        "readFileText" => {
            let file_path = params
                .get("filePath")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: filePath")?;
            let text = std::fs::read_to_string(file_path)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            Ok(json!({ "text": text }))
        }

        "getSettings" => {
            let st = state.lock().expect("app state lock poisoned");
            Ok(json!({
                "nodeURL": st.node_url,
                "authMode": "none",
                "tlsFingerprint": "",
                // Single version source: Cargo.toml — shown in Settings › About.
                "appVersion": env!("CARGO_PKG_VERSION"),
                "autoConnect": st.settings.auto_connect,
                "rpcApiEnabled": st.settings.rpc_api_enabled.unwrap_or(false),
                "rpcApiPort": st.settings.rpc_api_port.unwrap_or(8788),
                "mcpServerEnabled": st.settings.mcp_server_enabled.unwrap_or(false),
                "mcpServerPort": st.settings.mcp_server_port.unwrap_or(8789),
            }))
        }

        "saveSettings" => {
            let mut st = state.lock().expect("app state lock poisoned");
            if let Some(url) = params.get("nodeURL").and_then(|v| v.as_str()) {
                st.node_url = url.to_string();
                st.settings.node_url = url.to_string();
                if let Err(e) = security::store_credential(
                    security::KEY_NODE_URL,
                    url.as_bytes(),
                ) { eprintln!("credential store failed: {e}"); }
            }
            if let Some(auto) = params.get("autoConnect").and_then(|v| v.as_bool()) {
                st.settings.auto_connect = auto;
            }
            let _ = storage::save_settings(&st.settings);
            Ok(json!({ "ok": true }))
        }

        "getSecuritySettings" => {
            let st = state.lock().expect("app state lock poisoned");
            Ok(json!({
                "appLockEnabled": st.settings.app_lock_enabled,
                "lockTimeout": st.settings.lock_timeout,
                "reAuthForSends": st.settings.re_auth_for_sends,
            }))
        }

        "saveSecuritySettings" => {
            let mut st = state.lock().expect("app state lock poisoned");
            if let Some(enabled) = params.get("appLockEnabled").and_then(|v| v.as_bool()) {
                st.settings.app_lock_enabled = enabled;
            }
            if let Some(timeout) = params.get("lockTimeout").and_then(|v| v.as_u64()) {
                st.settings.lock_timeout = timeout as u32;
            }
            if let Some(re_auth) = params.get("reAuthForSends").and_then(|v| v.as_bool()) {
                st.settings.re_auth_for_sends = re_auth;
            }
            let _ = storage::save_settings(&st.settings);
            Ok(json!({ "ok": true }))
        }

        "testConnection" => {
            let url = params
                .get("url")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: url")?
                .to_string();

            let client = ApiClient::new(&url);
            let info = client
                .call_rpc("noble_getNodeInfo", json!([]))
                .await
                .map_err(|e| e.to_string())?;

            Ok(json!({
                "ok": true,
                "chainId": info.get("chain_id").or(info.get("chainId"))
                    .and_then(|v| v.as_str()).unwrap_or(""),
                "version": info.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                "blockHeight": info.get("block_height").or(info.get("blockHeight"))
                    .and_then(|v| v.as_u64()).unwrap_or(0),
            }))
        }

        "connectToNode" => {
            let url = {
                let mut st = state.lock().expect("app state lock poisoned");
                // Connecting is always a deliberate act — clear the flag that
                // suppresses automatic reconnection after a manual disconnect.
                st.user_disconnected = false;
                // Honor an explicit URL (Mac's handler requires it; home.js and
                // settings.js pass it) — persist it like saveSettings does, so
                // the dial target and the saved target can never diverge.
                if let Some(u) = params.get("url").and_then(|v| v.as_str()) {
                    if !u.is_empty() && u != st.node_url {
                        st.node_url = u.to_string();
                        st.settings.node_url = u.to_string();
                        if let Err(e) = storage::save_settings(&st.settings) {
                            eprintln!("settings save failed: {e}");
                        }
                    }
                }
                st.node_url.clone()
            };

            // Cancel any existing reconnect loop before attempting.
            {
                let mut st = state.lock().expect("app state lock poisoned");
                if let Some(handle) = st.reconnect_handle.take() {
                    handle.abort();
                }
            }

            let client = ApiClient::new(&url);
            match client.call_rpc("noble_getNodeInfo", json!([])).await {
                Ok(info) => {
                    let chain_id = info
                        .get("chain_id")
                        .or(info.get("chainId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let block_height = info
                        .get("block_height")
                        .or(info.get("blockHeight"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    {
                        let mut st = state.lock().expect("app state lock poisoned");
                        st.is_connected = true;
                        st.chain_id = chain_id.clone();
                        st.block_height = block_height;
                        st.api_client = Some(client);
                        st.poll_failure_count = 0;
                        if let Err(e) = security::store_credential(
                            security::KEY_NODE_URL,
                            st.node_url.as_bytes(),
                        ) { eprintln!("credential store failed: {e}"); }
                    }

                    // B1: Push connected state to WebView immediately.
                    if let Err(e) = proxy.send_event(UserEvent::PollTick(json!({
                        "isConnected": true,
                        "chainId": chain_id,
                        "blockHeight": block_height,
                    }))) { eprintln!("event send failed: {e:?}"); }

                    // Start polling
                    start_polling(state.clone(), proxy.clone(), tokio_handle.clone());

                    Ok(json!({
                        "ok": true,
                        "chainId": chain_id,
                        "blockHeight": block_height,
                    }))
                }
                Err(e) => {
                    // B1: Connection failed — keep retrying in the background so
                    // the WebUI's "Reconnecting…" banner is truthful.
                    spawn_reconnect_loop(state.clone(), proxy.clone(), tokio_handle.clone());
                    Err(format!("Connection failed: {e}"))
                }
            }
        }

        "disconnectNode" => {
            {
                let mut st = state.lock().expect("app state lock poisoned");
                st.is_connected = false;
                st.chain_id = String::new();
                st.block_height = 0;
                st.node_state = String::new();
                st.api_client = None;
                st.poll_failure_count = 0;
                // Deliberate disconnect: suppress every automatic reconnection
                // path (poll silent-reconnect, reconnect loop) until the user
                // explicitly connects again.
                st.user_disconnected = true;
                // Cancel any pending reconnect loop.
                if let Some(handle) = st.reconnect_handle.take() {
                    handle.abort();
                }
            }
            Ok(json!({ "ok": true }))
        }

        // -- Wallet Operations --

        "createWallet" => {
            let words = crypto::generate_mnemonic(12)?;
            let private_key = crypto::derive_private_key(&words)?;
            let address = crypto::derive_address(&private_key)?;

            security::store_credential(security::KEY_PRIVATE_KEY, &private_key)?;
            let mnemonic_data = words.join(" ");
            security::store_credential(security::KEY_MNEMONIC, mnemonic_data.as_bytes())?;

            {
                let mut st = state.lock().expect("app state lock poisoned");
                st.has_wallet = true;
                st.wallet_address = address.clone();
            }

            Ok(json!({
                "ok": true,
                "address": address,
                "mnemonic": words,
            }))
        }

        "importWallet" => {
            let mnemonic_str = params
                .get("mnemonic")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: mnemonic")?;
            let words: Vec<String> = mnemonic_str
                .split_whitespace()
                .map(|w| w.to_string())
                .collect();

            if !crypto::validate_mnemonic(&words) {
                return Err("Invalid mnemonic".to_string());
            }

            let private_key = crypto::derive_private_key(&words)?;
            let address = crypto::derive_address(&private_key)?;

            security::store_credential(security::KEY_PRIVATE_KEY, &private_key)?;
            security::store_credential(security::KEY_MNEMONIC, mnemonic_str.as_bytes())?;

            {
                let mut st = state.lock().expect("app state lock poisoned");
                st.has_wallet = true;
                st.wallet_address = address.clone();
            }

            Ok(json!({
                "ok": true,
                "address": address,
            }))
        }

        "exportWallet" => {
            let mnemonic_data = security::load_credential(security::KEY_MNEMONIC)?
                .ok_or("No mnemonic stored")?;
            let mnemonic = String::from_utf8(mnemonic_data)
                .map_err(|_| "Invalid mnemonic data")?;
            Ok(json!({ "mnemonic": mnemonic }))
        }

        // -- Drafts --

        "getDrafts" => {
            let drafts = storage::load_drafts();
            Ok(json!({ "drafts": drafts }))
        }

        "saveDraft" => {
            let draft = params
                .get("draft")
                .ok_or("Missing parameter: draft")?
                .clone();

            let mut drafts = storage::load_drafts();
            let id = draft.get("id").and_then(|v| v.as_str());

            if let Some(id) = id {
                if let Some(idx) = drafts.iter().position(|d| {
                    d.get("id").and_then(|v| v.as_str()) == Some(id)
                }) {
                    drafts[idx] = draft;
                } else {
                    drafts.push(draft);
                }
            } else {
                drafts.push(draft);
            }

            storage::save_drafts(&drafts)?;
            Ok(json!({ "ok": true }))
        }

        "deleteDraft" => {
            let id = params
                .get("id")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: id")?;

            let mut drafts = storage::load_drafts();
            drafts.retain(|d| {
                d.get("id").and_then(|v| v.as_str()) != Some(id)
            });
            storage::save_drafts(&drafts)?;

            Ok(json!({ "ok": true }))
        }

        // -- Web preferences --

        "getPreferences" => Ok(storage::load_preferences()),

        "setPreference" => {
            let key = params
                .get("key")
                .and_then(|v| v.as_str())
                .ok_or("Missing parameter: key")?;

            let mut prefs = storage::load_preferences();
            let obj = prefs
                .as_object_mut()
                .ok_or("preferences store corrupt (not a JSON object)")?;
            match params.get("value") {
                None | Some(Value::Null) => {
                    obj.remove(key);
                }
                Some(v) => {
                    obj.insert(key.to_string(), v.clone());
                }
            }
            storage::save_preferences(&prefs)?;
            Ok(json!({ "ok": true }))
        }

        _ => Err(format!("Unknown action: {action}")),
    }
}
