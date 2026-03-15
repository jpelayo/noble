// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Noble Document Client for Linux — WRY + WebKitGTK.
//!
//! Replicates the Apple clients' SwiftUI shell + WKWebView architecture using
//! Rust's tao (window) + wry (WebView). The same shared WebUI is embedded at
//! compile time. A JavaScript shim makes WRY's IPC look identical to WKWebView
//! so bridge.js works without modification.

mod api;
mod app;
mod assets;
mod bridge;
mod cbor;
mod crypto;
mod models;
mod security;
mod storage;

use bridge::{BridgeMessage, UserEvent};
use serde_json::json;
use tao::{
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

/// Build the NativeConfig init script.
/// No webkit shim needed — bridge.js detects window.ipc (WRY) directly.
fn build_init_script(state: app::SharedState) -> String {
    let st = state.lock().unwrap();
    let config = serde_json::json!({
        "platform": "linux",
        "version": "1.0.0",
        "isConnected": st.is_connected,
        "hasWallet": st.has_wallet,
        "walletAddress": st.wallet_address,
        "chainId": st.chain_id,
        "initialRoute": "home",
    });
    format!("window.NativeConfig = {};", config)
}

fn main() {
    // Initialize tokio runtime for async operations (API calls, polling)
    let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    let tokio_handle = runtime.handle().clone();

    // Create shared application state
    let state = app::create_shared_state();

    // Build init scripts (webkit shim + NativeConfig).
    let init_script = build_init_script(state.clone());

    // Build the tao event loop with custom UserEvent support
    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event()
        .build();
    let proxy = event_loop.create_proxy();

    // Create the application window
    let window = WindowBuilder::new()
        .with_title("Noble")
        .with_inner_size(tao::dpi::LogicalSize::new(1100.0, 750.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(700.0, 500.0))
        .build(&event_loop)
        .expect("Failed to create window");

    // ========================================================================
    // IPC Handler
    // ========================================================================

    let ipc_state = state.clone();
    let ipc_proxy = proxy.clone();
    let ipc_handle = tokio_handle.clone();

    let ipc_handler = move |request: wry::http::Request<String>| {
        let body = request.body();

        let msg: BridgeMessage = match serde_json::from_str(body) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("[IPC] Failed to parse bridge message: {e}");
                return;
            }
        };

        let handler = msg.handler.clone();
        let action = msg.action.clone();
        let params = msg.params.clone();
        let callback_id = msg.callback_id.clone();
        let state_clone = ipc_state.clone();
        let proxy_clone = ipc_proxy.clone();
        let handle_clone = ipc_handle.clone();

        // Spawn async task for the bridge action
        ipc_handle.spawn(async move {
            let result = dispatch_bridge_action(
                &handler,
                &action,
                &params,
                &state_clone,
                &proxy_clone,
                &callback_id,
                &handle_clone,
            )
            .await;

            let _ = proxy_clone.send_event(UserEvent::BridgeResponse {
                callback_id,
                result,
            });
        });
    };

    // ========================================================================
    // WebView Creation
    // ========================================================================

    // Build self-contained HTML with all CSS + JS inlined.
    // bridge.js now detects window.ipc directly — no webkit shim needed.
    let full_html = assets::build_self_contained_html(&init_script);
    eprintln!("[startup] self-contained HTML: {} bytes", full_html.len());

    // WRY's with_html handles the HTML directly. with_initialization_script
    // injects NativeConfig before any page scripts run.
    let webview = WebViewBuilder::new()
        .with_initialization_script(&init_script)
        .with_ipc_handler(ipc_handler)
        .with_html(&full_html)
        .with_devtools(cfg!(debug_assertions))
        .build(&window)
        .expect("Failed to create WebView");

    // ========================================================================
    // Auto-Connect on Launch
    // ========================================================================

    {
        let st = state.lock().unwrap();
        if st.settings.auto_connect && !st.node_url.is_empty() && st.has_wallet {
            let connect_state = state.clone();
            let connect_proxy = proxy.clone();
            let connect_handle = tokio_handle.clone();

            tokio_handle.spawn(async move {
                let node_url = {
                    let st = connect_state.lock().unwrap();
                    st.node_url.clone()
                };

                let client = api::ApiClient::new(&node_url);
                if let Ok(info) = client.call_rpc("noble_getNodeInfo", json!([])).await {
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
                        let mut st = connect_state.lock().unwrap();
                        st.is_connected = true;
                        st.chain_id = chain_id;
                        st.block_height = block_height;
                    }

                    // Push initial state
                    let snapshot = {
                        let st = connect_state.lock().unwrap();
                        st.snapshot()
                    };
                    let _ = connect_proxy.send_event(UserEvent::PollTick(snapshot));

                    // Start polling
                    app::start_polling(
                        connect_state,
                        connect_proxy,
                        connect_handle,
                    );
                }
            });
        }
    }

    // ========================================================================
    // Event Loop
    // ========================================================================

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }

            Event::UserEvent(user_event) => match user_event {
                UserEvent::BridgeResponse {
                    callback_id,
                    result,
                } => {
                    let script = bridge::build_callback_script(&callback_id, &result);
                    let _ = webview.evaluate_script(&script);
                }

                UserEvent::PollTick(state_json) => {
                    let script = bridge::build_state_update_script(&state_json);
                    let _ = webview.evaluate_script(&script);
                }
            },

            _ => {}
        }
    });
}

/// Dispatch a bridge action to the appropriate handler module.
async fn dispatch_bridge_action(
    handler: &str,
    action: &str,
    params: &serde_json::Value,
    state: &app::SharedState,
    proxy: &tao::event_loop::EventLoopProxy<UserEvent>,
    callback_id: &str,
    tokio_handle: &tokio::runtime::Handle,
) -> Result<serde_json::Value, String> {
    match handler {
        "noble_api" => {
            let (node_url, wallet_address, block_height) = {
                let st = state.lock().unwrap();
                if !st.is_connected && action != "getNodeInfo" {
                    return Err("Not connected to a NOBLE node".to_string());
                }
                (
                    st.node_url.clone(),
                    st.wallet_address.clone(),
                    st.block_height,
                )
            };
            let client = api::ApiClient::new(&node_url);
            api::handle_api_action(
                &client,
                action,
                params,
                &node_url,
                &wallet_address,
                block_height,
            )
            .await
        }

        "noble_crypto" => {
            let (wallet_address, chain_id) = {
                let st = state.lock().unwrap();
                (st.wallet_address.clone(), st.chain_id.clone())
            };
            let private_key = security::load_credential(security::KEY_PRIVATE_KEY)
                .map_err(|e| e.to_string())?
                .ok_or("No private key available")?;
            crypto::handle_crypto_action(action, params, &private_key, &wallet_address, &chain_id)
        }

        "noble_security" => security::handle_security_action(action, params),

        "noble_app" => {
            app::handle_app_action(action, params, state, proxy, callback_id, tokio_handle).await
        }

        "noble_storage" => storage::handle_storage_action(action, params),

        _ => Err(format!("Unknown bridge handler: {handler}")),
    }
}
