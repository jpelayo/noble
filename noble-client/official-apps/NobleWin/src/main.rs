// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

//! Noble Document Client for Windows — WRY + WebView2.
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
mod errors;
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
        // 'desktop' fallback for non-Windows dev builds — mirrors NobleDoc's
        // conditional so the WebUI's WRY platform set stays accurate.
        "platform": if cfg!(target_os = "windows") { "windows" } else { "desktop" },
        // Single version source: Cargo.toml (avoids a hardcoded ghost copy).
        "version": env!("CARGO_PKG_VERSION"),
        "isConnected": st.is_connected,
        "hasWallet": st.has_wallet,
        "walletAddress": st.wallet_address,
        "chainId": st.chain_id,
        // First run (no wallet in the keyring): land on the WebUI wallet-setup
        // flow — this shell has no native onboarding. app.js also route-guards
        // every section to wallet-setup while hasWallet is false.
        "initialRoute": if st.has_wallet { "home" } else { "wallet-setup" },
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

    // Serve the embedded WebUI per-file over a custom protocol so the browser
    // resolves the REAL ES-module import graph — the same architecture as the
    // Mac app's `noble-app://` scheme handler. This replaces the old
    // hand-bundled `with_html` approach, whose hardcoded file list silently
    // broke every time the shared WebUI gained a module.
    //
    // URL forms differ per platform (wry 0.48): Linux/WebKitGTK serves
    // `noble://localhost/...`; Windows/WebView2 maps custom protocols to
    // `http://noble.localhost/...`.
    let start_url = if cfg!(target_os = "windows") {
        "http://noble.localhost/index.html"
    } else {
        "noble://localhost/index.html"
    };

    // with_initialization_script works with custom-protocol URLs (unlike plain
    // remote http), so NativeConfig injects before any module runs — the same
    // guarantee as WKWebView's `.atDocumentStart`.
    // Finder/Explorer file drops → window._nobleHandleFileDrop([{name,path,size}]),
    // matching the Mac client's DroppableWebView (WebContentView.swift). Returning
    // true suppresses the WebView's default "navigate to the dropped file" action.
    let drop_proxy = proxy.clone();
    let drag_drop_handler = move |event: wry::DragDropEvent| {
        if let wry::DragDropEvent::Drop { paths, .. } = event {
            let files: Vec<serde_json::Value> = paths
                .iter()
                .map(|path| {
                    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                    serde_json::json!({
                        "path": path.to_string_lossy(),
                        "name": path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        "size": size,
                    })
                })
                .collect();
            let payload = serde_json::to_string(&files).unwrap_or_else(|_| "[]".to_string());
            let script = format!(
                "if (typeof window._nobleHandleFileDrop === 'function') {{ window._nobleHandleFileDrop({payload}); }}"
            );
            if let Err(e) = drop_proxy.send_event(UserEvent::EvalScript(script)) {
                eprintln!("[drag-drop] event send failed: {e:?}");
            }
            return true;
        }
        false
    };

    let webview = WebViewBuilder::new()
        .with_initialization_script(&init_script)
        .with_ipc_handler(ipc_handler)
        .with_drag_drop_handler(drag_drop_handler)
        .with_custom_protocol("noble".into(), |_id, request| {
            let path = request.uri().path().to_string();
            match assets::serve_asset(&path) {
                Some((bytes, mime)) => wry::http::Response::builder()
                    .status(200)
                    .header("Content-Type", mime)
                    // Match the Mac scheme handler's no-cache posture and keep
                    // cross-origin module fetches unrestricted.
                    .header("Cache-Control", "no-store, no-cache, must-revalidate")
                    .header("Access-Control-Allow-Origin", "*")
                    .body(std::borrow::Cow::Owned(bytes))
                    .unwrap_or_else(|_| {
                        wry::http::Response::new(std::borrow::Cow::Borrowed(&[][..]))
                    }),
                None => wry::http::Response::builder()
                    .status(404)
                    .header("Content-Type", "text/plain")
                    .body(std::borrow::Cow::Borrowed(&b"not found"[..]))
                    .unwrap_or_else(|_| {
                        wry::http::Response::new(std::borrow::Cow::Borrowed(&[][..]))
                    }),
            }
        })
        .with_url(start_url)
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

                UserEvent::EvalScript(script) => {
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
                    return Err(errors::ne_message("Not connected to a NOBLE node", errors::NE_NOT_CONNECTED));
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
                .ok_or(errors::ne_message("No private key available", errors::NE_NO_PRIVATE_KEY))?;
            crypto::handle_crypto_action(action, params, &private_key, &wallet_address, &chain_id)
        }

        "noble_security" => {
            if action == "downloadAndHash" {
                security::download_and_hash(params, proxy).await
            } else {
                // importPKCS12 blocks on a native file dialog and hashFile on
                // disk I/O — run on the blocking pool so a parked dialog can't
                // starve the async workers (which would stall every other
                // bridge call and fake a "Disconnected" state).
                let action = action.to_string();
                let params = params.clone();
                tokio::task::spawn_blocking(move || {
                    security::handle_security_action(&action, &params)
                })
                .await
                .map_err(|e| format!("security task panicked: {e}"))?
            }
        }

        "noble_app" => {
            app::handle_app_action(action, params, state, proxy, callback_id, tokio_handle).await
        }

        "noble_storage" => {
            // ensureMyCard seeds the My Card contact with the wallet address.
            let wallet_address = {
                let st = state.lock().unwrap();
                st.wallet_address.clone()
            };
            storage::handle_storage_action(action, params, &wallet_address)
        }

        _ => Err(errors::ne_message(&format!("Unknown bridge handler: {handler}"), errors::NE_UNKNOWN_HANDLER)),
    }
}
