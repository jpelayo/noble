// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! IPC bridge: parses JS messages, dispatches to handlers, sends callbacks.
//!
//! Replicates the Swift WebBridgeHandler message protocol so the same WebUI
//! bridge.js works unchanged (via the WebKit shim injected in main.rs).

use serde::Deserialize;
use serde_json::Value;

/// Incoming message from the WebUI bridge (JS → Rust).
///
/// Matches the shape produced by bridge.js:
/// `{ handler, callbackId, action, params }`
#[derive(Debug, Deserialize)]
pub struct BridgeMessage {
    pub handler: String,
    #[serde(rename = "callbackId")]
    pub callback_id: String,
    pub action: String,
    #[serde(default)]
    pub params: Value,
}

/// Events sent from background tasks back to the main event loop.
#[derive(Debug)]
pub enum UserEvent {
    /// Result of a bridge handler invocation — delivers callback to WebView.
    BridgeResponse {
        callback_id: String,
        result: Result<Value, String>,
    },
    /// Periodic poll tick — pushes state update to WebView.
    PollTick(Value),
}

/// Build the JavaScript callback invocation string.
///
/// Matches Swift's pattern:
/// ```js
/// NativeBridge._handleCallback('cb_123', null, '{"key":"value"}')
/// NativeBridge._handleCallback('cb_123', 'Error message', null)
/// ```
pub fn build_callback_script(callback_id: &str, result: &Result<Value, String>) -> String {
    match result {
        Ok(value) => {
            let json = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
            let escaped = escape_for_js_single_quote(&json);
            format!(
                "NativeBridge._handleCallback('{}', null, '{}')",
                escape_for_js_single_quote(callback_id),
                escaped
            )
        }
        Err(msg) => {
            let escaped = escape_for_js_single_quote(msg);
            format!(
                "NativeBridge._handleCallback('{}', '{}', null)",
                escape_for_js_single_quote(callback_id),
                escaped
            )
        }
    }
}

/// Escape single quotes and backslashes for embedding in JS single-quoted strings.
/// Matches Swift's `replacingOccurrences(of: "'", with: "\\'")`.
fn escape_for_js_single_quote(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

/// Build the JavaScript state update push string.
///
/// Matches Swift's `App.handleEvent('stateUpdate', {...})` pattern.
pub fn build_state_update_script(state: &Value) -> String {
    let json = serde_json::to_string(state).unwrap_or_else(|_| "{}".to_string());
    format!("App.handleEvent('stateUpdate', {})", json)
}
