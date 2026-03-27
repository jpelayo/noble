// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Embedded RPC + MCP server for Noble client applications.
//!
//! Provides two independent servers:
//! - **RPC API** (port 8788): Plain JSON-RPC 2.0 for scripts and automation.
//! - **MCP Server** (port 8789): Model Context Protocol for AI agents.
//!
//! Both route requests to the host application via a C callback function.
//! The host app (Swift/Rust) implements the callback to dispatch to its bridge handler.

pub mod server;

use server::{HandlerCallback, ServerHandle, ServerMode};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Arc, Mutex};

static RPC_HANDLE: Mutex<Option<ServerHandle>> = Mutex::new(None);
static MCP_HANDLE: Mutex<Option<ServerHandle>> = Mutex::new(None);

/// C callback type: receives JSON request, returns JSON response.
/// The host app must free the returned string with `noble_mcp_free()`.
pub type HandlerFn = extern "C" fn(request: *const c_char) -> *mut c_char;

/// Start the plain JSON-RPC server on the given port.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn noble_rpc_server_start(port: u16, handler: HandlerFn) -> i32 {
    start_server(port, handler, ServerMode::Rpc, &RPC_HANDLE)
}

/// Stop the plain JSON-RPC server.
#[no_mangle]
pub extern "C" fn noble_rpc_server_stop() {
    stop_server(&RPC_HANDLE);
}

/// Check if the RPC server is running.
#[no_mangle]
pub extern "C" fn noble_rpc_server_is_running() -> bool {
    RPC_HANDLE.lock().map(|h| h.is_some()).unwrap_or(false)
}

/// Start the MCP protocol server on the given port.
/// Returns 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn noble_mcp_server_start(port: u16, handler: HandlerFn) -> i32 {
    start_server(port, handler, ServerMode::Mcp, &MCP_HANDLE)
}

/// Stop the MCP protocol server.
#[no_mangle]
pub extern "C" fn noble_mcp_server_stop() {
    stop_server(&MCP_HANDLE);
}

/// Check if the MCP server is running.
#[no_mangle]
pub extern "C" fn noble_mcp_server_is_running() -> bool {
    MCP_HANDLE.lock().map(|h| h.is_some()).unwrap_or(false)
}

/// Free a string returned by the handler callback or by this library.
#[no_mangle]
pub extern "C" fn noble_mcp_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)); }
    }
}

// ── Internal helpers ──

fn start_server(
    port: u16,
    handler: HandlerFn,
    mode: ServerMode,
    handle_slot: &Mutex<Option<ServerHandle>>,
) -> i32 {
    // Wrap the C callback in an Arc<dyn Fn> for the server.
    let callback: HandlerCallback = Arc::new(move |request_json: &str| {
        let c_request = match CString::new(request_json) {
            Ok(s) => s,
            Err(_) => return r#"{"error":"invalid request encoding"}"#.to_string(),
        };

        let response_ptr = handler(c_request.as_ptr());
        if response_ptr.is_null() {
            return r#"{"error":"null response from handler"}"#.to_string();
        }

        let response = unsafe { CStr::from_ptr(response_ptr) }
            .to_string_lossy()
            .into_owned();

        // Free the string allocated by the host app's handler.
        // Convention: the host allocates with malloc/strdup, we free here.
        // For Rust hosts using CString, this is compatible.
        // For Swift hosts, the callback returns a pointer allocated via strdup().
        unsafe { libc::free(response_ptr as *mut libc::c_void); }

        response
    });

    match ServerHandle::start(port, callback, mode) {
        Ok(handle) => {
            if let Ok(mut slot) = handle_slot.lock() {
                *slot = Some(handle);
            }
            0
        }
        Err(e) => {
            eprintln!("[noble-client-api] Failed to start server: {e}");
            -1
        }
    }
}

fn stop_server(handle_slot: &Mutex<Option<ServerHandle>>) {
    if let Ok(mut slot) = handle_slot.lock() {
        if let Some(handle) = slot.take() {
            handle.stop();
        }
    }
}

// ── Rust-native API (for WRY apps that link directly) ──

/// Start the RPC server with a Rust closure (no FFI overhead).
pub fn start_rpc_server(port: u16, handler: impl Fn(&str) -> String + Send + Sync + 'static) -> Result<(), String> {
    let callback: HandlerCallback = Arc::new(handler);
    let handle = ServerHandle::start(port, callback, ServerMode::Rpc)?;
    if let Ok(mut slot) = RPC_HANDLE.lock() {
        *slot = Some(handle);
    }
    Ok(())
}

/// Start the MCP server with a Rust closure (no FFI overhead).
pub fn start_mcp_server(port: u16, handler: impl Fn(&str) -> String + Send + Sync + 'static) -> Result<(), String> {
    let callback: HandlerCallback = Arc::new(handler);
    let handle = ServerHandle::start(port, callback, ServerMode::Mcp)?;
    if let Ok(mut slot) = MCP_HANDLE.lock() {
        *slot = Some(handle);
    }
    Ok(())
}

/// Stop the RPC server.
pub fn stop_rpc() {
    stop_server(&RPC_HANDLE);
}

/// Stop the MCP server.
pub fn stop_mcp() {
    stop_server(&MCP_HANDLE);
}
