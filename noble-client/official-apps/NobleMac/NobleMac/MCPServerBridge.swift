// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleMCPServer

/// Swift bridge to the Rust-based embedded RPC + MCP servers.
/// Routes incoming JSON-RPC requests through the app's WebBridgeHandler.
///
/// The Rust FFI functions wrapped here are thread-safe (internal `Mutex`
/// guards around a global `ServerHandle`), so the static members are
/// `nonisolated` — callable from any thread, including a detached task
/// spawned to avoid freezing MainActor during the synchronous
/// `Runtime::drop` that `stopRPC`/`stopMCP` trigger.
final class MCPServerBridge {

    /// Shared handler callback. Set once at app startup.
    /// Receives a JSON request string, returns a JSON response string.
    nonisolated(unsafe) static var handler: ((String) -> String)?

    /// Start the plain JSON-RPC server on the given port.
    nonisolated static func startRPC(port: UInt16) {
        guard let h = handler else { return }
        // Store handler in a global so the C callback can access it.
        _globalHandler = h
        noble_rpc_server_start(port, _cHandler)
    }

    /// Stop the plain JSON-RPC server.
    nonisolated static func stopRPC() {
        noble_rpc_server_stop()
    }

    /// Start the MCP protocol server on the given port.
    nonisolated static func startMCP(port: UInt16) {
        guard let h = handler else { return }
        _globalHandler = h
        noble_mcp_server_start(port, _cHandler)
    }

    /// Stop the MCP protocol server.
    nonisolated static func stopMCP() {
        noble_mcp_server_stop()
    }

    /// Whether the RPC server is running.
    nonisolated static var isRPCRunning: Bool {
        noble_rpc_server_is_running()
    }

    /// Whether the MCP server is running.
    nonisolated static var isMCPRunning: Bool {
        noble_mcp_server_is_running()
    }
}

// ── C callback bridge ──
// The Rust library calls this C function for each incoming request.
// It must return a malloc'd string that the Rust library frees.

nonisolated(unsafe) private var _globalHandler: ((String) -> String)?

private let _cHandler: NobleMcpHandler = { requestPtr in
    guard let requestPtr else { return strdup("{}") }
    let request = String(cString: requestPtr)
    let response = _globalHandler?(request) ?? "{\"error\":\"handler not set\"}"
    return strdup(response)
}
