// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleMCPServer

/// Swift bridge to the Rust-based embedded RPC + MCP servers.
/// Routes incoming JSON-RPC requests through the app's WebBridgeHandler.
@MainActor
final class MCPServerBridge {

    /// Shared handler callback. Set once at app startup.
    /// Receives a JSON request string, returns a JSON response string.
    nonisolated(unsafe) static var handler: ((String) -> String)?

    /// Start the plain JSON-RPC server on the given port.
    static func startRPC(port: UInt16) {
        guard let h = handler else { return }
        // Store handler in a global so the C callback can access it.
        _globalHandler = h
        noble_rpc_server_start(port, _cHandler)
    }

    /// Stop the plain JSON-RPC server.
    static func stopRPC() {
        noble_rpc_server_stop()
    }

    /// Start the MCP protocol server on the given port.
    static func startMCP(port: UInt16) {
        guard let h = handler else { return }
        _globalHandler = h
        noble_mcp_server_start(port, _cHandler)
    }

    /// Stop the MCP protocol server.
    static func stopMCP() {
        noble_mcp_server_stop()
    }

    /// Whether the RPC server is running.
    static var isRPCRunning: Bool {
        noble_rpc_server_is_running()
    }

    /// Whether the MCP server is running.
    static var isMCPRunning: Bool {
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
