// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Embedded RPC + MCP server for Noble client applications.
// Shared Rust library exposed as stable C ABI.
//
// Two independent servers:
//   RPC API  (port 8788) — plain JSON-RPC for scripts/automation
//   MCP      (port 8789) — Model Context Protocol for AI agents
//
// Both route requests to the host app via a callback function.
// The callback receives a JSON request and returns a JSON response.
// The caller must free the response string with noble_mcp_free().

#ifndef NOBLE_MCP_H
#define NOBLE_MCP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Callback type: receives JSON request string, returns JSON response string.
/// The host app implements this to route requests to its bridge handler.
/// The returned string must be allocated with malloc/strdup — the library frees it.
typedef char* (*NobleMcpHandler)(const char *request_json);

// ── RPC Server (plain JSON-RPC 2.0) ──

/// Start the plain JSON-RPC server on the given port.
/// Returns 0 on success, -1 on failure.
int noble_rpc_server_start(uint16_t port, NobleMcpHandler handler);

/// Stop the plain JSON-RPC server.
void noble_rpc_server_stop(void);

/// Check if the RPC server is running.
bool noble_rpc_server_is_running(void);

// ── MCP Server (Model Context Protocol) ──

/// Start the MCP protocol server on the given port.
/// Returns 0 on success, -1 on failure.
int noble_mcp_server_start(uint16_t port, NobleMcpHandler handler);

/// Stop the MCP protocol server.
void noble_mcp_server_stop(void);

/// Check if the MCP server is running.
bool noble_mcp_server_is_running(void);

// ── Memory management ──

/// Free a string returned by this library.
void noble_mcp_free(char *ptr);

#ifdef __cplusplus
}
#endif

#endif // NOBLE_MCP_H
