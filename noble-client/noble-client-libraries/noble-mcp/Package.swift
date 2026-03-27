// swift-tools-version: 6.0
// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// SPM package for noble-mcp: embedded RPC + MCP server.
// This is a binary target — the Rust library is precompiled via build-apple.sh
// into NobleMCPServer.xcframework. SPM does not compile any source here.

import PackageDescription

let package = Package(
    name: "NobleMCPServer",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "NobleMCPServer", targets: ["NobleMCPServer"]),
    ],
    targets: [
        .binaryTarget(
            name: "NobleMCPServer",
            path: "NobleMCPServer.xcframework"
        ),
    ]
)
