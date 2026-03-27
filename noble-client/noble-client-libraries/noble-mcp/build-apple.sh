#!/bin/bash
# Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
# SPDX-License-Identifier: Apache-2.0
#
# Build noble-mcp for macOS and package as XCFramework.
# Run from the noble-mcp directory.

set -e

echo "Building noble-mcp for Apple targets..."
echo "NOTE: Desktop only — phone apps (NobleApp) do NOT link this library."

# Workspace root (cargo workspace builds to the root target/ directory)
WORKSPACE_ROOT="$(cd ../../../ && pwd)"
TARGET_DIR="$WORKSPACE_ROOT/target"

# macOS arm64 (the only target needed for NobleMac)
echo "  macOS arm64..."
cd "$WORKSPACE_ROOT" && MACOSX_DEPLOYMENT_TARGET=15.0 cargo build --release --target aarch64-apple-darwin --package noble-mcp
cd "$WORKSPACE_ROOT/noble-client/noble-client-libraries/noble-mcp"

# Remove old framework if it exists
rm -rf NobleMCPServer.xcframework

# Create XCFramework (macOS only — no iOS targets)
echo "Creating XCFramework..."
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-darwin/release/libnoble_mcp.a" \
    -headers include/ \
  -output NobleMCPServer.xcframework

echo "Done: NobleMCPServer.xcframework"
