#!/bin/bash
# Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
# SPDX-License-Identifier: Apache-2.0
#
# Build noble-cms-core for all Apple targets and package as XCFramework.
# Run from the noble-cms-core directory.

set -e

echo "Building noble-cms-core for Apple targets..."

# macOS arm64
echo "  macOS arm64..."
cargo build --release --target aarch64-apple-darwin

# iOS arm64
echo "  iOS arm64..."
cargo build --release --target aarch64-apple-ios

# iOS Simulator arm64
echo "  iOS Simulator arm64..."
cargo build --release --target aarch64-apple-ios-sim

# Remove old framework if it exists
rm -rf NobleCMSCore.xcframework

# Create XCFramework
echo "Creating XCFramework..."
xcodebuild -create-xcframework \
  -library target/aarch64-apple-darwin/release/libnoble_cms_core.a \
    -headers include/ \
  -library target/aarch64-apple-ios/release/libnoble_cms_core.a \
    -headers include/ \
  -library target/aarch64-apple-ios-sim/release/libnoble_cms_core.a \
    -headers include/ \
  -output NobleCMSCore.xcframework

echo "Done: NobleCMSCore.xcframework"
