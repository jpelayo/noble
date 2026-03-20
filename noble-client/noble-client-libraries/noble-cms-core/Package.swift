// swift-tools-version: 6.0
// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// SPM package for noble-cms-core: CMS/PKCS#7 signing module.
// This is a binary target — the Rust library is precompiled via build-apple.sh
// into NobleCMSCore.xcframework. SPM does not compile any source here.

import PackageDescription

let package = Package(
    name: "NobleCMSCore",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleCMSCore", targets: ["NobleCMSCore"]),
    ],
    targets: [
        .binaryTarget(
            name: "NobleCMSCore",
            path: "NobleCMSCore.xcframework"
        ),
    ]
)
