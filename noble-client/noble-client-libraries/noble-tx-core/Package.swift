// swift-tools-version: 6.0
// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// SPM package for noble-tx-core: shared C transaction library.
// Xcode compiles the C source for every Apple target natively.
//
// NOTE: secp256k1 is NOT compiled here — it comes from the P256K (secp256k1.swift)
// package that NobleClientCrypto already depends on. The secp256k1.h header in
// vendor/ is used for compilation only; the symbols resolve at link time from P256K.

import PackageDescription

let package = Package(
    name: "NobleTxCore",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [
        .library(name: "NobleTxCore", targets: ["NobleTxCore"]),
    ],
    targets: [
        .target(
            name: "NobleTxCore",
            path: ".",
            exclude: [
                "test",
                "Cargo.toml",
                "build.rs",
                "Package.swift",
                "rust-src",
                "vendor/secp256k1/src",
                "vendor/secp256k1/COPYING",
            ],
            sources: [
                "src/cbor.c",
                "src/cbor_decode.c",
                "src/sha256.c",
                "src/hex.c",
                "src/tx_builder.c",
                "src/signing.c",
                "src/coin_select.c",
                "src/json.c",
                "src/aes_gcm.c",
                "src/hkdf.c",
                "src/ecies.c",
                "src/metadata_fields.c",
                "src/noble_tx.c",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("src"),
                .headerSearchPath("vendor/secp256k1/include"),
                .unsafeFlags(["-Wno-unused-function"]),
            ]
        ),
    ]
)
