// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0
//
// Build script: compiles the noble-tx-core C source via the cc crate.
// Used by NobleWin (Windows) and NobleDoc (Linux) Rust apps.

fn main() {
    cc::Build::new()
        // Noble sources
        .file("src/cbor.c")
        .file("src/cbor_decode.c")
        .file("src/sha256.c")
        .file("src/hex.c")
        .file("src/tx_builder.c")
        .file("src/signing.c")
        .file("src/coin_select.c")
        .file("src/json.c")
        .file("src/aes_gcm.c")
        .file("src/hkdf.c")
        .file("src/ecies.c")
        .file("src/noble_tx.c")
        // Bitcoin Core's libsecp256k1
        .file("vendor/secp256k1/src/secp256k1.c")
        .file("vendor/secp256k1/src/precomputed_ecmult.c")
        .file("vendor/secp256k1/src/precomputed_ecmult_gen.c")
        // Include paths
        .include("src")
        .include("include")
        .include("vendor/secp256k1/include")
        .include("vendor/secp256k1/src")
        // Defines
        .define("HAVE_CONFIG_H", None)
        // Compiler flags
        .flag_if_supported("-Wno-unused-function")
        .opt_level(2)
        .compile("noble_tx_core");
}
