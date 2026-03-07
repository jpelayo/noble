// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import P256K

/// Helper for secp256k1 key operations using GigaBitcoin/secp256k1.swift (P256K).
///
/// Signing flow for NOBLE compatibility:
/// 1. Caller computes `signing_message = sha256(canonical_cbor(payload))`
/// 2. Caller passes `signing_message` to `sign(data:)`
/// 3. P256K internally computes `sha256(signing_message)` before ECDSA
/// 4. This matches Rust's `k256::SigningKey::sign(signing_message)` which also double-hashes
///
/// Signatures are 64-byte compact (r || s) format, matching NOBLE's wire format.
enum Secp256k1Helper {

    /// Derive the compressed (33-byte) public key from a 32-byte private key.
    static func compressedPublicKey(from privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else {
            throw CryptoError.invalidPrivateKey
        }
        let sk = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
        return sk.publicKey.dataRepresentation
    }

    /// Sign data with a secp256k1 private key.
    ///
    /// The P256K library internally computes SHA-256(data) before ECDSA signing.
    /// For NOBLE: pass the 32-byte `sha256(canonical_cbor(payload))` so the
    /// result matches Rust's `k256::SigningKey::sign(sha256(cbor))`.
    ///
    /// Returns the compact 64-byte (r || s) ECDSA signature.
    static func sign(data: [UInt8], privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else {
            throw CryptoError.invalidPrivateKey
        }

        let sk = try P256K.Signing.PrivateKey(dataRepresentation: privateKey)
        let ecdsaSig = try sk.signature(for: Data(data))
        return ecdsaSig.dataRepresentation
    }

    /// Verify a secp256k1 ECDSA signature over data.
    ///
    /// The library internally computes SHA-256(data) before verifying.
    static func verify(
        data: [UInt8],
        signature: Data,
        publicKey: Data
    ) throws -> Bool {
        let pk = try P256K.Signing.PublicKey(
            dataRepresentation: publicKey,
            format: .compressed
        )
        let sig = try P256K.Signing.ECDSASignature(dataRepresentation: signature)
        return pk.isValidSignature(sig, for: Data(data))
    }

    /// Generate a new random secp256k1 private key (32 bytes).
    static func generatePrivateKey() -> Data {
        let sk = try! P256K.Signing.PrivateKey()
        return sk.dataRepresentation
    }
}
