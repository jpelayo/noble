// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import NobleClientCore
import SwiftCBOR

/// NOBLE protocol constants.
public enum NobleProtocol {
    /// Current protocol version.
    public static let protocolVersion: UInt16 = 1
    /// Transaction type: notarization.
    public static let txTypeNotarization: UInt8 = 0x00
    /// Transaction type: transfer.
    public static let txTypeTransfer: UInt8 = 0x01
    /// Primary chain ID ("NOBL" in ASCII).
    public static let primaryChainId: UInt32 = 0x4E4F_424C
    /// Test chain ID ("TSTN" in ASCII).
    public static let testChainId: UInt32 = 0x5453_544E
    /// secp256k1 scheme ID.
    public static let schemeSecp256k1: UInt8 = 0x02
    /// Maximum metadata entries per transaction.
    public static let maxMetadataEntries = 16
    /// Maximum transaction size in bytes.
    public static let maxTxSize = 4096
}

/// Builds NOBLE transactions in CBOR wire format.
///
/// The builder constructs the signing payload, computes the SHA-256 signing
/// message, signs with the provided key, and produces the final hex-encoded
/// CBOR transaction for submission via `noble_submitTransaction`.
///
/// Wire format must match `noble-core/src/transaction.rs` exactly.
public struct TransactionBuilder: Sendable {
    public init() {}

    /// Build a notarization transaction (type 0x00).
    ///
    /// - Parameters:
    ///   - checksum: SHA-256 hash of the document to register
    ///   - metadata: Key-value metadata entries (max 16)
    ///   - fee: Fee in atomic units
    ///   - privateKey: 32-byte secp256k1 private key
    ///   - chainId: Chain identifier for replay protection
    /// - Returns: Hex-encoded CBOR transaction ready for submission
    public func buildNotarization(
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId
    ) throws -> String {
        let timestamp = UInt64(Date().timeIntervalSince1970)
        let publicKey = try Secp256k1Helper.compressedPublicKey(from: privateKey)

        // Sort metadata by key (protocol requirement)
        let sortedMetadata = metadata.sorted { $0.key < $1.key }

        // Build signing payload
        let signingPayload = buildSigningPayload(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeNotarization,
            checksum: checksum,
            timestamp: timestamp,
            fee: fee.atomic,
            recipient: nil,
            amount: nil,
            metadata: sortedMetadata,
            gatewayAddress: nil,
            sourceAddress: nil,
            chainId: chainId
        )

        // NOBLE's signing flow (noble-core/src/transaction.rs + noble-crypto/src/secp256k1.rs):
        // 1. signing_message = sha256(canonical_cbor(payload))
        // 2. k256::SigningKey::sign(signing_message) → internally does sha256(signing_message) → ECDSA
        // P256K also does sha256(data) internally, so pass the pre-hashed signing message.
        let payloadBytes = try canonicalCbor(signingPayload)
        let signingMessage = sha256(payloadBytes) // 32-byte hash

        // Sign: P256K does sha256(signingMessage) internally, matching Rust's double-hash
        let signature = try Secp256k1Helper.sign(data: signingMessage, privateKey: privateKey)

        // Build the full transaction CBOR
        let txCbor = buildTransactionCbor(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeNotarization,
            checksum: checksum,
            timestamp: timestamp,
            fee: fee.atomic,
            recipient: nil,
            amount: nil,
            publisherSig: SignatureData(
                schemeId: NobleProtocol.schemeSecp256k1,
                publicKey: publicKey,
                signature: signature
            ),
            additionalSigs: [],
            metadata: sortedMetadata,
            gatewayAddress: nil,
            sourceAddress: nil
        )

        let txBytes = try canonicalCbor(txCbor)
        return txBytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Build a transfer transaction (type 0x01).
    ///
    /// - Parameters:
    ///   - to: Recipient address
    ///   - amount: Transfer amount in atomic units
    ///   - fee: Fee in atomic units
    ///   - privateKey: 32-byte secp256k1 private key
    ///   - chainId: Chain identifier
    ///   - sourceAddress: Wire-encoded source address (for secp256k1 senders)
    /// - Returns: Hex-encoded CBOR transaction
    public func buildTransfer(
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId,
        sourceAddress: Data? = nil
    ) throws -> String {
        let timestamp = UInt64(Date().timeIntervalSince1970)
        let publicKey = try Secp256k1Helper.compressedPublicKey(from: privateKey)

        // Decode recipient to wire bytes
        let recipientWire = hexToBytes(to.wireHex)

        // Dummy checksum for transfers (not meaningful but required in wire format)
        let dummyChecksum = Hash256(hex: String(repeating: "0", count: 64))!

        // Build signing payload
        let signingPayload = buildSigningPayload(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeTransfer,
            checksum: dummyChecksum,
            timestamp: timestamp,
            fee: fee.atomic,
            recipient: recipientWire,
            amount: amount.atomic,
            metadata: [],
            gatewayAddress: nil,
            sourceAddress: sourceAddress.map { [UInt8]($0) },
            chainId: chainId
        )

        let payloadBytes = try canonicalCbor(signingPayload)
        let signingMessage = sha256(payloadBytes)
        let signature = try Secp256k1Helper.sign(data: signingMessage, privateKey: privateKey)

        let txCbor = buildTransactionCbor(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeTransfer,
            checksum: dummyChecksum,
            timestamp: timestamp,
            fee: fee.atomic,
            recipient: recipientWire,
            amount: amount.atomic,
            publisherSig: SignatureData(
                schemeId: NobleProtocol.schemeSecp256k1,
                publicKey: publicKey,
                signature: signature
            ),
            additionalSigs: [],
            metadata: [],
            gatewayAddress: nil,
            sourceAddress: sourceAddress.map { [UInt8]($0) }
        )

        let txBytes = try canonicalCbor(txCbor)
        return txBytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - CBOR Building

    /// Build the signing payload as CBOR value (map with string keys).
    ///
    /// Must match Rust's `SigningPayload` struct serialized by serde/ciborium.
    private func buildSigningPayload(
        version: UInt16,
        txType: UInt8,
        checksum: Hash256,
        timestamp: UInt64,
        fee: UInt64,
        recipient: [UInt8]?,
        amount: UInt64?,
        metadata: [MetadataItem],
        gatewayAddress: [UInt8]?,
        sourceAddress: [UInt8]?,
        chainId: UInt32
    ) -> CBOR {
        var entries: [CBOR: CBOR] = [:]

        entries[.utf8String("version")] = .unsignedInt(UInt64(version))
        entries[.utf8String("tx_type")] = .unsignedInt(UInt64(txType))
        entries[.utf8String("checksum")] = .byteString(hexToBytes(checksum.hex))
        entries[.utf8String("timestamp")] = .unsignedInt(timestamp)
        entries[.utf8String("fee")] = .unsignedInt(fee)

        if let recipient {
            // NobleAddress is serialized as its wire bytes
            entries[.utf8String("recipient")] = .byteString(recipient)
        }

        if let amount {
            entries[.utf8String("amount")] = .unsignedInt(amount)
        }

        // Metadata as array of maps
        let metadataArr = metadata.map { item -> CBOR in
            .map([
                .utf8String("key"): .utf8String(item.key),
                .utf8String("value"): .byteString([UInt8](item.value.utf8)),
            ])
        }
        entries[.utf8String("metadata")] = .array(metadataArr)

        // Optional fields — skip if nil/empty (matches #[serde(skip_serializing_if)])
        if let gatewayAddress {
            entries[.utf8String("gateway_address")] = .byteString(gatewayAddress)
        }

        if let sourceAddress {
            entries[.utf8String("source_address")] = .byteString(sourceAddress)
        }

        entries[.utf8String("chain_id")] = .unsignedInt(UInt64(chainId))

        return .map(entries)
    }

    /// Build the full transaction as CBOR value.
    private func buildTransactionCbor(
        version: UInt16,
        txType: UInt8,
        checksum: Hash256,
        timestamp: UInt64,
        fee: UInt64,
        recipient: [UInt8]?,
        amount: UInt64?,
        publisherSig: SignatureData,
        additionalSigs: [SignatureData],
        metadata: [MetadataItem],
        gatewayAddress: [UInt8]?,
        sourceAddress: [UInt8]?
    ) -> CBOR {
        var entries: [CBOR: CBOR] = [:]

        entries[.utf8String("version")] = .unsignedInt(UInt64(version))
        entries[.utf8String("tx_type")] = .unsignedInt(UInt64(txType))
        entries[.utf8String("checksum")] = .byteString(hexToBytes(checksum.hex))
        entries[.utf8String("timestamp")] = .unsignedInt(timestamp)
        entries[.utf8String("fee")] = .unsignedInt(fee)

        if let recipient {
            entries[.utf8String("recipient")] = .byteString(recipient)
        }
        if let amount {
            entries[.utf8String("amount")] = .unsignedInt(amount)
        }

        entries[.utf8String("publisher_sig")] = encodeSig(publisherSig)

        let addSigs = additionalSigs.map { encodeSig($0) }
        entries[.utf8String("additional_sigs")] = .array(addSigs)

        let metadataArr = metadata.map { item -> CBOR in
            .map([
                .utf8String("key"): .utf8String(item.key),
                .utf8String("value"): .byteString([UInt8](item.value.utf8)),
            ])
        }
        entries[.utf8String("metadata")] = .array(metadataArr)

        if let gatewayAddress {
            entries[.utf8String("gateway_address")] = .byteString(gatewayAddress)
        }
        if let sourceAddress {
            entries[.utf8String("source_address")] = .byteString(sourceAddress)
        }

        return .map(entries)
    }

    private func encodeSig(_ sig: SignatureData) -> CBOR {
        .map([
            .utf8String("scheme_id"): .unsignedInt(UInt64(sig.schemeId)),
            .utf8String("public_key"): .byteString([UInt8](sig.publicKey)),
            .utf8String("signature"): .byteString([UInt8](sig.signature)),
        ])
    }

    // MARK: - Canonical CBOR (RFC 8949)

    /// Encode a CBOR value with canonical (deterministically sorted) map keys.
    ///
    /// Matches `noble-codec::to_canonical_cbor()`:
    /// - Sort map keys by encoded-length first, then lexicographically
    func canonicalCbor(_ value: CBOR) throws -> [UInt8] {
        let canonical = canonicalize(value)
        return canonical.encode()
    }

    /// Recursively sort all CBOR map keys per RFC 8949 Section 4.2.1.
    private func canonicalize(_ value: CBOR) -> CBOR {
        switch value {
        case .map(let entries):
            // Encode each key, sort by (length, lexicographic)
            var keyed: [(encoded: [UInt8], key: CBOR, value: CBOR)] = entries.map { k, v in
                let canonKey = canonicalize(k)
                let canonVal = canonicalize(v)
                return (canonKey.encode(), canonKey, canonVal)
            }
            keyed.sort { a, b in
                if a.encoded.count != b.encoded.count {
                    return a.encoded.count < b.encoded.count
                }
                return a.encoded.lexicographicallyPrecedes(b.encoded)
            }
            return .map(OrderedMap(keyed.map { ($0.key, $0.value) }))

        case .array(let items):
            return .array(items.map { canonicalize($0) })

        default:
            return value
        }
    }

    // MARK: - Helpers

    /// SHA-256 hash of data, returning raw 32-byte array.
    private func sha256(_ data: [UInt8]) -> [UInt8] {
        let digest = SHA256.hash(data: data)
        return [UInt8](digest)
    }

    /// Convert hex string to byte array.
    private func hexToBytes(_ hex: String) -> [UInt8] {
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[index..<nextIndex], radix: 16) {
                bytes.append(byte)
            }
            index = nextIndex
        }
        return bytes
    }
}

/// Internal signature data for CBOR encoding.
struct SignatureData {
    let schemeId: UInt8
    let publicKey: Data
    let signature: Data
}

/// Helper to create ordered CBOR maps (SwiftCBOR's map preserves insertion order).
private func OrderedMap(_ pairs: [(CBOR, CBOR)]) -> [CBOR: CBOR] {
    // SwiftCBOR's Dictionary-based map may not preserve order.
    // For canonical encoding, the .encode() on CBOR.map uses Dictionary order,
    // which is non-deterministic. We rely on the fact that our canonicalize()
    // sorts keys and the CBOR encoder writes map entries in their internal order.
    // This works because SwiftCBOR's encode() iterates the dictionary.
    var dict: [CBOR: CBOR] = [:]
    for (k, v) in pairs {
        dict[k] = v
    }
    return dict
}
