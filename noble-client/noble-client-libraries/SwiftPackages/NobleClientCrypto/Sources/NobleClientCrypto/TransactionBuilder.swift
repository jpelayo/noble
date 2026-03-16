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
    /// Transaction type: coinbase.
    public static let txTypeCoinbase: UInt8 = 0x10
    /// Primary chain ID ("NOBL" in ASCII).
    public static let primaryChainId: UInt32 = 0x4E4F_424C
    /// Test chain ID ("TSTN" in ASCII).
    public static let testChainId: UInt32 = 0x5453_544E
    /// Ed25519 scheme ID.
    public static let schemeEd25519: UInt8 = 0x01
    /// secp256k1 scheme ID.
    public static let schemeSecp256k1: UInt8 = 0x02
    /// Maximum metadata entries per transaction.
    public static let maxMetadataEntries = 16
    /// Maximum transaction size in bytes.
    public static let maxTxSize = 4096
}

/// A UTXO outpoint reference for building transaction inputs.
public struct UtxoOutpoint: Sendable {
    public let txid: [UInt8]  // 32 bytes
    public let vout: UInt32
    public let value: UInt64  // Value of the referenced UTXO (for fee computation)

    public init(txid: [UInt8], vout: UInt32, value: UInt64) {
        self.txid = txid
        self.vout = vout
        self.value = value
    }

    /// Create from hex txid string.
    public init(txidHex: String, vout: UInt32, value: UInt64) {
        self.txid = TransactionBuilder.hexToBytes(txidHex)
        self.vout = vout
        self.value = value
    }
}

/// A transaction output for UTXO creation.
public struct TxOutputSpec: Sendable {
    public let value: UInt64
    public let addressWire: [UInt8]  // NobleAddress wire bytes

    public init(value: UInt64, addressWire: [UInt8]) {
        self.value = value
        self.addressWire = addressWire
    }
}

/// Builds NOBLE transactions in CBOR wire format (UTXO model).
///
/// The builder constructs the signing payload with input outpoints + outputs,
/// computes the SHA-256 signing message, signs with the provided key, and
/// produces the final hex-encoded CBOR transaction for submission via
/// `noble_submitTransaction`.
///
/// Wire format must match `noble-core/src/transaction.rs` exactly.
public struct TransactionBuilder: Sendable {
    public init() {}

    /// Build a notarization transaction (type 0x00, UTXO model).
    ///
    /// - Parameters:
    ///   - checksum: SHA-256 hash of the document to register
    ///   - metadata: Key-value metadata entries (max 16)
    ///   - fee: Desired fee in atomic units
    ///   - utxos: Selected UTXOs to spend (must cover fee)
    ///   - changeAddress: Wire-encoded address for change output
    ///   - privateKey: 32-byte secp256k1 private key
    ///   - chainId: Chain identifier for replay protection
    /// - Returns: Hex-encoded CBOR transaction ready for submission
    public func buildNotarization(
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId
    ) throws -> String {
        let timestamp = UInt64(Date().timeIntervalSince1970)
        let publicKey = try Secp256k1Helper.compressedPublicKey(from: privateKey)

        let sortedMetadata = metadata.sorted { $0.key < $1.key }

        // Build inputs from UTXOs
        let inputs = utxos.map { utxo in
            TxInputCbor(txid: utxo.txid, vout: utxo.vout)
        }

        // Build outputs: change = sum(inputs) - fee
        let totalInput = utxos.reduce(UInt64(0)) { $0 + $1.value }
        let change = totalInput - fee.atomic
        var outputs: [TxOutputCbor] = []
        if change > 0 {
            outputs.append(TxOutputCbor(value: change, addressWire: changeAddress))
        }

        let signingPayload = buildSigningPayload(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeNotarization,
            inputs: inputs,
            outputs: outputs,
            checksum: checksum,
            timestamp: timestamp,
            metadata: sortedMetadata,
            gatewayAddress: nil,
            chainId: chainId
        )

        let payloadBytes = canonicalCbor(signingPayload)
        let signingMessage = sha256(payloadBytes)
        let signature = try Secp256k1Helper.sign(data: signingMessage, privateKey: privateKey)

        let txCbor = buildTransactionCbor(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeNotarization,
            inputs: inputs,
            outputs: outputs,
            checksum: checksum,
            timestamp: timestamp,
            publisherSig: SignatureData(
                schemeId: NobleProtocol.schemeSecp256k1,
                publicKey: publicKey,
                signature: signature
            ),
            additionalSigs: [],
            metadata: sortedMetadata,
            gatewayAddress: nil
        )

        let txBytes = canonicalCbor(txCbor)
        return txBytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Build a transfer transaction (type 0x01, UTXO model).
    ///
    /// - Parameters:
    ///   - to: Recipient address
    ///   - amount: Transfer amount in atomic units
    ///   - fee: Fee in atomic units
    ///   - utxos: Selected UTXOs to spend (must cover amount + fee)
    ///   - changeAddress: Wire-encoded address for change output
    ///   - privateKey: 32-byte secp256k1 private key
    ///   - chainId: Chain identifier
    ///   - sourceAddress: Ignored (UTXO model — debit source is implicit from inputs)
    /// - Returns: Hex-encoded CBOR transaction
    public func buildTransfer(
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId,
        sourceAddress: Data? = nil
    ) throws -> String {
        let timestamp = UInt64(Date().timeIntervalSince1970)
        let publicKey = try Secp256k1Helper.compressedPublicKey(from: privateKey)
        let recipientWire = Self.hexToBytes(to.wireHex)

        let inputs = utxos.map { TxInputCbor(txid: $0.txid, vout: $0.vout) }

        // Build outputs: [0] recipient, [1] change (if any)
        var outputs: [TxOutputCbor] = [
            TxOutputCbor(value: amount.atomic, addressWire: recipientWire)
        ]
        let totalInput = utxos.reduce(UInt64(0)) { $0 + $1.value }
        let change = totalInput - amount.atomic - fee.atomic
        if change > 0 {
            outputs.append(TxOutputCbor(value: change, addressWire: changeAddress))
        }

        let dummyChecksum = Hash256(hex: String(repeating: "0", count: 64))!

        let signingPayload = buildSigningPayload(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeTransfer,
            inputs: inputs,
            outputs: outputs,
            checksum: dummyChecksum,
            timestamp: timestamp,
            metadata: [],
            gatewayAddress: nil,
            chainId: chainId
        )

        let payloadBytes = canonicalCbor(signingPayload)
        let signingMessage = sha256(payloadBytes)
        let signature = try Secp256k1Helper.sign(data: signingMessage, privateKey: privateKey)

        let txCbor = buildTransactionCbor(
            version: NobleProtocol.protocolVersion,
            txType: NobleProtocol.txTypeTransfer,
            inputs: inputs,
            outputs: outputs,
            checksum: dummyChecksum,
            timestamp: timestamp,
            publisherSig: SignatureData(
                schemeId: NobleProtocol.schemeSecp256k1,
                publicKey: publicKey,
                signature: signature
            ),
            additionalSigs: [],
            metadata: [],
            gatewayAddress: nil
        )

        let txBytes = canonicalCbor(txCbor)
        return txBytes.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Internal CBOR Types

    struct TxInputCbor {
        let txid: [UInt8]  // 32 bytes
        let vout: UInt32
    }

    struct TxOutputCbor {
        let value: UInt64
        let addressWire: [UInt8]
    }

    // MARK: - CBOR Building

    /// Build the signing payload as CBOR value (map with string keys).
    ///
    /// Must match Rust's `SigningPayload` struct serialized by serde/ciborium.
    private func buildSigningPayload(
        version: UInt16,
        txType: UInt8,
        inputs: [TxInputCbor],
        outputs: [TxOutputCbor],
        checksum: Hash256,
        timestamp: UInt64,
        metadata: [MetadataItem],
        gatewayAddress: [UInt8]?,
        chainId: UInt32
    ) -> CBOR {
        var entries: [CBOR: CBOR] = [:]

        entries[.utf8String("version")] = .unsignedInt(UInt64(version))
        entries[.utf8String("tx_type")] = .unsignedInt(UInt64(txType))

        // input_outpoints: array of outpoint maps
        let inputArr = inputs.map { inp -> CBOR in
            .map([
                .utf8String("txid"): .byteString(inp.txid),
                .utf8String("vout"): .unsignedInt(UInt64(inp.vout)),
            ])
        }
        entries[.utf8String("input_outpoints")] = .array(inputArr)

        // outputs: array of output maps
        let outputArr = outputs.map { out -> CBOR in
            .map([
                .utf8String("value"): .unsignedInt(out.value),
                .utf8String("address"): .byteString(out.addressWire),
            ])
        }
        entries[.utf8String("outputs")] = .array(outputArr)

        entries[.utf8String("checksum")] = .byteString(Self.hexToBytes(checksum.hex))
        entries[.utf8String("timestamp")] = .unsignedInt(timestamp)

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

        entries[.utf8String("chain_id")] = .unsignedInt(UInt64(chainId))

        return .map(entries)
    }

    /// Build the full transaction as CBOR value.
    private func buildTransactionCbor(
        version: UInt16,
        txType: UInt8,
        inputs: [TxInputCbor],
        outputs: [TxOutputCbor],
        checksum: Hash256,
        timestamp: UInt64,
        publisherSig: SignatureData,
        additionalSigs: [SignatureData],
        metadata: [MetadataItem],
        gatewayAddress: [UInt8]?
    ) -> CBOR {
        var entries: [CBOR: CBOR] = [:]

        entries[.utf8String("version")] = .unsignedInt(UInt64(version))
        entries[.utf8String("tx_type")] = .unsignedInt(UInt64(txType))

        // inputs: array of TxIn maps
        let inputArr = inputs.map { inp -> CBOR in
            .map([
                .utf8String("prev_output"): .map([
                    .utf8String("txid"): .byteString(inp.txid),
                    .utf8String("vout"): .unsignedInt(UInt64(inp.vout)),
                ]),
            ])
        }
        entries[.utf8String("inputs")] = .array(inputArr)

        // outputs: array of TxOut maps
        let outputArr = outputs.map { out -> CBOR in
            .map([
                .utf8String("value"): .unsignedInt(out.value),
                .utf8String("address"): .byteString(out.addressWire),
            ])
        }
        entries[.utf8String("outputs")] = .array(outputArr)

        entries[.utf8String("checksum")] = .byteString(Self.hexToBytes(checksum.hex))
        entries[.utf8String("timestamp")] = .unsignedInt(timestamp)

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

        return .map(entries)
    }

    private func encodeSig(_ sig: SignatureData) -> CBOR {
        .map([
            .utf8String("scheme_id"): .unsignedInt(UInt64(sig.schemeId)),
            .utf8String("public_key"): .byteString([UInt8](sig.publicKey)),
            .utf8String("signature"): .byteString([UInt8](sig.signature)),
        ])
    }

    // MARK: - Utilities

    static func hexToBytes(_ hex: String) -> [UInt8] {
        var bytes = [UInt8]()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let nextIdx = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[idx..<nextIdx], radix: 16) {
                bytes.append(byte)
            }
            idx = nextIdx
        }
        return bytes
    }

    func sha256(_ data: [UInt8]) -> [UInt8] {
        let hash = SHA256.hash(data: data)
        return Array(hash)
    }

    func canonicalCbor(_ value: CBOR) -> [UInt8] {
        // SwiftCBOR's encode produces canonical deterministic CBOR
        value.encode()
    }
}

/// Signature data for CBOR encoding.
public struct SignatureData: Sendable {
    let schemeId: UInt8
    let publicKey: Data
    let signature: Data

    public init(schemeId: UInt8, publicKey: Data, signature: Data) {
        self.schemeId = schemeId
        self.publicKey = publicKey
        self.signature = signature
    }
}
