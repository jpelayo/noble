// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore
import NobleTxCore

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
    public let value: UInt64

    public init(txid: [UInt8], vout: UInt32, value: UInt64) {
        self.txid = txid
        self.vout = vout
        self.value = value
    }

    /// Create from hex txid string.
    public init(txidHex: String, vout: UInt32, value: UInt64) {
        self.txid = Self.hexToBytes(txidHex)
        self.vout = vout
        self.value = value
    }

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
}

/// A transaction output for UTXO creation.
public struct TxOutputSpec: Sendable {
    public let value: UInt64
    public let addressWire: [UInt8]

    public init(value: UInt64, addressWire: [UInt8]) {
        self.value = value
        self.addressWire = addressWire
    }
}

/// Builds NOBLE transactions by delegating to the shared C library (`noble-tx-core`).
///
/// The C library produces byte-identical CBOR and signing payloads to the Rust node,
/// ensuring cross-platform transaction compatibility. All transaction building, signing,
/// and CBOR encoding happens in the C library — this struct is a thin Swift wrapper
/// that marshals parameters as JSON and parses the result.
public struct TransactionBuilder: Sendable {
    public init() {}

    /// Build a notarization transaction (type 0x00, UTXO model).
    public func buildNotarization(
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId
    ) throws -> String {
        let metadataArr = metadata.sorted { $0.key < $1.key }.map { item in
            ["key": item.key, "value": item.value] as [String: String]
        }

        let utxoArr = utxos.map { u in
            [
                "txid": u.txid.map { String(format: "%02x", $0) }.joined(),
                "vout": u.vout,
                "value": u.value,
            ] as [String: Any]
        }

        let params: [String: Any] = [
            "checksum": checksum.hex,
            "metadata": metadataArr,
            "fee": fee.atomic,
            "utxos": utxoArr,
            "change_address": changeAddress.map { String(format: "%02x", $0) }.joined(),
            "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
            "chain_id": chainId,
            "timestamp": UInt64(Date().timeIntervalSince1970),
        ]

        return try callNobleTxCore(noble_sign_notarization, params: params)
    }

    /// Build a transfer transaction (type 0x01, UTXO model).
    ///
    /// If `feeRate` > 0, the C library computes the exact fee from the actual
    /// transaction size (two-pass encoding). Otherwise `fee` is used as-is.
    public func buildTransfer(
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        feeRate: UInt64 = 0,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32 = NobleProtocol.primaryChainId,
        sourceAddress: Data? = nil
    ) throws -> String {
        let recipientWireHex = to.wireHex

        let utxoArr = utxos.map { u in
            [
                "txid": u.txid.map { String(format: "%02x", $0) }.joined(),
                "vout": u.vout,
                "value": u.value,
            ] as [String: Any]
        }

        var params: [String: Any] = [
            "recipient": recipientWireHex,
            "amount": amount.atomic,
            "fee": fee.atomic,
            "utxos": utxoArr,
            "change_address": changeAddress.map { String(format: "%02x", $0) }.joined(),
            "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
            "chain_id": chainId,
            "timestamp": UInt64(Date().timeIntervalSince1970),
        ]
        if feeRate > 0 {
            params["fee_rate"] = feeRate
        }

        return try callNobleTxCore(noble_sign_transfer, params: params)
    }

    // MARK: - C Library Bridge

    /// Call a noble-tx-core C function with JSON params, parse the JSON result.
    /// Returns the hex-encoded transaction CBOR string.
    private func callNobleTxCore(
        _ fn: @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
        params: [String: Any]
    ) throws -> String {
        let jsonData = try JSONSerialization.data(withJSONObject: params)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw TxBuilderError.serializationFailed("failed to encode params as UTF-8")
        }

        guard let resultPtr = jsonStr.withCString({ fn($0) }) else {
            throw TxBuilderError.signingFailed("noble-tx-core returned null")
        }

        let resultStr = String(cString: resultPtr)
        noble_free(resultPtr)

        guard let resultData = resultStr.data(using: .utf8),
              let result = try? JSONSerialization.jsonObject(with: resultData) as? [String: Any] else {
            throw TxBuilderError.signingFailed("failed to parse noble-tx-core result")
        }

        if let error = result["error"] as? String {
            throw TxBuilderError.signingFailed(error)
        }

        guard let txHex = result["tx_hex"] as? String else {
            throw TxBuilderError.signingFailed("missing tx_hex in result")
        }

        return txHex
    }
}

/// Errors from the transaction builder.
public enum TxBuilderError: Error, LocalizedError, @unchecked Sendable {
    case serializationFailed(String)
    case signingFailed(String)

    public var errorDescription: String? {
        switch self {
        case .serializationFailed(let msg): "Serialization error: \(msg) [NE-601]"
        case .signingFailed(let msg): "Signing error: \(msg) [NE-603]"
        }
    }
}

// MARK: - Coin Selection

/// UTXO coin selection — delegates to noble-tx-core C library.
public enum CoinSelector {

    /// Minimum value below which a change output is not worth creating.
    public static let dustThreshold: UInt64 = 500_000

    /// Select UTXOs to cover `target` (amount + fee).
    public static func select(
        from available: [UtxoOutpoint],
        target: UInt64
    ) throws -> [UtxoOutpoint] {
        let utxoArr = available.map { u in
            [
                "txid": u.txid.map { String(format: "%02x", $0) }.joined(),
                "vout": u.vout,
                "value": u.value,
            ] as [String: Any]
        }

        let params: [String: Any] = [
            "utxos": utxoArr,
            "target": target,
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: params)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw CoinSelectionError.insufficientFunds(available: 0, required: target)
        }

        guard let resultPtr = jsonStr.withCString({ noble_select_utxos($0) }) else {
            throw CoinSelectionError.insufficientFunds(available: 0, required: target)
        }

        let resultStr = String(cString: resultPtr)
        noble_free(resultPtr)

        guard let resultData = resultStr.data(using: .utf8),
              let result = try? JSONSerialization.jsonObject(with: resultData) as? [String: Any] else {
            throw CoinSelectionError.insufficientFunds(available: 0, required: target)
        }

        if result["error"] != nil {
            let total = available.reduce(UInt64(0)) { $0 + $1.value }
            throw CoinSelectionError.insufficientFunds(available: total, required: target)
        }

        guard let selectedArr = result["selected"] as? [[String: Any]] else {
            throw CoinSelectionError.insufficientFunds(available: 0, required: target)
        }

        return selectedArr.map { item in
            let txidHex = item["txid"] as? String ?? ""
            let vout = (item["vout"] as? NSNumber)?.uint32Value ?? 0
            let value = (item["value"] as? NSNumber)?.uint64Value ?? 0
            return UtxoOutpoint(txidHex: txidHex, vout: vout, value: value)
        }
    }
}

/// Errors from coin selection.
public enum CoinSelectionError: Error, LocalizedError {
    case insufficientFunds(available: UInt64, required: UInt64)

    public var errorDescription: String? {
        switch self {
        case .insufficientFunds(let available, let required):
            return "Insufficient funds: have \(available) atomic, need \(required) [NE-605]"
        }
    }
}

/// Signature data (kept for API compatibility with LiveTransactionSigner).
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
