// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Swift wrapper for the noble-client-core Rust shared library.
/// All transaction building, signing, and coin selection goes through here —
/// ensuring identical CBOR encoding with the node.
public enum NobleClientCore {

    /// Build and sign a transfer transaction.
    /// Returns JSON with `tx_hex` and `tx_id`, or throws on error.
    public static func signTransfer(
        recipient: String,
        amount: UInt64,
        fee: UInt64,
        utxos: [[String: Any]],
        changeAddress: String,
        privateKey: Data,
        chainId: UInt32
    ) throws -> (txHex: String, txId: String) {
        let params: [String: Any] = [
            "recipient": recipient,
            "amount": amount,
            "fee": fee,
            "utxos": utxos,
            "change_address": changeAddress,
            "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
            "chain_id": chainId,
        ]
        let result = try callFFI(noble_client_sign_transfer, params: params)
        guard let txHex = result["tx_hex"] as? String,
              let txId = result["tx_id"] as? String else {
            throw FFIError.missingField("tx_hex or tx_id")
        }
        return (txHex, txId)
    }

    /// Build and sign a notarization transaction.
    public static func signNotarization(
        checksum: String,
        metadata: [(key: String, value: String)],
        fee: UInt64,
        utxos: [[String: Any]],
        changeAddress: String,
        privateKey: Data,
        chainId: UInt32
    ) throws -> (txHex: String, txId: String) {
        let metadataArr = metadata.map { ["key": $0.key, "value": $0.value] }
        let params: [String: Any] = [
            "checksum": checksum,
            "metadata": metadataArr,
            "fee": fee,
            "utxos": utxos,
            "change_address": changeAddress,
            "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
            "chain_id": chainId,
        ]
        let result = try callFFI(noble_client_sign_notarization, params: params)
        guard let txHex = result["tx_hex"] as? String,
              let txId = result["tx_id"] as? String else {
            throw FFIError.missingField("tx_hex or tx_id")
        }
        return (txHex, txId)
    }

    /// Run coin selection on available UTXOs.
    public static func selectUtxos(
        utxos: [[String: Any]],
        target: UInt64
    ) throws -> [[String: Any]] {
        let params: [String: Any] = ["utxos": utxos, "target": target]
        let result = try callFFI(noble_client_select_utxos, params: params)
        return result["selected"] as? [[String: Any]] ?? []
    }

    /// Generate a BIP-39 mnemonic.
    public static func generateMnemonic(wordCount: Int) throws -> [String] {
        let params: [String: Any] = ["word_count": wordCount]
        let result = try callFFI(noble_client_generate_mnemonic, params: params)
        return result["words"] as? [String] ?? []
    }

    /// Derive a secp256k1 keypair from a mnemonic.
    public static func deriveKeypair(words: [String]) throws -> (privateKey: String, publicKey: String) {
        let params: [String: Any] = ["words": words]
        let result = try callFFI(noble_client_derive_keypair, params: params)
        guard let sk = result["private_key"] as? String,
              let pk = result["public_key"] as? String else {
            throw FFIError.missingField("private_key or public_key")
        }
        return (sk, pk)
    }

    // MARK: - FFI Bridge

    private static func callFFI(
        _ fn: (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
        params: [String: Any]
    ) throws -> [String: Any] {
        let jsonData = try JSONSerialization.data(withJSONObject: params)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw FFIError.encodingFailed
        }

        guard let resultPtr = jsonStr.withCString({ fn($0) }) else {
            throw FFIError.nullResult
        }
        defer { noble_client_free(resultPtr) }

        let resultStr = String(cString: resultPtr)
        guard let data = resultStr.data(using: .utf8),
              let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw FFIError.decodingFailed
        }

        if let error = dict["error"] as? String {
            throw FFIError.rustError(error)
        }

        return dict
    }

    public enum FFIError: LocalizedError {
        case encodingFailed
        case nullResult
        case decodingFailed
        case missingField(String)
        case rustError(String)

        public var errorDescription: String? {
            switch self {
            case .encodingFailed: "Failed to encode parameters [NE-205]"
            case .nullResult: "Rust FFI returned null [NE-704]"
            case .decodingFailed: "Failed to decode Rust response [NE-406]"
            case .missingField(let f): "Missing field in response: \(f) [NE-406]"
            case .rustError(let msg): "\(msg) [NE-701]"
            }
        }
    }
}
