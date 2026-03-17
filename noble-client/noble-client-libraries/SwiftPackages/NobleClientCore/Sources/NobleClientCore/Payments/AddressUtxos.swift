// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// UTXOs for a NOBLE address.
public struct AddressUtxos: Codable, Equatable, Sendable {
    public let address: String
    public let utxos: [UtxoEntry]

    public init(address: String, utxos: [UtxoEntry] = []) {
        self.address = address
        self.utxos = utxos
    }
}

/// A single unspent transaction output.
public struct UtxoEntry: Codable, Equatable, Sendable {
    public let txid: String
    public let vout: UInt32
    public let value: UInt64
    public let height: UInt64
    public let isCoinbase: Bool

    public init(txid: String, vout: UInt32, value: UInt64, height: UInt64 = 0, isCoinbase: Bool = false) {
        self.txid = txid
        self.vout = vout
        self.value = value
        self.height = height
        self.isCoinbase = isCoinbase
    }
}
