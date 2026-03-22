// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// A pending (mempool) transaction's UTXO flow relative to an address.
public struct PendingTransaction: Codable, Sendable, Identifiable {
    public var id: String { txId }
    public let txId: String
    /// Total value sent to other addresses (groats).
    public let sent: UInt64
    /// Change returned to the sender (groats).
    public let change: UInt64
    /// Transaction fee (groats).
    public let fee: UInt64
    /// Net debit: sent + fee (groats).
    public let netDebit: UInt64

    public init(txId: String, sent: UInt64, change: UInt64, fee: UInt64, netDebit: UInt64) {
        self.txId = txId
        self.sent = sent
        self.change = change
        self.fee = fee
        self.netDebit = netDebit
    }
}
