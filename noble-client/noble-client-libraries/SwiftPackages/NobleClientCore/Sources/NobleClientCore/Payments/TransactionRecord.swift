// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A transaction as returned by the node (both local and on-chain).
public struct TransactionRecord: Codable, Equatable, Sendable, Identifiable {
    public var id: String { txId.hex }
    public let txId: Hash256
    public let txType: TransactionType
    public let status: TransactionStatus
    public let from: NobleAddress
    public let to: NobleAddress?
    public let amount: NobleAmount
    public let fee: NobleAmount
    public let blockHeight: UInt64?
    public let timestamp: Date?
    public let checksum: Hash256?

    public init(
        txId: Hash256,
        txType: TransactionType,
        status: TransactionStatus,
        from: NobleAddress,
        to: NobleAddress? = nil,
        amount: NobleAmount = .zero,
        fee: NobleAmount = .zero,
        blockHeight: UInt64? = nil,
        timestamp: Date? = nil,
        checksum: Hash256? = nil
    ) {
        self.txId = txId
        self.txType = txType
        self.status = status
        self.from = from
        self.to = to
        self.amount = amount
        self.fee = fee
        self.blockHeight = blockHeight
        self.timestamp = timestamp
        self.checksum = checksum
    }
}
