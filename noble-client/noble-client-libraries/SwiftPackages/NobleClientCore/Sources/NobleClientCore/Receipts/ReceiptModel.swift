// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A receipt for a submitted transaction (shareable).
public struct ReceiptModel: Codable, Equatable, Sendable, Identifiable {
    public var id: String { txId.hex }
    public let txId: Hash256
    public let txType: TransactionType
    public let status: TransactionStatus
    public let timestamp: Date
    public let blockHeight: UInt64?
    public let feeBreakdown: FeeBreakdownModel
    public let checksum: Hash256?
    public let recipient: NobleAddress?
    public let amount: NobleAmount?

    public init(
        txId: Hash256,
        txType: TransactionType,
        status: TransactionStatus,
        timestamp: Date,
        blockHeight: UInt64? = nil,
        feeBreakdown: FeeBreakdownModel = FeeBreakdownModel(),
        checksum: Hash256? = nil,
        recipient: NobleAddress? = nil,
        amount: NobleAmount? = nil
    ) {
        self.txId = txId
        self.txType = txType
        self.status = status
        self.timestamp = timestamp
        self.blockHeight = blockHeight
        self.feeBreakdown = feeBreakdown
        self.checksum = checksum
        self.recipient = recipient
        self.amount = amount
    }
}
