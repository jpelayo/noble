// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Balance information for a NOBLE address.
public struct AddressBalance: Codable, Equatable, Sendable {
    public let address: NobleAddress
    public let balance: NobleAmount
    public let available: NobleAmount
    public let pending: NobleAmount
    public let txCount: UInt64
    public let immatureCount: UInt64
    public let immatureValue: UInt64

    public init(
        address: NobleAddress,
        balance: NobleAmount = .zero,
        available: NobleAmount = .zero,
        pending: NobleAmount = .zero,
        txCount: UInt64 = 0,
        immatureCount: UInt64 = 0,
        immatureValue: UInt64 = 0
    ) {
        self.address = address
        self.balance = balance
        self.available = available
        self.pending = pending
        self.txCount = txCount
        self.immatureCount = immatureCount
        self.immatureValue = immatureValue
    }
}
