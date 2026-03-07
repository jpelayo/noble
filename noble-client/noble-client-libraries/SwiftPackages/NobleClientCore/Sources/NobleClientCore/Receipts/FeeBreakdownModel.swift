// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Breakdown of fees for a transaction.
public struct FeeBreakdownModel: Codable, Equatable, Sendable {
    /// Base protocol fee.
    public let baseFee: NobleAmount
    /// Size-based fee component.
    public let sizeFee: NobleAmount
    /// Total fee paid.
    public let totalFee: NobleAmount

    public init(
        baseFee: NobleAmount = .zero,
        sizeFee: NobleAmount = .zero,
        totalFee: NobleAmount = .zero
    ) {
        self.baseFee = baseFee
        self.sizeFee = sizeFee
        self.totalFee = totalFee
    }
}
