// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Fee estimation from the node mempool.
public struct FeeEstimate: Codable, Equatable, Sendable {
    /// Minimum fee accepted by the node.
    public let minFee: NobleAmount
    /// Recommended fee for normal priority.
    public let recommendedFee: NobleAmount
    /// High-priority fee for expedited processing.
    public let highPriorityFee: NobleAmount

    public init(
        minFee: NobleAmount = NobleAmount(atomic: 1),
        recommendedFee: NobleAmount = NobleAmount(atomic: 100),
        highPriorityFee: NobleAmount = NobleAmount(atomic: 500)
    ) {
        self.minFee = minFee
        self.recommendedFee = recommendedFee
        self.highPriorityFee = highPriorityFee
    }
}
