// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Fee rate estimation from the node mempool and network peers.
/// All rates are in groats per byte.
public struct FeeEstimate: Codable, Equatable, Sendable {
    /// Low fee rate (P25 of mempool) in groats/byte.
    public let lowFeeRate: UInt64
    /// Recommended fee rate (P50) in groats/byte.
    public let recommendedFeeRate: UInt64
    /// High priority fee rate (P75) in groats/byte.
    public let highPriorityFeeRate: UInt64
    /// Lowest min_fee_rate among connected peers (from NodeAnnounce gossip).
    public let networkMinFeeRate: UInt64
    /// Median min_fee_rate among connected peers.
    public let networkMedianFeeRate: UInt64

    public init(
        lowFeeRate: UInt64 = 1,
        recommendedFeeRate: UInt64 = 1,
        highPriorityFeeRate: UInt64 = 1,
        networkMinFeeRate: UInt64 = 1,
        networkMedianFeeRate: UInt64 = 1
    ) {
        self.lowFeeRate = lowFeeRate
        self.recommendedFeeRate = recommendedFeeRate
        self.highPriorityFeeRate = highPriorityFeeRate
        self.networkMinFeeRate = networkMinFeeRate
        self.networkMedianFeeRate = networkMedianFeeRate
    }
}
