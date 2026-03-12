// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Network-level info from the connected NOBLE node.
public struct NetworkInfo: Codable, Equatable, Sendable {
    /// Total number of connected peers.
    public let peerCount: Int

    /// Number of inbound peers.
    public let inbound: Int

    /// Number of outbound peers.
    public let outbound: Int

    /// Median clock offset from peers in milliseconds.
    public let clockOffsetMs: Int64

    public init(
        peerCount: Int = 0,
        inbound: Int = 0,
        outbound: Int = 0,
        clockOffsetMs: Int64 = 0
    ) {
        self.peerCount = peerCount
        self.inbound = inbound
        self.outbound = outbound
        self.clockOffsetMs = clockOffsetMs
    }
}
