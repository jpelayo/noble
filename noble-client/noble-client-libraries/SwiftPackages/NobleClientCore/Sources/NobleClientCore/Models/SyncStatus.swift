// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Synchronization status of the connected node.
public struct SyncStatus: Codable, Equatable, Sendable {
    /// Whether the node considers itself fully synced.
    public let isSynced: Bool
    /// Current local chain height.
    public let currentHeight: UInt64
    /// Highest block height known from peers.
    public let highestKnown: UInt64
    /// Sync progress from 0.0 to 1.0.
    public let progress: Double
    /// Node alignment state label from the healing system.
    /// Values: "Aligned", "Syncing", "Catching Up", "Diverged",
    /// "Isolated", "Bootstrapping", "Creating", "Unknown".
    public let state: String

    public init(
        isSynced: Bool = true,
        currentHeight: UInt64 = 0,
        highestKnown: UInt64 = 0,
        progress: Double = 1.0,
        state: String = "Unknown"
    ) {
        self.isSynced = isSynced
        self.currentHeight = currentHeight
        self.highestKnown = highestKnown
        self.progress = progress
        self.state = state
    }
}
