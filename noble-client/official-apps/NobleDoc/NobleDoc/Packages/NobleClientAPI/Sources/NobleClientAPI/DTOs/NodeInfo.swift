// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Node information returned by `noble_getNodeInfo`.
public struct NodeInfo: Codable, Equatable, Sendable {
    /// Software version string (e.g. "0.20.0").
    public let version: String

    /// Network label (e.g. "mainnet", "testnet").
    public let network: String

    /// Current block height.
    public let blockHeight: UInt64

    /// Number of connected peers.
    public let peerCount: Int

    /// Whether the node is syncing.
    public let isSyncing: Bool

    public init(
        version: String = "",
        network: String = "",
        blockHeight: UInt64 = 0,
        peerCount: Int = 0,
        isSyncing: Bool = false
    ) {
        self.version = version
        self.network = network
        self.blockHeight = blockHeight
        self.peerCount = peerCount
        self.isSyncing = isSyncing
    }
}
