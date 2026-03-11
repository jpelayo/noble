// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Basic information about the connected NOBLE node.
public struct NodeInfo: Codable, Equatable, Sendable {
    /// Software version string (e.g. "0.30.0").
    public let version: String

    /// Genesis-derived chain identifier (e.g. "0x4E4F424C").
    public let chainId: String

    /// Current block height.
    public let blockHeight: UInt64

    /// Number of connected peers.
    public let peerCount: Int

    /// Whether the node is syncing.
    public let isSyncing: Bool

    /// Maps the JSON `network` key from the node RPC to `chainId`.
    private enum CodingKeys: String, CodingKey {
        case version
        case chainId = "network"
        case blockHeight
        case peerCount
        case isSyncing
    }

    public init(
        version: String = "",
        chainId: String = "",
        blockHeight: UInt64 = 0,
        peerCount: Int = 0,
        isSyncing: Bool = false
    ) {
        self.version = version
        self.chainId = chainId
        self.blockHeight = blockHeight
        self.peerCount = peerCount
        self.isSyncing = isSyncing
    }
}
