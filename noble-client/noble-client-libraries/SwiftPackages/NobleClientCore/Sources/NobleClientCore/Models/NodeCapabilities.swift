// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Detected capabilities of a connected NOBLE node.
///
/// Used for graceful degradation — the client skips UI features
/// when the connected node doesn't support the corresponding RPCs.
public struct NodeCapabilities: Codable, Equatable, Sendable {

    /// Whether the node supports `noble_getCycleStatus`.
    public var cycleStatus: Bool

    /// Whether the node supports `noble_getSyncStatus`.
    public var syncStatus: Bool

    /// Whether the node supports `noble_getPeerInfo`.
    public var peerInfo: Bool

    /// Whether the node supports `noble_getAddressBalance`.
    public var addressBalance: Bool

    /// Whether the node supports `noble_getAddressHistory`.
    public var addressHistory: Bool

    public init(
        cycleStatus: Bool = false,
        syncStatus: Bool = false,
        peerInfo: Bool = false,
        addressBalance: Bool = true,
        addressHistory: Bool = true
    ) {
        self.cycleStatus = cycleStatus
        self.syncStatus = syncStatus
        self.peerInfo = peerInfo
        self.addressBalance = addressBalance
        self.addressHistory = addressHistory
    }

    /// All capabilities available.
    public static let full = NodeCapabilities(
        cycleStatus: true,
        syncStatus: true,
        peerInfo: true,
        addressBalance: true,
        addressHistory: true
    )
}
