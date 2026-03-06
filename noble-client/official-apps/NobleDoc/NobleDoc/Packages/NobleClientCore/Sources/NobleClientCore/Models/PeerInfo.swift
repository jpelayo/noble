// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Information about a connected peer.
public struct PeerInfo: Codable, Equatable, Sendable, Identifiable {
    public var id: String { peerId }
    /// libp2p peer ID.
    public let peerId: String
    /// Connection direction ("inbound" or "outbound").
    public let direction: String
    /// Multiaddr of the peer.
    public let address: String?
    /// Operator's node name.
    public let nodeName: String?
    /// ISO country code.
    public let countryCode: String?
    /// When this peer connected.
    public let connectedAt: Date?
    /// Peer's reported chain height.
    public let chainTipHeight: UInt64?

    public init(
        peerId: String,
        direction: String = "outbound",
        address: String? = nil,
        nodeName: String? = nil,
        countryCode: String? = nil,
        connectedAt: Date? = nil,
        chainTipHeight: UInt64? = nil
    ) {
        self.peerId = peerId
        self.direction = direction
        self.address = address
        self.nodeName = nodeName
        self.countryCode = countryCode
        self.connectedAt = connectedAt
        self.chainTipHeight = chainTipHeight
    }
}
