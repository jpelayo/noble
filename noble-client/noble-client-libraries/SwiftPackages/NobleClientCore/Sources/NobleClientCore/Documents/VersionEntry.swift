// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A single version in a document's on-chain version history.
public struct VersionEntry: Codable, Equatable, Sendable, Identifiable {
    public var id: String { checksum.hex }
    public let checksum: Hash256
    public let previousChecksum: Hash256?
    public let txId: Hash256
    public let issuer: NobleAddress
    public let blockHeight: UInt64
    public let timestamp: Date

    public init(
        checksum: Hash256,
        previousChecksum: Hash256?,
        txId: Hash256,
        issuer: NobleAddress,
        blockHeight: UInt64,
        timestamp: Date
    ) {
        self.checksum = checksum
        self.previousChecksum = previousChecksum
        self.txId = txId
        self.issuer = issuer
        self.blockHeight = blockHeight
        self.timestamp = timestamp
    }
}
