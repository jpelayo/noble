// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// An on-chain document registration record returned by the node.
public struct RegistrationRecord: Codable, Equatable, Sendable, Identifiable {
    public var id: String { txId.hex }
    public let txId: Hash256
    public let checksum: Hash256
    public let issuer: NobleAddress
    public let blockHeight: UInt64
    public let timestamp: Date
    public let metadata: [MetadataItem]
    public let fee: NobleAmount

    public init(
        txId: Hash256,
        checksum: Hash256,
        issuer: NobleAddress,
        blockHeight: UInt64,
        timestamp: Date,
        metadata: [MetadataItem] = [],
        fee: NobleAmount = .zero
    ) {
        self.txId = txId
        self.checksum = checksum
        self.issuer = issuer
        self.blockHeight = blockHeight
        self.timestamp = timestamp
        self.metadata = metadata
        self.fee = fee
    }
}
