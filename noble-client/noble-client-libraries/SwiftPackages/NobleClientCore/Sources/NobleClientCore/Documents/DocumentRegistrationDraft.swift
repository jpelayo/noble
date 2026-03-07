// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A local draft for a document registration before signing and submission.
public struct DocumentRegistrationDraft: Identifiable, Sendable {
    public let id: UUID
    public var fileName: String
    public var fileURL: URL?
    public var checksum: Hash256?
    public var previousVersion: Hash256?
    public var metadata: [MetadataItem]
    public var fee: NobleAmount

    public init(
        id: UUID = UUID(),
        fileName: String = "",
        fileURL: URL? = nil,
        checksum: Hash256? = nil,
        previousVersion: Hash256? = nil,
        metadata: [MetadataItem] = [],
        fee: NobleAmount = .zero
    ) {
        self.id = id
        self.fileName = fileName
        self.fileURL = fileURL
        self.checksum = checksum
        self.previousVersion = previousVersion
        self.metadata = metadata
        self.fee = fee
    }

    /// Maximum metadata entries allowed by protocol.
    public static let maxMetadataEntries = 16
}
