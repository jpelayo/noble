// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// A single key-value metadata entry attached to a document registration.
///
/// Constraints (from NOBLE protocol):
/// - Max 16 entries per transaction
/// - Key max: 64 bytes
/// - Value max: 256 bytes
public struct MetadataItem: Codable, Equatable, Sendable, Identifiable {
    public var id: String { key }
    public var key: String
    public var value: String

    public init(key: String, value: String) {
        self.key = key
        self.value = value
    }

    /// Whether this entry fits within protocol limits.
    public var isValid: Bool {
        key.utf8.count <= 64 && value.utf8.count <= 256 && !key.isEmpty
    }
}
