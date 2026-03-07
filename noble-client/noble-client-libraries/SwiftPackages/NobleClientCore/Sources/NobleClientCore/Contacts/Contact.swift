// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A contact in the app's local address book.
///
/// Fields are compatible with vCard v3.0 format for import/export.
/// NOBLE-specific fields use custom `X-NOBLE-*` vCard extensions.
public struct Contact: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    public var firstName: String
    public var lastName: String
    public var company: String
    public var email: String
    /// NOBLE public key in wire-hex format (e.g. "0201abcdef...").
    public var noblePubkey: String
    /// Bitcoin address (bc1q.../bc1p.../1.../empty).
    public var bitcoinKey: String
    public var notes: String
    public var createdAt: Date
    public var updatedAt: Date
    public var isFavorite: Bool

    public init(
        id: UUID = UUID(),
        firstName: String = "",
        lastName: String = "",
        company: String = "",
        email: String = "",
        noblePubkey: String = "",
        bitcoinKey: String = "",
        notes: String = "",
        createdAt: Date = .now,
        updatedAt: Date = .now,
        isFavorite: Bool = false
    ) {
        self.id = id
        self.firstName = firstName
        self.lastName = lastName
        self.company = company
        self.email = email
        self.noblePubkey = noblePubkey
        self.bitcoinKey = bitcoinKey
        self.notes = notes
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.isFavorite = isFavorite
    }

    /// Full display name.
    public var displayName: String {
        let full = "\(firstName) \(lastName)".trimmingCharacters(in: .whitespaces)
        return full.isEmpty ? company : full
    }
}
