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
    /// Whether this contact represents the user's own identity ("My Card").
    /// Only one contact should have this flag set. My Card is undeletable.
    public var isMyCard: Bool
    /// PKCS#12-imported signing keys for CMS per-field metadata signatures.
    public var signingKeys: [SigningKeyEntry]

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
        isFavorite: Bool = false,
        isMyCard: Bool = false,
        signingKeys: [SigningKeyEntry] = []
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
        self.isMyCard = isMyCard
        self.signingKeys = signingKeys
    }

    // Custom Codable: decode new fields with defaults for backward compatibility.
    enum CodingKeys: String, CodingKey {
        case id, firstName, lastName, company, email, noblePubkey, bitcoinKey
        case notes, createdAt, updatedAt, isFavorite, isMyCard, signingKeys
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UUID.self, forKey: .id)
        firstName = try c.decodeIfPresent(String.self, forKey: .firstName) ?? ""
        lastName = try c.decodeIfPresent(String.self, forKey: .lastName) ?? ""
        company = try c.decodeIfPresent(String.self, forKey: .company) ?? ""
        email = try c.decodeIfPresent(String.self, forKey: .email) ?? ""
        noblePubkey = try c.decodeIfPresent(String.self, forKey: .noblePubkey) ?? ""
        bitcoinKey = try c.decodeIfPresent(String.self, forKey: .bitcoinKey) ?? ""
        notes = try c.decodeIfPresent(String.self, forKey: .notes) ?? ""
        createdAt = try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? .now
        updatedAt = try c.decodeIfPresent(Date.self, forKey: .updatedAt) ?? .now
        isFavorite = try c.decodeIfPresent(Bool.self, forKey: .isFavorite) ?? false
        isMyCard = try c.decodeIfPresent(Bool.self, forKey: .isMyCard) ?? false
        signingKeys = try c.decodeIfPresent([SigningKeyEntry].self, forKey: .signingKeys) ?? []
    }

    /// Full display name.
    public var displayName: String {
        let full = "\(firstName) \(lastName)".trimmingCharacters(in: .whitespaces)
        return full.isEmpty ? company : full
    }
}

/// A signing key entry stored on a contact card.
///
/// Private keys are stored in the system Keychain (referenced by `id`),
/// NOT in this struct. The `certificateDER` holds the full X.509 certificate
/// for CMS signature verification and signer identity display.
public struct SigningKeyEntry: Codable, Equatable, Sendable, Identifiable {
    public let id: UUID
    /// Human-readable label (e.g. "Work Certificate", "Personal").
    public var label: String
    /// Key algorithm: "p256" (corporate PKI) or "secp256k1" (Noble native).
    public var algorithm: String
    /// Compressed public key hex (33 bytes SEC1).
    public var publicKeyHex: String
    /// Whether the private key exists in the system Keychain.
    public var hasPrivateKey: Bool
    /// Certificate subject CN (e.g. "John Doe, Acme Corp"). Nil if no cert.
    public var certificateSubject: String?
    /// Base64-encoded DER X.509 certificate. Needed for CMS verification —
    /// the verifier uses it to validate the CA chain and display the subject name.
    public var certificateDER: String?
    /// SubjectKeyIdentifier hex (20 bytes, SHA-1 of public key).
    /// Links on-chain CMS `SignerInfo.sid` to this certificate.
    public var subjectKeyIdentifier: String?
    public var importedAt: Date

    public init(
        id: UUID = UUID(),
        label: String = "",
        algorithm: String = "p256",
        publicKeyHex: String = "",
        hasPrivateKey: Bool = false,
        certificateSubject: String? = nil,
        certificateDER: String? = nil,
        subjectKeyIdentifier: String? = nil,
        importedAt: Date = .now
    ) {
        self.id = id
        self.label = label
        self.algorithm = algorithm
        self.publicKeyHex = publicKeyHex
        self.hasPrivateKey = hasPrivateKey
        self.certificateSubject = certificateSubject
        self.certificateDER = certificateDER
        self.subjectKeyIdentifier = subjectKeyIdentifier
        self.importedAt = importedAt
    }
}
