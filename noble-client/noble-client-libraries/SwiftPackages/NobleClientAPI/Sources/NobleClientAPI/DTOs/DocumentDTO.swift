// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_lookupChecksum

public struct LookupChecksumParams: Encodable, Sendable {
    public let checksum: String
    public init(checksum: String) { self.checksum = checksum }
}

public struct ChecksumLookupDTO: Decodable, Sendable {
    public let found: Bool?
    public let records: [RegistrationRecordDTO]?
    public let version_chain: [String]?
}

/// Superset of fields from noble_lookupChecksum, noble_verifyDocument, noble_getDocumentsByIssuer.
/// All fields optional — each RPC populates a different subset.
public struct RegistrationRecordDTO: Decodable, Sendable {
    public let block_height: UInt64?
    public let tx_id: String?
    public let timestamp: UInt64?
    public let version: String?
    public let issuer: String?
    public let metadata: [MetadataDTO]?
    public let fee: UInt64?
    public let tx_type: String?
    public let prev_checksum: String?
    public let locked_tx_id: String?
}

// MARK: - noble_verifyDocument

public struct VerifyDocumentDTO: Decodable, Sendable {
    public let checksum: String?
    public let registered: Bool
    public let registrations: [RegistrationRecordDTO]?
    public let first_seen: UInt64?
    public let version_chain: [VersionEntryDTO]?
}

public struct VersionEntryDTO: Decodable, Sendable {
    public let checksum: String?
    public let tx_id: String?
    public let block_height: UInt64?
    public let timestamp: UInt64?
    public let version: UInt32?
}

// MARK: - noble_getDocumentHistory

public struct DocumentHistoryDTO: Decodable, Sendable {
    public let checksum: String?
    public let history: [RegistrationRecordDTO]?
}

// MARK: - noble_getDocumentVersions

public struct DocumentVersionsDTO: Decodable, Sendable {
    public let root_checksum: String?
    public let versions: [DocumentVersionDTO]?
    public let count: Int?
}

public struct DocumentVersionDTO: Decodable, Sendable {
    public let checksum: String?
    public let tx_id: String?
    public let block_height: UInt64?
    public let timestamp: UInt64?
}

// MARK: - noble_getDocumentsByIssuer

public struct DocumentsByIssuerDTO: Decodable, Sendable {
    public let issuer: String?
    public let documents: [RegistrationRecordDTO]?
    public let count: Int?
}
