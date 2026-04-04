// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

// MARK: - noble_lookupChecksum

struct LookupChecksumParams: Encodable, Sendable {
    let checksum: String
}

struct ChecksumLookupDTO: Decodable, Sendable {
    let found: Bool?
    let records: [RegistrationRecordDTO]?
    let version_chain: [String]?
}

/// Superset of fields from noble_lookupChecksum, noble_verifyDocument, noble_getDocumentsByIssuer.
/// All fields optional — each RPC populates a different subset.
struct RegistrationRecordDTO: Decodable, Sendable {
    let block_height: UInt64?
    let tx_id: String?
    let timestamp: UInt64?
    let version: String?        // lookupChecksum returns string
    let issuer: String?
    let metadata: [MetadataDTO]?
    let fee: UInt64?
    let tx_type: String?        // verifyDocument returns this
    let prev_checksum: String?
    let locked_tx_id: String?
}

// MARK: - noble_verifyDocument

struct VerifyDocumentDTO: Decodable, Sendable {
    let checksum: String?
    let registered: Bool
    let registrations: [RegistrationRecordDTO]?
    let first_seen: UInt64?
    let version_chain: [VersionEntryDTO]?
}

struct VersionEntryDTO: Decodable, Sendable {
    let checksum: String?
    let tx_id: String?
    let block_height: UInt64?
    let timestamp: UInt64?
    let version: UInt32?
}

// MARK: - noble_getDocumentHistory

struct DocumentHistoryDTO: Decodable, Sendable {
    let checksum: String?
    let history: [RegistrationRecordDTO]?
}

// MARK: - noble_getDocumentVersions

struct DocumentVersionsDTO: Decodable, Sendable {
    let root_checksum: String?
    let versions: [DocumentVersionDTO]?
    let count: Int?
}

struct DocumentVersionDTO: Decodable, Sendable {
    let checksum: String?
    let tx_id: String?
    let block_height: UInt64?
    let timestamp: UInt64?
}

// MARK: - noble_getDocumentsByIssuer

struct DocumentsByIssuerDTO: Decodable, Sendable {
    let issuer: String?
    let documents: [RegistrationRecordDTO]?
    let count: Int?
}
