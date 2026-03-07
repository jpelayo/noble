// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// The result of verifying a document checksum against the blockchain.
public struct VerificationResult: Codable, Equatable, Sendable {
    /// Whether this checksum was found on-chain.
    public let isRegistered: Bool
    /// The matching registration, if found.
    public let registration: RegistrationRecord?
    /// Total number of times this checksum was registered (re-registrations).
    public let registrationCount: Int
    /// Version history chain, if applicable.
    public let versions: [VersionEntry]

    public init(
        isRegistered: Bool,
        registration: RegistrationRecord? = nil,
        registrationCount: Int = 0,
        versions: [VersionEntry] = []
    ) {
        self.isRegistered = isRegistered
        self.registration = registration
        self.registrationCount = registrationCount
        self.versions = versions
    }
}
