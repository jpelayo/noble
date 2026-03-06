// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

// NobleClientSecurity — Keychain, app lock, and document hashing.

import Foundation
import NobleClientCore
import CryptoKit

/// Protocol for secure key storage in the system Keychain.
public protocol KeychainService: Sendable {
    /// Store a private key under a label. Returns true on success.
    func storeKey(_ data: Data, label: String) throws

    /// Retrieve a private key by label. Returns nil if not found.
    func loadKey(label: String) throws -> Data?

    /// Delete a stored key by label.
    func deleteKey(label: String) throws

    /// Check whether a key exists for the given label.
    func hasKey(label: String) throws -> Bool
}

/// SHA-256 document hasher for generating checksums before registration.
public struct DocumentHasher: Sendable {
    public init() {}

    /// Compute SHA-256 checksum of file data.
    public func hash(data: Data) -> Hash256 {
        let digest = SHA256.hash(data: data)
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        // SHA-256 always produces 64 hex chars — safe to force-unwrap.
        // swiftlint:disable:next force_unwrapping
        return Hash256(hex: hex)!
    }

    /// Compute SHA-256 checksum of a file at the given URL.
    public func hash(fileURL: URL) throws -> Hash256 {
        let data = try Data(contentsOf: fileURL)
        return hash(data: data)
    }
}

/// Protocol for biometric / passcode app-lock management.
public protocol AppLockService: Sendable {
    /// Whether biometric authentication is available.
    var isBiometricAvailable: Bool { get }

    /// Attempt biometric unlock. Returns true on success.
    func authenticateWithBiometrics(reason: String) async throws -> Bool
}

/// Placeholder Keychain stub that will be implemented in Sprint 3.
public struct StubKeychainService: KeychainService {
    public init() {}

    public func storeKey(_ data: Data, label: String) throws {
        fatalError("KeychainService not yet implemented — Sprint 3")
    }

    public func loadKey(label: String) throws -> Data? {
        fatalError("KeychainService not yet implemented — Sprint 3")
    }

    public func deleteKey(label: String) throws {
        fatalError("KeychainService not yet implemented — Sprint 3")
    }

    public func hasKey(label: String) throws -> Bool {
        fatalError("KeychainService not yet implemented — Sprint 3")
    }
}
