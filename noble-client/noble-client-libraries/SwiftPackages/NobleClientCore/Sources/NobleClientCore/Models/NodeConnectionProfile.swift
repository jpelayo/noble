// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A saved connection profile for a NOBLE node.
public struct NodeConnectionProfile: Identifiable, Codable, Equatable, Sendable {

    public let id: UUID
    public var name: String
    public var baseURL: URL
    public var chainId: String
    public var authMode: AuthMode

    public init(
        id: UUID = UUID(),
        name: String,
        baseURL: URL,
        chainId: String = "",
        authMode: AuthMode = .none
    ) {
        self.id = id
        self.name = name
        self.baseURL = baseURL
        self.chainId = chainId
        self.authMode = authMode
    }

    /// Default localhost connection (JSON-RPC HTTP on port 8783, WS on port 8784).
    /// Chain ID is populated at connection time from the node's response.
    public static let localhost = NodeConnectionProfile(
        name: "Local Node",
        baseURL: URL(string: "https://127.0.0.1:8783")!,
        authMode: .none
    )
}

/// Authentication mode for connecting to a NOBLE node.
public enum AuthMode: Codable, Equatable, Sendable {
    /// No authentication required.
    case none
    /// Bearer token (pre-shared, stored in Keychain).
    case bearerToken(String)
    /// TOTP code prompt — user enters 6-digit code, client SHA-256 hashes before sending.
    case totpCodePrompt
}
