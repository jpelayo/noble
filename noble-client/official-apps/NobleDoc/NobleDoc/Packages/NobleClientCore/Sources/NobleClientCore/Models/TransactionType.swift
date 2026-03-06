// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// The type of a NOBLE blockchain transaction.
public enum TransactionType: UInt8, Codable, Sendable, CaseIterable {
    case notarization = 0
    case transfer = 1
    case keyRotation = 2

    /// Types the client app can create and sign locally.
    public static let creatableTypes: Set<TransactionType> = [.notarization, .transfer]

    /// Human-readable label.
    public var label: String {
        switch self {
        case .notarization: "Notarization"
        case .transfer: "Transfer"
        case .keyRotation: "Key Rotation"
        }
    }
}
