// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// The lifecycle status of a transaction.
public enum TransactionStatus: String, Codable, Sendable {
    case pending
    case confirmed
    case rejected

    /// Human-readable label.
    public var label: String {
        switch self {
        case .pending: "Pending"
        case .confirmed: "Confirmed"
        case .rejected: "Rejected"
        }
    }
}
