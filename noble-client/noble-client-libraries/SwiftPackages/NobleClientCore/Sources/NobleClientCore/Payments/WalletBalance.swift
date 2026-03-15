// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Total wallet balance across all node keys (wallet + validator).
public struct WalletBalance: Codable, Equatable, Sendable {
    public let balance: NobleAmount
    public let available: NobleAmount
    public let pending: NobleAmount

    public init(
        balance: NobleAmount = .zero,
        available: NobleAmount = .zero,
        pending: NobleAmount = .zero
    ) {
        self.balance = balance
        self.available = available
        self.pending = pending
    }
}
