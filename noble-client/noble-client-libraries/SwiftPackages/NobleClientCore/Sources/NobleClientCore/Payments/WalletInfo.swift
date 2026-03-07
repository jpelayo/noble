// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Wallet state information from the node.
public struct WalletInfo: Codable, Equatable, Sendable {
    /// Whether the wallet is currently unlocked on the node.
    public let isUnlocked: Bool
    /// Number of addresses in the wallet.
    public let addressCount: Int
    /// The primary address (first key).
    public let primaryAddress: NobleAddress?

    public init(
        isUnlocked: Bool = false,
        addressCount: Int = 0,
        primaryAddress: NobleAddress? = nil
    ) {
        self.isUnlocked = isUnlocked
        self.addressCount = addressCount
        self.primaryAddress = primaryAddress
    }
}
