// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// A local payment draft before signing and submission.
public struct PaymentDraft: Identifiable, Sendable {
    public let id: UUID
    public var recipient: NobleAddress?
    public var amount: NobleAmount
    public var fee: NobleAmount
    public var memo: String

    public init(
        id: UUID = UUID(),
        recipient: NobleAddress? = nil,
        amount: NobleAmount = .zero,
        fee: NobleAmount = .zero,
        memo: String = ""
    ) {
        self.id = id
        self.recipient = recipient
        self.amount = amount
        self.fee = fee
        self.memo = memo
    }
}
