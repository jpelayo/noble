// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Represents an amount on the NOBLE blockchain in atomic units.
///
/// 1 NOBLE = 1,000,000 atomic units. The market decides fees;
/// the protocol minimum is 1 atomic unit.
public struct NobleAmount: Codable, Equatable, Comparable, Hashable, Sendable {

    // MARK: - Constants

    public static let atomicPerNoble: UInt64 = 1_000_000
    public static let zero = NobleAmount(atomic: 0)

    // MARK: - Properties

    /// The raw value in atomic units.
    public let atomic: UInt64

    // MARK: - Initializers

    public init(atomic: UInt64) {
        self.atomic = atomic
    }

    /// Create from a whole-NOBLE decimal (e.g. 1.5 → 1_500_000 atomic).
    public init(noble: Decimal) {
        let scaled = noble * Decimal(Self.atomicPerNoble)
        self.atomic = NSDecimalNumber(decimal: scaled).uint64Value
    }

    // MARK: - Display

    /// Decimal value in whole NOBLE units.
    public var displayNoble: Decimal {
        Decimal(atomic) / Decimal(Self.atomicPerNoble)
    }

    /// Always shows 6 decimal places: "123.456789".
    public var formatted: String {
        let whole = atomic / Self.atomicPerNoble
        let frac = atomic % Self.atomicPerNoble
        return "\(whole).\(String(format: "%06d", frac))"
    }

    /// Trims trailing zeros: "123.456" instead of "123.456000".
    public var formattedCompact: String {
        var s = formatted
        while s.hasSuffix("0") { s = String(s.dropLast()) }
        if s.hasSuffix(".") { s = String(s.dropLast()) }
        return s
    }

    // MARK: - Comparable

    public static func < (lhs: NobleAmount, rhs: NobleAmount) -> Bool {
        lhs.atomic < rhs.atomic
    }

    // MARK: - Arithmetic

    public static func + (lhs: NobleAmount, rhs: NobleAmount) -> NobleAmount {
        NobleAmount(atomic: lhs.atomic + rhs.atomic)
    }

    public static func - (lhs: NobleAmount, rhs: NobleAmount) -> NobleAmount {
        NobleAmount(atomic: lhs.atomic - rhs.atomic)
    }
}
