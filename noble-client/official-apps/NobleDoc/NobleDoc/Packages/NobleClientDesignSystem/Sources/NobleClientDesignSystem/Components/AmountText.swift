// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Displays a NOBLE amount with the unit suffix.
///
/// Input is in atomic units (1 NOBLE = 1,000,000 atomic).
/// Shows up to 6 decimal places, trimming trailing zeros.
public struct AmountText: View {
    private let atomicUnits: UInt64
    private let showUnit: Bool
    private let font: Font

    public init(
        _ atomicUnits: UInt64,
        showUnit: Bool = true,
        font: Font = NobleTypography.body
    ) {
        self.atomicUnits = atomicUnits
        self.showUnit = showUnit
        self.font = font
    }

    public var body: some View {
        Text(formatted)
            .font(font)
            .monospacedDigit()
    }

    private var formatted: String {
        let whole = atomicUnits / 1_000_000
        let frac = atomicUnits % 1_000_000
        let suffix = showUnit ? " NOBLE" : ""

        if frac == 0 {
            return "\(whole)\(suffix)"
        }

        let fracStr = String(format: "%06d", frac)
            .replacingOccurrences(of: "0+$", with: "", options: .regularExpression)
        return "\(whole).\(fracStr)\(suffix)"
    }
}
