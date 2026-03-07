// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// A pill-shaped status badge with a colored dot and label.
public struct StatusBadge: View {
    private let label: String
    private let color: Color

    public init(_ label: String, color: Color) {
        self.label = label
        self.color = color
    }

    public var body: some View {
        HStack(spacing: NobleSpacing.xs) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)

            Text(label)
                .font(NobleTypography.captionSmall)
                .foregroundStyle(color)
        }
        .padding(.horizontal, NobleSpacing.sm)
        .padding(.vertical, NobleSpacing.xs)
        .background(color.opacity(0.12))
        .clipShape(.capsule)
    }
}

// MARK: - Convenience Initializers

extension StatusBadge {
    /// Connected / success badge.
    public static func connected(_ label: String = "Connected") -> StatusBadge {
        StatusBadge(label, color: NobleColors.success)
    }

    /// Syncing / warning badge.
    public static func syncing(_ label: String = "Syncing") -> StatusBadge {
        StatusBadge(label, color: NobleColors.warning)
    }

    /// Disconnected / error badge.
    public static func disconnected(_ label: String = "Disconnected") -> StatusBadge {
        StatusBadge(label, color: NobleColors.error)
    }

    /// Network label badge.
    public static func network(_ label: String) -> StatusBadge {
        let color: Color = switch label.lowercased() {
        case "mainnet": NobleColors.mainnet
        case "testnet": NobleColors.testnet
        case "regtest": NobleColors.regtest
        default: NobleColors.accent
        }
        return StatusBadge(label, color: color)
    }
}
