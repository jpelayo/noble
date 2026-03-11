// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

#if canImport(AppKit)
import AppKit
#elseif canImport(UIKit)
import UIKit
#endif

/// Semantic color tokens for the NOBLE design system.
///
/// All colors adapt to light and dark appearance automatically.
/// Values are matched to the NOBLE dashboard CSS custom properties.
public enum NobleColors {

    // MARK: - Backgrounds

    /// Primary app background (#f8fafc / #0f172a).
    public static let bgPrimary = adaptive(light: 0xf8fafc, dark: 0x0f172a)

    /// Secondary background for grouped content (#f1f5f9 / #1e293b).
    public static let bgSecondary = adaptive(light: 0xf1f5f9, dark: 0x1e293b)

    /// Tertiary background for deeper nesting (#e2e8f0 / #334155).
    public static let bgTertiary = adaptive(light: 0xe2e8f0, dark: 0x334155)

    /// Surface background for cards and panels (#ffffff / #1e293b).
    public static let bgSurface = adaptive(light: 0xffffff, dark: 0x1e293b)

    // MARK: - Text

    /// Primary text (#0f172a / #e2e8f0).
    public static let textPrimary = adaptive(light: 0x0f172a, dark: 0xe2e8f0)

    /// Secondary text (#475569 / #94a3b8).
    public static let textSecondary = adaptive(light: 0x475569, dark: 0x94a3b8)

    /// Muted text for captions and placeholders (#94a3b8 / #64748b).
    public static let textMuted = adaptive(light: 0x94a3b8, dark: 0x64748b)

    // MARK: - Accent

    /// Primary accent / brand color (#3b82f6).
    public static let accent = Color(hex: 0x3b82f6)

    /// Accent hover state (#2563eb / #60a5fa).
    public static let accentHover = adaptive(light: 0x2563eb, dark: 0x60a5fa)

    /// Subtle accent background (12–15% opacity).
    public static let accentSubtle = accent.opacity(0.12)

    // MARK: - Semantic

    /// Success / connected (#10b981).
    public static let success = Color(hex: 0x10b981)

    /// Warning / syncing (#f59e0b).
    public static let warning = Color(hex: 0xf59e0b)

    /// Error / disconnected (#ef4444).
    public static let error = Color(hex: 0xef4444)

    /// Informational (#06b6d4).
    public static let info = Color(hex: 0x06b6d4)

    // MARK: - Borders

    /// Default border (#e2e8f0 / #334155).
    public static let border = adaptive(light: 0xe2e8f0, dark: 0x334155)

    /// Strong border for emphasis (#cbd5e1 / #475569).
    public static let borderStrong = adaptive(light: 0xcbd5e1, dark: 0x475569)

    // MARK: - Terminal

    /// Terminal background (#0d1117).
    public static let terminalBg = Color(hex: 0x0d1117)

    /// Terminal text (#e6edf3).
    public static let terminalText = Color(hex: 0xe6edf3)

    /// Terminal address highlight (#56d364).
    public static let terminalAddress = Color(hex: 0x56d364)

    /// Terminal value highlight (#79c0ff).
    public static let terminalValue = Color(hex: 0x79c0ff)
}

// MARK: - Color Helpers

extension Color {
    /// Create a color from a 24-bit hex integer (e.g. `0x3b82f6`).
    public init(hex: UInt) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}

// MARK: - Adaptive Color Factory

extension NobleColors {
    /// Create a color that adapts to the system appearance.
    static func adaptive(light: UInt, dark: UInt) -> Color {
        #if canImport(AppKit)
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            let hex = isDark ? dark : light
            return NSColor(
                srgbRed: CGFloat((hex >> 16) & 0xFF) / 255,
                green: CGFloat((hex >> 8) & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255,
                alpha: 1
            )
        })
        #elseif canImport(UIKit)
        Color(uiColor: UIColor { traits in
            let hex = traits.userInterfaceStyle == .dark ? dark : light
            return UIColor(
                red: CGFloat((hex >> 16) & 0xFF) / 255,
                green: CGFloat((hex >> 8) & 0xFF) / 255,
                blue: CGFloat(hex & 0xFF) / 255,
                alpha: 1
            )
        })
        #endif
    }
}
