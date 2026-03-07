// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Typography tokens for the NOBLE design system.
///
/// Uses Dynamic Type text styles for accessibility.
/// Monospace fonts use the system monospaced design for hash/address display.
public enum NobleTypography {

    // MARK: - Display

    /// Large display title — page headers.
    public static let displayLarge: Font = .largeTitle

    /// Medium display — section titles.
    public static let displayMedium: Font = .title

    /// Small display — card titles.
    public static let displaySmall: Font = .title3

    // MARK: - Body

    /// Primary body text.
    public static let body: Font = .body

    /// Secondary body text — descriptions.
    public static let bodySecondary: Font = .callout

    /// Small text — captions, timestamps.
    public static let caption: Font = .caption

    /// Extra-small text — badges, labels.
    public static let captionSmall: Font = .caption2

    // MARK: - Monospace

    /// Monospaced body — hashes, addresses, hex values.
    public static let mono: Font = .body.monospaced()

    /// Monospaced small — truncated hashes in lists.
    public static let monoSmall: Font = .caption.monospaced()

    /// Monospaced large — featured hash display.
    public static let monoLarge: Font = .title3.monospaced()
}
