// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Displays a hex hash string in monospace font with optional truncation.
///
/// Full 64-char hashes are truncated to `8...8` by default.
/// Tapping copies the full value to the pasteboard.
public struct HashText: View {
    private let hash: String
    private let prefixCount: Int
    private let suffixCount: Int
    private let font: Font

    public init(
        _ hash: String,
        prefix prefixCount: Int = 8,
        suffix suffixCount: Int = 8,
        font: Font = NobleTypography.monoSmall
    ) {
        self.hash = hash
        self.prefixCount = prefixCount
        self.suffixCount = suffixCount
        self.font = font
    }

    public var body: some View {
        Text(truncated)
            .font(font)
            .foregroundStyle(NobleColors.textSecondary)
            .help(hash)
    }

    private var truncated: String {
        guard hash.count > prefixCount + suffixCount + 3 else { return hash }
        let start = hash.prefix(prefixCount)
        let end = hash.suffix(suffixCount)
        return "\(start)...\(end)"
    }
}
