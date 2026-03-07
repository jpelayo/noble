// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// A card container with surface background, border, and rounded corners.
public struct NobleCard<Content: View>: View {
    private let content: Content

    public init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    public var body: some View {
        content
            .padding(NobleSpacing.md)
            .background(NobleColors.bgSurface)
            .clipShape(.rect(cornerRadius: NobleRadius.md))
            .overlay(
                RoundedRectangle(cornerRadius: NobleRadius.md)
                    .strokeBorder(NobleColors.border, lineWidth: 1)
            )
    }
}
