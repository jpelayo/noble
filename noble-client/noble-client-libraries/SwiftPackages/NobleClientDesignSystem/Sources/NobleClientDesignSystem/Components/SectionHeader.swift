// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// A section header with title and optional trailing accessory.
public struct SectionHeader<Accessory: View>: View {
    private let title: String
    private let accessory: Accessory

    public init(_ title: String, @ViewBuilder accessory: () -> Accessory) {
        self.title = title
        self.accessory = accessory()
    }

    public var body: some View {
        HStack {
            Text(title)
                .font(NobleTypography.bodySecondary)
                .foregroundStyle(NobleColors.textSecondary)
                .textCase(.uppercase)

            Spacer()

            accessory
        }
    }
}

extension SectionHeader where Accessory == EmptyView {
    /// Create a section header with no trailing accessory.
    public init(_ title: String) {
        self.title = title
        self.accessory = EmptyView()
    }
}
