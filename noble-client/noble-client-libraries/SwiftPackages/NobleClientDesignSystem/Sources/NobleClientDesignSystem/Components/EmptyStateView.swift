// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// A centered empty state placeholder with icon, title, and optional action.
public struct EmptyStateView: View {
    private let title: String
    private let systemImage: String
    private let description: String?

    public init(
        _ title: String,
        systemImage: String,
        description: String? = nil
    ) {
        self.title = title
        self.systemImage = systemImage
        self.description = description
    }

    public var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: systemImage)
        } description: {
            if let description {
                Text(description)
            }
        }
    }
}
