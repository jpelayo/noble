// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// A centered loading indicator with an optional message.
public struct LoadingOverlay: View {
    private let message: String?

    public init(_ message: String? = nil) {
        self.message = message
    }

    public var body: some View {
        VStack(spacing: NobleSpacing.sm) {
            ProgressView()

            if let message {
                Text(message)
                    .font(NobleTypography.caption)
                    .foregroundStyle(NobleColors.textSecondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
