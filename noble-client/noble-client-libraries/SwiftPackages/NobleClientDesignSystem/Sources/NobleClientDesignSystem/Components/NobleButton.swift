// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Button style variants for the NOBLE design system.
public enum NobleButtonVariant {
    case primary
    case secondary
    case destructive
}

/// A styled button matching the NOBLE design language.
public struct NobleButton: View {
    private let title: String
    private let systemImage: String?
    private let variant: NobleButtonVariant
    private let action: () -> Void

    public init(
        _ title: String,
        systemImage: String? = nil,
        variant: NobleButtonVariant = .primary,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.systemImage = systemImage
        self.variant = variant
        self.action = action
    }

    public var body: some View {
        switch variant {
        case .primary:
            button.buttonStyle(.borderedProminent)
        case .secondary:
            button.buttonStyle(.bordered)
        case .destructive:
            button.buttonStyle(.borderedProminent).tint(NobleColors.error)
        }
    }

    @ViewBuilder
    private var button: some View {
        if let systemImage {
            Button(title, systemImage: systemImage, action: action)
        } else {
            Button(title, action: action)
        }
    }
}
