// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import UIKit

/// Centralized haptic feedback for common app actions.
@MainActor
final class HapticManager {
    static let shared = HapticManager()

    private let impactLight = UIImpactFeedbackGenerator(style: .light)
    private let impactMedium = UIImpactFeedbackGenerator(style: .medium)
    private let notification = UINotificationFeedbackGenerator()
    private let selection = UISelectionFeedbackGenerator()

    private init() {
        // Pre-warm generators
        impactLight.prepare()
        impactMedium.prepare()
        notification.prepare()
        selection.prepare()
    }

    /// Light tap — tab switches, minor interactions.
    func tap() {
        impactLight.impactOccurred()
    }

    /// Medium impact — button presses, confirmations.
    func impact() {
        impactMedium.impactOccurred()
    }

    /// Success notification — transaction sent, copy confirmed, connection established.
    func success() {
        notification.notificationOccurred(.success)
    }

    /// Warning notification — connection issues, validation warnings.
    func warning() {
        notification.notificationOccurred(.warning)
    }

    /// Error notification — failed operations, invalid input.
    func error() {
        notification.notificationOccurred(.error)
    }

    /// Selection change — picker changes, list reordering.
    func selectionChanged() {
        selection.selectionChanged()
    }
}
