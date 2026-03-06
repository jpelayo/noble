// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Root onboarding container that routes between setup steps.
struct OnboardingView: View {
    @Bindable var appState: AppState

    var body: some View {
        VStack(spacing: 0) {
            // Progress indicator
            ProgressView(value: Double(appState.onboardingStep.rawValue), total: 3)
                .padding(.horizontal, 40)
                .padding(.top)

            Spacer()

            // Step content
            Group {
                switch appState.onboardingStep {
                case .welcome:
                    WelcomeStepView(appState: appState)
                case .walletSetup:
                    WalletSetupStepView(appState: appState)
                case .nodeConnection:
                    NodeConnectionStepView(appState: appState)
                case .complete:
                    OnboardingCompleteView(appState: appState)
                }
            }
            .frame(maxWidth: 500)

            Spacer()
        }
        .frame(minWidth: 600, minHeight: 450)
        .animation(.default, value: appState.onboardingStep)
    }
}
