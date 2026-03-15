// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Step 1: Welcome screen introducing the app.
struct WelcomeStepView: View {
    @Bindable var appState: AppState

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "doc.text.fill")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            Text("Welcome to NobleMac")
                .font(.largeTitle)
                .bold()

            Text("Register, verify, and manage documents on the NOBLE blockchain. Your files never leave your device — only their SHA-256 fingerprints are stored on-chain.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button("Get Started") {
                appState.onboardingStep = .walletSetup
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .padding()
    }
}
