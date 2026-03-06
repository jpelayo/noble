// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

@main
struct NobleDocApp: App {
    @State private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            Group {
                if appState.hasCompletedOnboarding {
                    MainView(appState: appState)
                } else {
                    OnboardingView(appState: appState)
                }
            }
            .task {
                appState.checkExistingWallet()
            }
        }
        #if os(macOS)
        .defaultSize(width: 960, height: 640)
        #endif
    }
}
