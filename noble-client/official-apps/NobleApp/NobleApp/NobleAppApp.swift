// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

@main
struct NobleAppApp: App {
    @State private var appState = AppState()
    @State private var isLaunching = true
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            Group {
                if isLaunching {
                    LaunchScreenView()
                } else if appState.hasCompletedOnboarding {
                    MainView(appState: appState)
                } else {
                    OnboardingView(appState: appState)
                }
            }
            .task {
                await appState.autoConnectIfNeeded()
                withAnimation(.easeOut(duration: 0.3)) {
                    isLaunching = false
                }
            }
            .onChange(of: scenePhase) { _, newPhase in
                switch newPhase {
                case .active:
                    if appState.isConnected {
                        appState.startPolling()
                    }
                case .background, .inactive:
                    appState.stopPolling()
                @unknown default:
                    break
                }
            }
        }
    }
}
