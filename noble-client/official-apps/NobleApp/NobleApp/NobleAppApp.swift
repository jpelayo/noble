// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import WebKit

@main
struct NobleAppApp: App {
    @State private var appState = AppState()
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // Kill all WKWebView caches so updated JS/CSS from new builds
        // are never masked by stale cached responses.
        let dataStore = WKWebsiteDataStore.default()
        let allTypes = WKWebsiteDataStore.allWebsiteDataTypes()
        dataStore.removeData(ofTypes: allTypes, modifiedSince: .distantPast) { }
        URLCache.shared.removeAllCachedResponses()
    }

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                Group {
                    if appState.hasCompletedOnboarding {
                        MainView(appState: appState)
                    } else {
                        OnboardingView(appState: appState)
                    }
                }
            }
            .task {
                if appState.autoConnect && !appState.nodeURL.isEmpty
                    && appState.hasWallet && appState.hasCompletedOnboarding {
                    await appState.connectToNode()
                }
            }
            .onChange(of: scenePhase) { _, newPhase in
                switch newPhase {
                case .active:
                    appState.startPolling()
                    if !appState.isConnected && !appState.nodeURL.isEmpty {
                        Task { await appState.connectToNode() }
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
