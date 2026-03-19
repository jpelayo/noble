// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import WebKit

@main
struct NobleMacApp: App {
    @State private var appState = AppState()

    init() {
        let dataStore = WKWebsiteDataStore.default()
        let allTypes = WKWebsiteDataStore.allWebsiteDataTypes()
        dataStore.removeData(ofTypes: allTypes, modifiedSince: .distantPast) { }
        URLCache.shared.removeAllCachedResponses()
    }

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
        .windowResizability(.contentMinSize)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandMenu("Navigate") {
                Button("Home") { appState.selectedSection = .home }
                    .keyboardShortcut("1", modifiers: .command)
                Button("Documents") { appState.selectedSection = .documents }
                    .keyboardShortcut("2", modifiers: .command)
                Button("Verify") { appState.selectedSection = .verify }
                    .keyboardShortcut("3", modifiers: .command)
                Button("Payments") { appState.selectedSection = .payments }
                    .keyboardShortcut("4", modifiers: .command)
                Button("Contacts") { appState.selectedSection = .contacts }
                    .keyboardShortcut("5", modifiers: .command)
                Button("Settings") { appState.selectedSection = .settings }
                    .keyboardShortcut(",", modifiers: .command)
            }
            CommandMenu("Node") {
                Button("Refresh") {
                    Task { await appState.pollTick() }
                }
                .keyboardShortcut("r", modifiers: .command)
                Button("Disconnect") { appState.disconnect() }
                    .keyboardShortcut("d", modifiers: [.command, .shift])
            }
        }
        #endif
    }
}
