// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import WebKit

@main
struct NobleMacApp: App {
    @State private var appState = AppState()
    @Environment(\.scenePhase) private var scenePhase

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
                // Launch connect. Do NOT rely on the scenePhase handler below —
                // .onChange only fires on transitions, and macOS does not
                // reliably deliver an initial one, which left the app forever
                // "Disconnected" with a healthy node. Double-firing with the
                // scenePhase path is benign: connectToNode is idempotent
                // (invalidates the retry timer, rebuilds the client).
                if appState.autoConnect && !appState.userDisconnected
                    && !appState.isConnected && !appState.nodeURL.isEmpty {
                    await appState.connectToNode()
                }
            }
            .onChange(of: scenePhase) { _, newPhase in
                switch newPhase {
                case .active:
                    appState.startPolling()
                    // Respect a deliberate disconnect — re-activating the app
                    // must not override the user's choice.
                    if !appState.isConnected && !appState.userDisconnected
                        && !appState.nodeURL.isEmpty {
                        Task { await appState.connectToNode() }
                    }
                case .background, .inactive:
                    appState.stopPolling()
                @unknown default:
                    break
                }
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
                Button("Wallet") { appState.selectedSection = .wallet }
                    .keyboardShortcut("4", modifiers: .command)
                Button("Contacts") { appState.selectedSection = .contacts }
                    .keyboardShortcut("5", modifiers: .command)
                Button("Settings") { appState.selectedSection = .settings }
                    .keyboardShortcut(",", modifiers: .command)
            }
            CommandMenu("Node") {
                Button("Refresh") {
                    // pollTick() is a silent no-op while disconnected (its first
                    // line bails when apiService is nil) — fall back to a real
                    // dial so ⌘R always does something useful.
                    Task {
                        if appState.isConnected {
                            await appState.pollTick()
                        } else {
                            await appState.connectToNode()
                        }
                    }
                }
                .keyboardShortcut("r", modifiers: .command)
                Button("Disconnect") { appState.disconnect() }
                    .keyboardShortcut("d", modifiers: [.command, .shift])
            }
        }
        #endif
    }
}
