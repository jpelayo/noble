// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Root view with a sidebar + detail split layout.
struct MainView: View {
    @Bindable var appState: AppState

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 180, ideal: 220)
        } detail: {
            detailContent
        }
        .navigationTitle(appState.selectedSection?.label ?? "NobleDoc")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(appState.isConnected ? Color.accentColor : Color(.systemRed))
                        .frame(width: 8, height: 8)
                    Text(appState.isConnected ? "Block \(appState.blockHeight)" : "Offline")
                        .font(.caption)
                        .monospacedDigit()
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel(appState.isConnected ? "Connected, block \(appState.blockHeight)" : "Offline")
            }
        }
        .frame(minWidth: 700, minHeight: 500)
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        List(selection: $appState.selectedSection) {
            Section("Noble") {
                ForEach(SidebarSection.allCases) { section in
                    Label(section.label, systemImage: section.systemImage)
                        .tag(section)
                }
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            ConnectionStatusBar(appState: appState)
        }
    }

    // MARK: - Detail

    @ViewBuilder
    private var detailContent: some View {
        WebContentView(appState: appState)
            .onChange(of: appState.selectedSection) { _, newValue in
                if let section = newValue {
                    appState.webViewCoordinator?.evaluateJS(
                        "App.navigateTo('\(section.webRoute)')"
                    )
                }
            }
    }
}
