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
        .navigationTitle(appState.selectedSection?.label ?? "NobleMac")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(appState.isConnected ? Color.green : Color(.systemRed))
                        .frame(width: 7, height: 7)

                    if appState.isConnected {
                        if let bal = appState.walletBalance {
                            Text("\(bal) NOBLE")
                                .font(.caption.monospacedDigit().bold())
                                .foregroundStyle(.primary)
                        }
                        if !appState.chainId.isEmpty {
                            Text(appState.chainId)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.tertiary)
                        }
                    } else {
                        Text("Disconnected")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.horizontal, 4)
                .accessibilityElement(children: .combine)
                .accessibilityLabel(
                    appState.isConnected
                        ? "Connected, \(appState.walletBalance ?? "0") NOBLE on \(appState.chainId)"
                        : "Disconnected"
                )
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
