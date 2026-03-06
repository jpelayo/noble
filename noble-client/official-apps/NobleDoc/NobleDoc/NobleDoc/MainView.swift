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
        .navigationTitle("")
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
        switch appState.selectedSection {
        case .documents:
            DocumentsPlaceholder()
        case .payments:
            PaymentsPlaceholder()
        case .contacts:
            ContactsPlaceholder()
        case .settings:
            SettingsPlaceholder()
        case nil:
            ContentUnavailableView {
                Label("NobleDoc", systemImage: "doc.text.fill")
            } description: {
                Text("Select a section from the sidebar.")
            }
        }
    }
}
