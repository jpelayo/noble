// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI
import UniformTypeIdentifiers

/// Root view — TabView on iPhone, NavigationSplitView on iPad.
struct MainView: View {
    @Bindable var appState: AppState
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @SceneStorage("selectedTab") private var selectedTab: String = "home"

    var body: some View {
        Group {
            if horizontalSizeClass == .regular {
                iPadLayout
            } else {
                iPhoneLayout
            }
        }
        .sheet(isPresented: $appState.showingShareSheet) {
            ShareSheet(items: appState.shareSheetItems)
                .presentationDetents([.medium, .large])
        }
        .fileImporter(
            isPresented: $appState.showingFilePicker,
            allowedContentTypes: [.item],
            allowsMultipleSelection: appState.filePickerAllowsMultiple
        ) { result in
            var files: [[String: Any]] = []
            if case .success(let urls) = result {
                files = urls.map { url in
                    let accessing = url.startAccessingSecurityScopedResource()
                    defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                    let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
                    let size = attrs?[.size] as? UInt64 ?? 0
                    return [
                        "path": url.path,
                        "name": url.lastPathComponent,
                        "size": size,
                    ] as [String: Any]
                }
            }
            appState.pendingFilePickerContinuation?.resume(returning: files)
            appState.pendingFilePickerContinuation = nil
        }
    }

    // MARK: - iPhone Layout (TabView)

    private var iPhoneLayout: some View {
        TabView(selection: $selectedTab) {
            Tab("Home", systemImage: "house.fill", value: "home") {
                webContent
            }

            Tab("Documents", systemImage: "doc.text.fill", value: "documents") {
                webContent
            }

            Tab("Verify", systemImage: "checkmark.seal.fill", value: "verify") {
                webContent
            }

            Tab("Payments", systemImage: "creditcard.fill", value: "payments") {
                webContent
            }

            Tab("Contacts", systemImage: "person.2.fill", value: "contacts") {
                webContent
            }
        }
        .onChange(of: selectedTab) { _, newTab in
            if let section = SidebarSection(rawValue: newTab) {
                appState.selectedSection = section
                appState.webViewCoordinator?.evaluateJS(
                    "App.navigateTo('\(section.webRoute)')"
                )
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                toolbarStatus
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button { navigateTo(.settings) } label: {
                        Label("Settings", systemImage: "gearshape")
                    }
                    Button { navigateTo(.drafts) } label: {
                        Label("Drafts", systemImage: "tray")
                    }
                    Button { navigateTo(.faucet) } label: {
                        Label("Faucet", systemImage: "drop")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
    }

    // MARK: - iPad Layout (NavigationSplitView)

    private var iPadLayout: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 180, ideal: 220)
        } detail: {
            webContent
        }
        .navigationTitle(appState.selectedSection?.label ?? "Noble")
        .toolbar {
            ToolbarItem(placement: .automatic) {
                toolbarStatus
            }
        }
    }

    // MARK: - Sidebar (iPad)

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
        .onChange(of: appState.selectedSection) { _, newValue in
            if let section = newValue {
                appState.webViewCoordinator?.evaluateJS(
                    "App.navigateTo('\(section.webRoute)')"
                )
            }
        }
    }

    // MARK: - Web Content

    private var webContent: some View {
        WebContentView(appState: appState)
            .refreshable {
                await appState.pollTick()
                HapticManager.shared.success()
            }
    }

    // MARK: - Toolbar Status

    private var toolbarStatus: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(appState.isConnected ? Color.green : Color(.systemRed))
                .frame(width: 7, height: 7)

            if appState.isConnected {
                if let bal = appState.walletBalance {
                    Text("\(bal) NOBLE")
                        .font(.caption2.monospacedDigit().bold())
                        .foregroundStyle(.primary)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(
            appState.isConnected
                ? "Connected, \(appState.walletBalance ?? "0") NOBLE"
                : "Disconnected"
        )
    }

    // MARK: - Navigation Helper

    private func navigateTo(_ section: SidebarSection) {
        appState.selectedSection = section
        selectedTab = section.rawValue
        appState.webViewCoordinator?.evaluateJS(
            "App.navigateTo('\(section.webRoute)')"
        )
    }
}
