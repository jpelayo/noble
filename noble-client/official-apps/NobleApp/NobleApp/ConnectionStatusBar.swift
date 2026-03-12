// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Compact status bar at the bottom of the sidebar showing connection state, version, and legal info.
struct ConnectionStatusBar: View {
    let appState: AppState

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1"
    }

    var body: some View {
        VStack(spacing: 4) {
            // Connection status
            HStack(spacing: 6) {
                Circle()
                    .fill(appState.isConnected ? Color.green : Color(.systemRed))
                    .frame(width: 7, height: 7)

                Text(appState.isConnected ? "Connected to node" : "Disconnected from node")
                    .font(.caption)
                    .foregroundStyle(appState.isConnected ? .secondary : .primary)

                Spacer()
            }

            // Balance + chain (only when connected)
            if appState.isConnected, !appState.chainId.isEmpty {
                HStack(spacing: 4) {
                    if let bal = appState.walletBalance {
                        Text("\(bal) NOBLE")
                            .font(.caption.monospacedDigit().bold())
                    }
                    Spacer()
                    Text(appState.chainId)
                        .font(.caption2.monospaced())
                        .foregroundStyle(.tertiary)
                }
            }

            // Version, copyright, license
            Divider()
                .padding(.vertical, 2)

            VStack(spacing: 2) {
                Text("v\(appVersion) \u{00B7} Apache-2.0")
                    .font(.caption2)
                    .foregroundStyle(.quaternary)
                Text("\u{00A9} 2026 InfiniteContext.com")
                    .font(.caption2)
                    .foregroundStyle(.quaternary)
            }
        }
        .accessibilityElement(children: .combine)
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }
}
