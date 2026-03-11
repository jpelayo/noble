// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Compact status bar at the bottom of the sidebar showing connection state.
struct ConnectionStatusBar: View {
    let appState: AppState

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(appState.isConnected ? Color.green : Color(.systemRed))
                .frame(width: 7, height: 7)
                .accessibilityLabel(appState.isConnected ? "Connected" : "Disconnected")

            if appState.isConnected {
                if !appState.chainId.isEmpty {
                    Text(appState.chainId)
                        .font(.caption.monospaced().bold())
                }
                Spacer()
                Text("Block \(appState.blockHeight)")
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.tertiary)
            } else {
                Text("Disconnected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
        .accessibilityElement(children: .combine)
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.bar)
    }
}
