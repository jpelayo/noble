// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Compact status bar at the bottom of the sidebar showing connection state.
struct ConnectionStatusBar: View {
    let appState: AppState

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(appState.isConnected ? .green : .red)
                .frame(width: 6, height: 6)

            if appState.isConnected {
                Text(appState.networkLabel.isEmpty ? "Connected" : appState.networkLabel)
                    .font(.caption)

                Spacer()

                Text("Block \(appState.blockHeight)")
                    .font(.caption)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            } else {
                Text("Disconnected")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Spacer()
            }
        }
        .padding(.horizontal)
        .padding(.vertical, 8)
        .background(.bar)
    }
}
