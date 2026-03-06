// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Step 3: Connect to a NOBLE node.
struct NodeConnectionStepView: View {
    @Bindable var appState: AppState
    @State private var isConnecting = false

    var body: some View {
        VStack(spacing: 24) {
            Text("Connect to a Node")
                .font(.title)
                .bold()

            Text("Enter the URL of your NOBLE node. The default works if you're running a node locally.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            VStack(alignment: .leading, spacing: 8) {
                Text("Node URL")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                TextField("https://localhost:8783", text: $appState.nodeURL)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
            }

            if let error = appState.connectionError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if appState.isConnected {
                connectedInfo
            }

            HStack {
                Button("Back") {
                    appState.onboardingStep = .walletSetup
                    appState.walletSetupMode = nil
                }
                .buttonStyle(.bordered)

                Spacer()

                if appState.isConnected {
                    Button("Continue") {
                        appState.onboardingStep = .complete
                    }
                    .buttonStyle(.borderedProminent)
                } else {
                    Button("Test Connection") {
                        testConnection()
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isConnecting || appState.nodeURL.isEmpty)
                }
            }

            Button("Skip for now") {
                appState.onboardingStep = .complete
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .font(.caption)
        }
        .padding()
    }

    private var connectedInfo: some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)

            VStack(alignment: .leading) {
                Text("Connected")
                    .font(.caption)
                    .bold()
                Text("Network: \(appState.networkLabel) · Block \(appState.blockHeight)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding()
        .background(.green.opacity(0.1))
        .clipShape(.rect(cornerRadius: 8))
    }

    private func testConnection() {
        isConnecting = true
        Task {
            await appState.connectToNode()
            isConnecting = false
        }
    }
}
