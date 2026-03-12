// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Step 3: Connect to a NOBLE node.
struct NodeConnectionStepView: View {
    @Bindable var appState: AppState
    @State private var nodeIP = "localhost"
    @State private var isConnecting = false

    var body: some View {
        VStack(spacing: 24) {
            Text("Connect to a Node")
                .font(.title)
                .bold()

            Text("Enter the IP address of your NOBLE node. The default works if you're running a node locally.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal)

            VStack(alignment: .leading, spacing: 8) {
                Text("Node IP Address")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                TextField("localhost", text: $nodeIP)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .keyboardType(.numbersAndPunctuation)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onSubmit { testConnection() }
            }

            if let error = appState.connectionError {
                Label(error, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(Color(.systemRed))
                    .fixedSize(horizontal: false, vertical: true)
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
                    .disabled(isConnecting || nodeIP.isEmpty)
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
        .onAppear {
            // Extract IP from saved URL if present
            if let url = URL(string: appState.nodeURL), let host = url.host {
                nodeIP = host
            }
        }
    }

    private var connectedInfo: some View {
        HStack(spacing: 8) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(Color.accentColor)
                .accessibilityHidden(true)

            VStack(alignment: .leading) {
                Text("Connected")
                    .font(.caption)
                    .bold()
                Text("Chain: \(appState.chainId) · Block \(appState.blockHeight)")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding()
        .background(Color.accentColor.opacity(0.1))
        .clipShape(.rect(cornerRadius: 8))
    }

    /// Build a full node URL from whatever the user typed — bare IP, hostname, or full URL.
    private static func buildNodeURL(from input: String) -> String {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        // Already a full URL — use as-is
        if let url = URL(string: trimmed), url.scheme != nil, url.host != nil {
            return trimmed
        }
        // Bare IP or hostname — wrap with https and default port
        return "https://\(trimmed):8783"
    }

    private func testConnection() {
        let input = nodeIP.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !input.isEmpty else { return }
        appState.nodeURL = Self.buildNodeURL(from: input)
        isConnecting = true
        Task {
            await appState.connectToNode()
            isConnecting = false
        }
    }
}
