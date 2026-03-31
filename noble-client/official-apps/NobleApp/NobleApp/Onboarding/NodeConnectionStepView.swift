// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Default NOBLE seed/recovery node hostname.
private let defaultNodeHostname = "node.infinitecontext.com"

/// Step 3: Connect to a NOBLE node.
struct NodeConnectionStepView: View {
    @Bindable var appState: AppState
    @State private var nodeIP = ""
    @State private var isConnecting = false

    var body: some View {
        VStack(spacing: 24) {
            Text("Connect to a Node")
                .font(.title)
                .bold()

            Text("Enter the IP address or hostname of your NOBLE node. If you don't run your own node, try **\(defaultNodeHostname)**.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal)

            VStack(alignment: .leading, spacing: 8) {
                Text("Node Address")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                TextField(defaultNodeHostname, text: $nodeIP)
                    .textFieldStyle(.roundedBorder)
                    .font(.body.monospaced())
                    .keyboardType(.numbersAndPunctuation)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onChange(of: nodeIP) { _, newValue in
                        if newValue.count > Self.maxInputLength {
                            nodeIP = String(newValue.prefix(Self.maxInputLength))
                        }
                    }
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
            // Cancel any stale reconnect timer from a previous session
            appState.cancelReconnect()
            appState.connectionError = nil
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

    /// Maximum input length for node address field.
    private static let maxInputLength = 256

    /// Build a full node URL from whatever the user typed — bare IP, hostname, host:port, or full URL.
    private static func buildNodeURL(from input: String) -> String {
        var trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.count > maxInputLength { trimmed = String(trimmed.prefix(maxInputLength)) }

        // Already a full URL with scheme + host — normalise to https if http.
        if let url = URL(string: trimmed), url.scheme?.hasPrefix("http") == true, url.host != nil {
            if url.scheme == "http" {
                var comps = URLComponents(url: url, resolvingAgainstBaseURL: false)!
                comps.scheme = "https"
                if comps.port == nil { comps.port = 8783 }
                return comps.string ?? trimmed
            }
            return trimmed
        }
        // Bracketed IPv6 — [::1] or [::1]:port
        if trimmed.hasPrefix("["), let bracket = trimmed.firstIndex(of: "]") {
            let ip6 = trimmed[trimmed.index(after: trimmed.startIndex)..<bracket]
            let afterBracket = trimmed[trimmed.index(after: bracket)...]
            if let portStr = afterBracket.first == ":" ? String(afterBracket.dropFirst()) : nil,
               let port = UInt16(portStr) {
                return "https://[\(ip6)]:\(port)"
            }
            return "https://[\(ip6)]:8783"
        }
        // host:port — try prepending https:// to parse it.
        if trimmed.contains(":") {
            let colonCount = trimmed.filter { $0 == ":" }.count
            if colonCount > 1 {
                return "https://[\(trimmed)]:8783"
            }
            let candidate = "https://\(trimmed)"
            if let url = URL(string: candidate), url.host != nil {
                return candidate
            }
        }
        // Bare IP or hostname — wrap with https and default RPC port.
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
