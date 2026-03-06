// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import SwiftUI

/// Step 4: Setup complete — summary and transition to main app.
struct OnboardingCompleteView: View {
    @Bindable var appState: AppState

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 64))
                .foregroundStyle(.green)

            Text("You're All Set")
                .font(.largeTitle)
                .bold()

            VStack(alignment: .leading, spacing: 12) {
                summaryRow(
                    icon: "wallet.bifold",
                    title: "Wallet",
                    detail: truncatedAddress
                )

                summaryRow(
                    icon: "network",
                    title: "Node",
                    detail: appState.isConnected ? appState.nodeURL : "Not connected"
                )
            }
            .padding()
            .background(.quaternary.opacity(0.5))
            .clipShape(.rect(cornerRadius: 12))

            Button("Start Using NobleDoc") {
                appState.completeOnboarding()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
        .padding()
    }

    private func summaryRow(icon: String, title: String, detail: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .frame(width: 24)
                .foregroundStyle(.tint)

            VStack(alignment: .leading) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(detail)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
    }

    private var truncatedAddress: String {
        guard let address = appState.walletAddress, address.count > 16 else {
            return appState.walletAddress ?? "Unknown"
        }
        let prefix = address.prefix(10)
        let suffix = address.suffix(6)
        return "\(prefix)...\(suffix)"
    }
}
