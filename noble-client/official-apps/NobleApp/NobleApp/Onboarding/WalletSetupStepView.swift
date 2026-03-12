// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import NobleClientCrypto
import SwiftUI

/// Step 2: Create a new wallet or import an existing one.
struct WalletSetupStepView: View {
    @Bindable var appState: AppState
    @State private var importText = ""
    @State private var errorMessage: String?
    @State private var isProcessing = false
    @State private var showMnemonic = false

    var body: some View {
        VStack(spacing: 24) {
            Text("Set Up Your Wallet")
                .font(.title)
                .bold()

            Text("Your wallet holds the private key used to sign document registrations and transfers.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            if appState.walletSetupMode == nil {
                modeSelection
            } else if appState.walletSetupMode == .createNew {
                createNewWallet
            } else {
                importExistingWallet
            }

            if let errorMessage {
                Text(errorMessage)
                    .font(.caption)
                    .foregroundStyle(Color(.systemRed))
            }
        }
        .padding()
    }

    // MARK: - Mode Selection

    private var modeSelection: some View {
        VStack(spacing: 12) {
            Button {
                generateMnemonic()
            } label: {
                Label("Create New Wallet", systemImage: "plus.circle")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)

            Button {
                appState.walletSetupMode = .importExisting
            } label: {
                Label("Import Existing Wallet", systemImage: "square.and.arrow.down")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .controlSize(.large)

            Button("Back") {
                appState.onboardingStep = .welcome
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
        }
    }

    // MARK: - Create New Wallet

    private var createNewWallet: some View {
        VStack(spacing: 16) {
            Text("Your Recovery Phrase")
                .font(.headline)

            Text("Write these 24 words down and store them safely. This is the only way to recover your wallet.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            if showMnemonic {
                mnemonicGrid
            }

            Toggle("I have safely backed up my recovery phrase", isOn: $appState.mnemonicBackupConfirmed)

            HStack {
                Button("Back") {
                    appState.walletSetupMode = nil
                    appState.mnemonicWords = []
                    appState.mnemonicBackupConfirmed = false
                    showMnemonic = false
                }
                .buttonStyle(.bordered)

                Spacer()

                Button("Continue") {
                    createWallet()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!appState.mnemonicBackupConfirmed || isProcessing)
            }
        }
    }

    // MARK: - Import Existing Wallet

    private var importExistingWallet: some View {
        VStack(spacing: 16) {
            Text("Enter Recovery Phrase")
                .font(.headline)

            Text("Enter your 24-word recovery phrase, separated by spaces.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            TextEditor(text: $importText)
                .font(.body.monospaced())
                .frame(height: 100)
                .clipShape(.rect(cornerRadius: 8))
                .overlay(
                    RoundedRectangle(cornerRadius: 8)
                        .stroke(.quaternary)
                )
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)

            HStack {
                Button("Back") {
                    appState.walletSetupMode = nil
                    importText = ""
                    errorMessage = nil
                }
                .buttonStyle(.bordered)

                Spacer()

                Button("Import") {
                    importWallet()
                }
                .buttonStyle(.borderedProminent)
                .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || isProcessing)
            }
        }
    }

    // MARK: - Mnemonic Display

    private var mnemonicGrid: some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 8) {
            ForEach(appState.mnemonicWords.enumerated().map { $0 }, id: \.offset) { index, word in
                HStack(spacing: 4) {
                    Text("\(index + 1).")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                        .frame(width: 20, alignment: .trailing)
                    Text(word)
                        .font(.caption.monospaced())
                }
                .padding(.vertical, 4)
                .padding(.horizontal, 6)
                .background(.quaternary)
                .clipShape(.rect(cornerRadius: 4))
            }
        }
        .privacySensitive()
    }

    // MARK: - Actions

    private func generateMnemonic() {
        errorMessage = nil
        do {
            appState.mnemonicWords = try appState.mnemonicProvider.generateMnemonic(wordCount: 24)
            appState.walletSetupMode = .createNew
            showMnemonic = true
        } catch {
            errorMessage = "Failed to generate mnemonic: \(error.localizedDescription)"
        }
    }

    private func createWallet() {
        errorMessage = nil
        isProcessing = true
        defer { isProcessing = false }

        do {
            try appState.createWallet(mnemonic: appState.mnemonicWords)
            appState.onboardingStep = .nodeConnection
        } catch {
            errorMessage = "Failed to create wallet: \(error.localizedDescription)"
        }
    }

    private func importWallet() {
        errorMessage = nil
        isProcessing = true
        defer { isProcessing = false }

        let words = importText
            .lowercased()
            .split(separator: /\s+/)
            .map(String.init)

        guard words.count == 24 else {
            errorMessage = "Please enter exactly 24 words."
            return
        }

        do {
            try appState.importWallet(mnemonic: words)
            appState.onboardingStep = .nodeConnection
        } catch {
            errorMessage = "Invalid recovery phrase. Please check your words and try again."
        }
    }
}
