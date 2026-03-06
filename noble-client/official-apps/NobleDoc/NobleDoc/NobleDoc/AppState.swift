// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import NobleClientAPI
import NobleClientCore
import NobleClientCrypto
import NobleClientSecurity
import SwiftUI

/// Onboarding steps for first-time setup.
enum OnboardingStep: Int, CaseIterable {
    case welcome
    case walletSetup
    case nodeConnection
    case complete
}

/// Wallet setup mode chosen during onboarding.
enum WalletSetupMode {
    case createNew
    case importExisting
}

/// Global app state shared across the view hierarchy.
@Observable
@MainActor
final class AppState {
    // MARK: - Navigation

    /// Currently selected sidebar section.
    var selectedSection: SidebarSection? = .documents

    // MARK: - Onboarding

    /// Whether onboarding has been completed.
    var hasCompletedOnboarding = false

    /// Current onboarding step.
    var onboardingStep: OnboardingStep = .welcome

    /// Wallet setup mode selected during onboarding.
    var walletSetupMode: WalletSetupMode?

    /// Mnemonic words generated or entered during onboarding.
    var mnemonicWords: [String] = []

    /// Whether the user confirmed they backed up the mnemonic.
    var mnemonicBackupConfirmed = false

    // MARK: - Connection

    /// Whether the app is connected to a NOBLE node.
    var isConnected = false

    /// Network label reported by the node (e.g. "testnet", "mainnet").
    var networkLabel = ""

    /// Current block height from the connected node.
    var blockHeight: UInt64 = 0

    /// Node base URL for JSON-RPC.
    var nodeURL = "https://localhost:8783"

    /// Error message from last connection attempt.
    var connectionError: String?

    // MARK: - Wallet

    /// Whether a wallet is stored in the Keychain.
    var hasWallet = false

    /// The wallet's NOBLE address (hex wire format).
    var walletAddress: String?

    /// Display-formatted wallet balance.
    var walletBalance: String?

    // MARK: - Services

    /// Live API service for the connected node.
    var apiService: (any NobleAPIService)?

    /// Keychain service for secure key storage.
    let keychainService: any KeychainService = LiveKeychainService()

    /// Mnemonic provider for wallet creation/import.
    let mnemonicProvider: any MnemonicProviding = LiveMnemonicProvider()

    /// Transaction signer for building signed transactions.
    let transactionSigner: any TransactionSigning = LiveTransactionSigner()

    /// Document hasher for computing SHA-256 checksums.
    let documentHasher = DocumentHasher()

    // MARK: - Keychain Labels

    static let privateKeyLabel = "nobledoc.wallet.privatekey"
    static let mnemonicLabel = "nobledoc.wallet.mnemonic"
    static let nodeURLLabel = "nobledoc.settings.nodeurl"

    // MARK: - Lifecycle

    /// Check if a wallet already exists on launch.
    func checkExistingWallet() {
        do {
            hasWallet = try keychainService.hasKey(label: Self.privateKeyLabel)
            if hasWallet {
                hasCompletedOnboarding = true
                loadWalletAddress()
                loadSavedNodeURL()
            }
        } catch {
            hasWallet = false
        }
    }

    // MARK: - Wallet Operations

    /// Create a new wallet from a mnemonic and store in Keychain.
    func createWallet(mnemonic: [String]) throws {
        let privateKey = try mnemonicProvider.derivePrivateKey(mnemonic: mnemonic)
        let address = try mnemonicProvider.deriveAddress(privateKey: privateKey)

        // Store private key
        try keychainService.storeKey(privateKey, label: Self.privateKeyLabel)

        // Store mnemonic for backup recovery
        let mnemonicData = Data(mnemonic.joined(separator: " ").utf8)
        try keychainService.storeKey(mnemonicData, label: Self.mnemonicLabel)

        hasWallet = true
        walletAddress = address.wireHex
    }

    /// Import a wallet from an existing mnemonic.
    func importWallet(mnemonic: [String]) throws {
        guard mnemonicProvider.validateMnemonic(mnemonic) else {
            throw CryptoError.invalidMnemonic
        }
        try createWallet(mnemonic: mnemonic)
    }

    /// Load the wallet address from the stored private key.
    private func loadWalletAddress() {
        do {
            guard let privateKey = try keychainService.loadKey(label: Self.privateKeyLabel) else {
                return
            }
            let address = try mnemonicProvider.deriveAddress(privateKey: privateKey)
            walletAddress = address.wireHex
        } catch {
            // Silently fail — address display is non-critical
        }
    }

    // MARK: - Node Connection

    /// Save the node URL to Keychain for persistence.
    func saveNodeURL(_ url: String) {
        nodeURL = url
        try? keychainService.storeKey(Data(url.utf8), label: Self.nodeURLLabel)
    }

    /// Load saved node URL from Keychain.
    private func loadSavedNodeURL() {
        do {
            if let data = try keychainService.loadKey(label: Self.nodeURLLabel),
               let url = String(data: data, encoding: .utf8)
            {
                nodeURL = url
            }
        } catch {
            // Use default
        }
    }

    /// Test connection to the node and update state.
    func connectToNode() async {
        connectionError = nil

        guard let url = URL(string: nodeURL) else {
            connectionError = "Invalid URL"
            return
        }

        let rpcClient = JSONRPCClient(baseURL: url)
        let service = LiveNobleAPIService(client: rpcClient)

        do {
            let nodeInfo = try await service.getNodeInfo()
            apiService = service
            isConnected = true
            networkLabel = nodeInfo.network
            blockHeight = nodeInfo.blockHeight
            saveNodeURL(nodeURL)
        } catch {
            isConnected = false
            connectionError = error.localizedDescription
        }
    }

    /// Disconnect from the current node.
    func disconnect() {
        apiService = nil
        isConnected = false
        networkLabel = ""
        blockHeight = 0
        connectionError = nil
    }

    /// Complete onboarding and transition to main app.
    func completeOnboarding() {
        hasCompletedOnboarding = true
        // Clear sensitive onboarding state
        mnemonicWords = []
        mnemonicBackupConfirmed = false
        walletSetupMode = nil
    }
}
