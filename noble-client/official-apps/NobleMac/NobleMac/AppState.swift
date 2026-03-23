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
    var selectedSection: SidebarSection? = .home

    // MARK: - WebView Bridge

    /// Reference to the WebView coordinator for JS evaluation.
    weak var webViewCoordinator: WebContentView.Coordinator?

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

    /// Chain ID reported by the node (e.g. "0x4E4F424C").
    var chainId = ""

    /// Current block height from the connected node.
    var blockHeight: UInt64 = 0

    /// Node base URL for JSON-RPC.
    var nodeURL = "https://node.infinitecontext.com:8783"

    /// Error message from last connection attempt.
    var connectionError: String?

    /// Chain ID as UInt32 for transaction signing.
    /// Parses the string chain ID (hex like "4E4F424C" or "0x4E4F424C") to a numeric value.
    /// Falls back to primary chain ID if parsing fails.
    var resolvedChainId: UInt32 {
        let hex = chainId.hasPrefix("0x") ? String(chainId.dropFirst(2)) : chainId
        return UInt32(hex, radix: 16) ?? NobleProtocol.primaryChainId
    }

    // MARK: - Wallet

    /// Whether a wallet is stored in the Keychain.
    var hasWallet = false

    /// The wallet's NOBLE address (nbl1 bech32 display format, or hex wire for non-Noble).
    var walletAddress: String?

    /// Display-formatted wallet balance.
    var walletBalance: String?

    // MARK: - Contacts

    /// Contact store with UserDefaults persistence.
    var contacts: [Contact] = []

    // MARK: - Polling

    /// RPC poll timer for live data refresh (30s interval).
    private var pollTimer: Timer?

    /// Reconnect timer — retries connectToNode every 10s after initial failure.
    private var reconnectTimer: Timer?

    /// Consecutive poll failures — disconnect after 3.
    private var pollFailureCount = 0

    // MARK: - Security Settings

    /// Whether biometric/PIN app lock is enabled.
    var appLockEnabled = false

    /// Lock timeout in seconds (0 = never).
    var lockTimeout = 300

    /// Whether re-authentication is required for send operations.
    var reAuthForSends = true

    /// Whether to auto-connect to saved node on launch.
    var autoConnect = true

    // MARK: - Services

    /// Live API service for the connected node.
    var apiService: (any NobleAPIService)?

    /// Keychain service for secure key storage.
    let keychainService: any KeychainService = LiveKeychainService(service: "com.infinitecontext.noblemac")

    /// Mnemonic provider for wallet creation/import.
    let mnemonicProvider: any MnemonicProviding = LiveMnemonicProvider()

    /// Transaction signer for building signed transactions.
    let transactionSigner: any TransactionSigning = LiveTransactionSigner()

    /// Document hasher for computing SHA-256 checksums.
    let documentHasher = DocumentHasher()

    // MARK: - Keychain Labels

    static let privateKeyLabel = "noblemac.wallet.privatekey"
    static let mnemonicLabel = "noblemac.wallet.mnemonic"
    static let nodeURLLabel = "noblemac.settings.nodeurl"

    // MARK: - UserDefaults Keys

    private static let contactsKey = "noblemac.contacts"
    private static let appLockEnabledKey = "noblemac.settings.appLockEnabled"
    private static let lockTimeoutKey = "noblemac.settings.lockTimeout"
    private static let reAuthForSendsKey = "noblemac.settings.reAuthForSends"
    private static let autoConnectKey = "noblemac.settings.autoConnect"
    private static let onboardingCompleteKey = "noblemac.onboardingComplete"
    private static let draftsKey = "noblemac.documentDrafts"

    // MARK: - Lifecycle

    /// Check if a wallet already exists on launch.
    func checkExistingWallet() {
        // Onboarding flag persists in UserDefaults — only set by completeOnboarding()
        hasCompletedOnboarding = UserDefaults.standard.bool(forKey: Self.onboardingCompleteKey)

        do {
            hasWallet = try keychainService.hasKey(label: Self.privateKeyLabel)
            if hasWallet {
                loadWalletAddress()
                loadSavedNodeURL()
            }
        } catch {
            hasWallet = false
        }
        loadContactsFromDefaults()
        loadSecuritySettings()
        // Auto-connect is handled by scene phase .active in NobleMacApp.swift
        // to avoid racing with a second connectToNode() call.
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
        walletAddress = address.nobleBech32
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
            walletAddress = address.nobleBech32
        } catch {
            // Silently fail — address display is non-critical
        }
    }

    /// Load the private key from Keychain. Returns nil if unavailable.
    func loadPrivateKey() -> Data? {
        do {
            return try keychainService.loadKey(label: Self.privateKeyLabel)
        } catch {
            print("[AppState] Failed to load private key from Keychain: \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - Node Connection

    /// Save the node URL to Keychain for persistence.
    func saveNodeURL(_ url: String) {
        nodeURL = url
        do {
            try keychainService.storeKey(Data(url.utf8), label: Self.nodeURLLabel)
        } catch {
            print("[AppState] Failed to save node URL to Keychain: \(error.localizedDescription)")
        }
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
        reconnectTimer?.invalidate()
        reconnectTimer = nil

        guard let url = URL(string: nodeURL) else {
            connectionError = NE.message("Invalid URL", code: NE.invalidURL)
            return
        }

        let rpcClient = JSONRPCClient(baseURL: url)
        let service = LiveNobleAPIService(client: rpcClient)

        do {
            let nodeInfo = try await service.getNodeInfo()
            apiService = service
            isConnected = true
            chainId = nodeInfo.chainId
            blockHeight = nodeInfo.blockHeight
            saveNodeURL(nodeURL)
            // Push connected state to WebView immediately (don't wait for first pollTick).
            pushStateToWebView([
                "isConnected": true,
                "blockHeight": nodeInfo.blockHeight,
                "chainId": nodeInfo.chainId,
            ])
            startPolling()
        } catch {
            isConnected = false
            let desc = error.localizedDescription
            if desc.localizedCaseInsensitiveContains("TLS")
                || desc.localizedCaseInsensitiveContains("certificate")
                || desc.localizedCaseInsensitiveContains("secure connection")
            {
                connectionError = NE.message("Could not establish a secure connection. Verify the node is running and reachable.", code: NE.tlsFailed)
            } else if desc.localizedCaseInsensitiveContains("Could not connect") || desc.localizedCaseInsensitiveContains("network") {
                connectionError = NE.message("Could not reach the node. Check the IP address and that the node is running.", code: NE.nodeUnreachable)
            } else if desc.localizedCaseInsensitiveContains("timed out") {
                connectionError = NE.message("Connection timed out.", code: NE.timeout)
            } else {
                connectionError = "\(desc) [\(NE.nodeUnreachable)]"
            }
            // Schedule automatic reconnect attempts every 10s.
            scheduleReconnect()
        }
    }

    /// Schedule repeating reconnect attempts (10s interval).
    /// Self-cancels when connectToNode succeeds.
    private func scheduleReconnect() {
        reconnectTimer?.invalidate()
        reconnectTimer = Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !self.isConnected, !self.nodeURL.isEmpty else {
                    self?.reconnectTimer?.invalidate()
                    self?.reconnectTimer = nil
                    return
                }
                await self.connectToNode()
            }
        }
    }

    /// Test connection to a specific URL without changing state.
    func testConnection(url: String) async throws {
        guard let nodeURL = URL(string: url) else {
            throw RPCClientError.connectionFailed(underlying: "Invalid URL")
        }
        let rpcClient = JSONRPCClient(baseURL: nodeURL)
        let service = LiveNobleAPIService(client: rpcClient)
        _ = try await service.getNodeInfo()
    }

    /// Test connection and return the node info for display (chain ID, version, etc.).
    func testConnectionWithInfo(url: String) async throws -> NodeInfo {
        guard let nodeURL = URL(string: url) else {
            throw RPCClientError.connectionFailed(underlying: "Invalid URL")
        }
        let rpcClient = JSONRPCClient(baseURL: nodeURL)
        let service = LiveNobleAPIService(client: rpcClient)
        return try await service.getNodeInfo()
    }

    /// Disconnect from the current node.
    func disconnect() {
        stopPolling()
        apiService = nil
        isConnected = false
        chainId = ""
        blockHeight = 0
        walletBalance = nil
        connectionError = nil
    }

    // MARK: - RPC Polling

    /// Start the 30-second poll timer for live data refresh.
    func startPolling() {
        stopPolling()
        pollFailureCount = 0
        pollTimer = Timer.scheduledTimer(withTimeInterval: 30.0, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                await self?.pollTick()
            }
        }
    }

    /// Stop the poll timer.
    func stopPolling() {
        pollTimer?.invalidate()
        pollTimer = nil
    }

    /// Single poll tick — fetches node info + balance and pushes to WebView.
    func pollTick() async {
        guard let service = apiService else { return }

        do {
            let nodeInfo = try await service.getNodeInfo()
            let syncStatus = try? await service.getSyncStatus()
            let cycleStatus = try? await service.getCycleStatus()

            // Update local state
            blockHeight = nodeInfo.blockHeight
            chainId = nodeInfo.chainId
            pollFailureCount = 0

            // Build state update for WebView
            var stateUpdate: [String: Any] = [
                "isConnected": true,
                "blockHeight": nodeInfo.blockHeight,
                "chainId": nodeInfo.chainId,
                "peerCount": nodeInfo.peerCount,
                "isSyncing": nodeInfo.isSyncing,
            ]

            if let sync = syncStatus {
                stateUpdate["syncStatus"] = [
                    "synced": sync.isSynced,
                    "currentHeight": sync.currentHeight,
                    "highestKnown": sync.highestKnown,
                    "state": sync.state,
                ]
                stateUpdate["nodeState"] = sync.state
            }

            if let cycle = cycleStatus {
                stateUpdate["cycleStatus"] = [
                    "cycleNumber": cycle.cycleNumber,
                    "phase": cycle.phase,
                    "phaseRemainingSecs": cycle.phaseRemainingSecs,
                ]
            }

            // Fetch total wallet balance (all keys: wallet + validator)
            if let walletInfo = try? await service.getFullWalletInfo() {
                walletBalance = walletInfo.balance.formatted
                stateUpdate["walletBalance"] = walletInfo.balance.atomic
                stateUpdate["walletAvailable"] = walletInfo.available.atomic
            } else if let address = walletAddress {
                // Fallback: query single address if getFullWalletInfo unavailable
                if let balance = try? await service.getBalance(address: address) {
                    walletBalance = balance.balance.formatted
                    stateUpdate["walletBalance"] = balance.balance.atomic
                    stateUpdate["walletAvailable"] = balance.available.atomic
                }
            }

            // Push to WebView
            pushStateToWebView(stateUpdate)

        } catch {
            pollFailureCount += 1
            if pollFailureCount >= 3 && isConnected {
                isConnected = false
                pushStateToWebView(["isConnected": false])
            }
            // Auto-reconnect: create a FRESH client (old NWConnection may be dead
            // after node restart). Retry every 2 ticks while disconnected.
            if !isConnected, pollFailureCount % 2 == 0 {
                guard let url = URL(string: nodeURL) else { return }
                let freshClient = JSONRPCClient(baseURL: url)
                let freshService = LiveNobleAPIService(client: freshClient)
                do {
                    let nodeInfo = try await freshService.getNodeInfo()
                    apiService = freshService  // Replace dead service
                    isConnected = true
                    pollFailureCount = 0
                    chainId = nodeInfo.chainId
                    blockHeight = nodeInfo.blockHeight
                    pushStateToWebView([
                        "isConnected": true,
                        "blockHeight": nodeInfo.blockHeight,
                        "chainId": nodeInfo.chainId,
                    ])
                } catch {
                    // Still down — will retry on next poll tick.
                }
            }
        }
    }

    /// Push a state dictionary to the WebView via evaluateJavaScript.
    private func pushStateToWebView(_ state: [String: Any]) {
        guard let coordinator = webViewCoordinator else { return }
        if let jsonData = try? JSONSerialization.data(withJSONObject: state),
           let jsonString = String(data: jsonData, encoding: .utf8)
        {
            coordinator.evaluateJS("App.handleEvent('stateUpdate', \(jsonString))")
        }
    }

    // MARK: - Contact Persistence

    /// Save contacts to UserDefaults.
    func saveContactsToDefaults() {
        if let data = try? JSONEncoder().encode(contacts) {
            UserDefaults.standard.set(data, forKey: Self.contactsKey)
        }
    }

    /// Load contacts from UserDefaults.
    func loadContactsFromDefaults() {
        guard let data = UserDefaults.standard.data(forKey: Self.contactsKey),
              let saved = try? JSONDecoder().decode([Contact].self, from: data)
        else { return }
        contacts = saved
    }

    // MARK: - Security Settings Persistence

    /// Save security settings to UserDefaults.
    func saveSecuritySettings() {
        let defaults = UserDefaults.standard
        defaults.set(appLockEnabled, forKey: Self.appLockEnabledKey)
        defaults.set(lockTimeout, forKey: Self.lockTimeoutKey)
        defaults.set(reAuthForSends, forKey: Self.reAuthForSendsKey)
        defaults.set(autoConnect, forKey: Self.autoConnectKey)
    }

    /// Load security settings from UserDefaults.
    private func loadSecuritySettings() {
        let defaults = UserDefaults.standard
        if defaults.object(forKey: Self.appLockEnabledKey) != nil {
            appLockEnabled = defaults.bool(forKey: Self.appLockEnabledKey)
        }
        if defaults.object(forKey: Self.lockTimeoutKey) != nil {
            lockTimeout = defaults.integer(forKey: Self.lockTimeoutKey)
        }
        if defaults.object(forKey: Self.reAuthForSendsKey) != nil {
            reAuthForSends = defaults.bool(forKey: Self.reAuthForSendsKey)
        }
        if defaults.object(forKey: Self.autoConnectKey) != nil {
            autoConnect = defaults.bool(forKey: Self.autoConnectKey)
        }
    }

    // MARK: - Document Drafts

    /// Load all drafts from UserDefaults as raw JSON arrays.
    func loadDrafts() -> [[String: Any]] {
        guard let data = UserDefaults.standard.data(forKey: Self.draftsKey),
              let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        else { return [] }
        return array
    }

    /// Save a draft (upsert by id).
    func saveDraft(_ draft: [String: Any]) {
        var all = loadDrafts()
        if let id = draft["id"] as? String,
           let idx = all.firstIndex(where: { ($0["id"] as? String) == id })
        {
            all[idx] = draft
        } else {
            all.append(draft)
        }
        persistDrafts(all)
    }

    /// Delete a draft by id.
    func deleteDraft(id: String) {
        var all = loadDrafts()
        all.removeAll { ($0["id"] as? String) == id }
        persistDrafts(all)
    }

    private func persistDrafts(_ drafts: [[String: Any]]) {
        if let data = try? JSONSerialization.data(withJSONObject: drafts) {
            UserDefaults.standard.set(data, forKey: Self.draftsKey)
        }
    }

    /// Complete onboarding and transition to main app.
    func completeOnboarding() {
        hasCompletedOnboarding = true
        UserDefaults.standard.set(true, forKey: Self.onboardingCompleteKey)
        // Clear sensitive onboarding state
        mnemonicWords = []
        mnemonicBackupConfirmed = false
        walletSetupMode = nil
    }
}
