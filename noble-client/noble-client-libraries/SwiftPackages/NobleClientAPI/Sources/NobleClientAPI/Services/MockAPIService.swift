// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Mock implementation of ``NobleAPIService`` for SwiftUI previews and tests.
///
/// Returns deterministic sample data with configurable delay.
public struct MockAPIService: NobleAPIService {
    /// Simulated network delay.
    private let delay: Duration

    public init(delay: Duration = .milliseconds(200)) {
        self.delay = delay
    }

    private func simulateDelay() async {
        try? await Task.sleep(for: delay)
    }

    // MARK: - Sample Addresses

    // swiftlint:disable:next force_unwrapping
    private static let sampleSender = NobleAddress(
        wireHex: "020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"
    )!

    // swiftlint:disable:next force_unwrapping
    private static let sampleReceiver = NobleAddress(
        wireHex: "0201fedcba9876543210fedcba9876543210fedcba9876543210fedcba98765432"
    )!

    // MARK: - Node Status

    public func getNodeInfo() async throws -> NodeInfo {
        await simulateDelay()
        return NodeInfo(
            version: "0.30.0",
            chainId: "0x5453544E",
            blockHeight: 1_247,
            peerCount: 3,
            isSyncing: false
        )
    }

    public func ping() async throws -> Bool {
        await simulateDelay()
        return true
    }

    public func getSyncStatus() async throws -> SyncStatus {
        await simulateDelay()
        return SyncStatus(
            isSynced: true,
            currentHeight: 1_247,
            highestKnown: 1_247,
            progress: 1.0
        )
    }

    public func getCycleStatus() async throws -> CycleStatus {
        await simulateDelay()
        return CycleStatus(
            cycleNumber: 42,
            phase: "Voting",
            phaseRemainingSecs: 180,
            cycleRemainingSecs: 780
        )
    }

    public func getPeers() async throws -> [PeerInfo] {
        await simulateDelay()
        return [
            PeerInfo(
                peerId: "12D3KooWExample1",
                direction: "outbound",
                address: "/ip4/192.168.1.100/tcp/8780",
                nodeName: "Blackview-Node",
                countryCode: "ESP",
                connectedAt: Date(timeIntervalSinceNow: -3600),
                chainTipHeight: 1_247
            ),
            PeerInfo(
                peerId: "12D3KooWExample2",
                direction: "inbound",
                address: "/ip4/10.0.0.50/tcp/8780",
                nodeName: "Mac-Validator",
                countryCode: "USA",
                connectedAt: Date(timeIntervalSinceNow: -7200),
                chainTipHeight: 1_245
            ),
        ]
    }

    public func getNetworkInfo() async throws -> NetworkInfo {
        await simulateDelay()
        return NetworkInfo(peerCount: 3, inbound: 1, outbound: 2, clockOffsetMs: -45)
    }

    // MARK: - Wallet

    public func getWalletInfo() async throws -> WalletInfo {
        await simulateDelay()
        return WalletInfo(
            isUnlocked: true,
            addressCount: 1,
            primaryAddress: Self.sampleSender
        )
    }

    public func getFullWalletInfo() async throws -> WalletBalance {
        await simulateDelay()
        return WalletBalance(
            balance: NobleAmount(atomic: 50_000_000),
            available: NobleAmount(atomic: 50_000_000),
            pending: .zero
        )
    }

    public func getBalance(address: String) async throws -> AddressBalance {
        await simulateDelay()
        let addr = NobleAddress(wireHex: address) ?? Self.sampleSender
        return AddressBalance(
            address: addr,
            balance: NobleAmount(atomic: 42_500_000),
            available: NobleAmount(atomic: 42_000_000),
            pending: NobleAmount(atomic: 500_000),
            txCount: 15
        )
    }

    public func validateAddress(_ address: String) async throws -> Bool {
        await simulateDelay()
        return address.count >= 4
    }

    // MARK: - Fees

    public func estimateFee() async throws -> FeeEstimate {
        await simulateDelay()
        return FeeEstimate(
            minFee: NobleAmount(atomic: 1),
            recommendedFee: NobleAmount(atomic: 100),
            highPriorityFee: NobleAmount(atomic: 500)
        )
    }

    // MARK: - Transactions

    public func submitTransaction(rawHex: String) async throws -> String {
        await simulateDelay()
        return "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    }

    public func getTransaction(txId: String) async throws -> TransactionRecord {
        await simulateDelay()
        let hash = Hash256(hex: txId) ?? Hash256(hex: String(repeating: "ab", count: 32))!
        return TransactionRecord(
            txId: hash,
            txType: .transfer,
            status: .confirmed,
            signer: Self.sampleSender,
            totalOutput: 5_000_000,
            inputs: [TxInput(txid: String(repeating: "00", count: 32), vout: 0)],
            outputs: [TxOutput(value: 5_000_000, address: Self.sampleReceiver.wireHex)],
            blockHeight: 1_230,
            timestamp: Date(timeIntervalSinceNow: -1800)
        )
    }

    public func getTransactionStatus(txId: String) async throws -> TransactionStatus {
        await simulateDelay()
        return .confirmed
    }

    public func getTransactionHistory(
        address: String,
        page: Int,
        limit: Int
    ) async throws -> [TransactionRecord] {
        await simulateDelay()
        return Self.makeSampleTransactions()
            .dropFirst(page * limit)
            .prefix(limit)
            .map { $0 }
    }

    // MARK: - Documents

    public func verifyDocument(checksum: String) async throws -> VerificationResult {
        await simulateDelay()
        guard let cs = Hash256(hex: checksum) else {
            return VerificationResult(isRegistered: false)
        }
        let txId = Hash256(hex: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3")!
        let record = RegistrationRecord(
            txId: txId,
            checksum: cs,
            publisher: Self.sampleSender,
            blockHeight: 1_200,
            timestamp: Date(timeIntervalSinceNow: -3600),
            metadata: [MetadataItem(key: "filename", value: "contract.pdf")],
            fee: NobleAmount(atomic: 100)
        )
        return VerificationResult(
            isRegistered: true,
            registration: record,
            registrationCount: 1,
            versions: []
        )
    }

    public func lookupChecksum(checksum: String) async throws -> [RegistrationRecord] {
        await simulateDelay()
        guard let cs = Hash256(hex: checksum) else { return [] }
        let txId = Hash256(hex: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3")!
        return [
            RegistrationRecord(
                txId: txId,
                checksum: cs,
                publisher: Self.sampleSender,
                blockHeight: 1_200,
                timestamp: Date(timeIntervalSinceNow: -3600),
                metadata: [MetadataItem(key: "filename", value: "contract.pdf")],
                fee: NobleAmount(atomic: 100)
            ),
        ]
    }

    public func getDocumentVersions(checksum: String) async throws -> [VersionEntry] {
        await simulateDelay()
        guard let cs = Hash256(hex: checksum) else { return [] }
        let txId = Hash256(hex: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")!
        return [
            VersionEntry(
                checksum: cs,
                previousChecksum: nil,
                txId: txId,
                publisher: Self.sampleSender,
                blockHeight: 1_200,
                timestamp: Date(timeIntervalSinceNow: -3600)
            ),
        ]
    }

    // MARK: - Sample Data Factory

    private static func makeSampleTransactions() -> [TransactionRecord] {
        var records: [TransactionRecord] = []
        for i in 0..<5 {
            let hexByte = String(format: "%02x", i)
            let hexString = String(repeating: hexByte, count: 32)
            guard let txId = Hash256(hex: hexString) else { continue }

            let outputValue = UInt64((i + 1) * 1_000_000)
            let record = TransactionRecord(
                txId: txId,
                txType: i % 2 == 0 ? .transfer : .notarization,
                status: .confirmed,
                signer: sampleSender,
                totalOutput: outputValue,
                inputs: [TxInput(txid: String(repeating: "00", count: 32), vout: 0)],
                outputs: [TxOutput(value: outputValue, address: sampleReceiver.wireHex)],
                blockHeight: UInt64(1_200 + i * 10),
                timestamp: Date(timeIntervalSinceNow: Double(-3600 + i * 600))
            )
            records.append(record)
        }
        return records
    }
}
