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
            version: "0.20.0",
            network: "testnet",
            blockHeight: 1_247,
            peerCount: 3,
            isSyncing: false
        )
    }

    public func ping() async throws -> Bool {
        await simulateDelay()
        return true
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

    public func getBalance(address: NobleAddress) async throws -> AddressBalance {
        await simulateDelay()
        return AddressBalance(
            address: address,
            balance: NobleAmount(atomic: 42_500_000),
            available: NobleAmount(atomic: 42_000_000),
            pending: NobleAmount(atomic: 500_000),
            txCount: 15
        )
    }

    // MARK: - Transactions

    public func submitTransaction(rawHex: String) async throws -> Hash256 {
        await simulateDelay()
        // swiftlint:disable:next force_unwrapping
        return Hash256(hex: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")!
    }

    public func getTransaction(txId: Hash256) async throws -> TransactionRecord {
        await simulateDelay()
        return TransactionRecord(
            txId: txId,
            txType: .transfer,
            status: .confirmed,
            from: Self.sampleSender,
            to: Self.sampleReceiver,
            amount: NobleAmount(atomic: 5_000_000),
            fee: NobleAmount(atomic: 100),
            blockHeight: 1_230,
            timestamp: Date(timeIntervalSinceNow: -1800)
        )
    }

    public func getTransactionHistory(
        address: NobleAddress,
        limit: Int,
        offset: Int
    ) async throws -> [TransactionRecord] {
        await simulateDelay()
        return Self.makeSampleTransactions()
            .dropFirst(offset)
            .prefix(limit)
            .map { $0 }
    }

    // MARK: - Documents

    public func queryDocuments(checksum: Hash256) async throws -> RegistrationRecord? {
        await simulateDelay()
        // swiftlint:disable:next force_unwrapping
        let txId = Hash256(hex: "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3")!
        return RegistrationRecord(
            txId: txId,
            checksum: checksum,
            publisher: Self.sampleSender,
            blockHeight: 1_200,
            timestamp: Date(timeIntervalSinceNow: -3600),
            metadata: [MetadataItem(key: "filename", value: "contract.pdf")],
            fee: NobleAmount(atomic: 100)
        )
    }

    public func getDocumentHistory(checksum: Hash256) async throws -> [VersionEntry] {
        await simulateDelay()
        // swiftlint:disable:next force_unwrapping
        let txId = Hash256(hex: "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")!
        return [
            VersionEntry(
                checksum: checksum,
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

            let record = TransactionRecord(
                txId: txId,
                txType: i % 2 == 0 ? .transfer : .notarization,
                status: .confirmed,
                from: sampleSender,
                to: sampleReceiver,
                amount: NobleAmount(atomic: UInt64((i + 1) * 1_000_000)),
                fee: NobleAmount(atomic: 100),
                blockHeight: UInt64(1_200 + i * 10),
                timestamp: Date(timeIntervalSinceNow: Double(-3600 + i * 600))
            )
            records.append(record)
        }
        return records
    }
}
