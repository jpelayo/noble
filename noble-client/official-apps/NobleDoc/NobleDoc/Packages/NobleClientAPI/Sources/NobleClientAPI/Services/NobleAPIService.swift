// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Protocol for all NOBLE node JSON-RPC operations used by the app.
///
/// Implementations:
/// - ``MockAPIService`` for SwiftUI previews and tests
/// - ``LiveNobleAPIService`` for real node connections
public protocol NobleAPIService: Sendable {

    // MARK: - Node Status

    /// Fetch basic node info (version, network, block height).
    func getNodeInfo() async throws -> NodeInfo

    /// Check if the node is reachable.
    func ping() async throws -> Bool

    /// Fetch sync status (height, syncing state, progress).
    func getSyncStatus() async throws -> SyncStatus

    /// Fetch current consensus cycle status.
    func getCycleStatus() async throws -> CycleStatus

    /// Fetch connected peers.
    func getPeers() async throws -> [PeerInfo]

    // MARK: - Wallet

    /// Fetch wallet state from the node.
    func getWalletInfo() async throws -> WalletInfo

    /// Fetch balance for a specific address.
    func getBalance(address: String) async throws -> AddressBalance

    /// Validate a NOBLE or Bitcoin address.
    func validateAddress(_ address: String) async throws -> Bool

    // MARK: - Fees

    /// Estimate transaction fees.
    func estimateFee() async throws -> FeeEstimate

    // MARK: - Transactions

    /// Submit a raw signed transaction (hex-encoded CBOR).
    func submitTransaction(rawHex: String) async throws -> String

    /// Fetch a transaction by its ID.
    func getTransaction(txId: String) async throws -> TransactionRecord

    /// Fetch transaction status.
    func getTransactionStatus(txId: String) async throws -> TransactionStatus

    /// Fetch transaction history for an address.
    func getTransactionHistory(
        address: String,
        page: Int,
        limit: Int
    ) async throws -> [TransactionRecord]

    // MARK: - Documents

    /// Verify a document checksum on-chain.
    func verifyDocument(checksum: String) async throws -> VerificationResult

    /// Fetch document registration records for a checksum.
    func lookupChecksum(checksum: String) async throws -> [RegistrationRecord]

    /// Fetch version history for a document checksum.
    func getDocumentVersions(checksum: String) async throws -> [VersionEntry]
}
