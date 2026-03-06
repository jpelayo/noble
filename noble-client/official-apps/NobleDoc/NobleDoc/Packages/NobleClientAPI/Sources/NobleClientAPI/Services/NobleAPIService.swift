// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Protocol for all NOBLE node JSON-RPC operations used by the app.
///
/// Implementations include:
/// - ``MockAPIService`` for SwiftUI previews and tests
/// - A real JSON-RPC client (Sprint 3)
public protocol NobleAPIService: Sendable {

    // MARK: - Node Status

    /// Fetch basic node info (version, network, block height).
    func getNodeInfo() async throws -> NodeInfo

    /// Check if the node is reachable.
    func ping() async throws -> Bool

    // MARK: - Wallet

    /// Fetch wallet state from the node.
    func getWalletInfo() async throws -> WalletInfo

    /// Fetch balance for a specific address.
    func getBalance(address: NobleAddress) async throws -> AddressBalance

    // MARK: - Transactions

    /// Submit a raw signed transaction (hex-encoded CBOR).
    func submitTransaction(rawHex: String) async throws -> Hash256

    /// Fetch a transaction by its ID.
    func getTransaction(txId: Hash256) async throws -> TransactionRecord

    /// Fetch transaction history for an address.
    func getTransactionHistory(
        address: NobleAddress,
        limit: Int,
        offset: Int
    ) async throws -> [TransactionRecord]

    // MARK: - Documents

    /// Query documents by checksum.
    func queryDocuments(checksum: Hash256) async throws -> RegistrationRecord?

    /// Fetch version history for a document checksum.
    func getDocumentHistory(checksum: Hash256) async throws -> [VersionEntry]
}
