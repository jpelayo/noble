// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Live implementation of ``NobleAPIService`` backed by ``JSONRPCClient``.
public struct LiveNobleAPIService: NobleAPIService {
    private let client: JSONRPCClient

    public init(client: JSONRPCClient) {
        self.client = client
    }

    // MARK: - Node Status

    public func getNodeInfo() async throws -> NodeInfo {
        let dto = try await client.call(method: "noble_getNodeInfo", expecting: NodeInfoDTO.self)
        // Fetch supplementary data from separate RPCs — use try? for graceful degradation
        let blockCount = try? await client.call(method: "noble_getBlockCount", expecting: BlockCountDTO.self)
        let networkInfo = try? await client.call(method: "noble_getNetworkInfo", expecting: NetworkInfoDTO.self)
        let syncStatus = try? await client.call(method: "noble_getSyncStatus", expecting: SyncStatusDTO.self)
        return NodeInfo(
            version: dto.version ?? dto.software_version ?? "unknown",
            chainId: dto.network_name ?? "unknown",
            blockHeight: UInt64(blockCount?.height ?? 0),
            peerCount: networkInfo?.peer_count ?? 0,
            isSyncing: !(syncStatus?.synced ?? true)
        )
    }

    public func ping() async throws -> Bool {
        try await client.testConnection()
    }

    public func getSyncStatus() async throws -> SyncStatus {
        let dto = try await client.call(method: "noble_getSyncStatus", expecting: SyncStatusDTO.self)
        return SyncStatus(
            isSynced: dto.synced,
            currentHeight: dto.current_height,
            highestKnown: dto.highest_known ?? dto.current_height,
            progress: dto.progress ?? (dto.synced ? 1.0 : 0.0)
        )
    }

    public func getCycleStatus() async throws -> CycleStatus {
        let dto = try await client.call(method: "noble_getCycleStatus", expecting: CycleStatusDTO.self)
        return CycleStatus(
            cycleNumber: dto.cycle_number,
            phase: dto.phase,
            phaseRemainingSecs: dto.phase_remaining_secs ?? 0,
            cycleRemainingSecs: dto.cycle_remaining_secs ?? 0
        )
    }

    public func getPeers() async throws -> [PeerInfo] {
        let dtos = try await client.call(method: "noble_getPeerInfo", expecting: [PeerInfoDTO].self)
        return dtos.map { dto in
            PeerInfo(
                peerId: dto.peer_id,
                direction: dto.direction ?? "unknown",
                address: dto.addr,
                nodeName: dto.node_name,
                countryCode: dto.country_code,
                connectedAt: dto.connected_at.map { Date(timeIntervalSince1970: TimeInterval($0)) },
                chainTipHeight: dto.chain_tip_height
            )
        }
    }

    public func getNetworkInfo() async throws -> NetworkInfo {
        let dto = try await client.call(method: "noble_getNetworkInfo", expecting: NetworkInfoDTO.self)
        return NetworkInfo(
            peerCount: dto.peer_count,
            inbound: dto.inbound ?? 0,
            outbound: dto.outbound ?? 0,
            clockOffsetMs: dto.clock_offset_ms ?? 0
        )
    }

    // MARK: - Wallet

    public func getWalletInfo() async throws -> WalletInfo {
        let dto = try await client.call(method: "noble_getWalletInfo", expecting: WalletInfoDTO.self)
        return WalletInfo(
            isUnlocked: dto.unlocked ?? false,
            addressCount: dto.key_count ?? 0,
            primaryAddress: nil // filled from listAddresses if needed
        )
    }

    /// Fetch total wallet balance across all keys (wallet + validator).
    /// Uses the parameterless `noble_getWalletInfo` which sums all address buckets.
    public func getFullWalletInfo() async throws -> WalletBalance {
        let dto = try await client.call(method: "noble_getWalletInfo", expecting: WalletInfoDTO.self)
        return WalletBalance(
            balance: NobleAmount(atomic: dto.balance ?? 0),
            available: NobleAmount(atomic: dto.available ?? dto.balance ?? 0),
            pending: NobleAmount(atomic: dto.pending ?? 0)
        )
    }

    public func getBalance(address: String) async throws -> AddressBalance {
        struct Params: Encodable, Sendable { let address: String }
        let dto = try await client.call(
            method: "noble_getAddressBalance",
            params: Params(address: address),
            expecting: AddressBalanceDTO.self
        )
        guard let addr = NobleAddress(wireHex: dto.public_key ?? address) ?? NobleAddress(wireHex: address) else {
            throw NSError(domain: "NobleAPI", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid address format: \(address)"])
        }
        return AddressBalance(
            address: addr,
            balance: NobleAmount(atomic: dto.balance),
            available: NobleAmount(atomic: dto.available ?? dto.balance),
            pending: NobleAmount(atomic: dto.pending ?? 0),
            txCount: dto.tx_count ?? 0
        )
    }

    public func validateAddress(_ address: String) async throws -> Bool {
        struct Params: Encodable, Sendable { let address: String }
        let dto = try await client.call(
            method: "noble_validateAddress",
            params: Params(address: address),
            expecting: ValidateAddressDTO.self
        )
        return dto.valid
    }

    public func getAddressUtxos(address: String) async throws -> AddressUtxos {
        struct Params: Encodable, Sendable { let address: String }
        let dto = try await client.call(
            method: "noble_getAddressUtxos",
            params: Params(address: address),
            expecting: AddressUtxosDTO.self
        )
        return AddressUtxos(
            address: dto.address ?? address,
            utxos: dto.utxos.map { u in
                UtxoEntry(txid: u.txid, vout: u.vout, value: u.value, height: u.height, isCoinbase: u.is_coinbase)
            }
        )
    }

    // MARK: - Fees

    public func estimateFee() async throws -> FeeEstimate {
        let dto = try await client.call(method: "noble_estimateFee", expecting: FeeEstimateDTO.self)
        return FeeEstimate(
            minFee: NobleAmount(atomic: dto.min_fee),
            recommendedFee: NobleAmount(atomic: dto.recommended_fee),
            highPriorityFee: NobleAmount(atomic: dto.high_priority_fee)
        )
    }

    // MARK: - Transactions

    public func submitTransaction(rawHex: String) async throws -> String {
        let dto = try await client.call(
            method: "noble_submitTransaction",
            params: SubmitTransactionParams(tx_hex: rawHex),
            expecting: SubmitTxDTO.self
        )
        guard dto.accepted ?? false, let txId = dto.tx_id else {
            throw RPCClientError.emptyResult(method: "noble_submitTransaction")
        }
        return txId
    }

    public func getTransaction(txId: String) async throws -> TransactionRecord {
        let dto = try await client.call(
            method: "noble_getTransactionReceipt",
            params: GetTransactionParams(tx_id: txId),
            expecting: TransactionReceiptDTO.self
        )
        return Self.mapTransaction(dto: dto.transaction, receipt: dto)
    }

    public func getTransactionStatus(txId: String) async throws -> TransactionStatus {
        let dto = try await client.call(
            method: "noble_getTransactionStatus",
            params: GetTransactionParams(tx_id: txId),
            expecting: TransactionStatusDTO.self
        )
        switch dto.status.lowercased() {
        case "confirmed": return .confirmed
        case "pending": return .pending
        default: return .pending
        }
    }

    public func getTransactionHistory(
        address: String,
        page: Int,
        limit: Int
    ) async throws -> [TransactionRecord] {
        struct Params: Encodable, Sendable {
            let address: String
            let page: UInt32
            let limit: UInt32
        }
        let dto = try await client.call(
            method: "noble_getAddressHistory",
            params: Params(address: address, page: UInt32(page), limit: UInt32(limit)),
            expecting: AddressHistoryDTO.self
        )
        // Address history returns tx IDs — fetch each receipt
        var records: [TransactionRecord] = []
        for txIdHex in dto.transactions.prefix(limit) {
            if let receipt = try? await getTransaction(txId: txIdHex) {
                records.append(receipt)
            }
        }
        return records
    }

    // MARK: - Documents

    public func verifyDocument(checksum: String) async throws -> VerificationResult {
        let dto = try await client.call(
            method: "noble_verifyDocument",
            params: LookupChecksumParams(checksum: checksum),
            expecting: VerifyDocumentDTO.self
        )
        let versions = try await getDocumentVersions(checksum: checksum)
        return VerificationResult(
            isRegistered: dto.registered,
            registration: nil, // populated from lookupChecksum if needed
            registrationCount: dto.registrations ?? 0,
            versions: versions
        )
    }

    public func lookupChecksum(checksum: String) async throws -> [RegistrationRecord] {
        let dto = try await client.call(
            method: "noble_lookupChecksum",
            params: LookupChecksumParams(checksum: checksum),
            expecting: ChecksumLookupDTO.self
        )
        return (dto.records ?? []).compactMap { Self.mapRegistration(dto: $0, checksum: checksum) }
    }

    public func getDocumentVersions(checksum: String) async throws -> [VersionEntry] {
        let dto = try await client.call(
            method: "noble_getDocumentVersions",
            params: LookupChecksumParams(checksum: checksum),
            expecting: DocumentVersionsDTO.self
        )
        return (dto.versions ?? []).compactMap { v in
            guard let cs = v.checksum.flatMap({ Hash256(hex: $0) }),
                  let txId = v.tx_id.flatMap({ Hash256(hex: $0) }) else { return nil }
            // Issuer not available in version DTO — placeholder (API limitation)
            let issuer = NobleAddress(wireHex: "0200000000000000000000000000000000000000000000000000000000000000000000")!  // swiftlint:disable:this force_unwrapping
            return VersionEntry(
                checksum: cs,
                previousChecksum: nil,
                txId: txId,
                issuer: issuer,
                blockHeight: v.block_height ?? 0,
                timestamp: v.timestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? .now
            )
        }
    }

    // MARK: - DTO Mappers

    private static func mapTransaction(dto: TransactionDTO?, receipt: TransactionReceiptDTO?) -> TransactionRecord {
        let txIdStr = dto?.tx_id ?? receipt?.transaction?.tx_id ?? ""
        let txId = Hash256(hex: txIdStr) ?? Hash256(hex: String(repeating: "0", count: 64))!
        let signer: NobleAddress
        if let signerStr = dto?.signer, let parsed = NobleAddress(wireHex: signerStr) {
            signer = parsed
        } else {
            print("[NobleAPI] Warning: could not parse signer '\(dto?.signer ?? "nil")' — using placeholder")
            signer = NobleAddress(wireHex: "0200000000000000000000000000000000000000000000000000000000000000000000")!  // swiftlint:disable:this force_unwrapping
        }
        let txType: TransactionType = (dto?.tx_type ?? "notarization") == "transfer" ? .transfer : .notarization
        let status: TransactionStatus = (receipt?.status ?? "pending") == "confirmed" ? .confirmed : .pending
        let checksum = dto?.checksum.flatMap { Hash256(hex: $0) }
        let timestamp = dto?.timestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) }

        let inputs = (dto?.inputs ?? []).map { TxInput(txid: $0.txid, vout: $0.vout) }
        let outputs = (dto?.outputs ?? []).map { TxOutput(value: $0.value, address: $0.address) }

        return TransactionRecord(
            txId: txId,
            txType: txType,
            status: status,
            signer: signer,
            totalOutput: dto?.total_output ?? 0,
            inputs: inputs,
            outputs: outputs,
            blockHeight: receipt?.block_height,
            timestamp: timestamp,
            checksum: checksum
        )
    }

    // MARK: - Capability Detection

    /// Probe the node to discover which optional RPCs are available.
    public func detectCapabilities() async -> NodeCapabilities {
        async let hasCycle = (try? await getCycleStatus()) != nil
        async let hasSync = (try? await getSyncStatus()) != nil
        async let hasPeers = (try? await getPeers()) != nil

        return await NodeCapabilities(
            cycleStatus: hasCycle,
            syncStatus: hasSync,
            peerInfo: hasPeers
        )
    }

    private static func mapRegistration(dto: RegistrationRecordDTO, checksum: String) -> RegistrationRecord? {
        guard let txId = dto.tx_id.flatMap({ Hash256(hex: $0) }),
              let cs = Hash256(hex: checksum) else { return nil }
        let issuer: NobleAddress
        if let pubStr = dto.issuer, let parsed = NobleAddress(wireHex: pubStr) {
            issuer = parsed
        } else {
            print("[NobleAPI] Warning: could not parse issuer '\(dto.issuer ?? "nil")' — using placeholder")
            issuer = NobleAddress(wireHex: "0200000000000000000000000000000000000000000000000000000000000000000000")!  // swiftlint:disable:this force_unwrapping
        }
        let metadata = (dto.metadata ?? []).map { MetadataItem(key: $0.key, value: $0.value) }
        let timestamp = dto.timestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) } ?? .now

        return RegistrationRecord(
            txId: txId,
            checksum: cs,
            issuer: issuer,
            blockHeight: dto.block_height ?? 0,
            timestamp: timestamp,
            metadata: metadata,
            fee: NobleAmount(atomic: dto.fee ?? 0)
        )
    }
}
