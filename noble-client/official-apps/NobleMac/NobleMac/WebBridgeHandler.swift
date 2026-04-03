// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import AppKit
import CryptoKit
import Foundation
import NobleClientAPI
import NobleClientCore
import NobleClientCrypto
import NobleClientSecurity
import NobleTxCore
import UniformTypeIdentifiers

// MARK: - Faucet DTOs (file-scope to avoid @MainActor isolation)

private nonisolated struct FaucetListDTO: Decodable, Sendable {
    let faucets: [FaucetEntryDTO]
}

private nonisolated struct FaucetEntryDTO: Decodable, Sendable {
    let url: String
    let faucet_address: String
    let faucet_balance: UInt64
    let drip_amount: UInt64
    let network: String
    let last_probed: UInt64
}

// MARK: - Snapshot params (file-scope to avoid @MainActor isolation)

private nonisolated struct SnapshotParams: Encodable, Sendable { let address: String }

/// Routes bridge messages from the web UI to Swift services.
@MainActor
final class WebBridgeHandler {
    private let appState: AppState

    init(appState: AppState) {
        self.appState = appState
    }

    /// Handle an incoming bridge message and resolve the callback.
    func handle(
        handler: String,
        action: String,
        params: [String: Any],
        callbackId: String,
        coordinator: WebContentView.Coordinator
    ) async {
        do {
            let result: Any
            switch handler {
            case "noble_api":
                result = try await handleAPI(action: action, params: params)
            case "noble_crypto":
                result = try await handleCrypto(action: action, params: params)
            case "noble_security":
                result = try await handleSecurity(action: action, params: params)
            case "noble_app":
                result = try await handleApp(action: action, params: params)
            case "noble_storage":
                result = try await handleStorage(action: action, params: params)
            default:
                throw BridgeError.unknownHandler(handler)
            }

            let json = try serializeToJSON(result)
            let escaped = json.replacingOccurrences(of: "'", with: "\\'")
            coordinator.evaluateJS("NativeBridge._handleCallback('\(callbackId)', null, '\(escaped)')")
        } catch {
            let msg = error.localizedDescription.replacingOccurrences(of: "'", with: "\\'")
            coordinator.evaluateJS("NativeBridge._handleCallback('\(callbackId)', '\(msg)', null)")
        }
    }

    // MARK: - API Handler

    private func handleAPI(action: String, params: [String: Any]) async throws -> Any {
        guard let api = appState.apiService else {
            throw BridgeError.notConnected
        }

        switch action {
        case "getBalance":
            guard let address = params["address"] as? String else {
                throw BridgeError.missingParam("address")
            }
            let balance = try await api.getBalance(address: address)
            return [
                "address": balance.address.nobleBech32,
                "balance": balance.balance.atomic,
                "available": balance.available.atomic,
                "pending": balance.pending.atomic,
                "txCount": balance.txCount,
                "immature_count": balance.immatureCount,
                "immature_value": balance.immatureValue,
            ] as [String: Any]

        case "getSyncStatus":
            let status = try await api.getSyncStatus()
            return [
                "synced": status.isSynced,
                "currentHeight": status.currentHeight,
                "highestKnown": status.highestKnown,
                "progress": status.progress,
            ] as [String: Any]

        case "getCycleStatus":
            let cycle = try await api.getCycleStatus()
            return [
                "cycleNumber": cycle.cycleNumber,
                "phase": cycle.phase,
                "phaseRemainingSecs": cycle.phaseRemainingSecs,
                "cycleRemainingSecs": cycle.cycleRemainingSecs,
            ] as [String: Any]

        case "getWalletSnapshot":
            // Atomic snapshot: balance + transactions under one chain_height.
            // Eliminates race condition where getBalance and getWalletTransactions
            // observe different chain tips when called in parallel.
            guard let addr = appState.walletAddress, !addr.isEmpty else {
                throw BridgeError.missingParam("walletAddress not set")
            }
            guard let liveSvc = api as? LiveNobleAPIService else {
                throw BridgeError.notConnected
            }
            let snap = try await liveSvc.client.call(
                method: "noble_getWalletSnapshot",
                params: SnapshotParams(address: addr),
                expecting: WalletSnapshotDTO.self
            )
            let txDicts: [[String: Any]] = snap.transactions.map { e in
                var dict: [String: Any] = [:]
                dict["txId"] = e.tx_id
                dict["tx_type"] = e.tx_type
                dict["direction"] = e.direction
                dict["amount"] = e.amount
                dict["confirmations"] = e.confirmations
                dict["status"] = e.status ?? "unknown"
                dict["timestamp"] = e.timestamp ?? 0
                if let tl = e.type_label { dict["type_label"] = tl; dict["type"] = tl }
                if let tv = e.transfer_value { dict["transfer_value"] = tv }
                if let f = e.fee { dict["fee"] = f }
                if let to = e.total_output { dict["total_output"] = to }
                if let bh = e.block_height { dict["blockHeight"] = bh }
                if let cp = e.recipient { dict["recipient"] = cp }
                if let s = e.signer { dict["signer"] = s }
                if let cs = e.checksum { dict["checksum"] = cs }
                if let hel = e.has_encrypted_locator { dict["has_encrypted_locator"] = hel }
                return dict
            }
            var result: [String: Any] = [:]
            result["chain_height"] = snap.chain_height
            result["balance"] = snap.balance
            result["available"] = snap.available
            result["pending"] = snap.pending
            result["immature_count"] = snap.immature_count ?? 0
            result["immature_value"] = snap.immature_value ?? 0
            result["transactions"] = txDicts
            return result

        case "getWalletTransactions", "getTransactionHistory":
            // Server now accepts optional addresses parameter — pass client's wallet address
            // so the server includes txs for the client's key (even if node keystore is locked).
            let txs: [TransactionRecord]
            if let addr = appState.walletAddress, !addr.isEmpty {
                txs = try await api.getWalletTransactions(addresses: [addr])
            } else {
                txs = try await api.getWalletTransactions()
            }
            var allDicts = txs.map { txToDict($0) }

            // Also fetch pending mempool txs for the client's address.
            if let addr = appState.walletAddress, !addr.isEmpty {
                let pending = (try? await api.getAddressPending(address: addr)) ?? []
                let confirmedIds = Set(allDicts.compactMap { $0["txId"] as? String })
                for p in pending where !confirmedIds.contains(p.txId) {
                    let isTransfer = p.sent > 0
                    allDicts.insert([
                        "txId": p.txId,
                        "tx_type": isTransfer ? 1 : 0,
                        "type": isTransfer ? "Pending Transfer" : "Pending Notarization",
                        "direction": "outgoing",
                        "amount": p.netDebit,
                        "fee": p.fee,
                        "status": "pending",
                        "confirmations": 0,
                        "recipient": isTransfer ? "Transfer" : "Self (Document)",
                        "total_output": p.change + p.sent,
                        "transfer_value": p.sent,
                        "timestamp": Date().timeIntervalSince1970,
                    ] as [String: Any], at: 0)
                    // If outputs return to self, add incoming entry
                    if p.change > 0 {
                        allDicts.insert([
                            "txId": p.txId,
                            "tx_type": 1,
                            "type": "Pending Transfer",
                            "direction": "incoming",
                            "amount": p.change,
                            "fee": 0,
                            "status": "pending",
                            "confirmations": 0,
                            "timestamp": Date().timeIntervalSince1970,
                        ] as [String: Any], at: 1)
                    }
                }
            }

            return ["transactions": allDicts] as [String: Any]

        case "estimateFee":
            let fee = try await api.estimateFee()
            return [
                "lowFeeRate": fee.lowFeeRate,
                "recommendedFeeRate": fee.recommendedFeeRate,
                "highPriorityFeeRate": fee.highPriorityFeeRate,
                "networkMinFeeRate": fee.networkMinFeeRate,
                "networkMedianFeeRate": fee.networkMedianFeeRate,
                "localMinFeeRate": fee.localMinFeeRate,
            ] as [String: Any]

        case "verifyDocument":
            guard let checksum = params["checksum"] as? String else {
                throw BridgeError.missingParam("checksum")
            }
            let result = try await api.verifyDocument(checksum: checksum)
            var dict: [String: Any] = [
                "isRegistered": result.isRegistered,
                "registrationCount": result.registrationCount,
                "versions": result.versions.map { versionToDict($0) },
            ]
            if let reg = result.registration {
                dict["registration"] = registrationToDict(reg)
            }
            return dict

        case "getDocumentVersions":
            guard let checksum = params["checksum"] as? String else {
                throw BridgeError.missingParam("checksum")
            }
            let versions = try await api.getDocumentVersions(checksum: checksum)
            return [
                "checksum": checksum,
                "versions": versions.map { versionToDict($0) },
            ] as [String: Any]

        case "submitTransaction":
            guard let rawHex = params["rawHex"] as? String ?? params["txHex"] as? String else {
                throw BridgeError.missingParam("rawHex")
            }
            let txId = try await api.submitTransaction(rawHex: rawHex)
            return [
                "txId": txId,
                "accepted": true,
            ] as [String: Any]

        case "getNodeInfo":
            let info = try await api.getNodeInfo()
            return [
                "chainId": info.chainId,
                "version": info.version,
                "blockHeight": info.blockHeight,
                "peerCount": info.peerCount,
                "isSyncing": info.isSyncing,
            ] as [String: Any]

        case "getBlockCount":
            let info = try await api.getNodeInfo()
            return [
                "height": info.blockHeight,
            ] as [String: Any]

        case "getNetworkInfo":
            let peers = try await api.getPeers()
            let inbound = peers.filter { $0.direction == "inbound" }.count
            let outbound = peers.filter { $0.direction == "outbound" }.count
            let networkInfo = try? await api.getNetworkInfo()
            return [
                "peer_count": peers.count,
                "inbound": inbound,
                "outbound": outbound,
                "clock_offset_ms": networkInfo?.clockOffsetMs ?? 0,
            ] as [String: Any]

        case "getPeers":
            let peers = try await api.getPeers()
            let inbound = peers.filter { $0.direction == "inbound" }.count
            let outbound = peers.filter { $0.direction == "outbound" }.count
            return [
                "total": peers.count,
                "inbound": inbound,
                "outbound": outbound,
                "peers": peers.map { p in
                    [
                        "peerId": p.peerId,
                        "direction": p.direction,
                        "address": p.address ?? "",
                        "nodeName": p.nodeName ?? "",
                        "countryCode": p.countryCode ?? "",
                        "chainTipHeight": p.chainTipHeight as Any,
                    ] as [String: Any]
                },
            ] as [String: Any]

        case "getTransaction":
            guard let txId = params["txId"] as? String else {
                throw BridgeError.missingParam("txId")
            }
            let tx = try await api.getTransaction(txId: txId)
            return txToDict(tx)

        case "getTransactionStatus":
            guard let txId = params["txId"] as? String else {
                throw BridgeError.missingParam("txId")
            }
            let status = try await api.getTransactionStatus(txId: txId)
            return [
                "status": status.rawValue,
            ]

        case "lookupChecksum":
            guard let checksum = params["checksum"] as? String else {
                throw BridgeError.missingParam("checksum")
            }
            let records = try await api.lookupChecksum(checksum: checksum)
            return [
                "found": !records.isEmpty,
                "records": records.map { registrationToDict($0) },
            ] as [String: Any]

        case "validateAddress":
            guard let address = params["address"] as? String else {
                throw BridgeError.missingParam("address")
            }
            let valid = try await api.validateAddress(address)
            return [
                "valid": valid,
            ]

        case "getAddressUtxos":
            guard let address = params["address"] as? String else {
                throw BridgeError.missingParam("address")
            }
            let result = try await api.getAddressUtxos(address: address)
            return [
                "address": result.address,
                "utxos": result.utxos.map { u in
                    [
                        "txid": u.txid,
                        "vout": u.vout,
                        "value": u.value,
                        "height": u.height,
                        "is_coinbase": u.isCoinbase,
                        "status": u.status,
                    ] as [String: Any]
                },
            ] as [String: Any]

        case "faucetStatus":
            return try await handleFaucetStatus()

        case "faucetRequest":
            guard let address = params["address"] as? String else {
                throw BridgeError.missingParam("address")
            }
            return try await handleFaucetRequest(address: address)

        case "getAvailableFaucets":
            guard let svc = appState.apiService else {
                return ["faucets": [Any]()] as [String: Any]
            }
            guard let liveSvc = svc as? LiveNobleAPIService else {
                return ["faucets": [Any]()] as [String: Any]
            }
            let dto = try await liveSvc.client.call(method: "noble_getAvailableFaucets", expecting: FaucetListDTO.self)
            let entries: [[String: Any]] = dto.faucets.map { f in
                [
                    "url": f.url,
                    "faucet_address": f.faucet_address,
                    "faucet_balance": f.faucet_balance,
                    "drip_amount": f.drip_amount,
                    "network": f.network,
                    "last_probed": f.last_probed,
                ]
            }
            return ["faucets": entries] as [String: Any]

        case "faucetHopRequest":
            guard let urlStr = params["url"] as? String,
                  let address = params["address"] as? String else {
                throw BridgeError.missingParam("url, address")
            }
            return try await handleFaucetHopRequest(faucetURL: urlStr, address: address)

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - Faucet HTTP

    /// Derive faucet URL from the node URL (same host, port 8786).
    private func faucetBaseURL() -> URL? {
        guard let nodeURL = URL(string: appState.nodeURL),
              let host = nodeURL.host else { return nil }
        return URL(string: "https://\(host):8786")
    }

    /// URLSession that accepts self-signed certs (faucet uses node's TLS cert).
    private static let faucetSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        let delegate = FaucetTLSDelegate()
        return URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }()

    private func handleFaucetStatus() async throws -> Any {
        guard let base = faucetBaseURL() else {
            throw BridgeError.faucetUnavailable
        }
        let url = base.appendingPathComponent("api/faucet/status")
        var req = URLRequest(url: url)
        req.setValue("noble", forHTTPHeaderField: "Gatekeeper")
        let (data, response) = try await Self.faucetSession.data(for: req)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw BridgeError.faucetUnavailable
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BridgeError.faucetUnavailable
        }
        return json
    }

    private func handleFaucetRequest(address: String) async throws -> Any {
        guard let base = faucetBaseURL() else {
            throw BridgeError.faucetUnavailable
        }
        let url = base.appendingPathComponent("api/faucet")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("noble", forHTTPHeaderField: "Gatekeeper")
        let body = try JSONSerialization.data(withJSONObject: ["address": address])
        request.httpBody = body

        let (data, response) = try await Self.faucetSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw BridgeError.faucetUnavailable
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BridgeError.faucetUnavailable
        }

        // Forward rate-limit errors as bridge errors with the server's message
        if http.statusCode == 429 || http.statusCode >= 400 {
            let msg = json["message"] as? String ?? "Faucet request failed"
            throw BridgeError.faucetError(msg)
        }

        return json
    }

    /// Request coins from a peer faucet by URL.
    private func handleFaucetHopRequest(faucetURL: String, address: String) async throws -> Any {
        guard let url = URL(string: faucetURL)?.appendingPathComponent("api/faucet") else {
            throw BridgeError.faucetUnavailable
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("noble", forHTTPHeaderField: "Gatekeeper")
        let body = try JSONSerialization.data(withJSONObject: ["address": address])
        request.httpBody = body

        let (data, response) = try await Self.faucetSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw BridgeError.faucetUnavailable
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BridgeError.faucetUnavailable
        }
        if http.statusCode == 429 || http.statusCode >= 400 {
            let msg = json["message"] as? String ?? "Faucet request failed"
            throw BridgeError.faucetError(msg)
        }
        return json
    }

    /// Generic RPC passthrough — calls the node JSON-RPC and returns raw JSON result.
    private func rpcPassthrough(_ method: String, params: [String: Any]? = nil) async throws -> Any {
        guard !appState.nodeURL.isEmpty, let baseURL = URL(string: appState.nodeURL) else {
            throw BridgeError.notConnected
        }
        let rpcParams = params ?? [:]
        let body: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": [rpcParams],
        ]
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let url = baseURL.appendingPathComponent("rpc")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("noble", forHTTPHeaderField: "Gatekeeper")
        request.httpBody = bodyData
        request.timeoutInterval = 10

        let (data, _) = try await Self.faucetSession.data(for: request)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw BridgeError.faucetUnavailable
        }
        if let error = json["error"] as? [String: Any] {
            let msg = error["message"] as? String ?? "RPC error"
            throw BridgeError.faucetError(msg)
        }
        return json["result"] ?? [String: Any]()
    }

    // MARK: - Serialization Helpers

    private func txToDict(_ tx: TransactionRecord) -> [String: Any] {
        var dict: [String: Any] = [
            "txId": tx.txId.hex,
            "tx_type": tx.txType.rawValue,
            "txType": tx.txType.label,
            "type": tx.txType.label,
            "status": tx.status.rawValue,
            "signer": tx.signer.nobleBech32,
            "total_output": tx.totalOutput,
            "inputs": tx.inputs.map { ["txid": $0.txid, "vout": $0.vout] as [String: Any] },
            "outputs": tx.outputs.map { ["value": $0.value, "address": $0.address] as [String: Any] },
            "has_encrypted_locator": tx.hasEncryptedLocator,
        ]
        if let h = tx.blockHeight { dict["blockHeight"] = h }
        if let t = tx.timestamp { dict["timestamp"] = t.timeIntervalSince1970 }
        if let c = tx.checksum { dict["checksum"] = c.hex }
        if let f = tx.fee { dict["fee"] = f }
        if let tv = tx.transferValue { dict["transfer_value"] = tv }
        if let conf = tx.confirmations { dict["confirmations"] = conf }
        if let meta = tx.metadata, !meta.isEmpty {
            dict["metadata"] = meta.map { ["key": $0.key, "value": $0.value] as [String: Any] }
        }

        // Use server-computed direction/recipient/amount when available.
        // The server has full wire-byte matching across all 3 address variants —
        // more reliable than client-side bech32 string comparison.
        if let dir = tx.direction {
            dict["direction"] = dir
        }
        if let cp = tx.recipient {
            dict["recipient"] = cp
        }
        if let amt = tx.displayAmount {
            dict["amount"] = amt
        }
        if let lbl = tx.typeLabel {
            dict["type_label"] = lbl
        }

        // Fallback: recompute direction if server didn't provide it (old server compat).
        if dict["direction"] == nil {
            let walletAddr = appState.walletAddress ?? ""
            switch tx.txType {
            case .transfer:
                if tx.signer.nobleBech32 == walletAddr {
                    dict["direction"] = "outgoing"
                    dict["recipient"] = dict["recipient"] ?? tx.outputs.first(where: { $0.address != walletAddr })?.address
                } else {
                    dict["direction"] = "incoming"
                    dict["recipient"] = dict["recipient"] ?? tx.signer.nobleBech32
                }
            case .coinbase:
                dict["direction"] = "incoming"
                dict["recipient"] = dict["recipient"] ?? "Block Reward"
            case .notarization, .locked, .unlocking:
                if tx.signer.nobleBech32 == walletAddr {
                    dict["direction"] = "outgoing"
                    dict["recipient"] = dict["recipient"] ?? "Self (Document)"
                } else {
                    dict["direction"] = "incoming"
                    dict["recipient"] = dict["recipient"] ?? tx.signer.nobleBech32
                }
            case .keyRotation:
                dict["direction"] = "self"
                dict["recipient"] = dict["recipient"] ?? "Key Rotation"
            case .badgeProposal, .badgeVote, .badgeRevocation:
                dict["direction"] = "self"
                dict["recipient"] = dict["recipient"] ?? "Governance"
            case .feeDistribution:
                dict["direction"] = "incoming"
                dict["recipient"] = dict["recipient"] ?? "Fee Distribution"
            }
        }

        // Confirmations fallback: compute from tip if not provided by RPC
        if dict["confirmations"] == nil {
            if let txHeight = tx.blockHeight {
                let tipHeight = UInt64(appState.blockHeight)
                dict["confirmations"] = tipHeight >= txHeight ? (tipHeight - txHeight + 1) : 0
            } else {
                dict["confirmations"] = 0
            }
        }
        return dict
    }

    private func registrationToDict(_ r: RegistrationRecord) -> [String: Any] {
        [
            "txId": r.txId.hex,
            "checksum": r.checksum.hex,
            "issuer": r.issuer.nobleBech32,
            "blockHeight": r.blockHeight,
            "timestamp": r.timestamp.timeIntervalSince1970,
            "fee": r.fee.atomic,
            "metadata": r.metadata.map { ["key": $0.key, "value": $0.value] },
        ] as [String: Any]
    }

    private func versionToDict(_ v: VersionEntry) -> [String: Any] {
        var dict: [String: Any] = [
            "checksum": v.checksum.hex,
            "txId": v.txId.hex,
            "issuer": v.issuer.nobleBech32,
            "blockHeight": v.blockHeight,
            "timestamp": v.timestamp.timeIntervalSince1970,
        ]
        if let prev = v.previousChecksum { dict["previousChecksum"] = prev.hex }
        return dict
    }

    // MARK: - Crypto Handler

    private func handleCrypto(action: String, params: [String: Any]) async throws -> Any {
        switch action {
        case "signNotarization":
            guard let checksumHex = params["checksum"] as? String,
                  let checksum = Hash256(hex: checksumHex) else {
                throw BridgeError.missingParam("checksum")
            }
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let feeAtomic = (params["fee"] as? NSNumber)?.uint64Value ?? 0
            let feeRate = (params["fee_rate"] as? NSNumber)?.uint64Value ?? 0
            let rawMetadata = params["metadata"] as? [[String: Any]] ?? []
            var metadataItems: [MetadataItem] = []
            var metadata: [[String: String]] = []
            for entry in rawMetadata {
                let key = entry["key"] as? String ?? ""
                var value = entry["value"] as? String ?? ""
                let mode = entry["mode"] as? String ?? "plaintext"
                let recipient = entry["recipient"] as? String ?? ""
                // ECIES encrypt: mode == "encrypted" with a recipient pubkey
                if mode == "encrypted" && !recipient.isEmpty {
                    let plaintextHex = value.data(using: .utf8)?.map { String(format: "%02x", $0) }.joined() ?? ""
                    let inputJson = "{\"plaintext_hex\":\"\(plaintextHex)\",\"recipient_pubkey_hex\":\"\(recipient)\"}"
                    if let cStr = inputJson.cString(using: .utf8),
                       let resultPtr = noble_ecies_encrypt(cStr) {
                        let resultStr = String(cString: resultPtr)
                        noble_free(resultPtr)
                        if let data = resultStr.data(using: .utf8),
                           let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                           let payloadHex = json["payload_hex"] as? String {
                            value = payloadHex
                        }
                    }
                }
                // Protected fields are already pre-encrypted in JS — pass through
                metadataItems.append(MetadataItem(key: key, value: value))
                metadata.append(["key": key, "value": value])
            }

            // Parse available UTXOs from JS, then run coin selection.
            // Use the C library to estimate real tx size for accurate coin selection.
            let allUtxos = try parseUtxoParams(params)
            let changeAddress = try walletChangeAddress()
            let chainId = appState.resolvedChainId
            let feeEstimate: UInt64
            if feeRate > 0 {
                let estSize = try estimateTxSizeViaC(txType: "notarization", checksum: checksumHex,
                    metadata: metadata, recipient: nil, changeAddress: changeAddress,
                    privateKey: privateKey, chainId: chainId)
                feeEstimate = feeRate * UInt64(estSize)
            } else {
                feeEstimate = feeAtomic
            }
            let selected = try CoinSelector.select(from: allUtxos, target: feeEstimate)

            let txHex = try appState.transactionSigner.signNotarization(
                checksum: checksum,
                metadata: metadataItems,
                fee: NobleAmount(atomic: feeAtomic),
                feeRate: feeRate,
                utxos: selected,
                changeAddress: changeAddress,
                privateKey: privateKey,
                chainId: chainId
            )
            return ["txHex": txHex]

        case "signTransfer":
            guard let recipientHex = params["recipient"] as? String,
                  let to = NobleAddress(wireHex: recipientHex) else {
                throw BridgeError.missingParam("recipient")
            }
            guard let amountAtomic = (params["amount"] as? NSNumber)?.uint64Value else {
                throw BridgeError.missingParam("amount")
            }
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let feeAtomic = (params["fee"] as? NSNumber)?.uint64Value ?? 0
            let feeRate = (params["fee_rate"] as? NSNumber)?.uint64Value ?? 0

            // Parse available UTXOs and estimate real tx size for accurate coin selection.
            let allUtxos = try parseUtxoParams(params)
            let changeAddress = try walletChangeAddress()
            let chainId = appState.resolvedChainId
            let feeEstimate: UInt64
            if feeRate > 0 {
                let estSize = try estimateTxSizeViaC(txType: "transfer", checksum: nil,
                    metadata: [], recipient: recipientHex, changeAddress: changeAddress,
                    privateKey: privateKey, chainId: chainId)
                feeEstimate = feeRate * UInt64(estSize)
            } else {
                feeEstimate = feeAtomic
            }
            let target = amountAtomic + feeEstimate
            let selected = try CoinSelector.select(from: allUtxos, target: target)

            let txHex = try appState.transactionSigner.signTransfer(
                to: to,
                amount: NobleAmount(atomic: amountAtomic),
                fee: NobleAmount(atomic: feeAtomic),
                feeRate: feeRate,
                utxos: selected,
                changeAddress: changeAddress,
                privateKey: privateKey,
                chainId: chainId
            )
            return ["txHex": txHex]

        case "decryptLockedTx":
            guard let txHex = params["tx_hex"] as? String,
                  let password = params["password"] as? String else {
                throw BridgeError.missingParam("tx_hex or password")
            }
            let decryptParams: [String: Any] = ["tx_hex": txHex, "password": password]
            let decryptJsonData = try JSONSerialization.data(withJSONObject: decryptParams)
            guard let decryptJsonStr = String(data: decryptJsonData, encoding: .utf8) else {
                throw BridgeError.operationFailed("decryptLockedTx: UTF-8 encoding failed")
            }
            guard let decryptPtr = noble_tx_decode_locked(decryptJsonStr) else {
                throw BridgeError.operationFailed("decryptLockedTx returned null")
            }
            let decryptStr = String(cString: decryptPtr)
            noble_free(decryptPtr)
            guard let decryptData = decryptStr.data(using: .utf8) else {
                throw BridgeError.operationFailed("decryptLockedTx: result not valid UTF-8")
            }
            let decryptJson: [String: Any]
            do {
                guard let parsed = try JSONSerialization.jsonObject(with: decryptData) as? [String: Any] else {
                    throw BridgeError.operationFailed("decryptLockedTx: result is not a JSON object")
                }
                decryptJson = parsed
            } catch let error as BridgeError {
                throw error
            } catch {
                throw BridgeError.operationFailed("decryptLockedTx: \(error.localizedDescription)")
            }
            if let err = decryptJson["error"] as? String {
                throw BridgeError.operationFailed(err)
            }
            return decryptJson

        case "buildTransaction":
            // Unified builder: inject private_key, change_address, chain_id, timestamp,
            // then forward the entire JSON to the C library.
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let changeAddress = try walletChangeAddress()
            let walletHex = changeAddress.map { String(format: "%02x", $0) }.joined()
            var buildParams = params
            buildParams["private_key"] = privateKey.map { String(format: "%02x", $0) }.joined()
            buildParams["change_address"] = walletHex
            buildParams["chain_id"] = appState.resolvedChainId
            buildParams["timestamp"] = UInt64(Date().timeIntervalSince1970)
            guard JSONSerialization.isValidJSONObject(buildParams) else {
                throw BridgeError.operationFailed("buildTransaction: invalid JSON params")
            }
            let buildJsonData = try JSONSerialization.data(withJSONObject: buildParams)
            guard let buildJsonStr = String(data: buildJsonData, encoding: .utf8) else {
                throw BridgeError.operationFailed("buildTransaction: UTF-8 encoding failed")
            }
            guard let buildResultPtr = noble_build_transaction(buildJsonStr) else {
                throw BridgeError.operationFailed("buildTransaction returned null")
            }
            let buildResultStr = String(cString: buildResultPtr)
            noble_free(buildResultPtr)
            guard let buildRData = buildResultStr.data(using: .utf8) else {
                throw BridgeError.operationFailed("buildTransaction: result not valid UTF-8")
            }
            let buildRJson: [String: Any]
            do {
                guard let parsed = try JSONSerialization.jsonObject(with: buildRData) as? [String: Any] else {
                    throw BridgeError.operationFailed("buildTransaction: result is not a JSON object")
                }
                buildRJson = parsed
            } catch let error as BridgeError {
                throw error
            } catch {
                throw BridgeError.operationFailed("buildTransaction: \(error.localizedDescription)")
            }
            if let err = buildRJson["error"] as? String {
                throw BridgeError.operationFailed(err)
            }
            guard let buildTxHex = buildRJson["tx_hex"] as? String,
                  let buildTxId = buildRJson["tx_id"] as? String else {
                throw BridgeError.operationFailed("buildTransaction: missing tx_hex/tx_id")
            }
            return [
                "txHex": buildTxHex,
                "txId": buildTxId,
                "fee": buildRJson["fee"] as? UInt64 ?? 0,
                "size": buildRJson["size"] as? UInt64 ?? 0
            ]

        case "signSplitTransfer":
            guard let outputsArr = params["outputs"] as? [[String: Any]] else {
                throw BridgeError.missingParam("outputs")
            }
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let allUtxos = try parseUtxoParams(params)
            let changeAddress = try walletChangeAddress()
            let chainId = appState.resolvedChainId
            let feeRate = (params["fee_rate"] as? NSNumber)?.uint64Value ?? 0
            let feeAtomic = (params["fee"] as? NSNumber)?.uint64Value ?? 0
            let walletHex = changeAddress.map { String(format: "%02x", $0) }.joined()
            var outputsJson: [[String: Any]] = []
            for (i, o) in outputsArr.enumerated() {
                guard let amt = (o["amount"] as? NSNumber)?.uint64Value else {
                    print("[Bridge] Skipping malformed split output at index \(i): \(o)")
                    continue
                }
                outputsJson.append(["address": walletHex, "amount": amt])
            }
            guard !outputsJson.isEmpty else {
                throw BridgeError.operationFailed("signSplitTransfer: all outputs invalid")
            }
            let utxoJson: [[String: Any]] = allUtxos.map { u in
                ["txid": u.txid.map { String(format: "%02x", $0) }.joined(), "vout": u.vout, "value": u.value]
            }
            let cParams: [String: Any] = [
                "outputs": outputsJson, "fee": feeAtomic, "fee_rate": feeRate,
                "change_address": changeAddress.map { String(format: "%02x", $0) }.joined(),
                "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
                "chain_id": chainId, "utxos": utxoJson,
                "timestamp": UInt64(Date().timeIntervalSince1970)
            ]
            guard JSONSerialization.isValidJSONObject(cParams) else {
                throw BridgeError.operationFailed("signSplitTransfer: invalid JSON params")
            }
            let jsonData = try JSONSerialization.data(withJSONObject: cParams)
            guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
                throw BridgeError.operationFailed("signSplitTransfer: UTF-8 encoding failed")
            }
            guard let resultPtr = noble_sign_split_transfer(jsonStr) else {
                throw BridgeError.operationFailed("split transfer signing returned null")
            }
            let resultStr = String(cString: resultPtr)
            noble_free(resultPtr)
            guard let rData = resultStr.data(using: .utf8) else {
                throw BridgeError.operationFailed("signSplitTransfer: result not valid UTF-8")
            }
            let rJson: [String: Any]
            do {
                guard let parsed = try JSONSerialization.jsonObject(with: rData) as? [String: Any] else {
                    throw BridgeError.operationFailed("signSplitTransfer: result is not a JSON object")
                }
                rJson = parsed
            } catch let error as BridgeError {
                throw error
            } catch {
                throw BridgeError.operationFailed("signSplitTransfer: \(error.localizedDescription)")
            }
            if let err = rJson["error"] as? String {
                throw BridgeError.operationFailed(err)
            }
            guard let txHex = rJson["tx_hex"] as? String else {
                throw BridgeError.operationFailed("missing tx_hex")
            }
            guard let txId = rJson["tx_id"] as? String else {
                throw BridgeError.operationFailed("signSplitTransfer: missing tx_id in result")
            }
            return ["txHex": txHex, "txId": txId]

        case "estimateTxSize":
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let changeAddress = try walletChangeAddress()
            let chainId = appState.resolvedChainId
            let txType = params["tx_type"] as? String ?? "notarization"
            let checksum = params["checksum"] as? String ?? String(repeating: "00", count: 32)
            let metaArr = (params["metadata"] as? [[String: Any]] ?? []).map {
                ["key": $0["key"] as? String ?? "", "value": $0["value"] as? String ?? ""]
            }
            let recipient = params["recipient"] as? String ?? changeAddress.map { String(format: "%02x", $0) }.joined()

            let estimateParams: [String: Any] = [
                "tx_type": txType,
                "checksum": checksum,
                "metadata": metaArr,
                "recipient": recipient,
                "change_address": changeAddress.map { String(format: "%02x", $0) }.joined(),
                "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
                "chain_id": chainId,
            ]
            guard let jsonData = try? JSONSerialization.data(withJSONObject: estimateParams),
                  let jsonStr = String(data: jsonData, encoding: .utf8) else {
                throw BridgeError.operationFailed("failed to serialize estimate params")
            }
            let cInput = jsonStr.cString(using: .utf8)!
            guard let resultPtr = noble_estimate_tx_size(cInput) else {
                throw BridgeError.operationFailed("estimate returned null")
            }
            let resultStr = String(cString: resultPtr)
            noble_free(resultPtr)
            guard let resultData = resultStr.data(using: .utf8),
                  let resultDict = try? JSONSerialization.jsonObject(with: resultData) as? [String: Any] else {
                throw BridgeError.operationFailed("failed to parse estimate result")
            }
            if let error = resultDict["error"] as? String {
                throw BridgeError.operationFailed(error)
            }
            return resultDict

        case "encryptField":
            guard let value = params["value"] as? String,
                  let mode = params["mode"] as? String else {
                throw BridgeError.missingParam("value, mode")
            }
            guard mode == "encrypted" else {
                // Protected fields are pre-encrypted in JS via Web Crypto
                throw BridgeError.operationFailed("encryptField: only mode 'encrypted' (ECIES) supported in bridge; protected fields use client-side Web Crypto")
            }
            guard let recipientPubkey = params["recipient_pubkey"] as? String, !recipientPubkey.isEmpty else {
                throw BridgeError.missingParam("recipient_pubkey")
            }
            let plaintextHex = value.data(using: .utf8)?.map { String(format: "%02x", $0) }.joined() ?? ""
            let encInput = "{\"plaintext_hex\":\"\(plaintextHex)\",\"recipient_pubkey_hex\":\"\(recipientPubkey)\"}"
            guard let cStr = encInput.cString(using: .utf8),
                  let resultPtr = noble_ecies_encrypt(cStr) else {
                throw BridgeError.operationFailed("ECIES encrypt failed")
            }
            let encResultStr = String(cString: resultPtr)
            noble_free(resultPtr)
            guard let encData = encResultStr.data(using: .utf8),
                  let encJson = try? JSONSerialization.jsonObject(with: encData) as? [String: Any],
                  let payloadHex = encJson["payload_hex"] as? String else {
                throw BridgeError.operationFailed("ECIES encrypt: invalid result")
            }
            return ["encrypted_hex": payloadHex]

        case "decryptField", "decryptEciesField":
            let payloadHex: String
            if let ph = params["payload_hex"] as? String {
                payloadHex = ph
            } else if let eh = params["encrypted_hex"] as? String {
                payloadHex = eh
            } else {
                throw BridgeError.missingParam("payload_hex or encrypted_hex")
            }
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let pkHex = privateKey.map { String(format: "%02x", $0) }.joined()
            let decInput = "{\"payload_hex\":\"\(payloadHex)\",\"private_key_hex\":\"\(pkHex)\"}"
            guard let decCStr = decInput.cString(using: .utf8),
                  let decResultPtr = noble_ecies_decrypt(decCStr) else {
                throw BridgeError.operationFailed("ECIES decrypt failed")
            }
            let decResultStr = String(cString: decResultPtr)
            noble_free(decResultPtr)
            guard let decData = decResultStr.data(using: .utf8),
                  let decJson = try? JSONSerialization.jsonObject(with: decData) as? [String: Any],
                  let plaintextHex = decJson["plaintext_hex"] as? String else {
                return ["error": "Not a recipient of this encrypted field"]
            }
            var decBytes = [UInt8]()
            var hIdx = plaintextHex.startIndex
            while hIdx < plaintextHex.endIndex {
                let next = plaintextHex.index(hIdx, offsetBy: 2)
                if let byte = UInt8(plaintextHex[hIdx..<next], radix: 16) { decBytes.append(byte) }
                hIdx = next
            }
            return ["plaintext": String(bytes: decBytes, encoding: .utf8) ?? plaintextHex, "value": String(bytes: decBytes, encoding: .utf8) ?? plaintextHex]

        case "signMetadataField":
            guard let keyIdStr = params["keyId"] as? String,
                  let keyId = UUID(uuidString: keyIdStr) else {
                throw BridgeError.missingParam("keyId")
            }
            guard let fieldValue = params["fieldValue"] as? String else {
                throw BridgeError.missingParam("fieldValue")
            }

            // Find the signing key entry to determine algorithm
            guard let myCard = appState.contacts.first(where: { $0.isMyCard }),
                  let keyEntry = myCard.signingKeys.first(where: { $0.id == keyId }) else {
                throw BridgeError.operationFailed("Signing key not found")
            }

            // Load private key + certificate from Keychain
            guard let privKeyData = try appState.keychainService.loadKey(label: "signing-key-\(keyIdStr)") else {
                throw BridgeError.operationFailed("Private key not found in keychain")
            }
            guard let certData = try appState.keychainService.loadKey(label: "signing-cert-\(keyIdStr)") else {
                throw BridgeError.operationFailed("Certificate not found in keychain")
            }

            // Delegate CMS construction to Rust FFI
            let privKeyHex = privKeyData.map { String(format: "%02x", $0) }.joined()
            let certB64 = certData.base64EncodedString()
            let cmsParams: [String: Any] = [
                "private_key_hex": privKeyHex,
                "certificate_der_b64": certB64,
                "field_value": fieldValue,
                "algorithm": keyEntry.algorithm,
            ]
            let cmsParamsJson = try serializeToJSON(cmsParams)
            let cmsResultStr = callCmsFFI(noble_sign_cms_ffi, params: cmsParamsJson)
            guard let resultDict = try? JSONSerialization.jsonObject(with: Data(cmsResultStr.utf8)) as? [String: Any],
                  resultDict["error"] == nil,
                  let cmsHex = resultDict["cms_hex"] as? String,
                  let size = resultDict["size"] as? Int else {
                let errMsg = (try? JSONSerialization.jsonObject(with: Data(cmsResultStr.utf8)) as? [String: Any])?["error"] as? String
                throw BridgeError.operationFailed(errMsg ?? "CMS signing failed")
            }

            return ["signatureHex": cmsHex, "size": size] as [String: Any]

        case "verifyMetadataField":
            guard let sigHex = params["signatureHex"] as? String else {
                throw BridgeError.missingParam("signatureHex")
            }
            guard let fieldValue = params["fieldValue"] as? String else {
                throw BridgeError.missingParam("fieldValue")
            }

            // Step 1: Parse CMS to extract SKI (no certificate needed yet)
            let parseParams: [String: Any] = [
                "cms_hex": sigHex,
                "field_value": fieldValue,
            ]
            let parseJson = try serializeToJSON(parseParams)
            let parseResultStr = callCmsFFI(noble_verify_cms_ffi, params: parseJson)
            guard let parsed = try? JSONSerialization.jsonObject(with: Data(parseResultStr.utf8)) as? [String: Any] else {
                throw BridgeError.operationFailed("CMS parse failed")
            }

            let signerSKI = parsed["signer_ski_hex"] as? String ?? "unknown"
            let algorithm = parsed["algorithm"] as? String ?? "unknown"

            // Step 2: Find certificate by SKI in contacts
            var certB64: String?
            var signerName: String?
            for contact in appState.contacts {
                for sk in contact.signingKeys {
                    if sk.subjectKeyIdentifier == signerSKI {
                        certB64 = sk.certificateDER
                        let keyLabel = sk.label.isEmpty ? "" : " (\(sk.label))"
                        signerName = contact.displayName + keyLabel
                        break
                    }
                }
                if certB64 != nil { break }
            }

            // Step 3: If certificate found, verify signature via Rust
            var valid = false
            var error: String?
            if let cert = certB64 {
                let verifyParams: [String: Any] = [
                    "cms_hex": sigHex,
                    "field_value": fieldValue,
                    "certificate_der_b64": cert,
                ]
                let verifyJson = try serializeToJSON(verifyParams)
                let verifyResultStr = callCmsFFI(noble_verify_cms_ffi, params: verifyJson)
                if let vDict = try? JSONSerialization.jsonObject(with: Data(verifyResultStr.utf8)) as? [String: Any] {
                    valid = vDict["valid"] as? Bool ?? false
                    error = vDict["error"] as? String
                }
            } else {
                error = "no certificate found for signer (SKI: \(signerSKI.prefix(12))...)"
            }

            return [
                "valid": valid,
                "signerSKI": signerSKI,
                "signerName": signerName as Any,
                "hasCertificate": certB64 != nil,
                "algorithm": algorithm,
                "error": error as Any,
            ] as [String: Any]

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - UTXO Helpers

    /// Estimate transaction CBOR size using the C library (no submission).
    private func estimateTxSizeViaC(
        txType: String, checksum: String?, metadata: [[String: String]],
        recipient: String?, changeAddress: [UInt8], privateKey: Data, chainId: UInt32
    ) throws -> UInt64 {
        var estimateParams: [String: Any] = [
            "tx_type": txType,
            "checksum": checksum ?? String(repeating: "00", count: 32),
            "metadata": metadata,
            "change_address": changeAddress.map { String(format: "%02x", $0) }.joined(),
            "private_key": privateKey.map { String(format: "%02x", $0) }.joined(),
            "chain_id": chainId,
        ]
        if let r = recipient { estimateParams["recipient"] = r }
        guard let jsonData = try? JSONSerialization.data(withJSONObject: estimateParams),
              let jsonStr = String(data: jsonData, encoding: .utf8) else {
            return 500 // safe fallback
        }
        let cInput = jsonStr.cString(using: .utf8)!
        guard let resultPtr = noble_estimate_tx_size(cInput) else { return 500 }
        let resultStr = String(cString: resultPtr)
        noble_free(resultPtr)
        guard let resultData = resultStr.data(using: .utf8),
              let resultDict = try? JSONSerialization.jsonObject(with: resultData) as? [String: Any],
              let size = resultDict["size"] as? UInt64 else {
            return 500
        }
        // +2% safety margin
        return size + (size / 50) + 1
    }

    /// Parse UTXO array from JS bridge params.
    /// Expects params["utxos"] as [[String: Any]] with keys: txid (hex), vout (UInt32), value (UInt64).
    private func parseUtxoParams(_ params: [String: Any]) throws -> [UtxoOutpoint] {
        guard let utxoArr = params["utxos"] as? [[String: Any]] else {
            throw BridgeError.missingParam("utxos")
        }
        var result = [UtxoOutpoint]()
        for (i, dict) in utxoArr.enumerated() {
            guard let txidHex = dict["txid"] as? String,
                  let vout = (dict["vout"] as? NSNumber)?.uint32Value,
                  let value = (dict["value"] as? NSNumber)?.uint64Value else {
                print("[Bridge] Skipping malformed UTXO at index \(i): \(dict)")
                continue
            }
            result.append(UtxoOutpoint(txidHex: txidHex, vout: vout, value: value))
        }
        guard !result.isEmpty else {
            throw BridgeError.missingParam("utxos (all entries malformed)")
        }
        return result
    }

    /// Get the wallet's change address as wire bytes.
    /// Handles both nbl1 bech32 and hex wire format via NobleAddress.
    private func walletChangeAddress() throws -> [UInt8] {
        guard let addrStr = appState.walletAddress,
              let addr = NobleAddress(wireHex: addrStr) else {
            throw BridgeError.operationFailed("No wallet address available for change output")
        }
        let hex = addr.wireHex
        var bytes = [UInt8]()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[idx..<next], radix: 16) {
                bytes.append(byte)
            }
            idx = next
        }
        return bytes
    }

    // MARK: - Security Handler

    private func handleSecurity(action: String, params: [String: Any]) async throws -> Any {
        switch action {
        case "hashFile":
            guard let filePath = params["filePath"] as? String else {
                throw BridgeError.missingParam("filePath")
            }
            let url = URL(fileURLWithPath: filePath)
            let hash = try appState.documentHasher.hash(fileURL: url)
            return ["hash": hash.hex]

        case "loadPrivateKey":
            // Security: never send the raw key to JS. Only report availability.
            let available = appState.loadPrivateKey() != nil
            return ["available": available]

        case "getMyCard":
            guard let myCard = appState.contacts.first(where: { $0.isMyCard }) else {
                return ["signingKeys": []] as [String: Any]
            }
            return contactToDict(myCard)

        case "importPKCS12":
            // Open file dialog for .p12/.pfx
            let panel = NSOpenPanel()
            panel.allowedContentTypes = [
                UTType(filenameExtension: "p12") ?? .data,
                UTType(filenameExtension: "pfx") ?? .data,
            ]
            panel.canChooseDirectories = false
            panel.allowsMultipleSelection = false
            let response = await panel.beginSheetModal(for: NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first!)
            guard response == .OK, let url = panel.url else {
                throw BridgeError.operationFailed("cancelled")
            }
            let p12Data = try Data(contentsOf: url)

            // Prompt for password
            let alert = NSAlert()
            alert.messageText = "PKCS#12 Password"
            alert.informativeText = "Enter the password for \(url.lastPathComponent):"
            let input = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 24))
            alert.accessoryView = input
            alert.addButton(withTitle: "Import")
            alert.addButton(withTitle: "Cancel")
            let alertResponse = await alert.beginSheetModal(for: NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.windows.first!)
            guard alertResponse == .alertFirstButtonReturn else {
                throw BridgeError.operationFailed("cancelled")
            }
            let password = input.stringValue

            // Import via Security.framework
            var importedItems: CFArray?
            let options = [kSecImportExportPassphrase: password] as NSDictionary
            let status = SecPKCS12Import(p12Data as CFData, options, &importedItems)
            guard status == errSecSuccess, let items = importedItems as? [[String: Any]],
                  let firstItem = items.first else {
                throw BridgeError.operationFailed("PKCS#12 import failed (wrong password or invalid file)")
            }

            // Extract identity (private key + certificate)
            guard let identityRef = firstItem[kSecImportItemIdentity as String] else {
                throw BridgeError.operationFailed("No identity found in PKCS#12")
            }
            let identity = identityRef as! SecIdentity

            var privateKeyRef: SecKey?
            let privStatus = SecIdentityCopyPrivateKey(identity, &privateKeyRef)
            guard privStatus == errSecSuccess, let privKey = privateKeyRef else {
                throw BridgeError.operationFailed("Cannot extract private key (OSStatus \(privStatus))")
            }

            var certRef: SecCertificate?
            let certStatus = SecIdentityCopyCertificate(identity, &certRef)
            guard certStatus == errSecSuccess, let cert = certRef else {
                throw BridgeError.operationFailed("Cannot extract certificate (OSStatus \(certStatus))")
            }

            // Determine key type
            guard let keyAttrs = SecKeyCopyAttributes(privKey) as? [String: Any],
                  let keyType = keyAttrs[kSecAttrKeyType as String] as? String else {
                throw BridgeError.operationFailed("Cannot determine key type")
            }

            // Only accept EC keys (P-256). Reject RSA.
            guard keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) else {
                throw BridgeError.operationFailed("Only ECDSA (P-256) keys are supported. RSA signatures exceed the 256-byte metadata slot limit.")
            }

            // Extract raw private key bytes
            guard let privKeyData = SecKeyCopyExternalRepresentation(privKey, nil) as? Data else {
                throw BridgeError.operationFailed("Cannot export private key")
            }

            // Certificate DER
            let certDER = SecCertificateCopyData(cert) as Data

            // Certificate subject
            let subjectSummary = SecCertificateCopySubjectSummary(cert) as? String ?? "Unknown"

            // Compressed public key (extract from private key data)
            // For EC keys, external representation is 04 || x || y (65 bytes for P-256)
            let pubKeyUncompressed: Data
            guard let pubKeyRef = SecKeyCopyPublicKey(privKey) else {
                throw BridgeError.operationFailed("Cannot derive public key from private key")
            }
            var pubKeyError: Unmanaged<CFError>?
            guard let pubKeyRaw = SecKeyCopyExternalRepresentation(pubKeyRef, &pubKeyError) as? Data else {
                let errMsg = pubKeyError?.takeRetainedValue().localizedDescription ?? "unknown"
                throw BridgeError.operationFailed("Cannot export public key: \(errMsg)")
            }
            pubKeyUncompressed = pubKeyRaw
            // Compress: if starts with 0x04, take x (32 bytes), prefix 0x02 or 0x03 based on y parity
            let compressedHex: String
            if pubKeyUncompressed.count == 65 && pubKeyUncompressed[0] == 0x04 {
                let x = pubKeyUncompressed[1...32]
                let yParity: UInt8 = pubKeyUncompressed[64] & 1 == 0 ? 0x02 : 0x03
                compressedHex = String(format: "%02x", yParity) + x.map { String(format: "%02x", $0) }.joined()
            } else {
                compressedHex = pubKeyUncompressed.map { String(format: "%02x", $0) }.joined()
            }

            // Compute SKI (SHA-1 of uncompressed public key)
            let skiData = Insecure.SHA1.hash(data: pubKeyUncompressed)
            let skiHex = skiData.map { String(format: "%02x", $0) }.joined()

            // Store private key + cert in Keychain
            let keyEntry = SigningKeyEntry(
                label: url.deletingPathExtension().lastPathComponent,
                algorithm: "p256",
                publicKeyHex: compressedHex,
                hasPrivateKey: true,
                certificateSubject: subjectSummary,
                certificateDER: certDER.base64EncodedString(),
                subjectKeyIdentifier: skiHex
            )

            try appState.keychainService.storeKey(privKeyData, label: "signing-key-\(keyEntry.id.uuidString)")
            try appState.keychainService.storeKey(certDER, label: "signing-cert-\(keyEntry.id.uuidString)")

            // Add to My Card's signing keys
            if let idx = appState.contacts.firstIndex(where: { $0.isMyCard }) {
                appState.contacts[idx].signingKeys.append(keyEntry)
                appState.saveContactsToDefaults()
            }

            return signingKeyToDict(keyEntry)

        case "generateSigningKey":
            // Generate a secp256k1 keypair
            var privKeyBytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, 32, &privKeyBytes) == errSecSuccess else {
                throw BridgeError.operationFailed("Failed to generate random key")
            }
            let privKeyData = Data(privKeyBytes)
            let pubKeyBytes = try appState.mnemonicProvider.derivePublicKey(privateKey: privKeyData)
            let compressedHex = pubKeyBytes.map { String(format: "%02x", $0) }.joined()
            let skiData = Insecure.SHA1.hash(data: pubKeyBytes)
            let skiHex = skiData.map { String(format: "%02x", $0) }.joined()

            let keyEntry = SigningKeyEntry(
                label: "Noble Key",
                algorithm: "secp256k1",
                publicKeyHex: compressedHex,
                hasPrivateKey: true,
                subjectKeyIdentifier: skiHex
            )

            try appState.keychainService.storeKey(privKeyData, label: "signing-key-\(keyEntry.id.uuidString)")

            if let idx = appState.contacts.firstIndex(where: { $0.isMyCard }) {
                appState.contacts[idx].signingKeys.append(keyEntry)
                appState.saveContactsToDefaults()
            }

            return signingKeyToDict(keyEntry)

        case "removeSigningKey":
            guard let keyIdStr = params["keyId"] as? String,
                  let keyId = UUID(uuidString: keyIdStr) else {
                throw BridgeError.missingParam("keyId")
            }
            // Remove from Keychain — fail if key deletion fails (prevent key material leak)
            try appState.keychainService.deleteKey(label: "signing-key-\(keyIdStr)")
            // Certificate deletion is best-effort (key material is the critical one)
            do { try appState.keychainService.deleteKey(label: "signing-cert-\(keyIdStr)") }
            catch { print("[Bridge] warning: cert cleanup failed (key removed): \(error)") }

            // Remove from contact's signing keys
            for i in 0..<appState.contacts.count {
                appState.contacts[i].signingKeys.removeAll { $0.id == keyId }
            }
            appState.saveContactsToDefaults()
            return ["ok": true]

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - App Handler

    private func handleApp(action: String, params: [String: Any]) async throws -> Any {
        switch action {
        case "getState":
            // Return cached state from last successful pollTick.
            // No live RPC call here — eliminates JS heartbeat timeout vector.
            let nodeState = (appState.lastPollState["nodeState"] as? String)
                ?? (appState.isConnected ? "Connected" : "Offline")
            var result: [String: Any] = [
                "isConnected": appState.isConnected,
                "hasWallet": appState.hasWallet,
                "walletAddress": appState.walletAddress ?? "",
                "chainId": appState.chainId,
                "blockHeight": appState.blockHeight,
                "selectedSection": appState.selectedSection?.webRoute ?? "home",
                "nodeState": nodeState,
            ]
            // Merge any extra cached fields (peerCount, syncStatus, cycleStatus, wallet)
            for (key, value) in appState.lastPollState where result[key] == nil {
                result[key] = value
            }
            return result as [String: Any]

        case "reportBridgeTimeout":
            appState.reportBridgeTimeout()
            return ["ok": true]

        case "navigateTo":
            guard let section = params["section"] as? String,
                  let target = SidebarSection(rawValue: section)
            else {
                throw BridgeError.missingParam("section")
            }
            appState.selectedSection = target
            appState.webViewCoordinator?.evaluateJS(
                "App.navigateTo('\(target.webRoute)')"
            )
            return ["ok": true]

        case "share":
            guard let text = params["text"] as? String else {
                throw BridgeError.missingParam("text")
            }
            let picker = NSSharingServicePicker(items: [text])
            if let webView = appState.webViewCoordinator?.webView {
                let anchor = CGRect(x: webView.bounds.maxX - 40, y: 0, width: 1, height: 1)
                picker.show(relativeTo: anchor, of: webView, preferredEdge: .minY)
            } else {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
            return ["ok": true]

        case "copyToClipboard":
            guard let text = params["text"] as? String else {
                throw BridgeError.missingParam("text")
            }
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
            return ["ok": true]

        case "openFileDialog":
            let allowMultiple = params["multiple"] as? Bool ?? true
            let result = await openFileDialog(allowMultiple: allowMultiple)
            return ["files": result]

        case "shareText":
            guard let text = params["text"] as? String else {
                throw BridgeError.missingParam("text")
            }
            let picker = NSSharingServicePicker(items: [text])
            if let webView = appState.webViewCoordinator?.webView {
                // Anchor the share picker to the top-right of the WebView
                let anchor = CGRect(x: webView.bounds.maxX - 40, y: 0, width: 1, height: 1)
                picker.show(relativeTo: anchor, of: webView, preferredEdge: .minY)
            } else {
                // Fallback: copy to clipboard
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
            }
            return ["ok": true]

        case "saveFileDialog":
            let suggestedName = params["filename"] as? String ?? "export.vcf"
            let content = params["content"] as? String ?? ""
            let ok = await saveFileDialog(suggestedName: suggestedName, content: content)
            return ["ok": ok]

        case "readFileText":
            guard let filePath = params["filePath"] as? String else {
                throw BridgeError.missingParam("filePath")
            }
            let url = URL(fileURLWithPath: filePath)
            let text = try String(contentsOf: url, encoding: .utf8)
            return ["text": text]

        case "getSettings":
            let _ = appState.apiService as? LiveNobleAPIService
            return [
                "nodeURL": appState.nodeURL,
                "authMode": "none",
                "tlsFingerprint": "",
                "appVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0",
                "autoConnect": appState.autoConnect,
                "rpcApiEnabled": appState.rpcApiEnabled,
                "rpcApiPort": appState.rpcApiPort,
                "mcpServerEnabled": appState.mcpServerEnabled,
                "mcpServerPort": appState.mcpServerPort,
            ] as [String: Any]

        case "saveSettings":
            if let url = params["nodeURL"] as? String {
                appState.saveNodeURL(url)
            }
            if let auto = params["autoConnect"] as? Bool {
                appState.autoConnect = auto
            }
            // Developer API settings
            if let v = params["rpcApiEnabled"] as? Bool { appState.rpcApiEnabled = v }
            if let v = params["rpcApiPort"] as? Int { appState.rpcApiPort = v }
            if let v = params["mcpServerEnabled"] as? Bool { appState.mcpServerEnabled = v }
            if let v = params["mcpServerPort"] as? Int { appState.mcpServerPort = v }
            appState.saveSecuritySettings()
            return ["ok": true]

        case "getSecuritySettings":
            return [
                "appLockEnabled": appState.appLockEnabled,
                "lockTimeout": appState.lockTimeout,
                "reAuthForSends": appState.reAuthForSends,
            ] as [String: Any]

        case "saveSecuritySettings":
            if let enabled = params["appLockEnabled"] as? Bool {
                appState.appLockEnabled = enabled
            }
            if let timeout = params["lockTimeout"] as? Int {
                appState.lockTimeout = timeout
            }
            if let reAuth = params["reAuthForSends"] as? Bool {
                appState.reAuthForSends = reAuth
            }
            appState.saveSecuritySettings()
            return ["ok": true]

        case "testConnection":
            guard let url = params["url"] as? String else {
                throw BridgeError.missingParam("url")
            }
            let info = try await appState.testConnectionWithInfo(url: url)
            return [
                "ok": true,
                "chainId": info.chainId,
                "version": info.version,
                "blockHeight": info.blockHeight,
            ] as [String: Any]

        case "connectToNode":
            guard let url = params["url"] as? String, !url.isEmpty else {
                throw BridgeError.missingParam("url")
            }
            appState.nodeURL = url
            appState.saveNodeURL(url)
            await appState.connectToNode()
            return ["connected": appState.isConnected]

        case "disconnectNode":
            appState.disconnect()
            return ["ok": true]

        // MARK: Document Drafts

        case "getDrafts":
            let drafts = appState.loadDrafts()
            return ["drafts": drafts]

        case "saveDraft":
            guard let draft = params["draft"] as? [String: Any] else {
                throw BridgeError.missingParam("draft")
            }
            appState.saveDraft(draft)
            return ["ok": true]

        case "deleteDraft":
            guard let id = params["id"] as? String else {
                throw BridgeError.missingParam("id")
            }
            appState.deleteDraft(id: id)
            return ["ok": true]

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - Storage Handler

    private func handleStorage(action: String, params: [String: Any]) async throws -> Any {
        switch action {
        case "getContacts":
            let sorted = appState.contacts.sorted { a, b in
                if a.isFavorite != b.isFavorite { return a.isFavorite }
                return a.displayName.localizedCaseInsensitiveCompare(b.displayName) == .orderedAscending
            }
            return [
                "contacts": sorted.map { contactToDict($0) },
            ] as [String: Any]

        case "saveContact":
            guard let contactDict = params["contact"] as? [String: Any] else {
                throw BridgeError.missingParam("contact")
            }
            let contact = dictToContact(contactDict)
            if let idx = appState.contacts.firstIndex(where: { $0.id == contact.id }) {
                appState.contacts[idx] = contact
            } else {
                appState.contacts.append(contact)
            }
            appState.saveContactsToDefaults()
            return ["ok": true, "id": contact.id.uuidString]

        case "deleteContact":
            guard let idStr = params["id"] as? String, let uuid = UUID(uuidString: idStr) else {
                throw BridgeError.missingParam("id")
            }
            // Prevent deleting My Card
            if appState.contacts.first(where: { $0.id == uuid })?.isMyCard == true {
                throw BridgeError.operationFailed("Cannot delete My Card")
            }
            appState.contacts.removeAll { $0.id == uuid }
            appState.saveContactsToDefaults()
            return ["ok": true]

        case "ensureMyCard":
            if appState.contacts.contains(where: { $0.isMyCard }) {
                return ["ok": true, "existed": true]
            }
            let walletAddr = appState.walletAddress ?? ""
            let myCard = Contact(
                firstName: "My",
                lastName: "Card",
                noblePubkey: walletAddr,
                isMyCard: true
            )
            appState.contacts.insert(myCard, at: 0)
            appState.saveContactsToDefaults()
            return ["ok": true, "existed": false, "id": myCard.id.uuidString]

        case "exportContactsVCF":
            let ids = params["ids"] as? [String]
            let selected: [Contact]
            if let ids {
                let uuids = Set(ids.compactMap { UUID(uuidString: $0) })
                selected = appState.contacts.filter { uuids.contains($0.id) }
            } else {
                selected = appState.contacts
            }
            let vcf = VCardFormat.serialize(selected)
            return ["vcf": vcf]

        case "importContactsVCF":
            guard let vcfString = params["vcf"] as? String else {
                throw BridgeError.missingParam("vcf")
            }
            let parsed = VCardFormat.parse(vcfString)
            return [
                "contacts": parsed.map { contactToDict($0) },
                "count": parsed.count,
            ] as [String: Any]

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - Helpers

    private func contactToDict(_ c: Contact) -> [String: Any] {
        var dict: [String: Any] = [
            "id": c.id.uuidString,
            "firstName": c.firstName,
            "lastName": c.lastName,
            "company": c.company,
            "email": c.email,
            "noblePubkey": c.noblePubkey,
            "bitcoinKey": c.bitcoinKey,
            "notes": c.notes,
            "isFavorite": c.isFavorite,
            "isMyCard": c.isMyCard,
            "displayName": c.displayName,
            "createdAt": c.createdAt.timeIntervalSince1970,
            "updatedAt": c.updatedAt.timeIntervalSince1970,
        ]
        if !c.signingKeys.isEmpty {
            dict["signingKeys"] = c.signingKeys.map { signingKeyToDict($0) }
        }
        return dict
    }

    private func signingKeyToDict(_ sk: SigningKeyEntry) -> [String: Any] {
        var d: [String: Any] = [
            "id": sk.id.uuidString,
            "label": sk.label,
            "algorithm": sk.algorithm,
            "publicKeyHex": sk.publicKeyHex,
            "hasPrivateKey": sk.hasPrivateKey,
            "importedAt": sk.importedAt.timeIntervalSince1970,
        ]
        if let subj = sk.certificateSubject { d["certificateSubject"] = subj }
        if let ski = sk.subjectKeyIdentifier { d["subjectKeyIdentifier"] = ski }
        // certificateDER intentionally omitted from JS (too large) — kept in Swift only
        return d
    }

    private func dictToContact(_ d: [String: Any]) -> Contact {
        let id: UUID
        if let idStr = d["id"] as? String, let uuid = UUID(uuidString: idStr) {
            id = uuid
        } else {
            id = UUID()
        }
        let signingKeys: [SigningKeyEntry]
        if let skArray = d["signingKeys"] as? [[String: Any]] {
            signingKeys = skArray.map { dictToSigningKey($0) }
        } else {
            signingKeys = []
        }
        return Contact(
            id: id,
            firstName: d["firstName"] as? String ?? "",
            lastName: d["lastName"] as? String ?? "",
            company: d["company"] as? String ?? "",
            email: d["email"] as? String ?? "",
            noblePubkey: d["noblePubkey"] as? String ?? "",
            bitcoinKey: d["bitcoinKey"] as? String ?? "",
            notes: d["notes"] as? String ?? "",
            createdAt: Date(timeIntervalSince1970: d["createdAt"] as? Double ?? Date.now.timeIntervalSince1970),
            updatedAt: .now,
            isFavorite: d["isFavorite"] as? Bool ?? false,
            isMyCard: d["isMyCard"] as? Bool ?? false,
            signingKeys: signingKeys
        )
    }

    private func dictToSigningKey(_ d: [String: Any]) -> SigningKeyEntry {
        SigningKeyEntry(
            id: UUID(uuidString: d["id"] as? String ?? "") ?? UUID(),
            label: d["label"] as? String ?? "",
            algorithm: d["algorithm"] as? String ?? "p256",
            publicKeyHex: d["publicKeyHex"] as? String ?? "",
            hasPrivateKey: d["hasPrivateKey"] as? Bool ?? false,
            certificateSubject: d["certificateSubject"] as? String,
            certificateDER: d["certificateDER"] as? String,
            subjectKeyIdentifier: d["subjectKeyIdentifier"] as? String,
            importedAt: Date(timeIntervalSince1970: d["importedAt"] as? Double ?? Date.now.timeIntervalSince1970)
        )
    }

    /// Call a CMS FFI function (noble_sign_cms_ffi / noble_verify_cms_ffi).
    private func callCmsFFI(
        _ fn: @convention(c) (UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>?,
        params: String
    ) -> String {
        guard let resultPtr = params.withCString({ fn($0) }) else {
            return "{\"error\":\"CMS FFI returned null\"}"
        }
        let result = String(cString: resultPtr)
        noble_free(resultPtr)
        return result
    }

    private func saveFileDialog(suggestedName: String, content: String) async -> Bool {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        panel.canCreateDirectories = true

        let response = panel.runModal()
        guard response == .OK, let url = panel.url else { return false }

        do {
            try content.write(to: url, atomically: true, encoding: .utf8)
            return true
        } catch {
            return false
        }
    }

    private func openFileDialog(allowMultiple: Bool) async -> [[String: Any]] {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = allowMultiple
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [.item]

        let response = panel.runModal()
        guard response == .OK else { return [] }

        return panel.urls.map { url in
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            let size = attrs?[.size] as? UInt64 ?? 0
            return [
                "path": url.path,
                "name": url.lastPathComponent,
                "size": size,
            ] as [String: Any]
        }
    }

    private func serializeToJSON(_ value: Any) throws -> String {
        if let dict = value as? [String: Any] {
            let data = try JSONSerialization.data(withJSONObject: dict)
            return String(data: data, encoding: .utf8) ?? "{}"
        }
        if let array = value as? [[String: Any]] {
            let data = try JSONSerialization.data(withJSONObject: array)
            return String(data: data, encoding: .utf8) ?? "[]"
        }
        return "{}"
    }
}

// MARK: - Bridge Errors

enum BridgeError: LocalizedError {
    case unknownHandler(String)
    case unknownAction(String)
    case missingParam(String)
    case notConnected
    case noPrivateKey
    case faucetUnavailable
    case faucetError(String)
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .unknownHandler(let h): "Unknown bridge handler: \(h) [\(NE.unknownHandler)]"
        case .unknownAction(let a): "Unknown action: \(a) [\(NE.unknownAction)]"
        case .missingParam(let p): "Missing parameter: \(p) [\(NE.missingParam)]"
        case .notConnected: "Not connected to a NOBLE node [\(NE.notConnected)]"
        case .noPrivateKey: "No private key available [\(NE.noPrivateKey)]"
        case .faucetUnavailable: "Faucet service is not available [\(NE.faucetUnavailable)]"
        case .faucetError(let msg): "\(msg) [\(NE.faucetError)]"
        case .operationFailed(let msg): "\(msg) [\(NE.operationFailed)]"
        }
    }
}

/// Accepts any server certificate (self-signed) for faucet HTTPS connections.
private final class FaucetTLSDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
