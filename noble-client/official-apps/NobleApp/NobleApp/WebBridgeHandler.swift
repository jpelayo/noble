// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientAPI
import NobleClientCore
import NobleClientCrypto
import NobleClientSecurity
import UIKit
import UniformTypeIdentifiers

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

        case "getTransactionHistory":
            guard let address = params["address"] as? String else {
                throw BridgeError.missingParam("address")
            }
            let page = params["page"] as? Int ?? 0
            let limit = params["limit"] as? Int ?? 20
            let txs = try await api.getTransactionHistory(address: address, page: page, limit: limit)
            return [
                "transactions": txs.map { tx in
                    txToDict(tx)
                },
            ] as [String: Any]

        case "estimateFee":
            let fee = try await api.estimateFee()
            return [
                "minFee": fee.minFee.atomic,
                "recommendedFee": fee.recommendedFee.atomic,
                "highPriorityFee": fee.highPriorityFee.atomic,
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

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - Faucet HTTP

    /// Derive faucet URL from the node URL (same host, port 8786).
    private func faucetBaseURL() -> URL? {
        guard let nodeURL = URL(string: appState.nodeURL),
              let host = nodeURL.host else { return nil }
        return URL(string: "http://\(host):8786")
    }

    /// URLSession that accepts self-signed certs (faucet may be local).
    private static let faucetSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 10
        return URLSession(configuration: config)
    }()

    private func handleFaucetStatus() async throws -> Any {
        guard let base = faucetBaseURL() else {
            throw BridgeError.faucetUnavailable
        }
        let url = base.appendingPathComponent("api/faucet/status")
        let (data, response) = try await Self.faucetSession.data(from: url)
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

    // MARK: - Serialization Helpers

    private func txToDict(_ tx: TransactionRecord) -> [String: Any] {
        var dict: [String: Any] = [
            "txId": tx.txId.hex,
            "txType": tx.txType.label,
            "type": tx.txType.label,
            "status": tx.status.rawValue,
            "signer": tx.signer.nobleBech32,
            "total_output": tx.totalOutput,
            "inputs": tx.inputs.map { ["txid": $0.txid, "vout": $0.vout] as [String: Any] },
            "outputs": tx.outputs.map { ["value": $0.value, "address": $0.address] as [String: Any] },
        ]
        if let h = tx.blockHeight { dict["blockHeight"] = h }
        if let t = tx.timestamp { dict["timestamp"] = t.timeIntervalSince1970 }
        if let c = tx.checksum { dict["checksum"] = c.hex }

        // Derived fields for WebUI compatibility
        let walletAddr = appState.walletAddress ?? ""
        let firstOutputAddr = tx.outputs.first?.address ?? ""
        if tx.txType == .transfer {
            if tx.signer.nobleBech32 == walletAddr {
                dict["direction"] = "outgoing"
                // Counterparty is the first output that isn't us
                let counterparty = tx.outputs.first(where: { $0.address != walletAddr })?.address ?? firstOutputAddr
                dict["counterparty"] = counterparty
            } else {
                dict["direction"] = "incoming"
                dict["counterparty"] = tx.signer.nobleBech32
            }
        }
        // Confirmations: compute from current block height if possible
        if let txHeight = tx.blockHeight {
            let tipHeight = UInt64(appState.blockHeight)
            dict["confirmations"] = tipHeight >= txHeight ? (tipHeight - txHeight + 1) : 0
        } else {
            dict["confirmations"] = 0
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
            guard let feeAtomic = (params["fee"] as? NSNumber)?.uint64Value else {
                throw BridgeError.missingParam("fee")
            }
            let metadata = params["metadata"] as? [[String: String]] ?? []
            let metadataItems = metadata.map {
                MetadataItem(key: $0["key"] ?? "", value: $0["value"] ?? "")
            }

            // Parse available UTXOs from JS, then run coin selection.
            let allUtxos = try parseUtxoParams(params)
            let selected = try CoinSelector.select(from: allUtxos, target: feeAtomic)

            let changeAddress = walletChangeAddress()
            let chainId = appState.resolvedChainId

            let txHex = try appState.transactionSigner.signNotarization(
                checksum: checksum,
                metadata: metadataItems,
                fee: NobleAmount(atomic: feeAtomic),
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
            guard let feeAtomic = (params["fee"] as? NSNumber)?.uint64Value else {
                throw BridgeError.missingParam("fee")
            }

            // Parse available UTXOs from JS, then run coin selection.
            let allUtxos = try parseUtxoParams(params)
            let target = amountAtomic + feeAtomic
            let selected = try CoinSelector.select(from: allUtxos, target: target)

            let changeAddress = walletChangeAddress()
            let chainId = appState.resolvedChainId

            let txHex = try appState.transactionSigner.signTransfer(
                to: to,
                amount: NobleAmount(atomic: amountAtomic),
                fee: NobleAmount(atomic: feeAtomic),
                utxos: selected,
                changeAddress: changeAddress,
                privateKey: privateKey,
                chainId: chainId
            )
            return ["txHex": txHex]

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - UTXO Helpers

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
    private func walletChangeAddress() -> [UInt8] {
        guard let addrStr = appState.walletAddress,
              let addr = NobleAddress(wireHex: addrStr) else { return [] }
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

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - App Handler

    private func handleApp(action: String, params: [String: Any]) async throws -> Any {
        switch action {
        case "getState":
            return [
                "isConnected": appState.isConnected,
                "hasWallet": appState.hasWallet,
                "walletAddress": appState.walletAddress ?? "",
                "chainId": appState.chainId,
                "blockHeight": appState.blockHeight,
                "selectedSection": appState.selectedSection?.webRoute ?? "home",
            ] as [String: Any]

        case "navigateTo":
            guard let section = params["section"] as? String,
                  let target = SidebarSection(rawValue: section)
            else {
                throw BridgeError.missingParam("section")
            }
            appState.selectedSection = target
            return ["ok": true]

        case "copyToClipboard":
            guard let text = params["text"] as? String else {
                throw BridgeError.missingParam("text")
            }
            UIPasteboard.general.string = text
            HapticManager.shared.success()
            return ["ok": true]

        case "openFileDialog":
            let allowMultiple = params["multiple"] as? Bool ?? true
            let files: [[String: Any]] = await withCheckedContinuation { continuation in
                appState.showingFilePicker = true
                appState.filePickerAllowsMultiple = allowMultiple
                appState.pendingFilePickerContinuation = continuation
            }
            return ["files": files]

        case "shareText":
            guard let text = params["text"] as? String else {
                throw BridgeError.missingParam("text")
            }
            appState.shareSheetItems = [text]
            appState.showingShareSheet = true
            return ["ok": true]

        case "saveFileDialog":
            let suggestedName = params["filename"] as? String ?? "export.vcf"
            let content = params["content"] as? String ?? ""
            // On iOS, write to temp and share via activity controller
            let tempURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(suggestedName)
            try content.write(to: tempURL, atomically: true, encoding: .utf8)
            appState.shareSheetItems = [tempURL]
            appState.showingShareSheet = true
            return ["ok": true]

        case "readFileText":
            guard let filePath = params["filePath"] as? String else {
                throw BridgeError.missingParam("filePath")
            }
            let url = URL(fileURLWithPath: filePath)
            let text = try String(contentsOf: url, encoding: .utf8)
            return ["text": text]

        case "getSettings":
            return [
                "nodeURL": appState.nodeURL,
                "authMode": "none",
                "tlsFingerprint": "",
                "appVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0",
                "autoConnect": appState.autoConnect,
            ] as [String: Any]

        case "saveSettings":
            if let url = params["nodeURL"] as? String {
                appState.saveNodeURL(url)
            }
            if let auto = params["autoConnect"] as? Bool {
                appState.autoConnect = auto
            }
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
            appState.contacts.removeAll { $0.id == uuid }
            appState.saveContactsToDefaults()
            return ["ok": true]

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
        [
            "id": c.id.uuidString,
            "firstName": c.firstName,
            "lastName": c.lastName,
            "company": c.company,
            "email": c.email,
            "noblePubkey": c.noblePubkey,
            "bitcoinKey": c.bitcoinKey,
            "notes": c.notes,
            "isFavorite": c.isFavorite,
            "displayName": c.displayName,
            "createdAt": c.createdAt.timeIntervalSince1970,
            "updatedAt": c.updatedAt.timeIntervalSince1970,
        ] as [String: Any]
    }

    private func dictToContact(_ d: [String: Any]) -> Contact {
        let id: UUID
        if let idStr = d["id"] as? String, let uuid = UUID(uuidString: idStr) {
            id = uuid
        } else {
            id = UUID()
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
            isFavorite: d["isFavorite"] as? Bool ?? false
        )
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

    var errorDescription: String? {
        switch self {
        case .unknownHandler(let h): "Unknown bridge handler: \(h) [\(NE.unknownHandler)]"
        case .unknownAction(let a): "Unknown action: \(a) [\(NE.unknownAction)]"
        case .missingParam(let p): "Missing parameter: \(p) [\(NE.missingParam)]"
        case .notConnected: "Not connected to a NOBLE node [\(NE.notConnected)]"
        case .noPrivateKey: "No private key available [\(NE.noPrivateKey)]"
        case .faucetUnavailable: "Faucet service is not available [\(NE.faucetUnavailable)]"
        case .faucetError(let msg): "\(msg) [\(NE.faucetError)]"
        }
    }
}
