// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import AppKit
import Foundation
import NobleClientAPI
import NobleClientCore
import NobleClientCrypto
import NobleClientSecurity
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
                "address": balance.address.wireHex,
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
                "network": info.network,
                "version": info.version,
                "blockHeight": info.blockHeight,
                "peerCount": info.peerCount,
                "isSyncing": info.isSyncing,
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

        default:
            throw BridgeError.unknownAction(action)
        }
    }

    // MARK: - Serialization Helpers

    private func txToDict(_ tx: TransactionRecord) -> [String: Any] {
        var dict: [String: Any] = [
            "txId": tx.txId.hex,
            "txType": tx.txType.label,
            "status": tx.status.rawValue,
            "from": tx.from.wireHex,
            "amount": tx.amount.atomic,
            "fee": tx.fee.atomic,
        ]
        if let to = tx.to { dict["to"] = to.wireHex }
        if let h = tx.blockHeight { dict["blockHeight"] = h }
        if let t = tx.timestamp { dict["timestamp"] = t.timeIntervalSince1970 }
        if let c = tx.checksum { dict["checksum"] = c.hex }
        return dict
    }

    private func registrationToDict(_ r: RegistrationRecord) -> [String: Any] {
        [
            "txId": r.txId.hex,
            "checksum": r.checksum.hex,
            "publisher": r.publisher.wireHex,
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
            "publisher": v.publisher.wireHex,
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
            let feeAtomic = params["fee"] as? UInt64 ?? 2000
            let metadata = params["metadata"] as? [[String: String]] ?? []
            let metadataItems = metadata.map {
                MetadataItem(key: $0["key"] ?? "", value: $0["value"] ?? "")
            }

            let txHex = try appState.transactionSigner.signNotarization(
                checksum: checksum,
                metadata: metadataItems,
                fee: NobleAmount(atomic: feeAtomic),
                privateKey: privateKey,
                chainId: NobleProtocol.mainnetChainId
            )
            return ["txHex": txHex]

        case "signTransfer":
            guard let recipientHex = params["recipient"] as? String,
                  let to = NobleAddress(wireHex: recipientHex) else {
                throw BridgeError.missingParam("recipient")
            }
            guard let amountAtomic = params["amount"] as? UInt64 else {
                throw BridgeError.missingParam("amount")
            }
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let feeAtomic = params["fee"] as? UInt64 ?? 2000

            let txHex = try appState.transactionSigner.signTransfer(
                to: to,
                amount: NobleAmount(atomic: amountAtomic),
                fee: NobleAmount(atomic: feeAtomic),
                privateKey: privateKey,
                chainId: NobleProtocol.mainnetChainId,
                sourceAddress: nil
            )
            return ["txHex": txHex]

        default:
            throw BridgeError.unknownAction(action)
        }
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
                "network": appState.networkLabel,
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
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
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
            return ["ok": true, "id": contact.id.uuidString]

        case "deleteContact":
            guard let idStr = params["id"] as? String, let uuid = UUID(uuidString: idStr) else {
                throw BridgeError.missingParam("id")
            }
            appState.contacts.removeAll { $0.id == uuid }
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

    var errorDescription: String? {
        switch self {
        case .unknownHandler(let h): "Unknown bridge handler: \(h)"
        case .unknownAction(let a): "Unknown action: \(a)"
        case .missingParam(let p): "Missing parameter: \(p)"
        case .notConnected: "Not connected to a NOBLE node"
        case .noPrivateKey: "No private key available"
        }
    }
}
