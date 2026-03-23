// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import NobleClientAPI
import NobleClientCore
import NobleClientCrypto
import NobleClientSecurity
import NobleTxCore
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

        case "getWalletTransactions", "getTransactionHistory":
            // Pass client wallet address so server includes client-key txs.
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
                        "counterparty": isTransfer ? "Transfer" : "Self (Document)",
                        "total_output": p.change + p.sent,
                        "transfer_value": p.sent,
                        "timestamp": Date().timeIntervalSince1970,
                    ] as [String: Any], at: 0)
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

        // Use server-computed direction/counterparty/amount when available.
        if let dir = tx.direction {
            dict["direction"] = dir
        }
        if let cp = tx.counterparty {
            dict["counterparty"] = cp
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
                    dict["counterparty"] = dict["counterparty"] ?? tx.outputs.first(where: { $0.address != walletAddr })?.address
                } else {
                    dict["direction"] = "incoming"
                    dict["counterparty"] = dict["counterparty"] ?? tx.signer.nobleBech32
                }
            case .coinbase:
                dict["direction"] = "incoming"
                dict["counterparty"] = dict["counterparty"] ?? "Block Reward"
            case .notarization, .locked, .unlocking:
                if tx.signer.nobleBech32 == walletAddr {
                    dict["direction"] = "outgoing"
                    dict["counterparty"] = dict["counterparty"] ?? "Self (Document)"
                } else {
                    dict["direction"] = "incoming"
                    dict["counterparty"] = dict["counterparty"] ?? tx.signer.nobleBech32
                }
            case .keyRotation:
                dict["direction"] = "self"
                dict["counterparty"] = dict["counterparty"] ?? "Key Rotation"
            case .badgeProposal, .badgeVote, .badgeRevocation:
                dict["direction"] = "self"
                dict["counterparty"] = dict["counterparty"] ?? "Governance"
            case .feeDistribution:
                dict["direction"] = "incoming"
                dict["counterparty"] = dict["counterparty"] ?? "Fee Distribution"
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
            let metadata = params["metadata"] as? [[String: String]] ?? []
            let metadataItems = metadata.map {
                MetadataItem(key: $0["key"] ?? "", value: $0["value"] ?? "")
            }

            // Parse available UTXOs and estimate real tx size for accurate coin selection.
            let allUtxos = try parseUtxoParams(params)
            let changeAddress = try walletChangeAddress()
            let chainId = appState.resolvedChainId
            let feeEstimate: UInt64
            if feeRate > 0 {
                let estSize = estimateTxSizeViaC(txType: "notarization", checksum: checksumHex,
                    metadata: metadata, recipient: nil, changeAddress: changeAddress,
                    privateKey: privateKey, chainId: chainId)
                feeEstimate = feeRate * estSize
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
                let estSize = estimateTxSizeViaC(txType: "transfer", checksum: nil,
                    metadata: [], recipient: recipientHex, changeAddress: changeAddress,
                    privateKey: privateKey, chainId: chainId)
                feeEstimate = feeRate * estSize
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

        case "estimateTxSize":
            guard let privateKey = appState.loadPrivateKey() else {
                throw BridgeError.noPrivateKey
            }
            let changeAddress = try walletChangeAddress()
            let chainId = appState.resolvedChainId
            let txType = params["tx_type"] as? String ?? "notarization"
            let checksum = params["checksum"] as? String ?? String(repeating: "00", count: 32)
            let metaArr = (params["metadata"] as? [[String: String]] ?? []).map {
                ["key": $0["key"] ?? "", "value": $0["value"] ?? ""]
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

        case "signMetadataField":
            guard let keyIdStr = params["keyId"] as? String,
                  let keyId = UUID(uuidString: keyIdStr) else {
                throw BridgeError.missingParam("keyId")
            }
            guard let fieldValue = params["fieldValue"] as? String else {
                throw BridgeError.missingParam("fieldValue")
            }

            guard let myCard = appState.contacts.first(where: { $0.isMyCard }),
                  let keyEntry = myCard.signingKeys.first(where: { $0.id == keyId }) else {
                throw BridgeError.operationFailed("Signing key not found")
            }

            guard let privKeyData = try appState.keychainService.loadKey(label: "signing-key-\(keyIdStr)") else {
                throw BridgeError.operationFailed("Private key not found in keychain")
            }
            guard let certData = try appState.keychainService.loadKey(label: "signing-cert-\(keyIdStr)") else {
                throw BridgeError.operationFailed("Certificate not found in keychain")
            }

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

            let parseParams: [String: Any] = ["cms_hex": sigHex, "field_value": fieldValue]
            let parseJson = try serializeToJSON(parseParams)
            let parseResultStr = callCmsFFI(noble_verify_cms_ffi, params: parseJson)
            guard let parsed = try? JSONSerialization.jsonObject(with: Data(parseResultStr.utf8)) as? [String: Any] else {
                throw BridgeError.operationFailed("CMS parse failed")
            }

            let signerSKI = parsed["signer_ski_hex"] as? String ?? "unknown"
            let algorithm = parsed["algorithm"] as? String ?? "unknown"

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

            var valid = false
            var error: String?
            if let cert = certB64 {
                let verifyParams: [String: Any] = [
                    "cms_hex": sigHex, "field_value": fieldValue, "certificate_der_b64": cert,
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
                "valid": valid, "signerSKI": signerSKI,
                "signerName": signerName as Any, "hasCertificate": certB64 != nil,
                "algorithm": algorithm, "error": error as Any,
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
    ) -> UInt64 {
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
            return 500
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
            // Step 1: Pick .p12/.pfx file via UIDocumentPicker
            let p12URL: URL = try await withCheckedThrowingContinuation { continuation in
                let types = [
                    UTType(filenameExtension: "p12") ?? .data,
                    UTType(filenameExtension: "pfx") ?? .data,
                ]
                let picker = UIDocumentPickerViewController(forOpeningContentTypes: types)
                picker.allowsMultipleSelection = false
                let delegate = PKCS12PickerDelegate(continuation: continuation)
                picker.delegate = delegate
                // Prevent delegate from being deallocated before callback
                objc_setAssociatedObject(picker, "delegate", delegate, .OBJC_ASSOCIATION_RETAIN)
                guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                      let root = scene.windows.first?.rootViewController else {
                    continuation.resume(throwing: BridgeError.operationFailed("Cannot present file picker"))
                    return
                }
                root.present(picker, animated: true)
            }

            let accessing = p12URL.startAccessingSecurityScopedResource()
            defer { if accessing { p12URL.stopAccessingSecurityScopedResource() } }
            let p12Data = try Data(contentsOf: p12URL)
            let fileName = p12URL.deletingPathExtension().lastPathComponent

            // Step 2: Prompt for password via UIAlertController
            let password: String = try await withCheckedThrowingContinuation { continuation in
                let alert = UIAlertController(
                    title: "PKCS#12 Password",
                    message: "Enter the password for \(p12URL.lastPathComponent):",
                    preferredStyle: .alert
                )
                alert.addTextField { field in
                    field.isSecureTextEntry = true
                    field.placeholder = "Password"
                }
                alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
                    continuation.resume(throwing: BridgeError.operationFailed("cancelled"))
                })
                alert.addAction(UIAlertAction(title: "Import", style: .default) { _ in
                    let pw = alert.textFields?.first?.text ?? ""
                    continuation.resume(returning: pw)
                })
                guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                      let root = scene.windows.first?.rootViewController else {
                    continuation.resume(throwing: BridgeError.operationFailed("Cannot present password prompt"))
                    return
                }
                // Present on the topmost presented controller
                var presenter = root
                while let next = presenter.presentedViewController { presenter = next }
                presenter.present(alert, animated: true)
            }

            // Step 3: Import via Security.framework (identical to macOS)
            var importedItems: CFArray?
            let options = [kSecImportExportPassphrase: password] as NSDictionary
            let importStatus = SecPKCS12Import(p12Data as CFData, options, &importedItems)
            guard importStatus == errSecSuccess,
                  let items = importedItems as? [[String: Any]],
                  let firstItem = items.first else {
                throw BridgeError.operationFailed("PKCS#12 import failed (wrong password or invalid file)")
            }

            guard let identityRef = firstItem[kSecImportItemIdentity as String] else {
                throw BridgeError.operationFailed("No identity found in PKCS#12")
            }
            // SecIdentity is a CF type — downcast always succeeds if the key exists.
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

            // Only accept EC keys (P-256). Reject RSA.
            guard let keyAttrs = SecKeyCopyAttributes(privKey) as? [String: Any],
                  let keyType = keyAttrs[kSecAttrKeyType as String] as? String else {
                throw BridgeError.operationFailed("Cannot determine key type")
            }
            guard keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) else {
                throw BridgeError.operationFailed("Only ECDSA (P-256) keys are supported. RSA signatures exceed the 256-byte metadata slot limit.")
            }

            guard let privKeyData = SecKeyCopyExternalRepresentation(privKey, nil) as? Data else {
                throw BridgeError.operationFailed("Cannot export private key")
            }

            let certDER = SecCertificateCopyData(cert) as Data
            let subjectSummary = SecCertificateCopySubjectSummary(cert) as? String ?? "Unknown"

            // Compressed public key
            guard let pubKeyRef = SecKeyCopyPublicKey(privKey) else {
                throw BridgeError.operationFailed("Cannot derive public key from private key")
            }
            var pubKeyError: Unmanaged<CFError>?
            guard let pubKeyRaw = SecKeyCopyExternalRepresentation(pubKeyRef, &pubKeyError) as? Data else {
                let errMsg = pubKeyError?.takeRetainedValue().localizedDescription ?? "unknown"
                throw BridgeError.operationFailed("Cannot export public key: \(errMsg)")
            }
            let compressedHex: String
            if pubKeyRaw.count == 65 && pubKeyRaw[0] == 0x04 {
                let x = pubKeyRaw[1...32]
                let yParity: UInt8 = pubKeyRaw[64] & 1 == 0 ? 0x02 : 0x03
                compressedHex = String(format: "%02x", yParity) + x.map { String(format: "%02x", $0) }.joined()
            } else {
                compressedHex = pubKeyRaw.map { String(format: "%02x", $0) }.joined()
            }

            // Compute SKI (SHA-1 of uncompressed public key)
            let skiData = Insecure.SHA1.hash(data: pubKeyRaw)
            let skiHex = skiData.map { String(format: "%02x", $0) }.joined()

            // Store in Keychain
            let keyEntry = SigningKeyEntry(
                label: fileName,
                algorithm: "p256",
                publicKeyHex: compressedHex,
                hasPrivateKey: true,
                certificateSubject: subjectSummary,
                certificateDER: certDER.base64EncodedString(),
                subjectKeyIdentifier: skiHex
            )

            try appState.keychainService.storeKey(privKeyData, label: "signing-key-\(keyEntry.id.uuidString)")
            try appState.keychainService.storeKey(certDER, label: "signing-cert-\(keyEntry.id.uuidString)")

            if let idx = appState.contacts.firstIndex(where: { $0.isMyCard }) {
                appState.contacts[idx].signingKeys.append(keyEntry)
                appState.saveContactsToDefaults()
            }

            return signingKeyToDict(keyEntry)

        case "generateSigningKey":
            // Generate a secp256k1 keypair using SecRandomCopyBytes + derivePublicKey
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
            // Key deletion MUST succeed — prevent key material leak.
            try appState.keychainService.deleteKey(label: "signing-key-\(keyIdStr)")
            // Certificate deletion is best-effort (key material is the critical one).
            do { try appState.keychainService.deleteKey(label: "signing-cert-\(keyIdStr)") }
            catch { print("[Bridge] warning: cert cleanup failed (key removed): \(error)") }

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
            // Also navigate the WebView content (native tab sets state but
            // doesn't tell the WebView to switch pages).
            appState.webViewCoordinator?.evaluateJS(
                "App.navigateTo('\(target.webRoute)')"
            )
            return ["ok": true]

        case "share":
            guard let text = params["text"] as? String else {
                throw BridgeError.missingParam("text")
            }
            let activityVC = UIActivityViewController(activityItems: [text], applicationActivities: nil)
            if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
               let root = scene.keyWindow?.rootViewController {
                activityVC.popoverPresentationController?.sourceView = root.view
                root.present(activityVC, animated: true)
            }
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

/// UIDocumentPicker delegate that resumes a continuation with the selected URL.
private final class PKCS12PickerDelegate: NSObject, UIDocumentPickerDelegate {
    private var continuation: CheckedContinuation<URL, any Error>?

    init(continuation: CheckedContinuation<URL, any Error>) {
        self.continuation = continuation
        super.init()
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        if let url = urls.first {
            continuation?.resume(returning: url)
        } else {
            continuation?.resume(throwing: BridgeError.operationFailed("cancelled"))
        }
        continuation = nil
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        continuation?.resume(throwing: BridgeError.operationFailed("cancelled"))
        continuation = nil
    }
}
