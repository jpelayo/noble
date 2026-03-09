// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import NobleClientCore

/// Subscription topics available on the NOBLE node WebSocket.
public enum SubscriptionTopic: String, Sendable {
    case newBlocks = "noble_subscribeNewBlocks"
    case newTransactions = "noble_subscribeNewTransactions"
    case cyclePhase = "noble_subscribeCyclePhase"
    case peerUpdates = "noble_subscribePeerUpdates"

    var unsubscribeMethod: String {
        switch self {
        case .newBlocks: "noble_unsubscribeNewBlocks"
        case .newTransactions: "noble_unsubscribeNewTransactions"
        case .cyclePhase: "noble_unsubscribeCyclePhase"
        case .peerUpdates: "noble_unsubscribePeerUpdates"
        }
    }
}

/// WebSocket client for NOBLE node real-time subscriptions.
///
/// Implements the jsonrpsee subscription protocol:
/// 1. Send subscribe method → receive subscription ID
/// 2. Receive notifications with subscription ID
/// 3. Send unsubscribe to stop
public actor WebSocketClient {

    /// The WebSocket URL (typically `wss://localhost:8784`).
    public let url: URL

    /// Optional bearer token for authenticated connections.
    public var bearerToken: String?

    private var webSocketTask: URLSessionWebSocketTask?
    private let delegate: TLSTrustDelegate
    private let session: URLSession
    private var nextId = 1
    private var activeSubscriptions: [String: String] = [:] // topic → sub_id
    private var continuations: [String: AsyncStream<Data>.Continuation] = [:] // sub_id → continuation
    private var receiveTask: Task<Void, Never>?

    public init(url: URL, bearerToken: String? = nil) {
        self.url = url
        self.bearerToken = bearerToken
        self.delegate = TLSTrustDelegate()
        self.delegate.trustOnFirstUse = true
        self.session = URLSession(
            configuration: .default,
            delegate: delegate,
            delegateQueue: nil
        )
    }

    /// Connect to the WebSocket endpoint.
    public func connect() async throws {
        var request = URLRequest(url: url)
        if let token = bearerToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let task = session.webSocketTask(with: request)
        task.resume()
        webSocketTask = task

        // Start receiving messages
        receiveTask = Task { [weak self] in
            await self?.receiveLoop()
        }
    }

    /// Disconnect and cancel all subscriptions.
    public func disconnect() {
        receiveTask?.cancel()
        receiveTask = nil
        webSocketTask?.cancel(with: .normalClosure, reason: nil)
        webSocketTask = nil

        for continuation in continuations.values {
            continuation.finish()
        }
        continuations.removeAll()
        activeSubscriptions.removeAll()
    }

    /// Subscribe to a topic and receive an `AsyncStream` of raw JSON data.
    public func subscribe(to topic: SubscriptionTopic) async throws -> AsyncStream<Data> {
        guard let ws = webSocketTask else {
            throw WebSocketError.notConnected
        }

        let requestId = nextId
        nextId += 1

        // Send subscription request
        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "id": requestId,
            "method": topic.rawValue,
            "params": [] as [Any],
        ]
        let data = try JSONSerialization.data(withJSONObject: request)
        try await ws.send(.string(String(data: data, encoding: .utf8) ?? ""))

        // Wait for subscription confirmation (the response with the subscription ID)
        // The receive loop handles this — we create the stream and store it
        let stream = AsyncStream<Data> { continuation in
            // Store continuation temporarily keyed by request ID
            self.continuations["pending_\(requestId)"] = continuation
        }

        // Give the receive loop a moment to process the subscription response
        try await Task.sleep(for: .milliseconds(100))

        return stream
    }

    /// Unsubscribe from a topic.
    public func unsubscribe(from topic: SubscriptionTopic) async throws {
        guard let ws = webSocketTask,
              let subId = activeSubscriptions[topic.rawValue] else { return }

        let requestId = nextId
        nextId += 1

        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "id": requestId,
            "method": topic.unsubscribeMethod,
            "params": [subId],
        ]
        let data = try JSONSerialization.data(withJSONObject: request)
        try await ws.send(.string(String(data: data, encoding: .utf8) ?? ""))

        continuations[subId]?.finish()
        continuations.removeValue(forKey: subId)
        activeSubscriptions.removeValue(forKey: topic.rawValue)
    }

    /// Whether the WebSocket is currently connected.
    public var isConnected: Bool {
        webSocketTask != nil
    }

    // MARK: - Private

    private func receiveLoop() async {
        guard let ws = webSocketTask else { return }

        while !Task.isCancelled {
            do {
                let message = try await ws.receive()
                switch message {
                case .string(let text):
                    if let data = text.data(using: .utf8) {
                        handleMessage(data)
                    }
                case .data(let data):
                    handleMessage(data)
                @unknown default:
                    break
                }
            } catch {
                // WebSocket disconnected
                break
            }
        }
    }

    private nonisolated func handleMessage(_ data: Data) {
        // Parse as JSON to determine message type
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return
        }

        // Subscription confirmation: {"jsonrpc":"2.0","id":1,"result":"sub_id_string"}
        if let id = json["id"] as? Int,
           let result = json["result"] as? String {
            Task { await self.handleSubscriptionConfirm(requestId: id, subId: result) }
            return
        }

        // Subscription notification: {"jsonrpc":"2.0","method":"noble_subscription","params":{"subscription":"sub_id","result":{...}}}
        if let params = json["params"] as? [String: Any],
           let subId = params["subscription"] as? String {
            let resultData: Data
            if let result = params["result"] {
                resultData = (try? JSONSerialization.data(withJSONObject: result)) ?? data
            } else {
                resultData = data
            }
            Task { await self.deliverNotification(subId: subId, data: resultData) }
        }
    }

    private func handleSubscriptionConfirm(requestId: Int, subId: String) {
        let pendingKey = "pending_\(requestId)"
        if let continuation = continuations.removeValue(forKey: pendingKey) {
            continuations[subId] = continuation
            // Find which topic this belongs to (by matching the request ID order)
            // For simplicity, store by sub_id and the receive loop delivers
        }
    }

    private func deliverNotification(subId: String, data: Data) {
        continuations[subId]?.yield(data)
    }
}

/// Errors from the WebSocket client.
public enum WebSocketError: Error, Sendable {
    case notConnected
    case subscriptionFailed(topic: String)
    case connectionClosed
}
