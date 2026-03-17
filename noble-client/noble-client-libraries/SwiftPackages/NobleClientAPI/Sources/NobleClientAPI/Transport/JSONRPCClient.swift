// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import Network
import CryptoKit

/// JSON-RPC 2.0 request envelope.
struct JSONRPCRequest<P: Encodable>: Encodable {
    let jsonrpc = "2.0"
    let id: Int
    let method: String
    let params: P?
}

/// JSON-RPC 2.0 response envelope.
struct JSONRPCResponse<R: Decodable>: Decodable {
    let jsonrpc: String
    let id: Int?
    let result: R?
    let error: JSONRPCError?
}

/// JSON-RPC 2.0 error object.
public struct JSONRPCError: Decodable, Error, Sendable {
    public let code: Int
    public let message: String
    public let data: String?
}

/// Low-level JSON-RPC 2.0 transport over HTTPS.
///
/// Uses Network.framework (NWConnection) instead of URLSession to bypass
/// ATS entirely. ATS on iOS 26 rejects self-signed certificates even when
/// `NSAllowsArbitraryLoads = true` and a URLSession delegate accepts them.
/// NWConnection handles TLS at the transport level with full trust control.
public actor JSONRPCClient {

    /// The base URL of the NOBLE node's JSON-RPC endpoint.
    public let baseURL: URL

    /// Optional bearer token for authenticated requests.
    public var bearerToken: String?

    /// The SHA-256 fingerprint of a trusted self-signed certificate.
    public var trustedFingerprint: String?

    /// Whether to trust any self-signed certificate on first connect (TOFU).
    public var trustOnFirstUse: Bool

    private let host: String
    private let port: UInt16
    private let path: String
    private var nextId = 1

    public init(
        baseURL: URL,
        bearerToken: String? = nil,
        trustedFingerprint: String? = nil,
        trustOnFirstUse: Bool = true
    ) {
        self.baseURL = baseURL
        self.bearerToken = bearerToken
        self.trustedFingerprint = trustedFingerprint
        self.trustOnFirstUse = trustOnFirstUse
        self.host = baseURL.host ?? "localhost"
        self.port = UInt16(baseURL.port ?? 8783)
        self.path = baseURL.path.isEmpty ? "/" : baseURL.path
    }

    /// Calls a JSON-RPC method with typed parameters and returns typed result.
    public func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        method: String,
        params: P?,
        expecting: R.Type
    ) async throws -> R {
        let requestId = nextId
        nextId += 1

        let rpcRequest = JSONRPCRequest(id: requestId, method: method, params: params)
        let bodyData = try JSONEncoder().encode(rpcRequest)

        let responseData = try await performHTTPS(body: bodyData)

        let rpcResponse = try JSONDecoder().decode(JSONRPCResponse<R>.self, from: responseData)

        if let error = rpcResponse.error {
            throw error
        }

        guard let result = rpcResponse.result else {
            throw RPCClientError.emptyResult(method: method)
        }

        return result
    }

    /// Convenience overload for methods with no parameters.
    public func call<R: Decodable & Sendable>(
        method: String,
        expecting: R.Type
    ) async throws -> R {
        try await call(method: method, params: nil as Empty?, expecting: expecting)
    }

    /// The fingerprint captured from the server's certificate.
    public var capturedFingerprint: String? {
        trustedFingerprint
    }

    /// Test connectivity by making a simple call.
    public func testConnection() async throws -> Bool {
        struct ApiVersion: Decodable {
            let api_version: String?
            let version: String?
        }
        let _ = try await call(method: "noble_getApiVersion", expecting: ApiVersion.self)
        return true
    }

    // MARK: - Network.framework HTTPS transport

    /// Perform a raw HTTPS POST using NWConnection. Bypasses ATS entirely.
    private func performHTTPS(body: Data) async throws -> Data {
        let tlsOptions = NWProtocolTLS.Options()
        let pinnedFP = trustedFingerprint
        let tofu = trustOnFirstUse

        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { metadata, trust, completion in
                let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                // Disable network fetch (OCSP/CRL) — self-signed certs have no revocation server.
                // Without this, iOS waits ~15s for the OCSP timeout on every connection.
                SecTrustSetNetworkFetchAllowed(secTrust, false)
                if let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                   let cert = chain.first {
                    let der = SecCertificateCopyData(cert) as Data
                    let digest = SHA256.hash(data: der)
                    let fp = digest.map { String(format: "%02x", $0) }.joined()

                    if let pinned = pinnedFP {
                        completion(fp.lowercased() == pinned.lowercased())
                        return
                    }
                    if tofu {
                        completion(true)
                        return
                    }
                }
                completion(false)
            },
            .global(qos: .userInitiated)
        )

        let params = NWParameters(tls: tlsOptions, tcp: .init())
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw RPCClientError.connectionFailed(underlying: "Invalid port: \(port)")
        }

        // Capture values outside the actor for use in Sendable closures
        let reqHost = host
        let reqPort = port
        let reqPath = path
        let reqBearer = bearerToken
        let connection = NWConnection(to: .hostPort(host: NWEndpoint.Host(reqHost), port: nwPort), using: params)

        // Thread-safe one-shot guard for the continuation
        let guard_ = ContinuationGuard()

        return try await withCheckedThrowingContinuation { continuation in
            connection.stateUpdateHandler = { [guard_] state in
                switch state {
                case .ready:
                    var headers = "POST \(reqPath) HTTP/1.1\r\n"
                    headers += "Host: \(reqHost):\(reqPort)\r\n"
                    headers += "Content-Type: application/json\r\n"
                    headers += "Gatekeeper: noble\r\n"
                    if let token = reqBearer {
                        headers += "Authorization: Bearer \(token)\r\n"
                    }
                    headers += "Content-Length: \(body.count)\r\n"
                    headers += "Connection: close\r\n"
                    headers += "\r\n"

                    var payload = Data(headers.utf8)
                    payload.append(body)

                    connection.send(content: payload, completion: .contentProcessed { [guard_] error in
                        if let error {
                            connection.cancel()
                            guard_.resume(continuation, throwing: error)
                            return
                        }
                        Self.readFullResponse(connection: connection) { [guard_] result in
                            connection.cancel()
                            guard_.resume(continuation, with: result)
                        }
                    })

                case .failed(let error):
                    connection.cancel()
                    guard_.resume(continuation, throwing: error)

                case .cancelled:
                    guard_.resume(continuation, throwing: RPCClientError.connectionFailed(underlying: "Connection cancelled"))

                default:
                    break
                }
            }

            // Timeout
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [guard_] in
                connection.cancel()
                guard_.resume(continuation, throwing: RPCClientError.connectionFailed(underlying: "Connection timed out"))
            }

            connection.start(queue: .global(qos: .userInitiated))
        }
    }

    /// Read the full HTTP response body.
    private static func readFullResponse(connection: NWConnection, completion: @escaping (Result<Data, Error>) -> Void) {
        var accumulated = Data()

        func readChunk() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let data { accumulated.append(data) }
                if isComplete || error != nil {
                    let separator = Data("\r\n\r\n".utf8)
                    if let range = accumulated.range(of: separator) {
                        // Parse status line
                        let headerData = accumulated.subdata(in: accumulated.startIndex..<range.lowerBound)
                        let headerStr = String(data: headerData, encoding: .utf8) ?? ""
                        let statusLine = headerStr.components(separatedBy: "\r\n").first ?? ""

                        // Check for non-200
                        if !statusLine.contains("200") {
                            let code = statusLine.split(separator: " ").dropFirst().first.flatMap { Int($0) } ?? 0
                            completion(.failure(RPCClientError.httpError(statusCode: code)))
                            return
                        }

                        let body = accumulated.subdata(in: range.upperBound..<accumulated.endIndex)
                        completion(.success(body))
                    } else {
                        completion(.success(accumulated))
                    }
                    return
                }
                readChunk()
            }
        }
        readChunk()
    }
}

/// Errors from the JSON-RPC transport layer.
public enum RPCClientError: Error, Sendable {
    case invalidResponse
    case httpError(statusCode: Int)
    case emptyResult(method: String)
    case connectionFailed(underlying: String)
    case tlsRejected(fingerprint: String)
}

/// Empty type for parameterless RPC calls.
struct Empty: Encodable {}

/// Thread-safe one-shot guard for continuation resumption.
/// Ensures a `CheckedContinuation` is resumed exactly once even when
/// multiple NWConnection callbacks race (ready + timeout, etc.).
private final class ContinuationGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var _resumed = false

    func resume(_ continuation: CheckedContinuation<Data, Error>, with result: Result<Data, Error>) {
        lock.lock()
        guard !_resumed else { lock.unlock(); return }
        _resumed = true
        lock.unlock()
        continuation.resume(with: result)
    }

    func resume(_ continuation: CheckedContinuation<Data, Error>, throwing error: Error) {
        resume(continuation, with: .failure(error))
    }
}
