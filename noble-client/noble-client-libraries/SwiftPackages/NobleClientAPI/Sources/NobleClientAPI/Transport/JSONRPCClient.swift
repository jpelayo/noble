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
public struct JSONRPCError: Decodable, Sendable, LocalizedError {
    public let code: Int
    public let message: String
    public let data: String?

    /// Maps JSON-RPC error code to an NE error code for user display.
    public var neCode: String {
        switch code {
        case -32700:          return "NE-105" // Parse error → invalidResponse
        case -32600:          return "NE-105" // Invalid request
        case -32601:          return "NE-703" // Method not found
        case -32602:          return "NE-702" // Invalid params
        case -32603:          return "NE-704" // Internal error
        case -32000:          return "NE-603" // TX rejected (generic)
        case -32020:          return "NE-610" // TX too large
        case -32021:          return "NE-611" // TX duplicate
        case -32022:          return "NE-612" // TX bad version
        case -32023:          return "NE-613" // TX structural validation
        case -32024:          return "NE-614" // TX bad signature
        case -32025:          return "NE-615" // TX fee too low
        case -32026:          return "NE-616" // TX sender rate limit
        case -32027:          return "NE-617" // TX mempool full
        case -32028:          return "NE-618" // TX immature coinbase
        case -32029:          return "NE-619" // TX double spend
        case -32030:          return "NE-620" // TX missing input (spent/unknown)
        case -32031:          return "NE-621" // TX insufficient input value
        case -32032:          return "NE-622" // TX expired
        case -32004:          return "NE-404" // Auth required → notConnected
        case -32007:          return "NE-306" // Wallet locked → noPrivateKey
        case -32009:          return "NE-605" // Insufficient balance
        case -32010:          return "NE-608" // Invalid address
        default:              return "NE-701" // Generic server error
        }
    }

    public var errorDescription: String? {
        "\(message) [\(neCode)]"
    }
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

    /// HH:mm:ss.SSS timestamp for logs.
    private static var ts: String {
        let d = Date()
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: d)
    }

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
        print("[\(Self.ts)] [RPC] NEW JSONRPCClient → \(baseURL.absoluteString)")
    }

    /// Calls a JSON-RPC method with typed parameters and returns typed result.
    public func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        method: String,
        params: P?,
        expecting: R.Type
    ) async throws -> R {
        let requestId = nextId
        nextId += 1
        let t0 = CFAbsoluteTimeGetCurrent()

        let rpcRequest = JSONRPCRequest(id: requestId, method: method, params: params)
        let bodyData = try JSONEncoder().encode(rpcRequest)

        let responseData = try await performHTTPS(body: bodyData, method: method, requestId: requestId)
        let tNet = CFAbsoluteTimeGetCurrent()

        let rpcResponse = try JSONDecoder().decode(JSONRPCResponse<R>.self, from: responseData)

        if let error = rpcResponse.error {
            let elapsed = Int((CFAbsoluteTimeGetCurrent() - t0) * 1000)
            print("[\(Self.ts)] [RPC] #\(requestId) \(method) ERROR \(error.code) in \(elapsed)ms")
            throw error
        }

        guard let result = rpcResponse.result else {
            throw RPCClientError.emptyResult(method: method)
        }

        let elapsed = Int((CFAbsoluteTimeGetCurrent() - t0) * 1000)
        let netMs = Int((tNet - t0) * 1000)
        print("[\(Self.ts)] [RPC] #\(requestId) \(method) OK net=\(netMs)ms total=\(elapsed)ms body=\(responseData.count)B")
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
    private func performHTTPS(body: Data, method: String = "?", requestId: Int = 0) async throws -> Data {
        let t0 = CFAbsoluteTimeGetCurrent()
        let tag = "#\(requestId) \(method)"
        print("[\(Self.ts)] [NET] \(tag) start conn to \(host):\(port)")

        let tlsOptions = NWProtocolTLS.Options()
        let pinnedFP = trustedFingerprint
        let tofu = trustOnFirstUse

        sec_protocol_options_set_verify_block(
            tlsOptions.securityProtocolOptions,
            { metadata, trust, completion in
                let tlsT0 = CFAbsoluteTimeGetCurrent()
                if tofu && pinnedFP == nil {
                    let ms = Int((CFAbsoluteTimeGetCurrent() - tlsT0) * 1000)
                    print("[\(Self.ts)] [NET] \(tag) TLS verify TOFU accept in \(ms)ms")
                    completion(true)
                    return
                }
                if let pinned = pinnedFP {
                    let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                    SecTrustSetNetworkFetchAllowed(secTrust, false)
                    if let chain = SecTrustCopyCertificateChain(secTrust) as? [SecCertificate],
                       let cert = chain.first {
                        let der = SecCertificateCopyData(cert) as Data
                        let digest = SHA256.hash(data: der)
                        let fp = digest.map { String(format: "%02x", $0) }.joined()
                        let match = fp.lowercased() == pinned.lowercased()
                        let ms = Int((CFAbsoluteTimeGetCurrent() - tlsT0) * 1000)
                        print("[\(Self.ts)] [NET] \(tag) TLS verify pinned \(match ? "OK" : "REJECT") in \(ms)ms")
                        completion(match)
                        return
                    }
                }
                print("[\(Self.ts)] [NET] \(tag) TLS verify REJECT (no TOFU, no pin)")
                completion(false)
            },
            .global(qos: .userInitiated)
        )

        let params = NWParameters(tls: tlsOptions, tcp: .init())
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw RPCClientError.connectionFailed(underlying: "Invalid port: \(port)")
        }

        let reqHost = host
        let reqPort = port
        let reqPath = path
        let reqBearer = bearerToken
        let connection = NWConnection(to: .hostPort(host: NWEndpoint.Host(reqHost), port: nwPort), using: params)
        let guard_ = ContinuationGuard()

        return try await withCheckedThrowingContinuation { continuation in
            connection.stateUpdateHandler = { [guard_] state in
                let elapsed = Int((CFAbsoluteTimeGetCurrent() - t0) * 1000)
                switch state {
                case .ready:
                    print("[\(Self.ts)] [NET] \(tag) .ready at +\(elapsed)ms")
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

                    let sendT0 = CFAbsoluteTimeGetCurrent()
                    connection.send(content: payload, completion: .contentProcessed { [guard_] error in
                        let sendMs = Int((CFAbsoluteTimeGetCurrent() - sendT0) * 1000)
                        if let error {
                            print("[\(Self.ts)] [NET] \(tag) send FAILED in \(sendMs)ms: \(error)")
                            connection.cancel()
                            guard_.resume(continuation, throwing: error)
                            return
                        }
                        print("[\(Self.ts)] [NET] \(tag) sent \(payload.count)B in \(sendMs)ms, reading response...")
                        let readT0 = CFAbsoluteTimeGetCurrent()
                        Self.readFullResponse(connection: connection) { [guard_] result in
                            let readMs = Int((CFAbsoluteTimeGetCurrent() - readT0) * 1000)
                            let totalMs = Int((CFAbsoluteTimeGetCurrent() - t0) * 1000)
                            switch result {
                            case .success(let data):
                                print("[\(Self.ts)] [NET] \(tag) response \(data.count)B read=\(readMs)ms total=\(totalMs)ms")
                            case .failure(let err):
                                print("[\(Self.ts)] [NET] \(tag) read FAILED in \(readMs)ms: \(err)")
                            }
                            connection.cancel()
                            guard_.resume(continuation, with: result)
                        }
                    })

                case .preparing:
                    print("[\(Self.ts)] [NET] \(tag) .preparing at +\(elapsed)ms")

                case .waiting(let error):
                    print("[\(Self.ts)] [NET] \(tag) .waiting at +\(elapsed)ms: \(error)")

                case .failed(let error):
                    print("[\(Self.ts)] [NET] \(tag) .failed at +\(elapsed)ms: \(error)")
                    connection.cancel()
                    guard_.resume(continuation, throwing: error)

                case .cancelled:
                    print("[\(Self.ts)] [NET] \(tag) .cancelled at +\(elapsed)ms")
                    guard_.resume(continuation, throwing: RPCClientError.connectionFailed(underlying: "Connection cancelled"))

                default:
                    break
                }
            }

            // Timeout
            DispatchQueue.global().asyncAfter(deadline: .now() + 10) { [guard_] in
                let elapsed = Int((CFAbsoluteTimeGetCurrent() - t0) * 1000)
                print("[\(Self.ts)] [NET] \(tag) TIMEOUT at +\(elapsed)ms")
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
public enum RPCClientError: LocalizedError, Sendable {
    case invalidResponse
    case httpError(statusCode: Int)
    case emptyResult(method: String)
    case connectionFailed(underlying: String)
    case tlsRejected(fingerprint: String)

    public var errorDescription: String? {
        switch self {
        case .invalidResponse:
            return "Invalid server response [NE-105]"
        case .httpError(let code):
            return "HTTP error \(code) [NE-104]"
        case .emptyResult(let method):
            return "Empty result from \(method) [NE-106]"
        case .connectionFailed(let reason):
            return "Connection failed: \(reason) [NE-103]"
        case .tlsRejected:
            return "TLS certificate rejected [NE-107]"
        }
    }
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
