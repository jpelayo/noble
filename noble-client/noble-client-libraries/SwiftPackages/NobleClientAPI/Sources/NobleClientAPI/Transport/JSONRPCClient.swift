// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation

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
/// Uses `URLSession` with a custom TLS trust delegate for connecting
/// to NOBLE nodes with self-signed certificates.
public actor JSONRPCClient {

    /// The base URL of the NOBLE node's JSON-RPC endpoint.
    public let baseURL: URL

    /// Optional bearer token for authenticated requests.
    public var bearerToken: String?

    /// The SHA-256 fingerprint of a trusted self-signed certificate.
    /// When set, only certificates matching this fingerprint are accepted.
    public var trustedFingerprint: String?

    /// Whether to trust any self-signed certificate on first connect (TOFU).
    public var trustOnFirstUse: Bool

    private let session: URLSession
    private let delegate: TLSTrustDelegate
    private var nextId = 1

    /// Creates a new JSON-RPC client.
    ///
    /// - Parameters:
    ///   - baseURL: The HTTPS URL of the node (e.g. `https://localhost:8783`)
    ///   - bearerToken: Optional authentication token
    ///   - trustedFingerprint: SHA-256 hex fingerprint of trusted cert
    ///   - trustOnFirstUse: Accept any self-signed cert on first connect
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
        self.delegate = TLSTrustDelegate()
        self.session = URLSession(
            configuration: .default,
            delegate: delegate,
            delegateQueue: nil
        )
    }

    /// Calls a JSON-RPC method with typed parameters and returns typed result.
    ///
    /// - Parameters:
    ///   - method: The RPC method name (e.g. "noble_getNodeInfo")
    ///   - params: Encodable parameters (use `Empty` for no-param calls)
    ///   - expecting: The expected response type
    /// - Returns: The decoded result
    public func call<P: Encodable & Sendable, R: Decodable & Sendable>(
        method: String,
        params: P?,
        expecting: R.Type
    ) async throws -> R {
        let requestId = nextId
        nextId += 1

        let rpcRequest = JSONRPCRequest(id: requestId, method: method, params: params)

        var urlRequest = URLRequest(url: baseURL)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("noble", forHTTPHeaderField: "Gatekeeper")

        if let token = bearerToken {
            urlRequest.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        let encoder = JSONEncoder()
        urlRequest.httpBody = try encoder.encode(rpcRequest)

        // Update delegate with current trust settings
        delegate.trustedFingerprint = trustedFingerprint
        delegate.trustOnFirstUse = trustOnFirstUse

        let (data, response) = try await session.data(for: urlRequest)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw RPCClientError.invalidResponse
        }

        guard httpResponse.statusCode == 200 else {
            throw RPCClientError.httpError(statusCode: httpResponse.statusCode)
        }

        // Capture the server certificate fingerprint if TOFU is enabled
        if trustOnFirstUse, trustedFingerprint == nil,
           let captured = delegate.lastCapturedFingerprint {
            trustedFingerprint = captured
        }

        let decoder = JSONDecoder()
        let rpcResponse = try decoder.decode(JSONRPCResponse<R>.self, from: data)

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

    /// The fingerprint captured from the server's certificate (after first successful call).
    public var capturedFingerprint: String? {
        delegate.lastCapturedFingerprint
    }

    /// Test connectivity by making a simple call.
    public func testConnection() async throws -> Bool {
        // Use getApiVersion as a lightweight health check
        struct ApiVersion: Decodable {
            let api_version: String
        }
        let _ = try await call(method: "noble_getApiVersion", expecting: ApiVersion.self)
        return true
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
