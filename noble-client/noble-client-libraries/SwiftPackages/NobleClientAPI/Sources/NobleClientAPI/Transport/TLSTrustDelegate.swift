// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import CryptoKit

/// URLSession delegate that accepts self-signed TLS certificates.
///
/// Used by WebSocketClient (which requires URLSession). The JSON-RPC client
/// uses Network.framework (NWConnection) instead, bypassing ATS entirely.
///
/// On iOS 26, ATS may reject self-signed certs even when this delegate
/// accepts them. WebSocket connections to self-signed nodes may fail on iOS;
/// polling via JSONRPCClient (NWConnection) remains functional.
final class TLSTrustDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, @unchecked Sendable {

    var trustedFingerprint: String?
    var trustOnFirstUse: Bool = true
    private(set) var lastCapturedFingerprint: String?

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, completionHandler: completionHandler)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        handleChallenge(challenge, completionHandler: completionHandler)
    }

    private func handleChallenge(
        _ challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let certificates = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let serverCert = certificates.first else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Make self-signed cert pass trust evaluation
        let policy = SecPolicyCreateBasicX509()
        SecTrustSetPolicies(serverTrust, policy)
        SecTrustSetAnchorCertificates(serverTrust, [serverCert] as CFArray)
        SecTrustSetAnchorCertificatesOnly(serverTrust, true)
        var error: CFError?
        _ = SecTrustEvaluateWithError(serverTrust, &error)

        let fingerprint = Self.sha256Fingerprint(of: serverCert)

        if let trusted = trustedFingerprint {
            if fingerprint.lowercased() == trusted.lowercased() {
                lastCapturedFingerprint = fingerprint
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
            } else {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
            return
        }

        if trustOnFirstUse {
            lastCapturedFingerprint = fingerprint
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
            return
        }

        completionHandler(.performDefaultHandling, nil)
    }

    static func sha256Fingerprint(of certificate: SecCertificate) -> String {
        let derData = SecCertificateCopyData(certificate) as Data
        let digest = SHA256.hash(data: derData)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
