// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import Foundation
import CryptoKit

/// URLSession delegate that handles TLS certificate trust for self-signed NOBLE node certs.
///
/// Supports two modes:
/// - **Trust On First Use (TOFU)**: Accept any self-signed cert on first connect,
///   then capture its fingerprint for future verification.
/// - **Pinned fingerprint**: Only accept certificates matching a known SHA-256 fingerprint.
final class TLSTrustDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {

    /// SHA-256 hex fingerprint of the trusted certificate. If set, only this cert is accepted.
    var trustedFingerprint: String?

    /// Whether to accept any self-signed cert on first connect.
    var trustOnFirstUse: Bool = true

    /// The fingerprint captured from the last successful connection.
    private(set) var lastCapturedFingerprint: String?

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {

        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            return (.performDefaultHandling, nil)
        }

        // Extract the server certificate
        guard let certificates = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let serverCert = certificates.first else {
            return (.cancelAuthenticationChallenge, nil)
        }

        let fingerprint = Self.sha256Fingerprint(of: serverCert)

        // Mode 1: Pinned fingerprint — strict match required
        if let trusted = trustedFingerprint {
            if fingerprint.lowercased() == trusted.lowercased() {
                lastCapturedFingerprint = fingerprint
                return (.useCredential, URLCredential(trust: serverTrust))
            }
            // Fingerprint mismatch — reject
            return (.cancelAuthenticationChallenge, nil)
        }

        // Mode 2: Trust On First Use — accept and capture fingerprint
        if trustOnFirstUse {
            lastCapturedFingerprint = fingerprint
            return (.useCredential, URLCredential(trust: serverTrust))
        }

        // No trust policy configured — fall back to system default
        return (.performDefaultHandling, nil)
    }

    /// Compute SHA-256 fingerprint of a DER-encoded certificate.
    static func sha256Fingerprint(of certificate: SecCertificate) -> String {
        let derData = SecCertificateCopyData(certificate) as Data
        let digest = SHA256.hash(data: derData)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
