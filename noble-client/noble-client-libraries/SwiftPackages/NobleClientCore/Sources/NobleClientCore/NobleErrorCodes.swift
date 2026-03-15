// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// Shared error code catalog for all Noble client applications.
///
/// Each error is prefixed `NE-` (Noble Error) followed by a numeric code.
/// The code appears in user-facing messages for debugging:
///   "Could not reach the node [NE-103]"
///
/// Ranges:
///   1xx — Connection & Network
///   2xx — Wallet & Cryptography
///   3xx — Keychain / Credential Storage
///   4xx — Bridge / IPC
///   5xx — Services (Faucet, WebSocket)
///   6xx — Documents & Transactions
public enum NE {

    // MARK: - 1xx Connection & Network

    /// URL format is invalid or unparseable.
    public static let invalidURL            = "NE-101"
    /// TLS handshake failed (self-signed cert rejected by OS or delegate).
    public static let tlsFailed             = "NE-102"
    /// Node unreachable (network timeout, DNS failure, refused).
    public static let nodeUnreachable       = "NE-103"
    /// HTTP response status was not 200.
    public static let httpError             = "NE-104"
    /// HTTP response body is not valid JSON-RPC.
    public static let invalidResponse       = "NE-105"
    /// JSON-RPC response has no `result` field.
    public static let emptyResult           = "NE-106"
    /// Server cert fingerprint does not match pinned value.
    public static let tlsFingerprint        = "NE-107"
    /// Request timed out.
    public static let timeout               = "NE-108"

    // MARK: - 2xx Wallet & Cryptography

    /// Private key data is malformed or invalid curve point.
    public static let invalidPrivateKey     = "NE-201"
    /// Public key derivation or parsing failed.
    public static let invalidPublicKey      = "NE-202"
    /// Mnemonic phrase invalid (bad checksum, wrong language).
    public static let invalidMnemonic       = "NE-203"
    /// ECDSA signing operation failed.
    public static let signingFailed         = "NE-204"
    /// CBOR encoding of transaction payload failed.
    public static let cborEncodingFailed    = "NE-205"
    /// Checksum is not a valid 64-character hex string.
    public static let invalidChecksum       = "NE-206"
    /// Address scheme byte not recognized.
    public static let unsupportedScheme     = "NE-207"
    /// Secure random entropy generation failed.
    public static let entropyFailed         = "NE-208"
    /// BIP-32 HD key derivation failed.
    public static let hdDerivationFailed    = "NE-209"
    /// Mnemonic word count is not 12, 15, 18, 21, or 24.
    public static let mnemonicWordCount     = "NE-210"
    /// Wallet creation failed (compound: keygen + store).
    public static let walletCreationFailed  = "NE-211"

    // MARK: - 3xx Keychain / Credential Storage

    /// Requested key label not found in keystore.
    public static let keyNotFound           = "NE-301"
    /// Keychain data is corrupted or wrong format.
    public static let invalidKeyData        = "NE-302"
    /// Keychain write (SecItemAdd) failed.
    public static let keychainStoreFailed   = "NE-303"
    /// Keychain read (SecItemCopyMatching) failed.
    public static let keychainLoadFailed    = "NE-304"
    /// Keychain delete (SecItemDelete) failed.
    public static let keychainDeleteFailed  = "NE-305"
    /// No private key available in keystore.
    public static let noPrivateKey          = "NE-306"

    // MARK: - 4xx Bridge / IPC

    /// Bridge handler name not recognized.
    public static let unknownHandler        = "NE-401"
    /// Action not supported by the bridge handler.
    public static let unknownAction         = "NE-402"
    /// Required parameter missing from bridge call.
    public static let missingParam          = "NE-403"
    /// Operation requires an active node connection.
    public static let notConnected          = "NE-404"
    /// Bridge call exceeded timeout.
    public static let bridgeTimeout         = "NE-405"
    /// Bridge response could not be parsed.
    public static let bridgeParseError      = "NE-406"

    // MARK: - 5xx Services

    /// Faucet service is not available.
    public static let faucetUnavailable     = "NE-501"
    /// Faucet returned an error.
    public static let faucetError           = "NE-502"
    /// WebSocket is not connected.
    public static let wsNotConnected        = "NE-503"
    /// WebSocket topic subscription failed.
    public static let wsSubscriptionFailed  = "NE-504"
    /// WebSocket connection closed unexpectedly.
    public static let wsClosed              = "NE-505"

    // MARK: - 6xx Documents & Transactions

    /// Document verification lookup failed.
    public static let verificationFailed    = "NE-601"
    /// File hash computation failed.
    public static let hashFailed            = "NE-602"
    /// Transaction was rejected by the node.
    public static let transactionRejected   = "NE-603"
    /// Transaction submission failed (network or encoding).
    public static let transactionFailed     = "NE-604"

    /// Format a user-facing error message with the error code appended.
    ///
    ///     NE.message("Could not reach the node", code: NE.nodeUnreachable)
    ///     // → "Could not reach the node [NE-103]"
    public static func message(_ text: String, code: String) -> String {
        "\(text) [\(code)]"
    }
}
