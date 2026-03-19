// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

// NobleClientCrypto — Transaction builder, signer, mnemonic, and address derivation.

import Foundation
import NobleClientCore

/// Protocol for building and signing NOBLE transactions locally.
///
/// Implementations use secp256k1 signing + CBOR serialization.
/// The signed transaction is submitted as raw hex via JSON-RPC.
public protocol TransactionSigning: Sendable {
    /// Build and sign a transfer transaction (UTXO model). Returns hex-encoded CBOR.
    func signTransfer(
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        feeRate: UInt64,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32
    ) throws -> String

    /// Build and sign a document notarization transaction (UTXO model). Returns hex-encoded CBOR.
    func signNotarization(
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        utxos: [UtxoOutpoint],
        changeAddress: [UInt8],
        privateKey: Data,
        chainId: UInt32
    ) throws -> String
}

/// Protocol for mnemonic wallet operations.
public protocol MnemonicProviding: Sendable {
    /// Generate a new BIP-39 mnemonic (24 words).
    func generateMnemonic(wordCount: Int) throws -> [String]

    /// Validate a BIP-39 mnemonic phrase.
    func validateMnemonic(_ words: [String]) -> Bool

    /// Derive the primary secp256k1 private key from a mnemonic.
    /// Uses derivation path m/44'/9999'/0'/0/0.
    func derivePrivateKey(mnemonic: [String]) throws -> Data

    /// Derive the compressed secp256k1 public key from a private key.
    func derivePublicKey(privateKey: Data) throws -> Data

    /// Derive the NOBLE wire-hex address from a private key.
    func deriveAddress(privateKey: Data) throws -> NobleAddress
}

/// Errors from the crypto package.
public enum CryptoError: Error, Sendable {
    case invalidPrivateKey
    case invalidPublicKey
    case invalidMnemonic
    case signingFailed(String)
    case cborEncodingFailed(String)
    case invalidChecksum
    case unsupportedScheme(UInt8)
}
