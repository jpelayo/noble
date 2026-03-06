// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

// NobleClientCrypto — Transaction builder, signer, mnemonic, and address derivation.

import Foundation
import NobleClientCore
import P256K
import SwiftCBOR

/// Protocol for building and signing NOBLE transactions locally.
///
/// Implementations use secp256k1 signing + CBOR serialization.
/// The signed transaction is submitted as raw hex via JSON-RPC.
public protocol TransactionSigner: Sendable {
    /// Build and sign a transfer transaction.
    func signTransfer(
        from: NobleAddress,
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        nonce: UInt64,
        privateKey: Data
    ) throws -> Data

    /// Build and sign a document notarization transaction.
    func signNotarization(
        from: NobleAddress,
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        nonce: UInt64,
        privateKey: Data
    ) throws -> Data
}

/// Protocol for mnemonic wallet operations.
public protocol MnemonicProvider: Sendable {
    /// Generate a new 24-word BIP-39 mnemonic.
    func generateMnemonic() throws -> [String]

    /// Derive the primary secp256k1 private key from a mnemonic.
    func derivePrivateKey(mnemonic: [String]) throws -> Data

    /// Derive the NOBLE wire-hex public key from a private key.
    func derivePublicKey(privateKey: Data) throws -> NobleAddress
}

/// Placeholder stub that will be implemented in Sprint 4.
public struct StubTransactionSigner: TransactionSigner {
    public init() {}

    public func signTransfer(
        from: NobleAddress,
        to: NobleAddress,
        amount: NobleAmount,
        fee: NobleAmount,
        nonce: UInt64,
        privateKey: Data
    ) throws -> Data {
        fatalError("TransactionSigner not yet implemented — Sprint 4")
    }

    public func signNotarization(
        from: NobleAddress,
        checksum: Hash256,
        metadata: [MetadataItem],
        fee: NobleAmount,
        nonce: UInt64,
        privateKey: Data
    ) throws -> Data {
        fatalError("TransactionSigner not yet implemented — Sprint 4")
    }
}

/// Placeholder stub that will be implemented in Sprint 4.
public struct StubMnemonicProvider: MnemonicProvider {
    public init() {}

    public func generateMnemonic() throws -> [String] {
        fatalError("MnemonicProvider not yet implemented — Sprint 4")
    }

    public func derivePrivateKey(mnemonic: [String]) throws -> Data {
        fatalError("MnemonicProvider not yet implemented — Sprint 4")
    }

    public func derivePublicKey(privateKey: Data) throws -> NobleAddress {
        fatalError("MnemonicProvider not yet implemented — Sprint 4")
    }
}
