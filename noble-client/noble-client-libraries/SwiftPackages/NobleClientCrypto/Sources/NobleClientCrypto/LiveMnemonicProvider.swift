// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import CryptoKit
import Foundation
import NobleClientCore
import P256K

/// Live implementation of ``MnemonicProviding`` using BIP-39 and BIP-32.
///
/// - BIP-39: Mnemonic generation, validation, and seed derivation (PBKDF2-HMAC-SHA512)
/// - BIP-32: HD key derivation at path m/44'/9999'/0'/0/0
/// - Address: secp256k1 compressed pubkey → NOBLE wire format (0x02 prefix)
public struct LiveMnemonicProvider: MnemonicProviding {
    public init() {}

    // MARK: - MnemonicProviding

    public func generateMnemonic(wordCount: Int) throws -> [String] {
        let entropyBits: Int
        switch wordCount {
        case 12: entropyBits = 128
        case 15: entropyBits = 160
        case 18: entropyBits = 192
        case 21: entropyBits = 224
        case 24: entropyBits = 256
        default: throw CryptoError.invalidMnemonic
        }

        let entropyBytes = entropyBits / 8
        var entropy = [UInt8](repeating: 0, count: entropyBytes)
        let status = SecRandomCopyBytes(kSecRandomDefault, entropyBytes, &entropy)
        guard status == errSecSuccess else {
            throw CryptoError.signingFailed("Failed to generate random entropy")
        }

        return mnemonicFromEntropy(entropy)
    }

    public func validateMnemonic(_ words: [String]) -> Bool {
        guard [12, 15, 18, 21, 24].contains(words.count) else { return false }

        let wordlist = BIP39Wordlist.english

        // Look up each word's index
        var indices = [Int]()
        for word in words {
            guard let index = wordlist.firstIndex(of: word.lowercased()) else {
                return false
            }
            indices.append(index)
        }

        // Convert indices to bits
        let totalBits = words.count * 11
        let entropyBits = totalBits - (totalBits / 33) // checksum bits = entropy_bits / 32
        let checksumBits = totalBits - entropyBits

        var bits = [Bool]()
        for index in indices {
            for bit in stride(from: 10, through: 0, by: -1) {
                bits.append((index >> bit) & 1 == 1)
            }
        }

        // Extract entropy bytes
        let entropyBytes = entropyBits / 8
        var entropy = [UInt8](repeating: 0, count: entropyBytes)
        for i in 0..<entropyBits {
            if bits[i] {
                entropy[i / 8] |= (1 << (7 - (i % 8)))
            }
        }

        // Compute expected checksum
        let hash = SHA256.hash(data: entropy)
        let hashBytes = [UInt8](hash)
        var expectedChecksumBits = [Bool]()
        for i in 0..<checksumBits {
            expectedChecksumBits.append((hashBytes[i / 8] >> (7 - (i % 8))) & 1 == 1)
        }

        // Compare checksum bits
        let actualChecksumBits = Array(bits[entropyBits..<totalBits])
        return actualChecksumBits == expectedChecksumBits
    }

    public func derivePrivateKey(mnemonic: [String]) throws -> Data {
        guard validateMnemonic(mnemonic) else {
            throw CryptoError.invalidMnemonic
        }

        // BIP-39: mnemonic → seed via PBKDF2-HMAC-SHA512
        let passphrase = mnemonic.joined(separator: " ")
        let salt = "mnemonic" // No additional passphrase
        let seed = pbkdf2SHA512(
            password: [UInt8](passphrase.utf8),
            salt: [UInt8](salt.utf8),
            iterations: 2048,
            keyLength: 64
        )

        // BIP-32: seed → master key → derive at m/44'/9999'/0'/0/0
        let masterKey = try deriveHDMasterKey(seed: seed)
        let childKey = try deriveHDPath(
            masterKey: masterKey,
            path: [
                0x8000_002C, // 44' (hardened)
                0x8000_270F, // 9999' (hardened)
                0x8000_0000, // 0' (hardened)
                0,           // 0 (normal)
                0,           // 0 (normal)
            ]
        )

        return Data(childKey.key)
    }

    public func derivePublicKey(privateKey: Data) throws -> Data {
        try Secp256k1Helper.compressedPublicKey(from: privateKey)
    }

    public func deriveAddress(privateKey: Data) throws -> NobleAddress {
        let pubKey = try derivePublicKey(privateKey: privateKey)
        // NOBLE wire format: 0x02 (secp256k1 scheme) + 33-byte compressed key = 34 bytes
        var wireBytes = [UInt8]()
        wireBytes.append(NobleProtocol.schemeSecp256k1) // 0x02
        wireBytes.append(contentsOf: pubKey)
        let wireHex = wireBytes.map { String(format: "%02x", $0) }.joined()
        guard let address = NobleAddress(wireHex: wireHex) else {
            throw CryptoError.invalidPublicKey
        }
        return address
    }

    // MARK: - BIP-39 Internals

    /// Convert entropy bytes to mnemonic words.
    private func mnemonicFromEntropy(_ entropy: [UInt8]) -> [String] {
        let hash = SHA256.hash(data: entropy)
        let hashBytes = [UInt8](hash)

        // Append checksum bits to entropy
        let entropyBits = entropy.count * 8
        let checksumBits = entropyBits / 32
        let totalBits = entropyBits + checksumBits

        var bits = [Bool]()
        for byte in entropy {
            for bit in stride(from: 7, through: 0, by: -1) {
                bits.append((byte >> bit) & 1 == 1)
            }
        }
        for i in 0..<checksumBits {
            bits.append((hashBytes[i / 8] >> (7 - (i % 8))) & 1 == 1)
        }

        // Split into 11-bit groups → word indices
        let wordCount = totalBits / 11
        let wordlist = BIP39Wordlist.english
        var words = [String]()

        for w in 0..<wordCount {
            var index = 0
            for bit in 0..<11 {
                if bits[w * 11 + bit] {
                    index |= (1 << (10 - bit))
                }
            }
            words.append(wordlist[index])
        }

        return words
    }

    // MARK: - PBKDF2-HMAC-SHA512

    /// PBKDF2 with HMAC-SHA512, used for BIP-39 seed derivation.
    private func pbkdf2SHA512(
        password: [UInt8],
        salt: [UInt8],
        iterations: Int,
        keyLength: Int
    ) -> [UInt8] {
        let hmacLength = 64 // SHA-512 output
        let numBlocks = (keyLength + hmacLength - 1) / hmacLength
        var derivedKey = [UInt8]()

        let key = SymmetricKey(data: password)

        for blockIndex in 1...numBlocks {
            // U1 = HMAC(password, salt || INT32_BE(blockIndex))
            var saltBlock = salt
            saltBlock.append(UInt8((blockIndex >> 24) & 0xFF))
            saltBlock.append(UInt8((blockIndex >> 16) & 0xFF))
            saltBlock.append(UInt8((blockIndex >> 8) & 0xFF))
            saltBlock.append(UInt8(blockIndex & 0xFF))

            var u = [UInt8](HMAC<SHA512>.authenticationCode(for: saltBlock, using: key))
            var result = u

            for _ in 1..<iterations {
                u = [UInt8](HMAC<SHA512>.authenticationCode(for: u, using: key))
                for j in 0..<hmacLength {
                    result[j] ^= u[j]
                }
            }

            derivedKey.append(contentsOf: result)
        }

        return Array(derivedKey.prefix(keyLength))
    }

    // MARK: - BIP-32 HD Key Derivation

    /// Extended key: 32-byte private key + 32-byte chain code.
    private struct ExtendedKey {
        let key: [UInt8]       // 32 bytes
        let chainCode: [UInt8] // 32 bytes
    }

    /// Derive BIP-32 master key from seed.
    private func deriveHDMasterKey(seed: [UInt8]) throws -> ExtendedKey {
        let hmacKey = SymmetricKey(data: [UInt8]("Bitcoin seed".utf8))
        let hmac = HMAC<SHA512>.authenticationCode(for: seed, using: hmacKey)
        let bytes = [UInt8](hmac)

        let key = Array(bytes[0..<32])
        let chainCode = Array(bytes[32..<64])

        // Validate key is valid secp256k1 scalar
        guard isValidScalar(key) else {
            throw CryptoError.invalidPrivateKey
        }

        return ExtendedKey(key: key, chainCode: chainCode)
    }

    /// Derive child key at a BIP-32 path (array of indices, hardened if >= 0x80000000).
    private func deriveHDPath(masterKey: ExtendedKey, path: [UInt32]) throws -> ExtendedKey {
        var current = masterKey
        for index in path {
            current = try deriveHDChild(parent: current, index: index)
        }
        return current
    }

    /// Derive a single BIP-32 child key.
    private func deriveHDChild(parent: ExtendedKey, index: UInt32) throws -> ExtendedKey {
        let hmacKey = SymmetricKey(data: parent.chainCode)
        var data = [UInt8]()

        if index >= 0x8000_0000 {
            // Hardened: 0x00 || parent_key || index
            data.append(0x00)
            data.append(contentsOf: parent.key)
        } else {
            // Normal: compressed_pubkey || index
            let sk = try P256K.Signing.PrivateKey(dataRepresentation: Data(parent.key))
            data.append(contentsOf: sk.publicKey.dataRepresentation)
        }

        // Append index as big-endian UInt32
        data.append(UInt8((index >> 24) & 0xFF))
        data.append(UInt8((index >> 16) & 0xFF))
        data.append(UInt8((index >> 8) & 0xFF))
        data.append(UInt8(index & 0xFF))

        let hmac = HMAC<SHA512>.authenticationCode(for: data, using: hmacKey)
        let bytes = [UInt8](hmac)

        let il = Array(bytes[0..<32])
        let ir = Array(bytes[32..<64])

        // child_key = (parse256(IL) + parent_key) mod n
        let childKey = addModN(il, parent.key)

        guard isValidScalar(childKey) else {
            throw CryptoError.invalidPrivateKey
        }

        return ExtendedKey(key: childKey, chainCode: ir)
    }

    // MARK: - secp256k1 Scalar Arithmetic

    /// secp256k1 curve order n.
    private static let secp256k1Order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]

    /// Add two 256-bit big-endian scalars modulo secp256k1 order.
    private func addModN(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var result = [UInt8](repeating: 0, count: 32)
        var carry: UInt16 = 0

        for i in stride(from: 31, through: 0, by: -1) {
            let sum = UInt16(a[i]) + UInt16(b[i]) + carry
            result[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
        }

        // If carry or result >= n, subtract n
        if carry > 0 || compare256(result, Self.secp256k1Order) >= 0 {
            var borrow: Int16 = 0
            for i in stride(from: 31, through: 0, by: -1) {
                let diff = Int16(result[i]) - Int16(Self.secp256k1Order[i]) - borrow
                if diff < 0 {
                    result[i] = UInt8((diff + 256) & 0xFF)
                    borrow = 1
                } else {
                    result[i] = UInt8(diff)
                    borrow = 0
                }
            }
        }

        return result
    }

    /// Compare two 256-bit big-endian byte arrays.
    /// Returns negative if a < b, 0 if equal, positive if a > b.
    private func compare256(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for i in 0..<32 {
            if a[i] != b[i] {
                return Int(a[i]) - Int(b[i])
            }
        }
        return 0
    }

    /// Check if a 256-bit scalar is valid for secp256k1 (0 < scalar < n).
    private func isValidScalar(_ scalar: [UInt8]) -> Bool {
        // Must not be zero
        let isZero = scalar.allSatisfy { $0 == 0 }
        if isZero { return false }
        // Must be less than n
        return compare256(scalar, Self.secp256k1Order) < 0
    }
}
