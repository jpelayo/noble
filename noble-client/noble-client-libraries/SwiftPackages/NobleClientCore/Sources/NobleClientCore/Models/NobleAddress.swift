// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

import CryptoKit

/// A NOBLE blockchain address — either bech32 `nbl1…` display format or wire-format hex.
///
/// Display format (from RPC):
/// - `nbl1p…` — secp256k1 (bech32m, witness v1)
///
/// Wire-hex format (legacy):
/// - `0x02` + 33 bytes — secp256k1
/// - `0x80` + 20 bytes — Bitcoin Hash160
/// - `0x81` + 32 bytes — Bitcoin Taproot
public struct NobleAddress: Codable, Equatable, Hashable, Sendable, Identifiable {

    /// The raw address string — may be `nbl1…` bech32 or hex wire format.
    public let raw: String

    public var id: String { raw }

    /// Whether this is a Noble native bech32 address (`nbl1…`).
    public var isNobleBech32: Bool {
        raw.lowercased().hasPrefix("nbl1")
    }

    /// The scheme identifier byte (first byte of wire data), or derived from bech32 prefix.
    public var schemeId: UInt8 {
        let lower = raw.lowercased()
        if lower.hasPrefix("nbl1p") { return 0x02 }      // secp256k1
        // Legacy hex path
        guard raw.count >= 2,
              let byte = UInt8(String(raw.prefix(2)), radix: 16) else { return 0 }
        return byte
    }

    /// Human-readable scheme name.
    public var schemeName: String {
        switch schemeId {
        case 0x02: "secp256k1"
        case 0x80: "Hash160"
        case 0x81: "Taproot"
        default: "Unknown"
        }
    }

    /// Truncated display: first 10 + "…" + last 6 characters.
    public var truncated: String {
        guard raw.count > 18 else { return raw }
        let start = raw.prefix(10)
        let end = raw.suffix(6)
        return "\(start)…\(end)"
    }

    /// Noble bech32 display string (`nbl1q…` or `nbl1p…`).
    ///
    /// If already bech32, returns as-is.
    /// If hex wire format with secp256k1 (0x02) prefix, encodes to bech32m.
    /// For non-Noble addresses (Bitcoin, unknown), returns `raw` unchanged.
    public var nobleBech32: String {
        if isNobleBech32 { return raw }
        // Only encode Noble native schemes
        guard schemeId == 0x02 else { return raw }
        let wireBytes = Self.hexToBytes(raw)
        guard wireBytes.count >= 2 else { return raw }
        let keyBytes = Array(wireBytes.dropFirst()) // strip scheme_id
        let witnessVersion: UInt8 = 1
        let useBech32m = true
        guard let encoded = Self.encodeBech32(hrp: "nbl", witnessVersion: witnessVersion, program: keyBytes, bech32m: useBech32m) else {
            return raw
        }
        return encoded
    }

    /// Wire-format hex string (scheme_id + key bytes).
    ///
    /// If the address is bech32 `nbl1…`, decodes back to wire hex.
    /// If the address is Bitcoin bech32 `bc1q…`/`bc1p…`, decodes the witness program
    /// and returns `0x80` + Hash160 (20 bytes) or `0x81` + x-only pubkey (32 bytes).
    /// If the address is Bitcoin Base58 (`1…` or `3…`), decodes the 20-byte hash.
    /// If already hex, returns as-is.
    public var wireHex: String {
        let lower = raw.lowercased()

        // Noble bech32 → decode to 0x02 + key bytes
        if lower.hasPrefix("nbl1") {
            guard let bytes = Self.decodeBech32Program(raw) else { return raw }
            let schemePrefix: UInt8 = 0x02
            return ([schemePrefix] + bytes).map { String(format: "%02x", $0) }.joined()
        }

        // Bitcoin bech32 segwit → decode witness program
        if lower.hasPrefix("bc1q") {
            // P2WPKH: witness v0, 20-byte program → 0x80 + 20 bytes
            guard let program = Self.decodeBech32Program(raw), program.count == 20 else { return raw }
            return ([UInt8(0x80)] + program).map { String(format: "%02x", $0) }.joined()
        }
        if lower.hasPrefix("bc1p") {
            // P2TR: witness v1, 32-byte program → 0x81 + 32 bytes
            guard let program = Self.decodeBech32Program(raw), program.count == 32 else { return raw }
            return ([UInt8(0x81)] + program).map { String(format: "%02x", $0) }.joined()
        }

        // Bitcoin Base58 legacy (P2PKH "1…" or P2SH "3…") → decode 20-byte hash
        if raw.hasPrefix("1") || raw.hasPrefix("3") {
            if let hash = Self.decodeBase58Check(raw), hash.count == 20 {
                return ([UInt8(0x80)] + hash).map { String(format: "%02x", $0) }.joined()
            }
            return raw
        }

        // Already hex wire format
        return raw
    }

    /// Decode a Base58Check address to its 20-byte hash payload (strips version + checksum).
    private static func decodeBase58Check(_ addr: String) -> [UInt8]? {
        let alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        var num: [UInt8] = [0]

        for ch in addr {
            guard let digitIdx = alphabet.firstIndex(of: ch) else { return nil }
            let digit = UInt8(alphabet.distance(from: alphabet.startIndex, to: digitIdx))
            var carry = UInt16(digit)
            for i in 0..<num.count {
                carry += UInt16(num[i]) * 58
                num[i] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                num.append(UInt8(carry & 0xFF))
                carry >>= 8
            }
        }

        // Count leading '1's (leading zero bytes)
        let leadingZeros = addr.prefix(while: { $0 == "1" }).count

        // Reverse (big-endian)
        var result = [UInt8](repeating: 0, count: leadingZeros) + num.reversed()

        // Strip trailing zeros that were added by the bignum arithmetic
        while result.last == 0 && result.count > leadingZeros + 25 {
            result.removeLast()
        }

        // Expected: 1 byte version + 20 byte hash + 4 byte checksum = 25 bytes
        guard result.count == 25 else { return nil }

        // Verify checksum (double SHA-256 of first 21 bytes)
        let payload = Array(result[0..<21])
        let hash1 = SHA256Hasher.hash(payload)
        let hash2 = SHA256Hasher.hash(hash1)
        guard Array(result[21..<25]) == Array(hash2[0..<4]) else { return nil }

        // Return the 20-byte hash (strip version byte)
        return Array(result[1..<21])
    }

    /// Minimal SHA-256 helper for Base58Check verification.
    private enum SHA256Hasher {
        static func hash(_ data: [UInt8]) -> [UInt8] {
            let digest = CryptoKit.SHA256.hash(data: data)
            return Array(digest)
        }
    }

    /// Decode the witness program from a bech32/bech32m segwit address.
    private static func decodeBech32Program(_ addr: String) -> [UInt8]? {
        let lower = addr.lowercased()
        // Find the separator '1' (last occurrence)
        guard let sepIdx = lower.lastIndex(of: "1"), sepIdx > lower.startIndex else { return nil }
        let dataStr = lower[lower.index(after: sepIdx)...]
        guard dataStr.count >= 7 else { return nil } // witness version + data + 6 checksum

        let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
        var data5 = [UInt8]()
        for ch in dataStr {
            guard let idx = charset.firstIndex(of: ch) else { return nil }
            data5.append(UInt8(charset.distance(from: charset.startIndex, to: idx)))
        }

        // Strip witness version (first element) and checksum (last 6)
        guard data5.count > 7 else { return nil }
        let payload5 = Array(data5[1 ..< data5.count - 6])

        // Convert 5-bit groups to 8-bit bytes
        var acc: UInt32 = 0
        var bits: UInt32 = 0
        var result = [UInt8]()
        for val in payload5 {
            acc = (acc << 5) | UInt32(val)
            bits += 5
            if bits >= 8 {
                bits -= 8
                result.append(UInt8((acc >> bits) & 0xFF))
            }
        }
        return result
    }

    /// Encode a witness program to bech32/bech32m.
    private static func encodeBech32(hrp: String, witnessVersion: UInt8, program: [UInt8], bech32m: Bool) -> String? {
        let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        // Convert 8-bit bytes to 5-bit groups
        var data5 = [UInt8]()
        var acc: UInt32 = 0
        var bits: UInt32 = 0
        for byte in program {
            acc = (acc << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                data5.append(UInt8((acc >> bits) & 0x1F))
            }
        }
        if bits > 0 {
            data5.append(UInt8((acc << (5 - bits)) & 0x1F))
        }

        // Prepend witness version
        let values = [witnessVersion] + data5

        // Compute checksum
        let checksumConst: UInt32 = bech32m ? 0x2BC830A3 : 1
        let checksum = bech32Checksum(hrp: hrp, values: values, const: checksumConst)

        // Build result string
        var result = hrp + "1"
        for v in values + checksum {
            let idx = charset.index(charset.startIndex, offsetBy: Int(v))
            result.append(charset[idx])
        }
        return result
    }

    /// Compute bech32/bech32m checksum.
    private static func bech32Checksum(hrp: String, values: [UInt8], const: UInt32) -> [UInt8] {
        let polymod = bech32Polymod(hrpExpand(hrp) + values + [0, 0, 0, 0, 0, 0]) ^ const
        var result = [UInt8]()
        for i in 0..<6 {
            result.append(UInt8((polymod >> (5 * (5 - i))) & 0x1F))
        }
        return result
    }

    private static func hrpExpand(_ hrp: String) -> [UInt8] {
        var result = [UInt8]()
        for c in hrp.utf8 { result.append(c >> 5) }
        result.append(0)
        for c in hrp.utf8 { result.append(c & 31) }
        return result
    }

    private static func bech32Polymod(_ values: [UInt8]) -> UInt32 {
        let gen: [UInt32] = [0x3B6A_57B2, 0x2650_8E6D, 0x1EA1_19FA, 0x3D42_33DD, 0x2A14_62B3]
        var chk: UInt32 = 1
        for v in values {
            let top = chk >> 25
            chk = ((chk & 0x1FF_FFFF) << 5) ^ UInt32(v)
            for i in 0..<5 {
                if (top >> i) & 1 == 1 {
                    chk ^= gen[i]
                }
            }
        }
        return chk
    }

    /// Hex string to byte array.
    private static func hexToBytes(_ hex: String) -> [UInt8] {
        var bytes = [UInt8]()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            if let byte = UInt8(hex[idx..<next], radix: 16) {
                bytes.append(byte)
            }
            idx = next
        }
        return bytes
    }

    /// Failable initializer — accepts bech32 `nbl1…`, Bitcoin `bc1…`, or hex wire format.
    public init?(wireHex: String) {
        let trimmed = wireHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = trimmed.lowercased()

        // Noble bech32 address (nbl1q…, nbl1p…)
        if lower.hasPrefix("nbl1") {
            guard lower.count >= 10 else { return nil }
            self.raw = lower
            return
        }

        // Bitcoin address passthrough (bc1…, 1…, 3…, etc.)
        if lower.hasPrefix("bc1") || trimmed.hasPrefix("1") || trimmed.hasPrefix("3") {
            self.raw = trimmed
            return
        }

        // Legacy hex wire format
        guard lower.count >= 4,
              lower.count.isMultiple(of: 2),
              lower.allSatisfy({ $0.isHexDigit }) else {
            return nil
        }
        self.raw = lower
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        guard let value = NobleAddress(wireHex: rawValue) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid NobleAddress: \(rawValue)"
            )
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(raw)
    }
}
