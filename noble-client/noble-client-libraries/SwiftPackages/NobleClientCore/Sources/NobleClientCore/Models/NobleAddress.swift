// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// A NOBLE blockchain address — either bech32 `nbl1…` display format or wire-format hex.
///
/// Display format (from RPC):
/// - `nbl1q…` — Ed25519 (bech32, witness v0)
/// - `nbl1p…` — secp256k1 (bech32m, witness v1)
///
/// Wire-hex format (legacy):
/// - `0x01` + 32 bytes — Ed25519
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
        if lower.hasPrefix("nbl1q") { return 0x01 }      // Ed25519
        if lower.hasPrefix("nbl1p") { return 0x02 }      // secp256k1
        // Legacy hex path
        guard raw.count >= 2,
              let byte = UInt8(String(raw.prefix(2)), radix: 16) else { return 0 }
        return byte
    }

    /// Human-readable scheme name.
    public var schemeName: String {
        switch schemeId {
        case 0x01: "Ed25519"
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

    /// Wire-format hex string (scheme_id + key bytes).
    ///
    /// If the address is bech32 `nbl1…`, decodes back to wire hex.
    /// If already hex, returns as-is.
    public var wireHex: String {
        guard isNobleBech32 else { return raw }
        // Decode bech32 segwit → scheme_id + key bytes
        guard let bytes = Self.decodeBech32Program(raw) else { return raw }
        let lower = raw.lowercased()
        let schemePrefix: UInt8 = lower.hasPrefix("nbl1q") ? 0x01 : 0x02
        return ([schemePrefix] + bytes).map { String(format: "%02x", $0) }.joined()
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
