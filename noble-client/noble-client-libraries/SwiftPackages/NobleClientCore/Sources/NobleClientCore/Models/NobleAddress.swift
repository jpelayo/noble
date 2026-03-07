// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// A NOBLE blockchain address in wire-format hex (scheme prefix + public key bytes).
///
/// Scheme prefixes:
/// - `0x01` — Ed25519
/// - `0x02` — secp256k1
/// - `0x80` — Bitcoin Hash160
/// - `0x81` — Bitcoin Taproot
public struct NobleAddress: Codable, Equatable, Hashable, Sendable, Identifiable {

    /// The full wire-hex string (e.g. 66 chars for Ed25519, 68 for secp256k1).
    public let wireHex: String

    public var id: String { wireHex }

    /// The scheme identifier byte (first byte of wire data).
    public var schemeId: UInt8 {
        guard wireHex.count >= 2,
              let byte = UInt8(String(wireHex.prefix(2)), radix: 16) else { return 0 }
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

    /// Truncated display: first 8 + "..." + last 8 characters.
    public var truncated: String {
        guard wireHex.count >= 16 else { return wireHex }
        let start = wireHex.prefix(8)
        let end = wireHex.suffix(8)
        return "\(start)...\(end)"
    }

    /// Failable initializer — validates hex format and minimum length.
    public init?(wireHex: String) {
        let lowered = wireHex.lowercased()
        guard lowered.count >= 4,
              lowered.count.isMultiple(of: 2),
              lowered.allSatisfy({ $0.isHexDigit }) else {
            return nil
        }
        self.wireHex = lowered
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let value = NobleAddress(wireHex: raw) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid NobleAddress wire hex: \(raw)"
            )
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(wireHex)
    }
}
