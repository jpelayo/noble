// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

/// A 256-bit hash represented as a 64-character lowercase hex string.
public struct Hash256: Codable, Equatable, Hashable, Sendable, Identifiable {

    /// The 64-character lowercase hex string.
    public let hex: String

    public var id: String { hex }

    /// Failable initializer — rejects non-64-char or non-hex strings.
    public init?(hex: String) {
        let lowered = hex.lowercased()
        guard lowered.count == 64,
              lowered.allSatisfy({ $0.isHexDigit }) else {
            return nil
        }
        self.hex = lowered
    }

    /// Truncated display: first 8 + "..." + last 8 characters.
    public var truncated: String {
        guard hex.count >= 16 else { return hex }
        let start = hex.prefix(8)
        let end = hex.suffix(8)
        return "\(start)...\(end)"
    }

    // MARK: - Codable

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let value = Hash256(hex: raw) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid Hash256: expected 64 hex characters, got \(raw.count)"
            )
        }
        self = value
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(hex)
    }
}
