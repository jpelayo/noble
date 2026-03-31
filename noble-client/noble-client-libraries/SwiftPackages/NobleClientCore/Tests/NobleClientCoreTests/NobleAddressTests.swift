import Testing
@testable import NobleClientCore

@Suite("NobleAddress Bech32 Tests")
struct NobleAddressTests {

    @Test func secp256k1HexToNbl1p() {
        let hex = "02" + String(repeating: "cd", count: 33)
        let addr = NobleAddress(wireHex: hex)!
        let bech32 = addr.nobleBech32
        #expect(bech32.hasPrefix("nbl1p"))
    }

    @Test func secp256k1Roundtrip() {
        let hex = "02" + String(repeating: "cd", count: 33)
        let addr = NobleAddress(wireHex: hex)!
        let bech32 = addr.nobleBech32
        let decoded = NobleAddress(wireHex: bech32)!
        #expect(decoded.wireHex == hex)
    }

    @Test func bitcoinAddressPassthrough() {
        let btc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        let addr = NobleAddress(wireHex: btc)!
        // Bitcoin addresses should not be encoded to nbl1
        #expect(addr.nobleBech32 == btc)
    }

    @Test func nbl1AlreadyBech32Passthrough() {
        // If already nbl1, nobleBech32 should return as-is
        let hex = "02" + String(repeating: "ff", count: 33)
        let addr = NobleAddress(wireHex: hex)!
        let bech32 = addr.nobleBech32
        let addr2 = NobleAddress(wireHex: bech32)!
        #expect(addr2.nobleBech32 == bech32)
    }

    @Test func schemeIdFromBech32() {
        let sec = NobleAddress(wireHex: "02" + String(repeating: "00", count: 33))!
        let bech32 = sec.nobleBech32
        let parsed = NobleAddress(wireHex: bech32)!
        #expect(parsed.schemeId == 0x02)
        #expect(parsed.schemeName == "secp256k1")
    }

    @Test func hash160AddressNotEncoded() {
        // Hash160 (0x80 prefix) should not get nbl1 encoding
        let hex = "80" + String(repeating: "ab", count: 20)
        let addr = NobleAddress(wireHex: hex)!
        #expect(addr.nobleBech32 == hex)
    }

    // ── decodeBech32Program tests (via wireHex / init) ──

    @Test func decodeBech32_secp256k1_33bytes() {
        // nbl1p… decodes to 33 bytes (compressed secp256k1 key)
        let keyHex = "02" + String(repeating: "ab", count: 33) // scheme + 33 byte key
        let addr = NobleAddress(wireHex: keyHex)!
        let bech32 = addr.nobleBech32
        #expect(bech32.hasPrefix("nbl1p"))
        // Decode back: wireHex should reconstruct original wire format
        let decoded = NobleAddress(wireHex: bech32)!
        #expect(decoded.wireHex == keyHex)
    }

    @Test func decodeBech32_roundtrip_with_different_keys() {
        // Multiple distinct keys all roundtrip correctly
        for fill: UInt8 in [0x00, 0x11, 0x77, 0xAA, 0xFF] {
            let keyHex = "02" + String(repeating: String(format: "%02x", fill), count: 33)
            let addr = NobleAddress(wireHex: keyHex)!
            let bech32 = addr.nobleBech32
            let decoded = NobleAddress(wireHex: bech32)!
            #expect(decoded.wireHex == keyHex, "roundtrip failed for fill=\(fill)")
        }
    }

    @Test func decodeBech32_tampered_produces_different_key() {
        // Tamper a valid nbl1p… address — the decoded key should differ from the original
        let keyHex = "02" + String(repeating: "cd", count: 33)
        let addr = NobleAddress(wireHex: keyHex)!
        var bech32 = addr.nobleBech32
        // Tamper a data character (not just checksum) to produce a different key
        let chars = Array(bech32)
        // Change a character in the middle of the data portion
        let midIdx = chars.count / 2
        let oldChar = chars[midIdx]
        let newChar: Character = (oldChar == "q") ? "p" : "q"
        var tampered = chars
        tampered[midIdx] = newChar
        let tamperedStr = String(tampered)
        let decoded = NobleAddress(wireHex: tamperedStr)
        if let d = decoded {
            // Tampered data should produce a DIFFERENT wireHex than the original
            #expect(d.wireHex != keyHex, "tampered address must not decode to original key")
        }
    }

    @Test func decodeBech32_wrong_hrp_rejected() {
        // "bc1p…" should NOT decode as a Noble address (different HRP)
        let btcAddr = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"
        let addr = NobleAddress(wireHex: btcAddr)
        if let a = addr {
            // schemeId should not be 0x02 from bech32 parsing — it's a Bitcoin address
            #expect(!a.isNobleBech32, "bc1 address must not be treated as nbl1")
        }
    }

    @Test func decodeBech32_short_address_rejected() {
        // Truncated nbl1 address should fail init or produce fallback
        let short = "nbl1p"
        let addr = NobleAddress(wireHex: short)
        #expect(addr == nil, "address too short should fail init")
    }

    @Test func decodeBech32_empty_rejected() {
        let addr = NobleAddress(wireHex: "")
        #expect(addr == nil, "empty string must fail init")
    }

    // ── decodeBase58Check tests (via wireHex) ──

    @Test func decodeBase58_valid_p2pkh() {
        // Bitcoin P2PKH address "1…" → wireHex = 0x80 + 20-byte hash160
        let btcAddr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" // genesis coinbase addr
        let addr = NobleAddress(wireHex: btcAddr)!
        let wire = addr.wireHex
        #expect(wire.hasPrefix("80"), "P2PKH should decode to 0x80 prefix")
        #expect(wire.count == 42, "0x80 + 20 bytes = 42 hex chars")
    }

    @Test func decodeBase58_invalid_checksum() {
        // Tamper a valid Base58 address — last char changed
        let btcAddr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb" // 'a' → 'b' at end
        let addr = NobleAddress(wireHex: btcAddr)!
        // Bad checksum → decodeBase58Check returns nil → wireHex returns raw string
        #expect(addr.wireHex == btcAddr, "invalid checksum should not decode")
    }

    @Test func decodeBase58_too_short() {
        let addr = NobleAddress(wireHex: "1Ab")
        // Short hex-like string starting with "1" may not init properly
        // The init requires at least 4 hex chars for wire format, and "1Ab" is base58
        if let a = addr {
            #expect(a.wireHex == "1Ab", "too-short base58 should not decode to hash")
        }
    }

    // ── encodeBech32 tests (via nobleBech32) ──

    @Test func encodeBech32_roundtrip() {
        // Encode wire hex → bech32 → decode → same wire hex
        let keyHex = "02" + String(repeating: "42", count: 33)
        let addr = NobleAddress(wireHex: keyHex)!
        let bech32 = addr.nobleBech32
        #expect(bech32.hasPrefix("nbl1p"), "secp256k1 should encode as nbl1p (bech32m v1)")
        let decoded = NobleAddress(wireHex: bech32)!
        #expect(decoded.wireHex == keyHex)
    }

    // ── wireHex tests ──

    @Test func wireHex_nbl1p_produces_34bytes() {
        // nbl1p… decoded wireHex should be: 0x02 (1 byte) + 33-byte SEC1 key = 34 bytes = 68 hex chars
        let keyHex = "02" + String(repeating: "ef", count: 33)
        let addr = NobleAddress(wireHex: keyHex)!
        let bech32 = addr.nobleBech32
        let decoded = NobleAddress(wireHex: bech32)!
        #expect(decoded.wireHex.count == 68, "wireHex should be 68 hex chars (34 bytes)")
    }

    @Test func wireHex_different_addresses_produce_different_hex() {
        let key1 = "02" + String(repeating: "11", count: 33)
        let key2 = "02" + String(repeating: "22", count: 33)
        let addr1 = NobleAddress(wireHex: key1)!
        let addr2 = NobleAddress(wireHex: key2)!
        #expect(addr1.wireHex != addr2.wireHex, "different keys must produce different wireHex")
        #expect(addr1.nobleBech32 != addr2.nobleBech32, "different keys must produce different bech32")
    }

    @Test func wireHex_hex_passthrough() {
        // Already hex wire format should pass through unchanged
        let hex = "02" + String(repeating: "aa", count: 33)
        let addr = NobleAddress(wireHex: hex)!
        #expect(addr.wireHex == hex)
    }

    @Test func wireHex_taproot_address() {
        // Bitcoin Taproot bc1p… → 0x81 + 32-byte x-only pubkey
        let hex = "81" + String(repeating: "bb", count: 32)
        let addr = NobleAddress(wireHex: hex)!
        #expect(addr.schemeId == 0x81)
        #expect(addr.schemeName == "Taproot")
    }

    @Test func truncated_display() {
        let hex = "02" + String(repeating: "cd", count: 33)
        let addr = NobleAddress(wireHex: hex)!
        let bech32 = addr.nobleBech32
        let truncated = NobleAddress(wireHex: bech32)!.truncated
        #expect(truncated.contains("…"), "long address should be truncated with ellipsis")
        #expect(truncated.count < bech32.count, "truncated must be shorter")
    }
}
