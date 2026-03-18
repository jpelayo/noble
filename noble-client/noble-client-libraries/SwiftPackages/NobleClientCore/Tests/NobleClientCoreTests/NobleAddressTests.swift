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
}
