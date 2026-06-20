import Foundation
import Testing

@Suite("WKD email parsing")
struct WKDEmailParseTests {
    @Test
    func `parses simple address`() {
        let parsed = WKDClient.parseEmail("alice@example.com")
        #expect(parsed?.0 == "alice")
        #expect(parsed?.1 == "example.com")
    }

    @Test
    func `lowercases the domain`() {
        let parsed = WKDClient.parseEmail("Alice@EXAMPLE.COM")
        #expect(parsed?.1 == "example.com")
        // localpart is preserved; only the domain is canonicalised here.
        #expect(parsed?.0 == "Alice")
    }

    @Test
    func `rejects whitespace and angle brackets`() {
        #expect(WKDClient.parseEmail("alice <a@b.co>") == nil)
        #expect(WKDClient.parseEmail("alice @b.co") == nil)
        #expect(WKDClient.parseEmail("alice@b .co") == nil)
    }

    @Test
    func `rejects missing parts`() {
        #expect(WKDClient.parseEmail("@b.co") == nil)
        #expect(WKDClient.parseEmail("alice@") == nil)
        #expect(WKDClient.parseEmail("alice") == nil)
        #expect(WKDClient.parseEmail("alice@b") == nil) // no TLD dot
    }
}

@Suite("WKD zbase32 encoding")
struct WKDZBase32Tests {
    @Test
    func `encodes empty input to empty string`() {
        #expect(WKDClient.zbase32(Data()) == "")
    }

    @Test
    func `encodes the WKD test vector for 'Joe.Doe'`() {
        // From draft-koch-openpgp-webkey-service §3.1: lowercase localpart
        // "joe.doe" SHA1 zbase32-encoded is "iy9q119eutrkn8s1mk4r39qejnbu3n5q".
        let lowered = Data("joe.doe".utf8)
        let hash = WKDClient.sha1(lowered)
        #expect(WKDClient.zbase32(hash) == "iy9q119eutrkn8s1mk4r39qejnbu3n5q")
    }

    @Test
    func `encodes a single zero byte`() {
        // 0x00 = bits 00000_000 → first 5-bit group is 0 → 'y',
        // remainder 3 bits left-aligned → 0 → 'y'.
        #expect(WKDClient.zbase32(Data([0x00])) == "yy")
    }

    @Test
    func `encodes well-known SHA1 length to 32 chars`() {
        let hash = WKDClient.sha1(Data("anything".utf8))
        #expect(WKDClient.zbase32(hash).count == 32)
    }
}
