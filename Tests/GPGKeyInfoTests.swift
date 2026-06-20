import Foundation
import Testing

struct GPGKeyInfoTests {
    @Test
    func `displayName uses first UID`() {
        let key = GPGKeyInfo(fingerprint: "AABBCCDD", userIDs: ["Alice <alice@example.com>", "Bob"], capabilities: "sc")
        #expect(key.displayName == "Alice <alice@example.com>")
    }

    @Test
    func `displayName falls back to fingerprint when no UIDs`() {
        let key = GPGKeyInfo(fingerprint: "AABBCCDD", userIDs: [], capabilities: "sc")
        #expect(key.displayName == "AABBCCDD")
    }

    @Test
    func `shortName strips email from UID`() {
        let key = GPGKeyInfo(
            fingerprint: "AABBCCDD",
            userIDs: ["Alice Example <alice@example.com>"],
            capabilities: "sc",
        )
        #expect(key.shortName == "Alice Example")
    }

    @Test
    func `shortName returns UID as-is when no email bracket`() {
        let key = GPGKeyInfo(fingerprint: "AABBCCDD", userIDs: ["JustAName"], capabilities: "sc")
        #expect(key.shortName == "JustAName")
    }

    @Test
    func `shortName falls back to fingerprint prefix when no UIDs`() {
        let key = GPGKeyInfo(fingerprint: "AABBCCDDEE112233", userIDs: [], capabilities: "sc")
        #expect(key.shortName == "AABBCCDD")
    }

    @Test
    func `shortFingerprint formats last 16 hex chars with spaces`() {
        let key = GPGKeyInfo(fingerprint: "1234567890ABCDEF1234567890ABCDEF12345678", userIDs: [], capabilities: "sc")
        #expect(key.shortFingerprint == "90AB CDEF 1234 5678")
    }

    @Test
    func `shortFingerprint returns raw when less than 16 chars`() {
        let key = GPGKeyInfo(fingerprint: "ABCD", userIDs: [], capabilities: "sc")
        #expect(key.shortFingerprint == "ABCD")
    }

    @Test
    func `Codable roundtrip preserves all fields`() throws {
        let expiry = Date(timeIntervalSince1970: 1_700_000_000)
        let original = GPGKeyInfo(
            fingerprint: "AABB", userIDs: ["Test <test@test.com>"],
            capabilities: "scESC", hasSecretKey: true, expiryDate: expiry,
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(GPGKeyInfo.self, from: data)
        #expect(decoded.fingerprint == original.fingerprint)
        #expect(decoded.userIDs == original.userIDs)
        #expect(decoded.capabilities == original.capabilities)
        #expect(decoded.hasSecretKey == true)
        #expect(decoded.expiryDate == expiry)
    }

    @Test
    func `Codable roundtrip with subkeys preserves all fields`() throws {
        let sub = GPGSubkey(
            fingerprint: String(repeating: "B", count: 40),
            capabilities: "e",
            expiryDate: Date(timeIntervalSince1970: 1_800_000_000),
            algorithm: "RSA 3072",
            isRevoked: false,
        )
        let original = GPGKeyInfo(
            fingerprint: "AA",
            userIDs: ["Test <test@test.com>"],
            capabilities: "scESC",
            hasSecretKey: true,
            expiryDate: Date(timeIntervalSince1970: 1_700_000_000),
            subkeys: [sub],
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(GPGKeyInfo.self, from: data)
        #expect(decoded.fingerprint == original.fingerprint)
        #expect(decoded.userIDs == original.userIDs)
        #expect(decoded.capabilities == original.capabilities)
        #expect(decoded.hasSecretKey == true)
        #expect(decoded.expiryDate == original.expiryDate)
        #expect(decoded.subkeys == original.subkeys)
    }

    @Test
    func `id matches fingerprint`() {
        let key = GPGKeyInfo(fingerprint: "FP123", userIDs: [], capabilities: "sc")
        #expect(key.id == "FP123")
    }
}
