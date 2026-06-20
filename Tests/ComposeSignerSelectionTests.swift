import Foundation
import Testing

@Suite("GPGKeyInfo email extraction")
struct GPGKeyInfoEmailsTests {
    private func key(uids: [String]) -> GPGKeyInfo {
        GPGKeyInfo(
            fingerprint: String(repeating: "A", count: 40),
            userIDs: uids,
            capabilities: "scESC",
            hasSecretKey: true,
        )
    }

    @Test
    func `extracts email from a typical UID`() {
        #expect(key(uids: ["Alice Example <alice@example.com>"]).emails == ["alice@example.com"])
    }

    @Test
    func `lowercases extracted addresses`() {
        #expect(key(uids: ["Alice <Alice@Example.COM>"]).emails == ["alice@example.com"])
    }

    @Test
    func `ignores UIDs that have no angle-bracketed address`() {
        #expect(key(uids: ["just a name", "(comment only)"]).emails.isEmpty)
    }

    @Test
    func `extracts addresses from multiple UIDs`() {
        let result = key(uids: [
            "Alice <a@b.co>",
            "Alice (work) <alice@work.example>",
        ]).emails
        #expect(result == ["a@b.co", "alice@work.example"])
    }
}
