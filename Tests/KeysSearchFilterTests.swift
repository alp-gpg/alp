import Foundation
import Testing

@Suite("Keys table search filter")
struct KeysSearchFilterTests {
    private func key(uids: [String], fingerprint: String) -> GPGKeyInfo {
        GPGKeyInfo(
            fingerprint: fingerprint,
            userIDs: uids,
            capabilities: "scESC",
            hasSecretKey: false,
        )
    }

    private let alice = GPGKeyInfo(
        fingerprint: "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        userIDs: ["Alice Example <alice@example.com>"],
        capabilities: "scESC",
    )
    private let bob = GPGKeyInfo(
        fingerprint: "0011223344556677889900AABBCCDDEEFF001122",
        userIDs: ["Bob <bob@work.example>"],
        capabilities: "scESC",
    )

    @Test
    func `empty query returns every key unchanged`() {
        let result = KeySettingsView.matching(query: "", in: [alice, bob])
        #expect(result.count == 2)
    }

    @Test
    func `whitespace-only query returns every key unchanged`() {
        let result = KeySettingsView.matching(query: "   ", in: [alice, bob])
        #expect(result.count == 2)
    }

    @Test
    func `matches against display name case-insensitively`() {
        let result = KeySettingsView.matching(query: "ALICE", in: [alice, bob])
        #expect(result == [alice])
    }

    @Test
    func `matches against UID email`() {
        let result = KeySettingsView.matching(query: "work.example", in: [alice, bob])
        #expect(result == [bob])
    }

    @Test
    func `matches against fingerprint substring`() {
        let result = KeySettingsView.matching(query: "abcdef", in: [alice, bob])
        #expect(result == [alice])
    }

    @Test
    func `non-matching query returns empty`() {
        let result = KeySettingsView.matching(query: "nope", in: [alice, bob])
        #expect(result.isEmpty)
    }

    @Test
    func `matches against subkey fingerprint`() {
        let withSubkey = GPGKeyInfo(
            fingerprint: "1111222233334444555566667777888899990000",
            userIDs: ["Carol <c@example.org>"],
            capabilities: "scESC",
            subkeys: [
                GPGSubkey(
                    fingerprint: "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555",
                    capabilities: "e",
                    expiryDate: nil,
                    algorithm: "Cv25519",
                    isRevoked: false,
                ),
            ],
        )
        let result = KeySettingsView.matching(query: "aaaa1111", in: [alice, bob, withSubkey])
        #expect(result == [withSubkey])
    }
}
