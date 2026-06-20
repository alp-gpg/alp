import Foundation
import Testing

@Suite("GPG Helper")
struct GPGHelperTests {
    let helper: GPGHelper

    init() async {
        helper = await GPGHelper()
    }

    /// Returns the fingerprint of the first secret key, or skips the test.
    private func firstSecretKeyFingerprint() async throws -> String {
        let keys = try await helper._listSecretKeys()
        guard let key = keys.first else {
            Issue.record("No secret keys in keyring — skipping")
            throw GPGError.noSigningKey
        }
        return key.fingerprint
    }

    @Test
    func `GPG binary is found`() async throws {
        let keys = try await helper._listSecretKeys()
        _ = keys
    }

    @Test
    func `List secret keys returns non-empty array when keys exist`() async throws {
        let keys = try await helper._listSecretKeys()
        #expect(!keys.isEmpty, "Expected at least one secret key in the keyring")
    }

    @Test
    func `Public key lookup — self`() async throws {
        let keys = try await helper._listSecretKeys()
        guard let key = keys.first, let email = key.emails.first else {
            Issue.record("No secret keys with an email — skipping")
            throw GPGError.noSigningKey
        }
        let (found, resultFP) = try await helper._publicKeyExists(email: email)
        #expect(found)
        #expect(resultFP != nil)
    }

    @Test
    func `Round-trip encrypt / decrypt`() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let plaintext = Data("Hello, Alp!".utf8)
        let cipher = try await helper._encrypt(plaintext, [fp], fp)
        let (decrypted, signer, _) = try await helper._decrypt(cipher)
        #expect(decrypted == plaintext)
        #expect(signer != nil)
    }

    @Test
    func `Sign and verify (detached)`() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let data = Data("Signed message".utf8)
        let (signature, micalg) = try await helper._sign(data, signer: fp)
        #expect(micalg.hasPrefix("pgp-"))
        let (valid, signer, _) = try await helper._verify(data, signature: signature)
        #expect(valid)
        #expect(signer != nil)
    }
}
