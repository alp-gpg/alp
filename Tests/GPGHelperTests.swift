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

    @Test("GPG binary is found")
    func gpgFound() async throws {
        let keys = try await helper._listSecretKeys()
        _ = keys
    }

    @Test("List secret keys returns non-empty array when keys exist")
    func listSecretKeys() async throws {
        let keys = try await helper._listSecretKeys()
        #expect(!keys.isEmpty, "Expected at least one secret key in the keyring")
    }

    @Test("Public key lookup — self")
    func publicKeyLookup() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let (found, resultFP) = try await helper._publicKeyExists(email: fp)
        #expect(found)
        #expect(resultFP != nil)
    }

    @Test("Round-trip encrypt / decrypt")
    func encryptDecrypt() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let plaintext = Data("Hello, Alp!".utf8)
        let cipher = try await helper._encrypt(plaintext, [fp], fp)
        let (decrypted, signer, _) = try await helper._decrypt(cipher)
        #expect(decrypted == plaintext)
        #expect(signer != nil)
    }

    @Test("Sign and verify (detached)")
    func signVerify() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let data = Data("Signed message".utf8)
        let (signature, micalg) = try await helper._sign(data, signer: fp)
        #expect(micalg.hasPrefix("pgp-"))
        let (valid, signer, _) = try await helper._verify(data, signature: signature)
        #expect(valid)
        #expect(signer != nil)
    }
}
