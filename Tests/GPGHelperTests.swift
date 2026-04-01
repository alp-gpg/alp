import Foundation
import Testing

@Suite("GPG Helper")
struct GPGHelperTests {
    // Replace with a fingerprint from your local keyring for real round-trip tests
    let fingerprint = "2BC83F55A4007468864C680E1B7CC8D4D4E914AA"

    @Test("GPG binary is found")
    func gpgFound() async throws {
        let helper = await GPGHelper()
        // If gpg isn't installed the next line will throw .gpgNotFound
        let keys = try await helper._listSecretKeys()
        // Just asserting we get a result without throwing is sufficient
        _ = keys
    }

    @Test("List secret keys returns non-empty array when keys exist")
    func listSecretKeys() async throws {
        let helper = await GPGHelper()
        let keys = try await helper._listSecretKeys()
        // This will pass on any machine with at least one secret key
        #expect(!keys.isEmpty, "Expected at least one secret key in the keyring")
    }

    @Test("Public key lookup — self")
    func publicKeyLookup() async throws {
        let helper = await GPGHelper()
        // Look up by the full fingerprint used as a pseudo-email (gpg accepts it)
        let (found, fp) = try await helper._publicKeyExists(email: fingerprint)
        #expect(found)
        #expect(fp != nil)
    }

    @Test("Round-trip encrypt / decrypt")
    func encryptDecrypt() async throws {
        let helper = await GPGHelper()
        let plaintext = Data("Hello, Alp!".utf8)
        let cipher = try await helper._encrypt(plaintext, [fingerprint], fingerprint)
        let (decrypted, signer, _) = try await helper._decrypt(cipher)
        #expect(decrypted == plaintext)
        #expect(signer != nil)
    }

    @Test("Sign and verify (detached)")
    func signVerify() async throws {
        let helper = await GPGHelper()
        let data = Data("Signed message".utf8)
        let signature = try await helper._sign(data, signer: fingerprint)
        let (valid, signer, _) = try await helper._verify(data, signature: signature)
        #expect(valid)
        #expect(signer != nil)
    }
}
