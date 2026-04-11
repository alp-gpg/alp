import Foundation
import Testing

/// Verifies that GPGHelper correctly rejects tampered ciphertext, missing keys,
/// and forged signatures. These are the audit's P3 #18 and #19 test gaps.
@Suite("GPGHelper tamper resistance")
struct GPGTamperResistanceTests {
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

    @Test("tampered ciphertext fails to decrypt")
    func tamperedCiphertextFailsToDecrypt() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let plaintext = Data("tamper me".utf8)
        let ciphertext = try await helper._encrypt(plaintext, [fp], nil)

        // Flip a byte somewhere inside the ASCII-armored body (past the
        // header line). The resulting blob is no longer a valid PGP message.
        var tampered = ciphertext
        let idx = tampered.count / 2
        tampered[idx] = tampered[idx] &+ 1

        await #expect(throws: (any Error).self) {
            _ = try await helper._decrypt(tampered)
        }
    }

    @Test("decrypting random bytes fails cleanly")
    func decryptingRandomBytesFails() async throws {
        let garbage = Data((0..<2048).map { _ in UInt8.random(in: 0...255) })
        await #expect(throws: (any Error).self) {
            _ = try await helper._decrypt(garbage)
        }
    }

    @Test("verifying tampered detached signature returns invalid")
    func verifyingTamperedSignatureReturnsInvalid() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let body = Data("sign-me body".utf8)
        let (signature, _) = try await helper._sign(body, signer: fp)

        // Verify against a different body — the signature must not validate.
        let differentBody = Data("sign-me BODY".utf8)
        let (valid, _, _) = try await helper._verify(differentBody, signature: signature)
        #expect(valid == false)
    }

    @Test("encrypt rejects obviously malformed fingerprints")
    func encryptRejectsMalformedFingerprints() async throws {
        let plaintext = Data("x".utf8)
        await #expect(throws: (any Error).self) {
            _ = try await helper._encrypt(plaintext, ["--homedir=/tmp/fake"], nil)
        }
        await #expect(throws: (any Error).self) {
            _ = try await helper._encrypt(plaintext, ["0000000000000000"], nil) // too short
        }
    }
}
