import Foundation
import Testing

/// Verifies that the GPGHelper correctly bridges between async and XPC reply-block patterns.
/// These tests call the actor directly (no actual XPC transport) to validate bridging logic.
@Suite("XPC Bridge Roundtrip")
struct XPCRoundtripTests {
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

    @Test("nonisolated encrypt bridge calls reply with data")
    func encryptBridgeCallsReply() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let plaintext = Data("bridge test".utf8)

        let result: Data = try await withCheckedThrowingContinuation { cont in
            helper.encrypt(
                data: plaintext,
                recipientFingerprints: [fp],
                signingFingerprint: fp
            ) { data, error in
                if let error { cont.resume(throwing: error) }
                else if let data { cont.resume(returning: data) }
                else { cont.resume(throwing: GPGError.encodingError("nil")) }
            }
        }
        #expect(!result.isEmpty)
    }

    @Test("nonisolated listSecretKeys bridge returns JSON-encoded array")
    func listSecretKeysBridgeReturnsJSON() async throws {
        let dataList: [Data] = try await withCheckedThrowingContinuation { cont in
            helper.listSecretKeys { dataList, error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume(returning: dataList ?? []) }
            }
        }
        #expect(!dataList.isEmpty)
        for data in dataList {
            let key = try JSONDecoder().decode(GPGKeyInfo.self, from: data)
            #expect(!key.fingerprint.isEmpty)
        }
    }

    @Test("sign bridge returns signature and micalg")
    func signBridgeReturnsSignatureAndMicalg() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let body = Data("hello, micalg\r\n".utf8)

        let (signature, micalg): (Data, String?) = try await withCheckedThrowingContinuation { cont in
            helper.sign(data: body, signingFingerprint: fp) { data, micalg, error in
                if let error { cont.resume(throwing: error) }
                else if let data { cont.resume(returning: (data, micalg)) }
                else { cont.resume(throwing: GPGError.encodingError("nil signature")) }
            }
        }
        #expect(!signature.isEmpty)
        // micalg should be a recognized RFC 3156 name when gpg emits SIG_CREATED.
        let known: Set<String> = ["pgp-sha1", "pgp-sha224", "pgp-sha256", "pgp-sha384", "pgp-sha512"]
        #expect(micalg.map { known.contains($0) } ?? false)
    }

    @Test("decrypt bridge round-trips encrypted payload")
    func decryptBridgeRoundTrips() async throws {
        let fp = try await firstSecretKeyFingerprint()
        let plaintext = Data("round-trip payload".utf8)
        let ciphertext = try await helper._encrypt(plaintext, [fp], nil)

        let result: (Data, String?, String?) = try await withCheckedThrowingContinuation { cont in
            helper.decrypt(data: ciphertext) { plain, signer, signerName, error in
                if let error { cont.resume(throwing: error) }
                else if let plain { cont.resume(returning: (plain, signer, signerName)) }
                else { cont.resume(throwing: GPGError.decryptionFailed("nil")) }
            }
        }
        #expect(result.0 == plaintext)
    }

    @Test("encrypt bridge rejects bad fingerprints")
    func encryptBridgeRejectsBadFingerprints() async throws {
        let error: NSError? = await withCheckedContinuation { cont in
            helper.encrypt(
                data: Data("x".utf8),
                recipientFingerprints: ["NOT_A_FINGERPRINT"],
                signingFingerprint: nil
            ) { _, error in cont.resume(returning: error) }
        }
        #expect(error != nil)
    }

    @Test("_importKey throws on malformed payload")
    func importKeyThrowsOnGarbage() async {
        await #expect(throws: (any Error).self) {
            _ = try await self.helper._importKey(Data("not a key".utf8))
        }
    }

    @Test("importKey bridge returns GPGImportResult")
    func importKeyBridgeReturnsResult() async throws {
        let fp = try await firstSecretKeyFingerprint()
        // Export an existing key so we have real armored data to re-import.
        let exported = try await helper._export(fp)
        let resultData: Data = try await withCheckedThrowingContinuation { cont in
            helper.importKey(armoredKey: exported) { data, error in
                if let error { cont.resume(throwing: error) }
                else if let data { cont.resume(returning: data) }
                else { cont.resume(throwing: GPGError.encodingError("nil")) }
            }
        }
        let result = try JSONDecoder().decode(GPGImportResult.self, from: resultData)
        // Re-importing an already-present key should not mark it as new.
        #expect(result.newKey == false)
        #expect(result.fingerprint != nil)
    }
}
