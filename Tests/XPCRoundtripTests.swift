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
}
