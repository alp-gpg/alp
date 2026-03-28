import Testing
@testable import AlpHelper

/// Verifies that the GPGHelper correctly bridges between async and XPC reply-block patterns.
/// These tests call the actor directly (no actual XPC transport) to validate bridging logic.
@Suite("XPC Bridge Roundtrip")
struct XPCRoundtripTests {
    let fingerprint = "2BC83F55A4007468864C680E1B7CC8D4D4E914AA"

    @Test("nonisolated encrypt bridge calls reply with data")
    func encryptBridgeCallsReply() async throws {
        let helper = await GPGHelper()
        let plaintext = Data("bridge test".utf8)

        let result: Data = try await withCheckedThrowingContinuation { cont in
            helper.encrypt(
                data: plaintext,
                recipientFingerprints: [fingerprint],
                signingFingerprint: fingerprint
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
        let helper = await GPGHelper()

        let dataList: [Data] = try await withCheckedThrowingContinuation { cont in
            helper.listSecretKeys { dataList, error in
                if let error { cont.resume(throwing: error) }
                else { cont.resume(returning: dataList ?? []) }
            }
        }
        #expect(!dataList.isEmpty)
        // Verify each element decodes to a GPGKeyInfo
        for data in dataList {
            let key = try JSONDecoder().decode(GPGKeyInfo.self, from: data)
            #expect(!key.fingerprint.isEmpty)
        }
    }
}
