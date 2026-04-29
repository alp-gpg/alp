import Foundation
import Testing

@Suite("ComposeSessionStore")
@MainActor
struct ComposeSessionStoreTests {
    /// Uses an isolated in-memory UserDefaults so tests don't touch the
    /// real app group suite or bleed state between runs.
    private func makeStore(
        signDefault: Bool = false,
        encryptDefault: Bool = false,
        signerDefault: String? = nil,
    ) throws -> ComposeSessionStore {
        let suite = "ComposeSessionStoreTests-\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else {
            Issue.record("Could not create UserDefaults suite \(suite)")
            throw TestFailure.couldNotCreateDefaults
        }
        defaults.set(signDefault, forKey: "signByDefault")
        defaults.set(encryptDefault, forKey: "encryptByDefault")
        if let signerDefault {
            defaults.set(signerDefault, forKey: "defaultSignerFingerprint")
        }
        return ComposeSessionStore(defaults: defaults)
    }

    private enum TestFailure: Error { case couldNotCreateDefaults }

    @Test
    func `unknown context ID falls back to UserDefaults, not another session`() throws {
        // Covers P0 #2 from the audit: a compose window with no matching
        // session must NOT inherit encrypt/sign state from a different window.
        let store = try makeStore(signDefault: false, encryptDefault: false)

        // Session A: user chose to encrypt + sign with a specific fingerprint.
        store.register(
            contextID: UUID(), sessionID: UUID(),
            sign: true, encrypt: true,
            signer: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

        // A different compose window queries state before its session registers.
        let (shouldSign, shouldEncrypt, signer) = store.state(forContextID: UUID())
        #expect(shouldSign == false) // from defaults, not session A
        #expect(shouldEncrypt == false) // from defaults, not session A
        #expect(signer == nil) // from defaults, not session A
    }

    @Test
    func `known context returns that session's state`() throws {
        let store = try makeStore()
        let ctx = UUID()
        store.register(
            contextID: ctx, sessionID: UUID(),
            sign: true, encrypt: true,
            signer: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        )
        let (sign, encrypt, signer) = store.state(forContextID: ctx)
        #expect(sign == true)
        #expect(encrypt == true)
        #expect(signer == "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    }

    @Test
    func `unregister removes session state`() throws {
        let store = try makeStore(signDefault: true)
        let ctx = UUID()
        let session = UUID()
        store.register(contextID: ctx, sessionID: session, sign: false, encrypt: false, signer: nil)
        store.unregister(contextID: ctx, sessionID: session)
        // After unregister, query falls back to the default (sign=true).
        let (sign, _, _) = store.state(forContextID: ctx)
        #expect(sign == true)
    }

    @Test
    func `fallback honors UserDefaults values`() throws {
        let store = try makeStore(
            signDefault: true,
            encryptDefault: true,
            signerDefault: "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE",
        )
        let (sign, encrypt, signer) = store.state(forContextID: UUID())
        #expect(sign == true)
        #expect(encrypt == true)
        #expect(signer == "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE")
    }
}
