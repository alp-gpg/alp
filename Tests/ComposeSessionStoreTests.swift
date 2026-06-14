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
        let (shouldSign, shouldEncrypt, signer, inline) = store.state(forContextID: UUID())
        #expect(shouldSign == false) // from defaults, not session A
        #expect(shouldEncrypt == false) // from defaults, not session A
        #expect(signer == nil) // from defaults, not session A
        #expect(inline == false) // inline is per-message; never inherited
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
        let (sign, encrypt, signer, _) = store.state(forContextID: ctx)
        #expect(sign == true)
        #expect(encrypt == true)
        #expect(signer == "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    }

    @Test
    func `inline-PGP flag round-trips`() throws {
        let store = try makeStore()
        let ctx = UUID()
        store.register(
            contextID: ctx, sessionID: UUID(),
            sign: true, encrypt: false,
            signer: "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE",
            useInlinePGP: true,
        )
        let (_, _, _, inline) = store.state(forContextID: ctx)
        #expect(inline == true)
    }

    @Test
    func `unregister removes session state`() throws {
        let store = try makeStore(signDefault: true)
        let ctx = UUID()
        let session = UUID()
        store.register(contextID: ctx, sessionID: session, sign: false, encrypt: false, signer: nil)
        store.unregister(contextID: ctx, sessionID: session)
        // After unregister, query falls back to the default (sign=true).
        let (sign, _, _, _) = store.state(forContextID: ctx)
        #expect(sign == true)
    }

    @Test
    func `state survives extension teardown via app-group write-through`() throws {
        // §1.2: if the extension is torn down (jetsam/crash/relaunch) between
        // the user enabling Encrypt and pressing Send, a fresh process must
        // recover the persisted choice — NOT fall open to the plaintext
        // global defaults (sign=false, encrypt=false here).
        let suite = "ComposeSessionStoreTests-\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else {
            throw TestFailure.couldNotCreateDefaults
        }
        defaults.set(false, forKey: "signByDefault")
        defaults.set(false, forKey: "encryptByDefault")
        let ctx = UUID()

        let original = ComposeSessionStore(defaults: defaults)
        original.register(
            contextID: ctx, sessionID: UUID(),
            sign: true, encrypt: true,
            signer: "BEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF",
        )

        // Simulate a process restart: a brand-new store with empty in-memory
        // state, backed by the same app-group suite.
        let restarted = ComposeSessionStore(defaults: defaults)
        let (sign, encrypt, signer, _) = restarted.state(forContextID: ctx)
        #expect(sign == true, "Recovered sign state, not plaintext default")
        #expect(encrypt == true, "Recovered encrypt state, not plaintext default")
        #expect(signer == "BEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEFBEEF")

        // After unregister the persisted record is gone and a later restart
        // falls back to defaults.
        restarted.unregister(contextID: ctx, sessionID: UUID())
        let afterUnregister = ComposeSessionStore(defaults: defaults)
        let (sign2, encrypt2, _, _) = afterUnregister.state(forContextID: ctx)
        #expect(sign2 == false)
        #expect(encrypt2 == false)
    }

    @Test
    func `fallback honors UserDefaults values`() throws {
        let store = try makeStore(
            signDefault: true,
            encryptDefault: true,
            signerDefault: "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE",
        )
        let (sign, encrypt, signer, _) = store.state(forContextID: UUID())
        #expect(sign == true)
        #expect(encrypt == true)
        #expect(signer == "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE")
    }
}
