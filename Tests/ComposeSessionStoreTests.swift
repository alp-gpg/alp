import Foundation
import Testing

@Suite("ComposeSessionStore")
@MainActor
struct ComposeSessionStoreTests {
    /// Isolated in-memory UserDefaults so tests don't touch the real app-group
    /// suite or bleed state between runs.
    private func makeStore(signerDefault: String? = nil) throws -> ComposeSessionStore {
        let suite = "ComposeSessionStoreTests-\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else {
            Issue.record("Could not create UserDefaults suite \(suite)")
            throw TestFailure.couldNotCreateDefaults
        }
        if let signerDefault {
            defaults.set(signerDefault, forKey: "defaultSignerFingerprint")
        }
        return ComposeSessionStore(defaults: defaults)
    }

    private enum TestFailure: Error { case couldNotCreateDefaults }

    @Test
    func `unknown context ID falls back to default signer, not another session`() throws {
        // A compose window with no matching session must NOT inherit another
        // window's signer. (Sign/encrypt no longer live here — they come from
        // MEComposeContext — so there is nothing else to leak.)
        let store = try makeStore()
        store.register(
            contextID: UUID(), sessionID: UUID(),
            signer: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )

        let (signer, inline) = store.state(forContextID: UUID())
        #expect(signer == nil) // from defaults, not session A
        #expect(inline == false) // inline is per-message; never inherited
    }

    @Test
    func `known context returns that session's signer`() throws {
        let store = try makeStore()
        let ctx = UUID()
        store.register(
            contextID: ctx, sessionID: UUID(),
            signer: "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF",
        )
        let (signer, _) = store.state(forContextID: ctx)
        #expect(signer == "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
    }

    @Test
    func `inline-PGP flag round-trips`() throws {
        let store = try makeStore()
        let ctx = UUID()
        store.register(
            contextID: ctx, sessionID: UUID(),
            signer: "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE",
            useInlinePGP: true,
        )
        let (_, inline) = store.state(forContextID: ctx)
        #expect(inline == true)
    }

    @Test
    func `unregister removes session state`() throws {
        let store = try makeStore(signerDefault: "CAFECAFECAFECAFECAFECAFECAFECAFECAFECAFE")
        let ctx = UUID()
        let session = UUID()
        store.register(contextID: ctx, sessionID: session, signer: "0000000000000000000000000000000000000000")
        store.unregister(contextID: ctx, sessionID: session)
        // After unregister, query falls back to the default signer.
        let (signer, _) = store.state(forContextID: ctx)
        #expect(signer == "CAFECAFECAFECAFECAFECAFECAFECAFECAFECAFE")
    }

    @Test
    func `fallback honors the default signer`() throws {
        let store = try makeStore(signerDefault: "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE")
        let (signer, inline) = store.state(forContextID: UUID())
        #expect(signer == "FEEDFACEFEEDFACEFEEDFACEFEEDFACEFEEDFACE")
        #expect(inline == false)
    }
}
