import Foundation

/// Bridges ComposeViewModel state to SecurityHandler (which has no session reference).
///
/// Keyed by the compose session's UUID. Lookups go `contextID → sessionID → state`
/// so SecurityHandler can resolve the right per-window preferences from the
/// MEComposeContext it receives in encode().
///
/// This type intentionally has no MailKit dependency so it can be unit-tested
/// without instantiating MEComposeSession (which is not publicly constructable).
/// A MailKit-aware `register(session:)` / `unregister(session:)` convenience
/// lives in AlpExtension as an extension on this type.
@MainActor
final class ComposeSessionStore {
    static let shared = ComposeSessionStore()

    struct State: Equatable, Codable {
        var shouldSign: Bool
        var shouldEncrypt: Bool
        var signerFingerprint: String?
        /// True when the user picked inline ASCII-armor (RFC 4880) instead
        /// of PGP/MIME (RFC 3156) for this message. Required by recipients on
        /// older clients that can't decode multipart/encrypted bodies.
        var useInlinePGP: Bool = false
    }

    private var sessions: [UUID: State] = [:]
    /// Maps contextID → sessionID so SecurityHandler can resolve the correct
    /// per-window state from the MEComposeContext it receives in encode().
    private var contextToSession: [UUID: UUID] = [:]

    /// Test seam: allow injection of the UserDefaults used for fallback reads.
    /// Production code uses `sharedAppGroupDefaults()`.
    private let defaults: UserDefaults?

    init(defaults: UserDefaults? = ComposeSessionStore.sharedAppGroupDefaults()) {
        self.defaults = defaults
    }

    static func sharedAppGroupDefaults() -> UserDefaults? {
        UserDefaults(suiteName: BuildConfig.appGroup)
    }

    func register(
        contextID: UUID,
        sessionID: UUID,
        sign: Bool,
        encrypt: Bool,
        signer: String?,
        useInlinePGP: Bool = false,
    ) {
        let state = State(
            shouldSign: sign,
            shouldEncrypt: encrypt,
            signerFingerprint: signer,
            useInlinePGP: useInlinePGP,
        )
        sessions[sessionID] = state
        contextToSession[contextID] = sessionID
        // Write-through to the app group so the user's choice survives an
        // extension teardown (jetsam, crash, Mail relaunch) between toggling
        // Encrypt ON and pressing Send. Without this the in-memory state is
        // gone on restart and encode() would silently fall back to the
        // plaintext global defaults — the one failure a crypto tool must
        // never have. See state(forContextID:).
        persist(state: state, forContextID: contextID)
    }

    func unregister(contextID: UUID, sessionID: UUID) {
        sessions.removeValue(forKey: sessionID)
        contextToSession.removeValue(forKey: contextID)
        removePersisted(forContextID: contextID)
    }

    /// Look up compose state by context ID (passed to SecurityHandler at encode time).
    ///
    /// On miss the return value is read from UserDefaults, never from another
    /// session's state — borrowing from a different window would apply user A's
    /// encryption preference to user B's outgoing message.
    func state(
        forContextID contextID: UUID,
    ) -> (shouldSign: Bool, shouldEncrypt: Bool, signerFingerprint: String?, useInlinePGP: Bool) {
        // In-memory state is authoritative while the extension is alive.
        if let state = contextToSession[contextID].flatMap({ sessions[$0] }) {
            return (state.shouldSign, state.shouldEncrypt, state.signerFingerprint, state.useInlinePGP)
        }
        // In-memory miss: the extension was torn down after the user set their
        // preferences. Recover the persisted record rather than falling open to
        // the plaintext global defaults — if the user enabled encryption for
        // this context, honor it (encode() then throws if keys are missing,
        // never sends plaintext silently).
        if let persisted = persistedState(forContextID: contextID) {
            return (persisted.shouldSign, persisted.shouldEncrypt,
                    persisted.signerFingerprint, persisted.useInlinePGP)
        }
        return (shouldSignFallback, shouldEncryptFallback, signerFingerprintFallback, false)
    }

    private var shouldSignFallback: Bool {
        defaults?.object(forKey: "signByDefault") as? Bool ?? false
    }

    private var shouldEncryptFallback: Bool {
        defaults?.bool(forKey: "encryptByDefault") ?? false
    }

    private var signerFingerprintFallback: String? {
        defaults?.string(forKey: "defaultSignerFingerprint")
    }

    // MARK: – Write-through persistence (fail-closed recovery)

    /// One persisted compose-state snapshot plus the timestamp used for TTL
    /// expiry. `Codable` so the marshalling stays in sync with `State`
    /// automatically — no stringly-typed keys.
    private struct Record: Codable {
        var state: State
        var ts: Double
    }

    /// App-group key holding `contextID.uuidString → Record` for compose
    /// windows whose live state may be lost to an extension restart.
    private static let persistKey = "composeSessionStates"
    /// Discard persisted records older than this so a crash that skips
    /// `unregister` can't grow the store unbounded.
    private static let persistTTL: TimeInterval = 7 * 24 * 3600

    /// Load and TTL-prune in one place so reads and writes agree on which
    /// records are live.
    private func liveRecords() -> [String: Record] {
        guard let data = defaults?.data(forKey: Self.persistKey),
              let all = try? JSONDecoder().decode([String: Record].self, from: data)
        else { return [:] }
        let now = Date().timeIntervalSince1970
        return all.filter { now - $0.value.ts < Self.persistTTL }
    }

    private func persist(state: State, forContextID contextID: UUID) {
        guard let defaults else { return }
        var all = liveRecords()
        // `register` runs on every compose toggle and at the end of every
        // `refresh()` (i.e. on every recipient edit). Skip the plist write when
        // the recovery snapshot wouldn't actually change.
        if all[contextID.uuidString]?.state == state { return }
        all[contextID.uuidString] = Record(state: state, ts: Date().timeIntervalSince1970)
        defaults.set(try? JSONEncoder().encode(all), forKey: Self.persistKey)
    }

    private func persistedState(forContextID contextID: UUID) -> State? {
        liveRecords()[contextID.uuidString]?.state
    }

    private func removePersisted(forContextID contextID: UUID) {
        guard let defaults else { return }
        var all = liveRecords()
        guard all.removeValue(forKey: contextID.uuidString) != nil else { return }
        defaults.set(try? JSONEncoder().encode(all), forKey: Self.persistKey)
    }
}
