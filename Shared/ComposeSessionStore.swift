import Foundation

/// Bridges per-compose-window preferences — signing key and inline-PGP — to
/// SecurityHandler, which has no session reference. Keyed by the compose
/// session's UUID; SecurityHandler resolves the right window via the
/// `contextID → sessionID → state` chain from the MEComposeContext it receives
/// in encode().
///
/// The sign/encrypt **decision is not stored here** — it comes straight from
/// `MEComposeContext.shouldSign`/`.shouldEncrypt` (Mail's native security UI),
/// which Mail hands to encode()/getEncodingStatus() and which survives an
/// extension teardown because Mail owns it. So there is nothing safety-critical
/// to persist: a lost in-memory entry falls back to the default signer and
/// PGP/MIME, never to plaintext.
///
/// No MailKit dependency, so it stays unit-testable without MEComposeSession
/// (which isn't publicly constructable). MailKit-aware register/unregister
/// wrappers live in AlpExtension.
@MainActor
final class ComposeSessionStore {
    static let shared = ComposeSessionStore()

    struct State {
        var signerFingerprint: String?
        /// True when the user picked inline ASCII-armor (RFC 4880) instead of
        /// PGP/MIME (RFC 3156) for this message — for recipients on older
        /// clients that can't decode multipart/encrypted bodies.
        var useInlinePGP: Bool = false
    }

    private var sessions: [UUID: State] = [:]
    /// Maps contextID → sessionID so SecurityHandler can resolve the correct
    /// per-window state from the MEComposeContext it receives in encode().
    private var contextToSession: [UUID: UUID] = [:]

    /// Test seam for the default-signer fallback read.
    private let defaults: UserDefaults?

    init(defaults: UserDefaults? = ComposeSessionStore.sharedAppGroupDefaults()) {
        self.defaults = defaults
    }

    static func sharedAppGroupDefaults() -> UserDefaults? {
        UserDefaults(suiteName: BuildConfig.appGroup)
    }

    func register(contextID: UUID, sessionID: UUID, signer: String?, useInlinePGP: Bool = false) {
        sessions[sessionID] = State(signerFingerprint: signer, useInlinePGP: useInlinePGP)
        contextToSession[contextID] = sessionID
    }

    func unregister(contextID: UUID, sessionID: UUID) {
        sessions.removeValue(forKey: sessionID)
        contextToSession.removeValue(forKey: contextID)
    }

    /// Look up the signer + inline preference by context ID. On an in-memory
    /// miss (e.g. extension restarted), fall back to the global default signer
    /// — never another window's state. No plaintext risk: encrypt/sign come
    /// from MEComposeContext, not from here.
    func state(forContextID contextID: UUID) -> (signerFingerprint: String?, useInlinePGP: Bool) {
        if let state = contextToSession[contextID].flatMap({ sessions[$0] }) {
            return (state.signerFingerprint, state.useInlinePGP)
        }
        return (signerFingerprintFallback, false)
    }

    private var signerFingerprintFallback: String? {
        defaults?.string(forKey: "defaultSignerFingerprint")
    }
}
