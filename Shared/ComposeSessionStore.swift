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

    struct State: Equatable {
        var shouldSign: Bool
        var shouldEncrypt: Bool
        var signerFingerprint: String?
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

    func register(contextID: UUID, sessionID: UUID, sign: Bool, encrypt: Bool, signer: String?) {
        sessions[sessionID] = State(
            shouldSign: sign, shouldEncrypt: encrypt, signerFingerprint: signer,
        )
        contextToSession[contextID] = sessionID
    }

    func unregister(contextID: UUID, sessionID: UUID) {
        sessions.removeValue(forKey: sessionID)
        contextToSession.removeValue(forKey: contextID)
    }

    /// Look up compose state by context ID (passed to SecurityHandler at encode time).
    ///
    /// On miss the return value is read from UserDefaults, never from another
    /// session's state — borrowing from a different window would apply user A's
    /// encryption preference to user B's outgoing message.
    func state(forContextID contextID: UUID) -> (shouldSign: Bool, shouldEncrypt: Bool, signerFingerprint: String?) {
        let state = contextToSession[contextID].flatMap { sessions[$0] }
        return (
            state?.shouldSign ?? shouldSignFallback,
            state?.shouldEncrypt ?? shouldEncryptFallback,
            state?.signerFingerprint ?? signerFingerprintFallback,
        )
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

    /// Legacy accessors for encoding-status calls (no context available).
    var shouldSignDefault: Bool {
        shouldSignFallback
    }

    var shouldEncryptDefault: Bool {
        shouldEncryptFallback
    }

    var signerFingerprintDefault: String? {
        signerFingerprintFallback
    }
}
