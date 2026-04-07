import Foundation
import MailKit

/// Bridges ComposeViewModel state to SecurityHandler (which has no session reference).
/// Keyed by MEComposeSession.sessionID.
@MainActor
final class ComposeSessionStore {
    static let shared = ComposeSessionStore()

    private struct State {
        var shouldSign: Bool
        var shouldEncrypt: Bool
        var signerFingerprint: String?
    }

    private var sessions: [String: State] = [:]
    /// Maps MEComposeContext.contextID → MEComposeSession.sessionID for cross-reference.
    private var contextToSession: [String: String] = [:]

    func register(session: MEComposeSession, sign: Bool, encrypt: Bool, signer: String?) {
        let sessionKey = session.sessionID.uuidString
        sessions[sessionKey] = State(
            shouldSign: sign, shouldEncrypt: encrypt, signerFingerprint: signer
        )
        contextToSession[session.composeContext.contextID.uuidString] = sessionKey
    }

    func unregister(session: MEComposeSession) {
        let sessionKey = session.sessionID.uuidString
        sessions.removeValue(forKey: sessionKey)
        contextToSession.removeValue(forKey: session.composeContext.contextID.uuidString)
    }

    /// Look up compose state by context ID (passed to SecurityHandler at encode time).
    func state(forContextID contextID: UUID) -> (shouldSign: Bool, shouldEncrypt: Bool, signerFingerprint: String?) {
        let sessionKey = contextToSession[contextID.uuidString]
        let state = sessionKey.flatMap { sessions[$0] }
        return (
            state?.shouldSign ?? shouldSignFallback,
            state?.shouldEncrypt ?? shouldEncryptFallback,
            state?.signerFingerprint ?? signerFingerprintFallback
        )
    }

    // Fallbacks read from UserDefaults when no matching session is found.
    private static let sharedDefaults = UserDefaults(suiteName: BuildConfig.appGroup)

    private var shouldSignFallback: Bool {
        sessions.values.first?.shouldSign
            ?? (Self.sharedDefaults?.object(forKey: "signByDefault") as? Bool ?? false)
    }

    private var shouldEncryptFallback: Bool {
        sessions.values.first?.shouldEncrypt
            ?? (Self.sharedDefaults?.bool(forKey: "encryptByDefault") ?? false)
    }

    private var signerFingerprintFallback: String? {
        sessions.values.first?.signerFingerprint
            ?? Self.sharedDefaults?.string(forKey: "defaultSignerFingerprint")
    }

    // Legacy accessors for encoding-status calls (no context available).
    var shouldSignDefault: Bool { shouldSignFallback }
    var shouldEncryptDefault: Bool { shouldEncryptFallback }
    var signerFingerprintDefault: String? { signerFingerprintFallback }
}
