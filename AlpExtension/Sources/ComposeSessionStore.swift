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

    func register(session: MEComposeSession, sign: Bool, encrypt: Bool, signer: String?) {
        sessions[session.sessionID.uuidString] = State(
            shouldSign: sign, shouldEncrypt: encrypt, signerFingerprint: signer
        )
    }

    func unregister(session: MEComposeSession) {
        sessions.removeValue(forKey: session.sessionID.uuidString)
    }

    func shouldSign(for message: MEMessage) -> Bool {
        // MEMessage doesn't expose a session ID; use the first active session as heuristic.
        sessions.values.first?.shouldSign ?? false
    }

    func shouldEncrypt(for message: MEMessage) -> Bool {
        sessions.values.first?.shouldEncrypt ?? false
    }

    func signerFingerprint(for message: MEMessage) -> String? {
        sessions.values.first?.signerFingerprint
    }

    // Simple accessors for use from nonisolated contexts (avoids sending MEMessage)
    var shouldSignDefault: Bool {
        sessions.values.first?.shouldSign ?? false
    }

    var shouldEncryptDefault: Bool {
        sessions.values.first?.shouldEncrypt ?? false
    }

    var signerFingerprintDefault: String? {
        sessions.values.first?.signerFingerprint
    }
}
