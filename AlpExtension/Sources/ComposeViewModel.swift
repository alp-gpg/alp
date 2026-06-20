import MailKit
import Observation

@Observable @MainActor
final class ComposeViewModel {
    var shouldSign: Bool
    var shouldEncrypt: Bool
    var canEncrypt: Bool = false
    var missingKeyEmails: [String] = []
    var availableSecretKeys: [GPGKeyInfo] = []
    var selectedSignerFingerprint: String?
    /// Per-message override: send as inline ASCII-armored PGP (RFC 4880)
    /// instead of PGP/MIME. Off by default; on for legacy recipients.
    var useInlinePGP: Bool = false

    var canSign: Bool {
        !availableSecretKeys.isEmpty
    }

    var selectedKey: GPGKeyInfo? {
        availableSecretKeys.first { $0.fingerprint == selectedSignerFingerprint }
    }

    private let session: MEComposeSession
    private static let sharedDefaults = UserDefaults(suiteName: BuildConfig.appGroup)

    init(session: MEComposeSession) {
        self.session = session
        let defaults = Self.sharedDefaults
        // Respect stored compose defaults; fall back to sign=false, encrypt=false.
        shouldSign = defaults?.object(forKey: "signByDefault") as? Bool ?? false
        shouldEncrypt = defaults?.bool(forKey: "encryptByDefault") ?? false
    }

    func refresh() async {
        // Load secret keys for the signer picker
        if let keys = try? await GPGXPCClient.shared.listSecretKeys() {
            availableSecretKeys = keys
            if selectedSignerFingerprint == nil {
                selectedSignerFingerprint = preferredSigner(for: senderEmail, available: keys)
            }
        }

        // Can't sign without a key — override the stored default.
        if availableSecretKeys.isEmpty {
            shouldSign = false
        }

        // Check recipient keys
        let message = session.mailMessage
        let allAddresses = message.toAddresses + message.ccAddresses + message.bccAddresses
        var missing: [String] = []
        for addr in allAddresses {
            if let (found, _) = try? await GPGXPCClient.shared
                .publicKeyExists(email: addr.addressString ?? addr.rawString), !found
            {
                missing.append(addr.addressString ?? addr.rawString)
            }
        }
        missingKeyEmails = missing
        canEncrypt = missing.isEmpty && !allAddresses.isEmpty

        syncStateToStore()
    }

    /// Lowercased sender address from the compose session's mail message,
    /// or nil when the From line is missing or unparseable. Used to look up
    /// the per-account signing-key preference.
    private var senderEmail: String? {
        let address = session.mailMessage.fromAddress
        let candidate = address.addressString ?? address.rawString
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed.lowercased()
    }

    /// Returns the fingerprint that should sign messages from `email`, in this
    /// priority order:
    ///   1. A saved per-account preference (last user choice for that From).
    ///   2. A secret key whose UID email matches `email` exactly.
    ///   3. The global "Default Signing Key" picked in Settings.
    ///   4. The first available secret key.
    private func preferredSigner(for email: String?, available: [GPGKeyInfo]) -> String? {
        if let email, let saved = Self.savedSigner(for: email),
           available.contains(where: { $0.fingerprint == saved })
        {
            return saved
        }
        if let email,
           let match = available.first(where: { $0.emails.contains(email) })
        {
            return match.fingerprint
        }
        if let global = Self.sharedDefaults?.string(forKey: "defaultSignerFingerprint"),
           available.contains(where: { $0.fingerprint == global })
        {
            return global
        }
        return available.first?.fingerprint
    }

    private static func defaultsKey(forSender email: String) -> String {
        "signerForFrom.\(email.lowercased())"
    }

    private static func savedSigner(for email: String) -> String? {
        sharedDefaults?.string(forKey: defaultsKey(forSender: email))
    }

    fileprivate static func saveSigner(_ fingerprint: String?, for email: String) {
        let key = defaultsKey(forSender: email)
        if let fingerprint {
            sharedDefaults?.set(fingerprint, forKey: key)
        } else {
            sharedDefaults?.removeObject(forKey: key)
        }
    }

    /// Push current toggle state to the session store without re-running the
    /// XPC keyserver/recipient checks. Cheap; safe to call on every toggle.
    func syncStateToStore() {
        ComposeSessionStore.shared.register(
            session: session,
            sign: shouldSign,
            encrypt: shouldEncrypt,
            signer: selectedSignerFingerprint,
            useInlinePGP: useInlinePGP,
        )
        // Persist per-account signer so the next compose window from the
        // same address picks the same key without the user re-selecting.
        if let senderEmail {
            Self.saveSigner(selectedSignerFingerprint, for: senderEmail)
        }
    }
}
