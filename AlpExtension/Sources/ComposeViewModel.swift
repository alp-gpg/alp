import Observation
import MailKit

@Observable @MainActor
final class ComposeViewModel {
    var shouldSign: Bool
    var shouldEncrypt: Bool
    var canEncrypt: Bool = false
    var missingKeyEmails: [String] = []
    var availableSecretKeys: [GPGKeyInfo] = []
    var selectedSignerFingerprint: String?

    var canSign: Bool { !availableSecretKeys.isEmpty }

    var selectedKey: GPGKeyInfo? {
        availableSecretKeys.first { $0.fingerprint == selectedSignerFingerprint }
    }

    private let session: MEComposeSession
    private static let sharedDefaults = UserDefaults(suiteName: BuildConfig.appGroup)

    init(session: MEComposeSession) {
        self.session = session
        let defaults = Self.sharedDefaults
        // Respect stored compose defaults; fall back to sign=false, encrypt=false.
        self.shouldSign = defaults?.object(forKey: "signByDefault") as? Bool ?? false
        self.shouldEncrypt = defaults?.bool(forKey: "encryptByDefault") ?? false
    }

    func refresh() async {
        // Load secret keys for the signer picker
        if let keys = try? await GPGXPCClient.shared.listSecretKeys() {
            availableSecretKeys = keys
            if selectedSignerFingerprint == nil {
                let savedFP = Self.sharedDefaults?.string(forKey: "defaultSignerFingerprint")
                selectedSignerFingerprint = savedFP ?? keys.first?.fingerprint
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
            if let (found, _) = try? await GPGXPCClient.shared.publicKeyExists(email: addr.addressString ?? addr.rawString), !found {
                missing.append(addr.addressString ?? addr.rawString)
            }
        }
        missingKeyEmails = missing
        canEncrypt = missing.isEmpty && !allAddresses.isEmpty

        syncStateToStore()
    }

    /// Push current toggle state to the session store without re-running the
    /// XPC keyserver/recipient checks. Cheap; safe to call on every toggle.
    func syncStateToStore() {
        ComposeSessionStore.shared.register(
            session: session,
            sign: shouldSign,
            encrypt: shouldEncrypt,
            signer: selectedSignerFingerprint
        )
    }
}
