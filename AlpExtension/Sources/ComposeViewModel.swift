import Observation
import MailKit

@Observable @MainActor
final class ComposeViewModel {
    var shouldSign: Bool = true
    var shouldEncrypt: Bool = false
    var canEncrypt: Bool = false
    var missingKeyEmails: [String] = []
    var availableSecretKeys: [GPGKeyInfo] = []
    var selectedSignerFingerprint: String?

    private let session: MEComposeSession

    init(session: MEComposeSession) {
        self.session = session
    }

    func refresh() async {
        // Load secret keys for the signer picker
        if let keys = try? await GPGXPCClient.shared.listSecretKeys() {
            availableSecretKeys = keys
            if selectedSignerFingerprint == nil {
                selectedSignerFingerprint = keys.first?.fingerprint
            }
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

        // Push current state to the session store so SecurityHandler can read it
        ComposeSessionStore.shared.register(
            session: session,
            sign: shouldSign,
            encrypt: shouldEncrypt,
            signer: selectedSignerFingerprint
        )
    }
}
