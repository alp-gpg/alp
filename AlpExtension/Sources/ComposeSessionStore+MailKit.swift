import Foundation
import MailKit

/// MailKit-aware convenience wrappers over the plain-UUID API in Shared/.
/// Keeping this extension out of Shared lets us unit-test the store without
/// linking MailKit into the test bundle.
extension ComposeSessionStore {
    func register(
        session: MEComposeSession,
        sign: Bool,
        encrypt: Bool,
        signer: String?,
        useInlinePGP: Bool = false,
    ) {
        register(
            contextID: session.composeContext.contextID,
            sessionID: session.sessionID,
            sign: sign,
            encrypt: encrypt,
            signer: signer,
            useInlinePGP: useInlinePGP,
        )
    }

    func unregister(session: MEComposeSession) {
        unregister(
            contextID: session.composeContext.contextID,
            sessionID: session.sessionID,
        )
    }
}
