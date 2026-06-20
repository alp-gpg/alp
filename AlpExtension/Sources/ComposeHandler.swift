import Foundation
import MailKit

/// Manages the compose toolbar view controller lifecycle.
///
/// MailKit may invoke these factory methods from its private XPC queue rather
/// than the main thread (hence the `nonisolated` entry points, matching
/// `AlpExtensionPrincipal`). Because `viewController(for:)` and
/// `mailComposeSessionDidEnd` run in different isolation domains, the
/// `controllers` map is guarded by a lock rather than left
/// `nonisolated(unsafe)` — that suppressed checker was masking a real data
/// race with multiple compose windows (§3.1).
final class ComposeHandler: NSObject, MEComposeSessionHandler {
    private let lock = NSLock()
    private var controllers: [UUID: ComposeViewController] = [:]

    override nonisolated init() {
        super.init()
    }

    private func controller(forSessionID id: UUID) -> ComposeViewController? {
        lock.withLock { controllers[id] }
    }

    func mailComposeSessionDidBegin(_: MEComposeSession) {
        // Nothing to do — view controller is created on demand in viewController(for:)
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        lock.withLock { _ = controllers.removeValue(forKey: session.sessionID) }
        Task { @MainActor in
            ComposeSessionStore.shared.unregister(session: session)
        }
    }

    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        if let existing = controller(forSessionID: session.sessionID) { return existing }
        let vc = ComposeViewController()
        vc.configure(session: session)
        lock.withLock { controllers[session.sessionID] = vc }
        return vc
    }

    /// Mail invokes this as the user edits To/Cc/Bcc. Recompute recipient key
    /// availability live — the toolbar panel's `.task` only fires when the
    /// panel (re)appears, so without this `canEncrypt`/`missingKeyEmails` go
    /// stale (§1.4) — and mark key-less recipients inline.
    /// @MainActor (not nonisolated): `MEComposeSessionHandler` is NS_SWIFT_UI_ACTOR
    /// and Mail invokes this on the main actor, so the session can be touched
    /// directly without a Sendable hop.
    @MainActor
    func annotateAddressesForSession(
        _ session: MEComposeSession,
        completion: @escaping ([MEEmailAddress: MEAddressAnnotation]) -> Void,
    ) {
        guard let vm = controller(forSessionID: session.sessionID)?.viewModel else {
            completion([:])
            return
        }
        Task { @MainActor in
            await vm.refresh()
            let missing = Set(vm.missingKeyEmails)
            let message = session.mailMessage
            let recipients = message.toAddresses + message.ccAddresses + message.bccAddresses
            var annotations: [MEEmailAddress: MEAddressAnnotation] = [:]
            for address in recipients {
                let email = address.addressString ?? address.rawString
                if missing.contains(email) {
                    annotations[address] = MEAddressAnnotation.error(
                        withLocalizedDescription: String(
                            localized: "No PGP key — can't encrypt to this recipient",
                        ),
                    )
                }
            }
            completion(annotations)
        }
    }
}
