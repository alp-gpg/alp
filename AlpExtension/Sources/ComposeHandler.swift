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
    // nonisolated(unsafe): the class is @MainActor (MEComposeSessionHandler is
    // NS_SWIFT_UI_ACTOR), yet MailKit drives the lifecycle callbacks off its XPC
    // queue, so this map is read and written across isolation domains. The NSLock
    // provides the actual mutual exclusion; nonisolated(unsafe) only tells the
    // type system we take responsibility for it. Both are required — the lock
    // alone doesn't satisfy Swift 6 isolation, the opt-out alone would race.
    private nonisolated(unsafe) var controllers: [UUID: ComposeViewController] = [:]

    override nonisolated init() {
        super.init()
    }

    // nonisolated: lock-guarded dictionary access with no main-actor state, so
    // the nonisolated lifecycle callbacks (annotate/didEnd) can call it without
    // an isolation check. Leaving it main-actor-isolated traps (SIGTRAP) when
    // Mail drives annotateAddressesForSession off its XPC queue.
    private nonisolated func controller(forSessionID id: UUID) -> ComposeViewController? {
        lock.withLock { controllers[id] }
    }

    nonisolated func mailComposeSessionDidBegin(_: MEComposeSession) {
        // Nothing to do — view controller is created on demand in viewController(for:)
    }

    nonisolated func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        // MailKit invokes this from its private XPC queue, not the main actor,
        // even though MEComposeSessionHandler is NS_SWIFT_UI_ACTOR — so this
        // MUST be nonisolated, or the @objc thunk's main-actor assertion traps
        // (SIGTRAP) on every session end. (SecurityHandler guards the same way.)
        // Extract the Sendable IDs here; hop to the main actor only for the
        // store mutation, never capturing the non-Sendable session.
        let sessionID = session.sessionID
        let contextID = session.composeContext.contextID
        lock.withLock { _ = controllers.removeValue(forKey: sessionID) }
        Task { @MainActor in
            ComposeSessionStore.shared.unregister(contextID: contextID, sessionID: sessionID)
        }
    }

    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        if let existing = controller(forSessionID: session.sessionID) {
            return existing
        }
        let vc = ComposeViewController()
        vc.configure(session: session)
        lock.withLock { controllers[session.sessionID] = vc }
        return vc
    }

    /// Mail invokes this as the user edits To/Cc/Bcc. Recompute recipient key
    /// availability live — the toolbar panel's `.task` only fires when the
    /// panel (re)appears, so without this `missingKeyEmails` goes stale (§1.4)
    /// — and mark key-less recipients inline.
    /// nonisolated: despite `MEComposeSessionHandler` being NS_SWIFT_UI_ACTOR,
    /// Mail also calls this from its private XPC queue (it crashed here with a
    /// main-actor SIGTRAP). Resolve the controller + recipients on the calling
    /// thread, then hop to the main actor for the view-model work.
    nonisolated func annotateAddressesForSession(
        _ session: MEComposeSession,
        completion: @escaping ([MEEmailAddress: MEAddressAnnotation]) -> Void,
    ) {
        let sessionID = session.sessionID
        let vc = controller(forSessionID: sessionID)
        let message = session.mailMessage
        nonisolated(unsafe) let recipients = message.toAddresses + message.ccAddresses + message.bccAddresses
        nonisolated(unsafe) let completion = completion
        Task { @MainActor in
            guard let vm = vc?.viewModel else {
                completion([:])
                return
            }
            await vm.refresh()
            let missing = Set(vm.missingKeyEmails)
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
