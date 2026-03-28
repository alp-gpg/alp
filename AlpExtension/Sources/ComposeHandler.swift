import MailKit

/// Manages the compose toolbar view controller lifecycle.
final class ComposeHandler: NSObject, MEComposeSessionHandler {
    private nonisolated(unsafe) var controllers: [UUID: ComposeViewController] = [:]

    nonisolated override init() {
        super.init()
    }

    func mailComposeSessionDidBegin(_ session: MEComposeSession) {
        // Nothing to do — view controller is created on demand in viewController(for:)
    }

    func mailComposeSessionDidEnd(_ session: MEComposeSession) {
        controllers.removeValue(forKey: session.sessionID)
        Task { @MainActor in
            ComposeSessionStore.shared.unregister(session: session)
        }
    }

    func viewController(for session: MEComposeSession) -> MEExtensionViewController {
        if let existing = controllers[session.sessionID] { return existing }
        let vc = ComposeViewController()
        vc.configure(session: session)
        controllers[session.sessionID] = vc
        return vc
    }
}
