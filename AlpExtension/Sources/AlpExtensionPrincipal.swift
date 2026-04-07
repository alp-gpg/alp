import MailKit

/// Entry point for the Mail extension — returns handlers to Mail.app.
///
/// MailKit instantiates the principal class from its XPC queue, not the main
/// thread. Every entry point must be nonisolated to avoid @MainActor assertion
/// failures under Swift 6 strict concurrency.
final class AlpExtensionPrincipal: NSObject, MEExtension {
    nonisolated override init() {
        super.init()
        // Write a heartbeat so the host app can detect the extension is active.
        UserDefaults(suiteName: BuildConfig.appGroup)?.set(Date(), forKey: "extensionLastSeen")
    }

    nonisolated func handlerForMessageSecurity() -> any MEMessageSecurityHandler {
        SecurityHandler()
    }

    nonisolated func handler(for session: MEComposeSession) -> any MEComposeSessionHandler {
        ComposeHandler()
    }
}
