import Foundation

/// Owns the `NSXPCConnection` to AlpHelper plus the timeout and single-resume
/// machinery every helper call needs. Shared by both clients — the app's
/// `HelperXPCClient` and the extension's `GPGXPCClient` — which differ only in
/// which helper methods they wrap, not in how a call is made.
///
/// @unchecked Sendable: NSXPCConnection proxy calls are thread-safe and this
/// type carries no actor isolation, so a `CheckedContinuation` resumed from
/// NSXPCConnection's private serial queue won't trip a `dispatch_assert_queue`.
final class HelperConnection: @unchecked Sendable {
    /// Upper bound on any single helper call. gpg + gpg-agent can take a few
    /// seconds; 60s is generous but still prevents an indefinitely hung
    /// continuation from leaking when the helper crashes mid-reply.
    static let callTimeout: TimeInterval = 60

    /// Longer bound for calls that route through pinentry — the user may take
    /// several minutes to type a passphrase. 5 minutes is enough for any
    /// realistic prompt without leaking forever on a wedged pinentry.
    static let interactiveCallTimeout: TimeInterval = 300

    private var connection: NSXPCConnection
    private let lock = NSLock()
    private var connectionInvalidated = false

    init() {
        connection = Self.makeConnection()
    }

    private static func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: BuildConfig.helperMachService)
        conn.remoteObjectInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        conn.setCodeSigningRequirement(BuildConfig.helperRequirement)
        conn.resume()
        return conn
    }

    /// Makes an XPC call with a hard timeout and continuation-leak protection.
    ///
    /// If the helper crashes mid-call and neither the reply block nor the
    /// connection error handler ever fires, the timer guarantees the
    /// continuation is resumed after `timeout`. `ResumeGuard` ensures exactly
    /// one of reply / error / timeout wins the race. The lock is held across
    /// reconnect + proxy acquisition so a concurrent invalidation can't race us
    /// to a stale proxy; `body()` runs outside the lock since it initiates the
    /// async call.
    func call<T: Sendable>(
        timeout: TimeInterval = HelperConnection.callTimeout,
        _ body: @Sendable (any GPGHelperProtocol, @escaping @Sendable (Result<T, any Error>) -> Void) -> Void,
    ) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, any Error>) in
            let resumedGuard = ResumeGuard()
            let resume: @Sendable (Result<T, any Error>) -> Void = { result in
                guard resumedGuard.claim() else { return }
                switch result {
                case let .success(value): cont.resume(returning: value)
                case let .failure(error): cont.resume(throwing: error)
                }
            }

            let timer = DispatchSource.makeTimerSource()
            timer.schedule(deadline: .now() + timeout)
            timer.setEventHandler {
                resume(.failure(GPGError.xpcUnavailable))
                timer.cancel()
            }
            timer.resume()

            lock.lock()
            if connectionInvalidated {
                connection = Self.makeConnection()
                connectionInvalidated = false
            }
            connection.invalidationHandler = { [weak self] in
                self?.lock.withLock { self?.connectionInvalidated = true }
                resume(.failure(GPGError.xpcUnavailable))
            }
            // NSXPCConnection.remoteObjectProxy… is typed `Any`; casting to the
            // protocol is the supported pattern. swiftlint can't see that the
            // Objective-C bridge guarantees the type, so suppress here.
            // swiftlint:disable force_cast
            let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] _ in
                self?.lock.withLock { self?.connectionInvalidated = true }
                resume(.failure(GPGError.xpcUnavailable))
            } as! any GPGHelperProtocol
            // swiftlint:enable force_cast
            lock.unlock()

            body(proxy) { result in
                timer.cancel()
                resume(result)
            }
        }
    }
}

/// Single-shot guard: ensures exactly one of reply / error / timeout resumes
/// the `CheckedContinuation` in `HelperConnection.call`.
private final class ResumeGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed {
            return false
        }
        claimed = true
        return true
    }
}
