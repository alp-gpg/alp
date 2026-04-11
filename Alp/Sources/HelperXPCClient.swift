import Foundation

/// Lightweight XPC client for the main Alp app (settings UI key listing).
/// @unchecked Sendable: NSXPCConnection proxy calls are thread-safe; no actor isolation
/// so CheckedContinuation is not bound to any actor and cont.resume() can be called
/// from NSXPCConnection's private serial queue without a dispatch_assert_queue crash.
final class HelperXPCClient: @unchecked Sendable {
    static let shared = HelperXPCClient()

    /// Upper bound on any single helper call; see `GPGXPCClient.callTimeout`.
    static let callTimeout: TimeInterval = 60

    private var connection: NSXPCConnection
    private let lock = NSLock()
    private var connectionInvalidated = false

    private init() {
        connection = Self.makeConnection()
    }

    private static func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: BuildConfig.helperMachService)
        conn.remoteObjectInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        conn.setCodeSigningRequirement(BuildConfig.codeSigningRequirement)
        conn.resume()
        return conn
    }

    func listSecretKeys() async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.listSecretKeys { dataList, error in
                if let error { resume(.failure(error)) }
                else { resume(.success(Self.decodeKeys(dataList))) }
            }
        }
    }

    func listAllKeys() async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.listAllKeys { dataList, error in
                if let error { resume(.failure(error)) }
                else { resume(.success(Self.decodeKeys(dataList))) }
            }
        }
    }

    func checkHealth() async throws -> GPGHealthStatus {
        try await call { proxy, resume in
            proxy.checkHealth { data, error in
                if let error { resume(.failure(error)) }
                else if let data {
                    do {
                        let status = try JSONDecoder().decode(GPGHealthStatus.self, from: data)
                        resume(.success(status))
                    } catch {
                        resume(.failure(error))
                    }
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    /// Decodes the JSON-encoded GPGImportResult from the helper's reply.
    /// Mirror of the sibling client in the other target — keep them in sync.
    func importKey(_ armoredKey: Data) async throws -> GPGImportResult {
        try await call { proxy, resume in
            proxy.importKey(armoredKey: armoredKey) { data, error in
                if let error { resume(.failure(error)) }
                else if let data {
                    do {
                        let result = try JSONDecoder().decode(GPGImportResult.self, from: data)
                        resume(.success(result))
                    } catch {
                        resume(.failure(error))
                    }
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    // MARK: – Private

    /// Shared timeout + single-resume guard pattern. See `GPGXPCClient.call`
    /// for rationale — both clients implement the same contract.
    private func call<T: Sendable>(
        _ body: @Sendable (any GPGHelperProtocol, @escaping @Sendable (Result<T, any Error>) -> Void) -> Void
    ) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, any Error>) in
            let resumedGuard = ResumeGuard()
            let resume: @Sendable (Result<T, any Error>) -> Void = { result in
                guard resumedGuard.claim() else { return }
                switch result {
                case .success(let value): cont.resume(returning: value)
                case .failure(let error): cont.resume(throwing: error)
                }
            }

            let timer = DispatchSource.makeTimerSource()
            timer.schedule(deadline: .now() + Self.callTimeout)
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

    private static func decodeKeys(_ dataList: [Data]?) -> [GPGKeyInfo] {
        (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
    }
}

/// Single-shot guard; duplicated from GPGXPCClient because the two clients
/// live in different targets and shouldn't share private implementation types.
private final class ResumeGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
