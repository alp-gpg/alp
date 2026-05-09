import Foundation

/// Lightweight XPC client for the main Alp app (settings UI key listing).
/// @unchecked Sendable: NSXPCConnection proxy calls are thread-safe; no actor isolation
/// so CheckedContinuation is not bound to any actor and cont.resume() can be called
/// from NSXPCConnection's private serial queue without a dispatch_assert_queue crash.
final class HelperXPCClient: @unchecked Sendable {
    static let shared = HelperXPCClient()

    /// Upper bound on any single helper call; see `GPGXPCClient.callTimeout`.
    static let callTimeout: TimeInterval = 60

    /// Longer bound for calls that route through pinentry — the user may take
    /// several minutes to type a passphrase. 5 minutes is enough for any
    /// realistic prompt without leaking forever on a wedged pinentry.
    static let interactiveCallTimeout: TimeInterval = 300

    private var connection: NSXPCConnection
    private let lock = NSLock()
    private var connectionInvalidated = false

    private init() {
        connection = Self.makeConnection()
    }

    private static func makeConnection() -> NSXPCConnection {
        let conn = NSXPCConnection(machServiceName: BuildConfig.helperMachService)
        conn.remoteObjectInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        conn.setCodeSigningRequirement(BuildConfig.helperRequirement)
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

    /// Decodes the JSON-encoded [GPGKeyInfo] preview from the helper's reply.
    /// Mirror of the sibling client in AlpExtension — keep them in sync.
    func previewKey(_ armoredKey: Data) async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.previewKey(armoredKey: armoredKey) { dataList, error in
                if let error { resume(.failure(error)) }
                else { resume(.success(Self.decodeKeys(dataList))) }
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

    func exportPublicKey(fingerprint: String) async throws -> Data {
        try await call { proxy, resume in
            proxy.exportPublicKey(fingerprint: fingerprint) { data, error in
                if let error { resume(.failure(error)) }
                else if let data { resume(.success(data)) }
                else { resume(.failure(GPGError.xpcUnavailable)) }
            }
        }
    }

    /// Long timeout because gpg-agent will prompt for the passphrase via
    /// pinentry. The user might leave the prompt open for a while.
    func exportSecretKey(fingerprint: String) async throws -> Data {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.exportSecretKey(fingerprint: fingerprint) { data, error in
                if let error { resume(.failure(error)) }
                else if let data { resume(.success(data)) }
                else { resume(.failure(GPGError.xpcUnavailable)) }
            }
        }
    }

    func deletePublicKey(fingerprint: String) async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.deletePublicKey(fingerprint: fingerprint) { error in
                if let error { resume(.failure(error)) }
                else { resume(.success(true)) }
            }
        }
    }

    func deleteSecretKey(fingerprint: String) async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.deleteSecretKey(fingerprint: fingerprint) { error in
                if let error { resume(.failure(error)) }
                else { resume(.success(true)) }
            }
        }
    }

    func generatePrimaryKey(
        name: String,
        email: String,
        comment: String?,
        expiryDays: Int,
    ) async throws -> String {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.generatePrimaryKey(
                name: name,
                email: email,
                comment: comment,
                expiryDays: expiryDays,
            ) { fp, error in
                if let error { resume(.failure(error)) }
                else if let fp { resume(.success(fp)) }
                else { resume(.failure(GPGError.xpcUnavailable)) }
            }
        }
    }

    func changePassphrase(fingerprint: String) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.changePassphrase(fingerprint: fingerprint) { error in
                if let error { resume(.failure(error)) }
                else { resume(.success(true)) }
            }
        }
    }

    func setExpiry(fingerprint: String, expiryDays: Int) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.setExpiry(fingerprint: fingerprint, expiryDays: expiryDays) { error in
                if let error { resume(.failure(error)) }
                else { resume(.success(true)) }
            }
        }
    }

    func revokePrimaryKey(
        fingerprint: String,
        reasonCode: Int,
        description: String?,
    ) async throws -> Data {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.revokePrimaryKey(
                fingerprint: fingerprint,
                reasonCode: reasonCode,
                description: description,
            ) { data, error in
                if let error { resume(.failure(error)) }
                else if let data { resume(.success(data)) }
                else { resume(.failure(GPGError.xpcUnavailable)) }
            }
        }
    }

    // MARK: – Private

    /// Shared timeout + single-resume guard pattern. See `GPGXPCClient.call`
    /// for rationale — both clients implement the same contract.
    private func call<T: Sendable>(
        timeout: TimeInterval = HelperXPCClient.callTimeout,
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
