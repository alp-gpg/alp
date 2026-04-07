import Foundation

/// Lightweight XPC client for the main Alp app (settings UI key listing).
/// @unchecked Sendable: NSXPCConnection proxy calls are thread-safe; no actor isolation
/// so CheckedContinuation is not bound to any actor and cont.resume() can be called
/// from NSXPCConnection's private serial queue without a dispatch_assert_queue crash.
final class HelperXPCClient: @unchecked Sendable {
    static let shared = HelperXPCClient()

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

    /// Recreate the connection if it was invalidated (helper crash/restart).
    private func ensureConnection() {
        lock.lock()
        defer { lock.unlock() }
        if connectionInvalidated {
            connection = Self.makeConnection()
            connectionInvalidated = false
        }
    }

    func listSecretKeys() async throws -> [GPGKeyInfo] {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.listSecretKeys { dataList, error in
                    if let error { cont.resume(throwing: error) }
                    else { cont.resume(returning: Self.decodeKeys(dataList)) }
                }
            }
        }
    }

    func listAllKeys() async throws -> [GPGKeyInfo] {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.listAllKeys { dataList, error in
                    if let error { cont.resume(throwing: error) }
                    else { cont.resume(returning: Self.decodeKeys(dataList)) }
                }
            }
        }
    }

    func checkHealth() async throws -> GPGHealthStatus {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.checkHealth { data, error in
                    if let error { cont.resume(throwing: error) }
                    else if let data {
                        do {
                            let status = try JSONDecoder().decode(GPGHealthStatus.self, from: data)
                            cont.resume(returning: status)
                        } catch {
                            cont.resume(throwing: error)
                        }
                    } else {
                        cont.resume(throwing: GPGError.xpcUnavailable)
                    }
                }
            }
        }
    }

    func importKey(_ armoredKey: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, any Error>) in
            proxy(cont) { proxy in
                proxy.importKey(armoredKey: armoredKey) { error in
                    if let error { cont.resume(throwing: error) }
                    else { cont.resume() }
                }
            }
        }
    }

    // MARK: – Private

    private func proxy<T>(_ cont: CheckedContinuation<T, any Error>, body: (any GPGHelperProtocol) -> Void) {
        ensureConnection()
        connection.invalidationHandler = { [weak self] in
            self?.lock.withLock { self?.connectionInvalidated = true }
        }
        // swiftlint:disable:next force_cast
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] error in
            self?.lock.withLock { self?.connectionInvalidated = true }
            cont.resume(throwing: GPGError.xpcUnavailable)
        } as! any GPGHelperProtocol
        body(proxy)
    }

    private static func decodeKeys(_ dataList: [Data]?) -> [GPGKeyInfo] {
        (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
    }
}
