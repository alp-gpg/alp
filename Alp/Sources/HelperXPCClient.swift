import Foundation

/// Lightweight XPC client for the main Alp app (settings UI key listing).
/// @unchecked Sendable: NSXPCConnection proxy calls are thread-safe; no actor isolation
/// so CheckedContinuation is not bound to any actor and cont.resume() can be called
/// from NSXPCConnection's private serial queue without a dispatch_assert_queue crash.
final class HelperXPCClient: @unchecked Sendable {
    static let shared = HelperXPCClient()

    private let connection: NSXPCConnection

    private init() {
        connection = NSXPCConnection(machServiceName: BuildConfig.helperMachService)
        connection.remoteObjectInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        connection.setCodeSigningRequirement(BuildConfig.codeSigningRequirement)
        connection.resume()
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
        // swiftlint:disable:next force_cast
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            cont.resume(throwing: error)
        } as! any GPGHelperProtocol
        body(proxy)
    }

    private static func decodeKeys(_ dataList: [Data]?) -> [GPGKeyInfo] {
        (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
    }
}
