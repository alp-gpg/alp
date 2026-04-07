import Foundation

/// Sandboxed extension-side async wrapper around the XPC helper connection.
/// NSXPCConnection is thread-safe for proxy calls; no actor isolation needed.
/// @unchecked Sendable because NSXPCConnection does not conform to Sendable
/// but its proxy API is documented as safe to call from any thread.
final class GPGXPCClient: @unchecked Sendable {
    static let shared = GPGXPCClient()

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

    private func ensureConnection() {
        lock.lock()
        defer { lock.unlock() }
        if connectionInvalidated {
            connection = Self.makeConnection()
            connectionInvalidated = false
        }
    }

    // MARK: – Async wrappers

    func encrypt(
        _ data: Data,
        recipients: [String],
        signer: String? = nil
    ) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.encrypt(data: data, recipientFingerprints: recipients, signingFingerprint: signer) { result, error in
                    if let error { cont.resume(throwing: error) }
                    else if let result { cont.resume(returning: result) }
                    else { cont.resume(throwing: GPGError.encodingError("nil result")) }
                }
            }
        }
    }

    func decrypt(_ data: Data) async throws -> (plaintext: Data, signer: String?, signerName: String?) {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.decrypt(data: data) { plain, signer, signerName, error in
                    if let error { cont.resume(throwing: error) }
                    else if let plain { cont.resume(returning: (plain, signer, signerName)) }
                    else { cont.resume(throwing: GPGError.decryptionFailed("nil result")) }
                }
            }
        }
    }

    func sign(_ data: Data, signer: String) async throws -> Data {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.sign(data: data, signingFingerprint: signer) { result, error in
                    if let error { cont.resume(throwing: error) }
                    else if let result { cont.resume(returning: result) }
                    else { cont.resume(throwing: GPGError.encodingError("nil signature")) }
                }
            }
        }
    }

    func verify(_ data: Data, signature: Data? = nil) async throws -> (valid: Bool, signer: String?, signerName: String?) {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.verify(data: data, signatureData: signature) { valid, signer, signerName, error in
                    if let error { cont.resume(throwing: error) }
                    else { cont.resume(returning: (valid, signer, signerName)) }
                }
            }
        }
    }

    func listSecretKeys() async throws -> [GPGKeyInfo] {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.listSecretKeys { dataList, error in
                    if let error {
                        cont.resume(throwing: error)
                    } else {
                        let keys = (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
                        cont.resume(returning: keys)
                    }
                }
            }
        }
    }

    func previewKey(_ armoredKey: Data) async throws -> [GPGKeyInfo] {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.previewKey(armoredKey: armoredKey) { dataList, error in
                    if let error { cont.resume(throwing: error) }
                    else {
                        let keys = (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
                        cont.resume(returning: keys)
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

    func publicKeyExists(email: String) async throws -> (found: Bool, fingerprint: String?) {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.publicKeyExists(email: email) { found, fp, error in
                    if let error { cont.resume(throwing: error) }
                    else { cont.resume(returning: (found, fp)) }
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
}
