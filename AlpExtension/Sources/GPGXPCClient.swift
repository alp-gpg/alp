import Foundation

/// Sandboxed extension-side async wrapper around the XPC helper connection.
/// NSXPCConnection is thread-safe for proxy calls; no actor isolation needed.
/// @unchecked Sendable because NSXPCConnection does not conform to Sendable
/// but its proxy API is documented as safe to call from any thread.
final class GPGXPCClient: @unchecked Sendable {
    static let shared = GPGXPCClient()

    /// Upper bound on any single helper call. gpg + gpg-agent pinentry can take
    /// a few seconds; 60s is generous but still prevents an indefinitely hung
    /// continuation from leaking when the helper crashes mid-reply.
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

    // MARK: – Async wrappers

    func encrypt(
        _ data: Data,
        recipients: [String],
        signer: String? = nil
    ) async throws -> Data {
        try await call { proxy, resume in
            proxy.encrypt(data: data, recipientFingerprints: recipients, signingFingerprint: signer) { result, error in
                if let error { resume(.failure(error)) }
                else if let result { resume(.success(result)) }
                else { resume(.failure(GPGError.encodingError("nil result"))) }
            }
        }
    }

    func decrypt(_ data: Data) async throws -> (plaintext: Data, signer: String?, signerName: String?) {
        try await call { proxy, resume in
            proxy.decrypt(data: data) { plain, signer, signerName, error in
                if let error { resume(.failure(error)) }
                else if let plain { resume(.success((plain, signer, signerName))) }
                else { resume(.failure(GPGError.decryptionFailed("nil result"))) }
            }
        }
    }

    func sign(_ data: Data, signer: String) async throws -> (signature: Data, micalg: String) {
        try await call { proxy, resume in
            proxy.sign(data: data, signingFingerprint: signer) { result, micalg, error in
                if let error { resume(.failure(error)) }
                else if let result { resume(.success((result, micalg ?? "pgp-sha256"))) }
                else { resume(.failure(GPGError.encodingError("nil signature"))) }
            }
        }
    }

    func verify(_ data: Data, signature: Data? = nil) async throws -> (valid: Bool, signer: String?, signerName: String?) {
        try await call { proxy, resume in
            proxy.verify(data: data, signatureData: signature) { valid, signer, signerName, error in
                if let error { resume(.failure(error)) }
                else { resume(.success((valid, signer, signerName))) }
            }
        }
    }

    func listSecretKeys() async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.listSecretKeys { dataList, error in
                if let error { resume(.failure(error)) }
                else {
                    let keys = (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
                    resume(.success(keys))
                }
            }
        }
    }

    func previewKey(_ armoredKey: Data) async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.previewKey(armoredKey: armoredKey) { dataList, error in
                if let error { resume(.failure(error)) }
                else {
                    let keys = (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
                    resume(.success(keys))
                }
            }
        }
    }

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

    func publicKeyExists(email: String) async throws -> (found: Bool, fingerprint: String?) {
        try await call { proxy, resume in
            proxy.publicKeyExists(email: email) { found, fp, error in
                if let error { resume(.failure(error)) }
                else { resume(.success((found, fp))) }
            }
        }
    }

    // MARK: – Private

    /// Makes an XPC call with a hard timeout and continuation-leak protection.
    ///
    /// If the helper crashes mid-call and neither the reply block nor the
    /// connection error handler ever fires, the timer guarantees the
    /// continuation is resumed after `callTimeout`. `resumedGuard` ensures that
    /// exactly one of reply / error / timeout wins the race.
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

            // Hold the lock across the full connection + invalidation handler
            // + proxy acquisition so that a concurrent invalidation cannot
            // race us to a stale proxy. body() is called outside the lock
            // because it initiates an async XPC call.
            lock.lock()
            if connectionInvalidated {
                connection = Self.makeConnection()
                connectionInvalidated = false
            }
            connection.invalidationHandler = { [weak self] in
                self?.lock.withLock { self?.connectionInvalidated = true }
                resume(.failure(GPGError.xpcUnavailable))
            }
            // NSXPCConnection.remoteObjectProxy... is typed `Any`; casting to
            // the protocol is the supported pattern. swiftlint can't see that
            // the Objective-C bridge guarantees the type, so suppress here.
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

/// Tiny single-shot guard used by `GPGXPCClient.call` to ensure exactly one
/// of reply / error / timeout wins the race to resume a CheckedContinuation.
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
