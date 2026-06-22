import Foundation

/// Sandboxed extension-side async wrapper around the XPC helper connection.
/// The connection + timeout machinery lives in `HelperConnection` (Shared);
/// this type only maps helper methods to async calls.
final class GPGXPCClient: @unchecked Sendable {
    static let shared = GPGXPCClient()

    /// Re-exported so wrappers can request the longer pinentry timeout without
    /// naming `HelperConnection` at each call site.
    static let interactiveCallTimeout = HelperConnection.interactiveCallTimeout

    private let conn = HelperConnection()

    private init() {}

    /// Forwards to the shared connection. See `HelperConnection.call`.
    private func call<T: Sendable>(
        timeout: TimeInterval = HelperConnection.callTimeout,
        _ body: @Sendable (any GPGHelperProtocol, @escaping @Sendable (Result<T, any Error>) -> Void) -> Void,
    ) async throws -> T {
        try await conn.call(timeout: timeout, body)
    }

    // MARK: – Async wrappers

    func encrypt(
        _ data: Data,
        recipients: [String],
        signer: String? = nil,
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
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
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

    func verify(_ data: Data,
                signature: Data? = nil) async throws -> (valid: Bool, signer: String?, signerName: String?)
    {
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

    func publicKeyExists(email: String) async throws -> (found: Bool, fingerprint: String?) {
        try await call { proxy, resume in
            proxy.publicKeyExists(email: email) { found, fp, error in
                if let error { resume(.failure(error)) }
                else { resume(.success((found, fp))) }
            }
        }
    }
}
