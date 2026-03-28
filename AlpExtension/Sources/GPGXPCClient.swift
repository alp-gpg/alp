import Foundation

/// Sandboxed extension-side async wrapper around the XPC helper connection.
/// NSXPCConnection is thread-safe for proxy calls; no actor isolation needed.
/// @unchecked Sendable because NSXPCConnection does not conform to Sendable
/// but its proxy API is documented as safe to call from any thread.
final class GPGXPCClient: @unchecked Sendable {
    static let shared = GPGXPCClient()

    private let connection: NSXPCConnection

    private init() {
        connection = NSXPCConnection(machServiceName: "com.CXM87Z432P.alp.helper")
        connection.remoteObjectInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        connection.setCodeSigningRequirement(
            "anchor apple generic and certificate leaf[subject.OU] = \"3G6WR6H4M5\""
        )
        connection.resume()
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

    func decrypt(_ data: Data) async throws -> (plaintext: Data, signer: String?) {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.decrypt(data: data) { plain, signer, error in
                    if let error { cont.resume(throwing: error) }
                    else if let plain { cont.resume(returning: (plain, signer)) }
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

    func verify(_ data: Data, signature: Data? = nil) async throws -> (valid: Bool, signer: String?) {
        try await withCheckedThrowingContinuation { cont in
            proxy(cont) { proxy in
                proxy.verify(data: data, signatureData: signature) { valid, signer, error in
                    if let error { cont.resume(throwing: error) }
                    else { cont.resume(returning: (valid, signer)) }
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
        // swiftlint:disable:next force_cast
        let proxy = connection.remoteObjectProxyWithErrorHandler { error in
            cont.resume(throwing: error)
        } as! any GPGHelperProtocol
        body(proxy)
    }
}
