import Foundation

/// Lightweight XPC client for the main Alp app (settings UI key listing).
/// @unchecked Sendable: NSXPCConnection proxy calls are thread-safe; no actor isolation
/// so CheckedContinuation is not bound to any actor and cont.resume() can be called
/// from NSXPCConnection's private serial queue without a dispatch_assert_queue crash.
final class HelperXPCClient: @unchecked Sendable {
    static let shared = HelperXPCClient()

    /// Re-exported so the wrappers below can request the longer pinentry
    /// timeout without naming `HelperConnection` at every call site.
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

    func listAllKeys() async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.listAllKeys { dataList, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(Self.decodeKeys(dataList)))
                }
            }
        }
    }

    struct PinentryConfig {
        /// Path written in `~/.gnupg/gpg-agent.conf`, or nil when no
        /// `pinentry-program` directive is present.
        let configuredPath: String?
        /// True when the configured path equals the Alp shim location.
        let isAlpPinentry: Bool
    }

    func pinentryConfigStatus() async throws -> PinentryConfig {
        try await call { proxy, resume in
            proxy.pinentryConfigStatus { path, isAlp, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(PinentryConfig(configuredPath: path, isAlpPinentry: isAlp)))
                }
            }
        }
    }

    func installAlpPinentry(bundlePath: String) async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.installAlpPinentry(bundlePath: bundlePath) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func uninstallAlpPinentry() async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.uninstallAlpPinentry { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    /// Produce a passphrase-protected backup bundle for a key. The
    /// helper drives two pinentry prompts: secret-key passphrase to
    /// export, then archive passphrase to symmetric-encrypt the
    /// bundle. Returns the armored bundle bytes for the caller to
    /// write to disk. Long timeout because two pinentry prompts.
    func backupKey(fingerprint: String) async throws -> Data {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.backupKey(fingerprint: fingerprint) { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    /// Decrypt + import the bundle at `bundlePath`. Returns the
    /// fingerprints of every key the import touched. Long timeout —
    /// pinentry collects the archive passphrase.
    func restoreBackup(bundlePath: String) async throws -> [String] {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.restoreBackup(bundlePath: bundlePath) { fps, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(fps ?? []))
                }
            }
        }
    }

    func checkHealth() async throws -> GPGHealthStatus {
        try await call { proxy, resume in
            proxy.checkHealth { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
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
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(Self.decodeKeys(dataList)))
                }
            }
        }
    }

    /// Decodes the JSON-encoded GPGImportResult from the helper's reply.
    /// Mirror of the sibling client in the other target — keep them in sync.
    func importKey(_ armoredKey: Data) async throws -> GPGImportResult {
        try await call { proxy, resume in
            proxy.importKey(armoredKey: armoredKey) { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
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
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    /// Long timeout because gpg-agent will prompt for the passphrase via
    /// pinentry. The user might leave the prompt open for a while.
    func exportSecretKey(fingerprint: String) async throws -> Data {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.exportSecretKey(fingerprint: fingerprint) { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    func deletePublicKey(fingerprint: String) async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.deletePublicKey(fingerprint: fingerprint) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func deleteSecretKey(fingerprint: String) async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.deleteSecretKey(fingerprint: fingerprint) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
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
                if let error {
                    resume(.failure(error))
                } else if let fp {
                    resume(.success(fp))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    func changePassphrase(fingerprint: String) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.changePassphrase(fingerprint: fingerprint) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func setExpiry(fingerprint: String, expiryDays: Int) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.setExpiry(fingerprint: fingerprint, expiryDays: expiryDays) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func addSubkey(
        fingerprint: String,
        algoTag: String,
        expiryDays: Int,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.addSubkey(
                fingerprint: fingerprint,
                algoTag: algoTag,
                expiryDays: expiryDays,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func revokeSubkey(
        fingerprint: String,
        subkeyIndex: Int,
        reasonCode: Int,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.revokeSubkey(
                fingerprint: fingerprint,
                subkeyIndex: subkeyIndex,
                reasonCode: reasonCode,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func deleteSubkey(
        fingerprint: String,
        subkeyIndex: Int,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.deleteSubkey(
                fingerprint: fingerprint,
                subkeyIndex: subkeyIndex,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func deleteSubkeys(
        fingerprint: String,
        subkeyIndices: [Int],
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.deleteSubkeys(
                fingerprint: fingerprint,
                subkeyIndices: subkeyIndices.map { NSNumber(value: $0) },
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func addUserID(
        fingerprint: String,
        name: String,
        email: String,
        comment: String?,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.addUserID(
                fingerprint: fingerprint,
                name: name,
                email: email,
                comment: comment,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func revokeUserID(fingerprint: String, uidIndex: Int) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.revokeUserID(fingerprint: fingerprint, uidIndex: uidIndex) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func signKey(
        fingerprint: String,
        signer: String,
        exportable: Bool,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.signKey(
                fingerprint: fingerprint,
                signerFingerprint: signer,
                exportable: exportable,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    func setOwnerTrust(fingerprint: String, level: Int) async throws {
        let _: Bool = try await call { proxy, resume in
            proxy.setOwnerTrust(fingerprint: fingerprint, level: level) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
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
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    func generateRevocationCertificate(fingerprint: String) async throws -> Data {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.generateRevocationCertificate(fingerprint: fingerprint) { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    func decrypt(_ data: Data) async throws -> (plaintext: Data, signer: String?, signerName: String?) {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.decrypt(data: data) { plain, signer, signerName, error in
                if let error {
                    resume(.failure(error))
                } else if let plain {
                    resume(.success((plain, signer, signerName)))
                } else {
                    resume(.failure(GPGError.decryptionFailed("nil plaintext")))
                }
            }
        }
    }

    func verify(
        _ data: Data,
        signature: Data? = nil,
    ) async throws -> (valid: Bool, signer: String?, signerName: String?) {
        try await call { proxy, resume in
            proxy.verify(data: data, signatureData: signature) { valid, signer, signerName, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success((valid, signer, signerName)))
                }
            }
        }
    }

    /// File-level decrypt. The helper streams ciphertext from `inputPath` to
    /// plaintext at `outputPath`, so the XPC payload stays tiny regardless
    /// of file size. Returns the signer info parsed from gpg's status output
    /// (both nil when the source was unsigned).
    func decryptFile(
        inputPath: String,
        outputPath: String,
    ) async throws -> (signer: String?, signerName: String?) {
        try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.decryptFile(inputPath: inputPath, outputPath: outputPath) { signer, signerName, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success((signer, signerName)))
                }
            }
        }
    }

    /// File-level verify. Pass `signaturePath` for detached signatures, or
    /// nil for clearsigned / standalone armored signature files. `trust`
    /// is the local ownertrust label on the signing key (lowercase
    /// "ultimate", "fully", "marginal", "never", "undefined") or nil.
    func verifyFile(
        inputPath: String,
        signaturePath: String? = nil,
    ) async throws -> (valid: Bool, signer: String?, signerName: String?, trust: String?) {
        try await call { proxy, resume in
            proxy
                .verifyFile(inputPath: inputPath,
                            signaturePath: signaturePath)
                { valid, signer, signerName, trust, error in
                    if let error {
                        resume(.failure(error))
                    } else {
                        resume(.success((valid, signer, signerName, trust)))
                    }
                }
        }
    }

    /// File-level detached signature.
    func signFile(
        inputPath: String,
        outputPath: String,
        signer: String,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.signFile(
                inputPath: inputPath,
                outputPath: outputPath,
                signingFingerprint: signer,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    /// File-level encrypt to one or more recipients, optionally also signing.
    func encryptFile(
        inputPath: String,
        outputPath: String,
        recipients: [String],
        signer: String?,
    ) async throws {
        let _: Bool = try await call(timeout: Self.interactiveCallTimeout) { proxy, resume in
            proxy.encryptFile(
                inputPath: inputPath,
                outputPath: outputPath,
                recipientFingerprints: recipients,
                signingFingerprint: signer,
            ) { error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success(true))
                }
            }
        }
    }

    // MARK: – Private

    private static func decodeKeys(_ dataList: [Data]?) -> [GPGKeyInfo] {
        (dataList ?? []).compactMap { try? JSONDecoder().decode(GPGKeyInfo.self, from: $0) }
    }
}
