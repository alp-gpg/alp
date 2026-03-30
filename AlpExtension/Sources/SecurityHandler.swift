import Foundation
import MailKit
import os.log

private let log = Logger(subsystem: "com.CXM87Z432P.alp.extension", category: "SecurityHandler")

/// Handles GPG encrypt/sign/decrypt/verify for Apple Mail.
///
/// MailKit delivers all calls via XPC on its own private queue, not the main
/// thread. Every protocol method is explicitly `nonisolated` to prevent
/// dispatch_assert_queue crashes under Swift 6 strict concurrency.
final class SecurityHandler: NSObject, MEMessageSecurityHandler {
    private nonisolated let parser = PGPMessageParser()

    nonisolated override init() {
        super.init()
    }

    // MARK: – MEMessageSecurityHandler (optional UI)

    nonisolated func extensionViewController(signers: [MEMessageSigner]) -> MEExtensionViewController? { nil }
    nonisolated func extensionViewController(messageContext: Data) -> MEExtensionViewController? { nil }
    nonisolated func primaryActionClicked(forMessageContext context: Data) async -> MEExtensionViewController? { nil }

    // MARK: – MEMessageDecoder

    nonisolated func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        let sema = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var decoded: MEDecodedMessage?
        let parser = self.parser
        Task.detached {
            decoded = await Self.decrypt(data: data, parser: parser)
            sema.signal()
        }
        sema.wait()
        return decoded
    }

    // MARK: – MEMessageEncoder

    nonisolated func getEncodingStatus(
        for message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void
    ) {
        // Extract values synchronously on the calling thread, then do async work.
        let allAddresses = message.allRecipientAddresses
        let emails = allAddresses.map { $0.addressString ?? $0.rawString }
        let handler = unsafeBitCast(completionHandler, to: (@Sendable (MEOutgoingMessageEncodingStatus) -> Void).self)

        Task.detached {
            var missingEmails: [String] = []
            for email in emails {
                do {
                    let (found, _) = try await GPGXPCClient.shared.publicKeyExists(email: email)
                    if !found { missingEmails.append(email) }
                } catch {
                    missingEmails.append(email)
                }
            }
            let missingAddresses = missingEmails.map { MEEmailAddress(rawString: $0) }
            let encryptionError: NSError? = missingEmails.isEmpty ? nil :
                NSError(domain: MEMessageSecurityErrorDomain,
                        code: 0,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Missing public keys for: \(missingEmails.joined(separator: ", "))"])
            handler(MEOutgoingMessageEncodingStatus(
                canSign: true,
                canEncrypt: missingEmails.isEmpty,
                securityError: encryptionError,
                addressesFailingEncryption: missingAddresses
            ))
        }
    }

    nonisolated func encode(
        _ message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEMessageEncodingResult) -> Void
    ) {
        // Extract all needed values synchronously before the async boundary.
        let rawData = message.rawData
        let recipientEmails = message.allRecipientAddresses.map { $0.addressString ?? $0.rawString }
        let handler = unsafeBitCast(completionHandler, to: (@Sendable (MEMessageEncodingResult) -> Void).self)

        Task.detached {
            // Access ComposeSessionStore on main actor — use first active session heuristic
            let (shouldSign, shouldEncrypt, signerFP) = await MainActor.run {
                let store = ComposeSessionStore.shared
                return (
                    store.shouldSignDefault,
                    store.shouldEncryptDefault,
                    store.signerFingerprintDefault
                )
            }

            do {
                let encoded = try await Self.buildOutgoing(
                    rawData: rawData,
                    recipientEmails: recipientEmails,
                    shouldSign: shouldSign,
                    shouldEncrypt: shouldEncrypt,
                    signerFingerprint: signerFP
                )
                handler(MEMessageEncodingResult(
                    encodedMessage: encoded, signingError: nil, encryptionError: nil
                ))
            } catch {
                let nsError = Self.mailKitError(for: error, isEncoding: true)
                let isSigningError: Bool
                if case GPGError.noSigningKey = error { isSigningError = true } else { isSigningError = false }
                handler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: isSigningError ? nsError : nil,
                    encryptionError: isSigningError ? nil : nsError
                ))
            }
        }
    }

    // MARK: – Decode implementation

    private nonisolated static func decrypt(data: Data, parser: PGPMessageParser) async -> MEDecodedMessage {
        guard let pgp = parser.parse(data) else {
            return MEDecodedMessage(data: data, securityInformation: .notSecured, context: nil)
        }
        log.info("PGP content detected")
        do {
            switch pgp {
            case .mime(let cipher), .inline(let cipher):
                let (plain, signer, signerName) = try await GPGXPCClient.shared.decrypt(cipher)
                log.info("Decrypted successfully")
                return MEDecodedMessage(
                    data: plain,
                    securityInformation: MEMessageSecurityInformation(
                        signers: makeSigner(signer, displayName: signerName), isEncrypted: true,
                        signingError: nil, encryptionError: nil
                    ),
                    context: nil
                )

            case .inlineSigned(let body):
                let (valid, signer, signerName) = try await GPGXPCClient.shared.verify(body)
                return MEDecodedMessage(
                    data: data,
                    securityInformation: MEMessageSecurityInformation(
                        signers: makeSigner(signer, displayName: signerName), isEncrypted: false,
                        signingError: valid ? nil : mailKitError(code: 1, description: "Invalid signature"),
                        encryptionError: nil
                    ),
                    context: nil
                )

            case .mimeSignature(let body, let sig):
                let (valid, signer, signerName) = try await GPGXPCClient.shared.verify(body, signature: sig)
                return MEDecodedMessage(
                    data: data,
                    securityInformation: MEMessageSecurityInformation(
                        signers: makeSigner(signer, displayName: signerName), isEncrypted: false,
                        signingError: valid ? nil : mailKitError(code: 1, description: "Invalid signature"),
                        encryptionError: nil
                    ),
                    context: nil
                )
            }
        } catch {
            log.error("Decrypt failed")
            return MEDecodedMessage(
                data: data,
                securityInformation: MEMessageSecurityInformation(
                    signers: [], isEncrypted: false,
                    signingError: nil,
                    encryptionError: mailKitError(for: error, isEncoding: false)
                ),
                context: nil
            )
        }
    }

    // MARK: – Encode implementation

    private nonisolated static func buildOutgoing(
        rawData: Data?,
        recipientEmails: [String],
        shouldSign: Bool,
        shouldEncrypt: Bool,
        signerFingerprint: String?
    ) async throws -> MEEncodedOutgoingMessage {
        guard let rawData else {
            throw GPGError.encodingError("MEMessage has no rawData")
        }

        if shouldEncrypt {
            var fingerprints: [String] = []
            for email in recipientEmails {
                let (found, fp) = try await GPGXPCClient.shared.publicKeyExists(email: email)
                guard found, let fp else { throw GPGError.missingKeys([email]) }
                fingerprints.append(fp)
            }
            let ciphertext = try await GPGXPCClient.shared.encrypt(
                rawData,
                recipients: fingerprints,
                signer: shouldSign ? signerFingerprint : nil
            )
            return MEEncodedOutgoingMessage(
                rawData: pgpMIMEEncrypted(ciphertext), isSigned: shouldSign, isEncrypted: true
            )
        }

        if shouldSign {
            guard let fp = signerFingerprint else { throw GPGError.noSigningKey }
            let signature = try await GPGXPCClient.shared.sign(rawData, signer: fp)
            return MEEncodedOutgoingMessage(
                rawData: pgpMIMESigned(rawData, signature: signature), isSigned: true, isEncrypted: false
            )
        }

        return MEEncodedOutgoingMessage(rawData: rawData, isSigned: false, isEncrypted: false)
    }

    // MARK: – PGP/MIME builders

    private nonisolated static func pgpMIMEEncrypted(_ ciphertext: Data) -> Data {
        let boundary = "AlpBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let cipher = String(data: ciphertext, encoding: .utf8) ?? ""
        let mime = """
        Content-Type: multipart/encrypted; boundary="\(boundary)"; protocol="application/pgp-encrypted"\r
        \r
        --\(boundary)\r
        Content-Type: application/pgp-encrypted\r
        Content-Description: PGP/MIME version identification\r
        \r
        Version: 1\r
        \r
        --\(boundary)\r
        Content-Type: application/octet-stream; name="encrypted.asc"\r
        Content-Description: OpenPGP encrypted message\r
        Content-Disposition: inline; filename="encrypted.asc"\r
        \r
        \(cipher)\r
        --\(boundary)--\r
        """
        return Data(mime.utf8)
    }

    private nonisolated static func pgpMIMESigned(_ body: Data, signature: Data) -> Data {
        let boundary = "AlpSigBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let bodyStr = String(data: body, encoding: .utf8) ?? ""
        let sigStr = String(data: signature, encoding: .utf8) ?? ""
        let mime = """
        Content-Type: multipart/signed; boundary="\(boundary)"; protocol="application/pgp-signature"; micalg="pgp-sha256"\r
        \r
        --\(boundary)\r
        \(bodyStr)\r
        --\(boundary)\r
        Content-Type: application/pgp-signature; name="signature.asc"\r
        Content-Description: OpenPGP digital signature\r
        Content-Disposition: attachment; filename="signature.asc"\r
        \r
        \(sigStr)\r
        --\(boundary)--\r
        """
        return Data(mime.utf8)
    }

    // MARK: – Helpers

    private nonisolated static func makeSigner(_ fingerprint: String?, displayName: String?) -> [MEMessageSigner] {
        guard let fingerprint else { return [] }
        let label = displayName ?? String(fingerprint.prefix(16))
        return [MEMessageSigner(
            emailAddresses: [],
            signatureLabel: label,
            context: fingerprint.data(using: .utf8)
        )]
    }

    private nonisolated static func mailKitError(for error: any Error, isEncoding: Bool) -> NSError {
        let code = isEncoding ? 0 : 1
        return mailKitError(code: code, description: error.localizedDescription)
    }

    private nonisolated static func mailKitError(code: Int, description: String) -> NSError {
        NSError(
            domain: MEMessageSecurityErrorDomain,
            code: code,
            userInfo: [NSLocalizedDescriptionKey: description]
        )
    }
}

private extension MEMessageSecurityInformation {
    static var notSecured: MEMessageSecurityInformation {
        MEMessageSecurityInformation(signers: [], isEncrypted: false, signingError: nil, encryptionError: nil)
    }
}
