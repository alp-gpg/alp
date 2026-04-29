import Foundation
import MailKit
import os.log

private let log = Logger(subsystem: "app.alp.Alp.extension", category: "SecurityHandler")

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
        // Bound the wait so a stuck gpg/gpg-agent cannot freeze Mail's XPC
        // thread indefinitely. Must exceed GPGXPCClient.callTimeout (60s) so
        // legitimate slow XPC replies (pinentry, slow keyserver) aren't cut
        // short by this outer guard.
        if sema.wait(timeout: .now() + 75) == .timedOut {
            log.error("decodedMessage timed out after 75s")
            return MEDecodedMessage(data: data, securityInformation: .notSecured, context: nil)
        }
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
        // MailKit's completion handlers aren't annotated @Sendable but are
        // designed to be invoked from arbitrary XPC callback queues. Use
        // nonisolated(unsafe) so the detached Task can capture the handler
        // without unsafeBitCast lying about the type.
        nonisolated(unsafe) let handler = completionHandler

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
        let contextID = composeContext.contextID
        nonisolated(unsafe) let handler = completionHandler

        Task.detached {
            // Look up the correct session state by context ID.
            let (shouldSign, shouldEncrypt, signerFP) = await MainActor.run {
                ComposeSessionStore.shared.state(forContextID: contextID)
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
            let canonicalBody = canonicalizeForSigning(rawData)
            let (signature, micalg) = try await GPGXPCClient.shared.sign(canonicalBody, signer: fp)
            return MEEncodedOutgoingMessage(
                rawData: pgpMIMESigned(canonicalBody, signature: signature, micalg: micalg),
                isSigned: true, isEncrypted: false
            )
        }

        return MEEncodedOutgoingMessage(rawData: rawData, isSigned: false, isEncrypted: false)
    }

    // MARK: – PGP/MIME builders

    /// Builds a multipart/encrypted RFC 3156 message.
    /// Ciphertext is appended as bytes — never round-tripped through String —
    /// so ASCII-armored output is preserved exactly and binary ciphertext is
    /// never silently replaced with an empty string.
    private nonisolated static func pgpMIMEEncrypted(_ ciphertext: Data) -> Data {
        let boundary = "AlpBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let header = [
            "Content-Type: multipart/encrypted; boundary=\"\(boundary)\"; protocol=\"application/pgp-encrypted\"",
            "",
            "--\(boundary)",
            "Content-Type: application/pgp-encrypted",
            "Content-Description: PGP/MIME version identification",
            "",
            "Version: 1",
            "",
            "--\(boundary)",
            "Content-Type: application/octet-stream; name=\"encrypted.asc\"",
            "Content-Description: OpenPGP encrypted message",
            "Content-Disposition: inline; filename=\"encrypted.asc\"",
            "",
            "",  // trailing empty = extra CRLF before body
        ].joined(separator: "\r\n")
        var out = Data(header.utf8)
        out.append(ciphertext)
        out.appendUTF8("\r\n--\(boundary)--\r\n")
        return out
    }

    /// Builds a multipart/signed RFC 3156 message.
    /// - `body` is expected to already be canonicalized (CRLF) because the same
    ///   bytes are hashed by gpg for the signature.
    /// - `micalg` must match the actual hash algorithm used by gpg; we pass it
    ///   through from the SIG_CREATED status line rather than hardcoding it.
    private nonisolated static func pgpMIMESigned(_ body: Data, signature: Data, micalg: String) -> Data {
        let boundary = "AlpSigBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let header = [
            "Content-Type: multipart/signed; boundary=\"\(boundary)\"; protocol=\"application/pgp-signature\"; micalg=\"\(micalg)\"",
            "",
            "--\(boundary)",
            "",
        ].joined(separator: "\r\n")
        var out = Data(header.utf8)
        out.append(body)
        let sigHeader = [
            "",
            "--\(boundary)",
            "Content-Type: application/pgp-signature; name=\"signature.asc\"",
            "Content-Description: OpenPGP digital signature",
            "Content-Disposition: attachment; filename=\"signature.asc\"",
            "",
            "",
        ].joined(separator: "\r\n")
        out.appendUTF8(sigHeader)
        out.append(signature)
        out.appendUTF8("\r\n--\(boundary)--\r\n")
        return out
    }

    /// Canonicalize a message body per RFC 3156 §5: normalize line endings to
    /// CRLF and ensure a trailing CRLF. The same byte sequence is then hashed
    /// for the signature and included in the multipart/signed body, so a
    /// receiving client sees identical bytes in both.
    private nonisolated static func canonicalizeForSigning(_ data: Data) -> Data {
        guard let text = String(data: data, encoding: .utf8) else {
            // If the body isn't valid UTF-8 we cannot safely normalize line
            // endings — just guarantee a trailing CRLF and return the bytes.
            var out = data
            if !out.hasSuffix([0x0D, 0x0A]) { out.append(contentsOf: [0x0D, 0x0A]) }
            return out
        }
        var normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        normalized = normalized.replacingOccurrences(of: "\n", with: "\r\n")
        if !normalized.hasSuffix("\r\n") { normalized += "\r\n" }
        return Data(normalized.utf8)
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

private extension Data {
    mutating func appendUTF8(_ string: String) {
        append(Data(string.utf8))
    }

    func hasSuffix(_ bytes: [UInt8]) -> Bool {
        guard count >= bytes.count else { return false }
        return suffix(bytes.count).elementsEqual(bytes)
    }
}
