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

    /// "Encrypt to my own key" toggle (default ON). Read on demand — a local
    /// `UserDefaults` keeps this `nonisolated`-safe without a shared instance.
    private nonisolated static func encryptToSelfEnabled() -> Bool {
        UserDefaults(suiteName: BuildConfig.appGroup)?
            .object(forKey: BuildConfig.DefaultsKey.encryptToSelf) as? Bool ?? true
    }

    override nonisolated init() {
        super.init()
    }

    // MARK: – MEMessageSecurityHandler (optional UI)

    nonisolated func extensionViewController(signers _: [MEMessageSigner]) -> MEExtensionViewController? {
        nil
    }

    nonisolated func extensionViewController(messageContext _: Data) -> MEExtensionViewController? {
        nil
    }

    nonisolated func primaryActionClicked(forMessageContext _: Data) async -> MEExtensionViewController? {
        nil
    }

    // MARK: – MEMessageDecoder

    nonisolated func decodedMessage(forMessageData data: Data) -> MEDecodedMessage? {
        let sema = DispatchSemaphore(value: 0)
        nonisolated(unsafe) var decoded: MEDecodedMessage?
        let parser = parser
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
        completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void,
    ) {
        // Extract values synchronously on the calling thread, then do async work.
        let allAddresses = message.allRecipientAddresses
        let emails = allAddresses.map { $0.addressString ?? $0.rawString }
        // Encrypt/sign intent comes from Mail's native security UI — the single
        // source of truth — not from any Alp-side toggle.
        let shouldEncrypt = composeContext.shouldEncrypt
        // MailKit's completion handlers aren't annotated @Sendable but are
        // designed to be invoked from arbitrary XPC callback queues. Use
        // nonisolated(unsafe) so the detached Task can capture the handler
        // without unsafeBitCast lying about the type.
        nonisolated(unsafe) let handler = completionHandler

        Task.detached {
            // A missing-key error is only meaningful when the user actually
            // intends to encrypt (§5.3).

            var missingEmails: [String] = []
            var helperDown = false
            for email in emails {
                do {
                    let (found, _) = try await GPGXPCClient.shared.publicKeyExists(email: email)
                    if !found {
                        missingEmails.append(email)
                    }
                } catch GPGError.xpcUnavailable {
                    helperDown = true
                    break
                } catch {
                    missingEmails.append(email)
                }
            }

            // Helper not running: surface the actionable "helper not running"
            // text rather than the cryptic "Missing public keys for: <everyone>".
            if helperDown {
                handler(MEOutgoingMessageEncodingStatus(
                    canSign: true,
                    canEncrypt: false,
                    securityError: shouldEncrypt ? GPGError.xpcUnavailable.asNSError : nil,
                    addressesFailingEncryption: [],
                ))
                return
            }

            let missingAddresses = missingEmails.map { MEEmailAddress(rawString: $0) }
            let encryptionError: NSError? = (shouldEncrypt && !missingEmails.isEmpty) ?
                NSError(domain: MEMessageSecurityErrorDomain,
                        code: 0,
                        userInfo: [NSLocalizedDescriptionKey:
                            "Missing public keys for: \(missingEmails.joined(separator: ", "))"]) : nil
            handler(MEOutgoingMessageEncodingStatus(
                canSign: true,
                canEncrypt: missingEmails.isEmpty,
                securityError: encryptionError,
                addressesFailingEncryption: missingAddresses,
            ))
        }
    }

    nonisolated func encode(
        _ message: MEMessage,
        composeContext: MEComposeContext,
        completionHandler: @escaping (MEMessageEncodingResult) -> Void,
    ) {
        // Extract all needed values synchronously before the async boundary.
        let rawData = message.rawData
        let recipientEmails = message.allRecipientAddresses.map { $0.addressString ?? $0.rawString }
        let contextID = composeContext.contextID
        // Sign/encrypt decision = Mail's native security UI (source of truth).
        // The popover only contributes the signer key + inline-PGP choice.
        let shouldSign = composeContext.shouldSign
        let shouldEncrypt = composeContext.shouldEncrypt
        nonisolated(unsafe) let handler = completionHandler

        Task.detached {
            let (signerFP, useInlinePGP) = await MainActor.run {
                ComposeSessionStore.shared.state(forContextID: contextID)
            }

            // "Encrypt to my own key" (default ON): add the user's own key as a
            // recipient so their Sent items remain decryptable. The signer
            // fingerprint is the user's own key and is populated even when
            // signing is off, so it doubles as the self-encryption key.
            let encryptToSelf = Self.encryptToSelfEnabled()

            do {
                let encoded = try await Self.buildOutgoing(
                    rawData: rawData,
                    recipientEmails: recipientEmails,
                    shouldSign: shouldSign,
                    shouldEncrypt: shouldEncrypt,
                    signerFingerprint: signerFP,
                    useInlinePGP: useInlinePGP,
                    selfFingerprint: encryptToSelf ? signerFP : nil,
                )
                handler(MEMessageEncodingResult(
                    encodedMessage: encoded, signingError: nil, encryptionError: nil,
                ))
            } catch {
                // Log the error TYPE only — never its message, which can carry a
                // recipient address or key detail. This is the one place we learn
                // why an encode failed.
                log.error("encode failed: \(String(describing: type(of: error)), privacy: .public)")
                let nsError = Self.mailKitError(for: error, isEncoding: true)
                // Classify by intent: a sign-only message has no encryption step,
                // so its failure must surface as a signing error — otherwise Mail
                // shows the misleading "couldn't encrypt" alert on a sign action.
                handler(MEMessageEncodingResult(
                    encodedMessage: nil,
                    signingError: shouldEncrypt ? nil : nsError,
                    encryptionError: shouldEncrypt ? nsError : nil,
                ))
            }
        }
    }

    // MARK: – Decode implementation

    private nonisolated static func decrypt(data: Data, parser: PGPMessageParser) async -> MEDecodedMessage? {
        guard let pgp = parser.parse(data) else {
            // Not a PGP message: return nil so Mail keeps its own rendering
            // path instead of routing the message through the extension's
            // re-serialization for nothing (§3.3).
            return nil
        }
        log.info("PGP content detected")
        do {
            switch pgp {
            case let .mime(cipher), let .inline(cipher):
                let (plain, signer, signerName) = try await GPGXPCClient.shared.decrypt(cipher)
                log.info("Decrypted successfully")
                // gpg returns only the decrypted MIME entity (Content-* +
                // body). Mail parses the bytes we return as the *complete*
                // message — its post-send indexer reads sender/subject out of
                // them and aborts on nil (-[__NSSetM addObject:]) if the
                // envelope is missing. Re-attach the original envelope.
                return MEDecodedMessage(
                    data: OutgoingMIMEParser.mergingEnvelope(of: data, withEntity: plain),
                    securityInformation: MEMessageSecurityInformation(
                        signers: makeSigner(signer, displayName: signerName), isEncrypted: true,
                        signingError: nil, encryptionError: nil,
                    ),
                    context: nil,
                )

            case let .inlineSigned(body):
                let (valid, signer, signerName) = try await GPGXPCClient.shared.verify(body)
                return MEDecodedMessage(
                    data: data,
                    securityInformation: MEMessageSecurityInformation(
                        signers: makeSigner(signer, displayName: signerName), isEncrypted: false,
                        signingError: valid ? nil : mailKitError(code: 1, description: "Invalid signature"),
                        encryptionError: nil,
                    ),
                    context: nil,
                )

            case let .mimeSignature(body, sig):
                let (valid, signer, signerName) = try await GPGXPCClient.shared.verify(body, signature: sig)
                return MEDecodedMessage(
                    data: data,
                    securityInformation: MEMessageSecurityInformation(
                        signers: makeSigner(signer, displayName: signerName), isEncrypted: false,
                        signingError: valid ? nil : mailKitError(code: 1, description: "Invalid signature"),
                        encryptionError: nil,
                    ),
                    context: nil,
                )
            }
        } catch {
            log.error("Decrypt failed")
            // Per MEDecodedMessage.h: when decryption fails rawData "should be
            // left nil and an error message will be displayed to the user".
            // Returning the original bytes instead makes Mail render raw
            // armored ciphertext as the message body.
            return MEDecodedMessage(
                data: nil,
                securityInformation: MEMessageSecurityInformation(
                    signers: [], isEncrypted: false,
                    signingError: nil,
                    encryptionError: mailKitError(for: error, isEncoding: false),
                ),
                context: nil,
            )
        }
    }

    // MARK: – Encode implementation

    private nonisolated static func buildOutgoing(
        rawData: Data?,
        recipientEmails: [String],
        shouldSign: Bool,
        shouldEncrypt: Bool,
        signerFingerprint: String?,
        useInlinePGP: Bool = false,
        selfFingerprint: String? = nil,
    ) async throws -> MEEncodedOutgoingMessage {
        guard let rawData else {
            throw GPGError.encodingError("MEMessage has no rawData")
        }

        // Strip Bcc before anything is signed or encrypted: the result is read
        // by every recipient, so a Bcc header riding inside the signed visible
        // part or the encrypted payload would leak the blind-copy list to all
        // of them. Mail delivers Bcc via the compose session's recipient list,
        // not via a header in the bytes we return, so removing it here is safe
        // (§5.5). The plaintext passthrough below keeps the original rawData.
        let payload = (shouldSign || shouldEncrypt)
            ? OutgoingMIMEParser.removingHeader("Bcc", from: rawData)
            : rawData

        // Everything below emits the compose message's own line endings: Mail's
        // outgoing serializer mis-parses a returned message whose EOLs differ
        // from the compose bytes and ships it with an empty/flattened body
        // (macOS 26.5 — verified on the wire; ref mahaupt/mailgpg, which hit
        // the same and matches EOL). splitEnvelope preserves the original EOL;
        // the builders join synthesized headers with `eol` and rewrite gpg's
        // bare-LF armor to it. The detached signature stays valid either way
        // because the helper signs in canonical text mode (--textmode).
        let eol = OutgoingMIMEParser.detectEOL(in: rawData)

        // Inline mode is only viable for single-part text bodies because
        // armored ciphertext has to land in a plain text/plain part —
        // multipart messages with attachments fall back to PGP/MIME
        // silently rather than refuse to send.
        let inlineCandidate = useInlinePGP ? OutgoingMIMEParser.split(payload) : nil

        if shouldEncrypt {
            var fingerprints: [String] = []
            for email in recipientEmails {
                let (found, fp) = try await GPGXPCClient.shared.publicKeyExists(email: email)
                guard found, let fp else { throw GPGError.missingKeys([email]) }
                fingerprints.append(fp)
            }
            // Encrypt-to-self: append the user's own key so their Sent copy is
            // decryptable. Deduplicated so a user who is also an explicit
            // recipient isn't added twice.
            if let selfFingerprint, !fingerprints.contains(selfFingerprint) {
                fingerprints.append(selfFingerprint)
            }
            if let parsed = inlineCandidate {
                let ciphertext = try await GPGXPCClient.shared.encrypt(
                    parsed.body,
                    recipients: fingerprints,
                    signer: shouldSign ? signerFingerprint : nil,
                )
                return MEEncodedOutgoingMessage(
                    rawData: inlinePGPMessage(headers: parsed.headers, body: ciphertext, eol: eol),
                    isSigned: shouldSign, isEncrypted: true,
                )
            }
            // PGP/MIME: the original envelope (To/From/Subject/Date/…) stays on
            // the outer message; only the content entity is encrypted (RFC 3156).
            guard let envelope = OutgoingMIMEParser.splitEnvelope(payload) else {
                throw GPGError.encodingError("could not split outgoing message headers")
            }
            let ciphertext = try await GPGXPCClient.shared.encrypt(
                envelope.contentEntity,
                recipients: fingerprints,
                signer: shouldSign ? signerFingerprint : nil,
            )
            return MEEncodedOutgoingMessage(
                rawData: pgpMIMEEncrypted(ciphertext, envelopeHeaders: envelope.outerHeaders, eol: eol),
                isSigned: shouldSign, isEncrypted: true,
            )
        }

        if shouldSign {
            guard let fp = signerFingerprint else { throw GPGError.noSigningKey }
            guard let envelope = OutgoingMIMEParser.splitEnvelope(payload) else {
                throw GPGError.encodingError("could not split outgoing message headers")
            }
            // Normalize the signed part to the shipping EOL and sign those
            // exact bytes. The helper signs with --textmode (canonical text,
            // RFC 4880 class 0x01), so verification is EOL-independent — the
            // signature survives SMTP re-normalizing LF to CRLF on the wire.
            let canonicalBody = OutgoingMIMEParser.normalizingEOL(envelope.contentEntity, to: eol)
            let (signature, micalg) = try await GPGXPCClient.shared.sign(canonicalBody, signer: fp)
            return MEEncodedOutgoingMessage(
                rawData: pgpMIMESigned(
                    canonicalBody, signature: signature, micalg: micalg,
                    envelopeHeaders: envelope.outerHeaders, eol: eol,
                ),
                isSigned: true, isEncrypted: false,
            )
        }

        return MEEncodedOutgoingMessage(rawData: rawData, isSigned: false, isEncrypted: false)
    }

    /// Replaces the body of an outgoing RFC 822 message with `body`, rewriting
    /// the Content-Type and Content-Transfer-Encoding headers to text/plain.
    /// Original headers like Subject, From, To, Date, Message-ID survive.
    private nonisolated static func inlinePGPMessage(headers: Data, body: Data, eol: Data) -> Data {
        let rewritten = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers)
        // rewriteContentTypeHeaders re-emits CRLF joins; bring the header block
        // to the message EOL (it ends with one), then a blank line, then armor.
        var out = OutgoingMIMEParser.normalizingEOL(rewritten, to: eol)
        out.append(eol)
        out.append(normalizedArmor(body, eol: eol))
        return out
    }

    /// gpg emits bare-LF ASCII armor; rewrite it to the message EOL. Binary
    /// (non-armored) output passes through untouched — EOL rewriting would
    /// corrupt it. The helper always passes --armor today; this guard keeps
    /// that invariant local instead of trusting it at a distance.
    private nonisolated static func normalizedArmor(_ data: Data, eol: Data) -> Data {
        data.starts(with: Data("-----BEGIN PGP".utf8))
            ? OutgoingMIMEParser.normalizingEOL(data, to: eol) : data
    }

    // MARK: – PGP/MIME builders

    /// Builds a multipart/encrypted RFC 3156 message with the routing envelope
    /// on the outer message (Mail reads the sender from it to pick an account).
    /// Every line terminator is `eol` — the compose message's own, which Mail's
    /// serializer requires (see buildOutgoing).
    private nonisolated static func pgpMIMEEncrypted(_ ciphertext: Data, envelopeHeaders: Data, eol: Data) -> Data {
        let ciphertext = normalizedArmor(ciphertext, eol: eol)
        let sep = eol == Data([0x0A]) ? "\n" : "\r\n"
        let boundary = "AlpBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let header = [
            "MIME-Version: 1.0",
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
            "", // trailing empty = extra EOL before body
        ].joined(separator: sep)
        var out = Data()
        out.append(envelopeHeaders)
        out.append(eol)
        out.append(Data(header.utf8))
        out.append(ciphertext)
        out.append(Data("\(sep)--\(boundary)--\(sep)".utf8))
        return out
    }

    /// Builds a multipart/signed RFC 3156 message with `eol` terminators.
    /// - `body` must already be normalized to `eol` — the same bytes were
    ///   hashed by gpg (in canonical text mode) for the signature.
    /// - `micalg` must match the actual hash algorithm used by gpg; we pass it
    ///   through from the SIG_CREATED status line rather than hardcoding it.
    private nonisolated static func pgpMIMESigned(
        _ body: Data, signature: Data, micalg: String, envelopeHeaders: Data, eol: Data,
    ) -> Data {
        let signature = normalizedArmor(signature, eol: eol)
        let sep = eol == Data([0x0A]) ? "\n" : "\r\n"
        let boundary = "AlpSigBoundary\(UUID().uuidString.replacingOccurrences(of: "-", with: ""))"
        let header = [
            "MIME-Version: 1.0",
            "Content-Type: multipart/signed; boundary=\"\(boundary)\"; protocol=\"application/pgp-signature\"; micalg=\"\(micalg)\"",
            "",
            "--\(boundary)",
            "",
        ].joined(separator: sep)
        var out = Data()
        out.append(envelopeHeaders)
        out.append(eol)
        out.append(Data(header.utf8))
        out.append(body)
        let sigHeader = [
            "",
            "--\(boundary)",
            "Content-Type: application/pgp-signature; name=\"signature.asc\"",
            "Content-Description: OpenPGP digital signature",
            "Content-Disposition: attachment; filename=\"signature.asc\"",
            "",
            "",
        ].joined(separator: sep)
        out.append(Data(sigHeader.utf8))
        out.append(signature)
        out.append(Data("\(sep)--\(boundary)--\(sep)".utf8))
        return out
    }

    // MARK: – Helpers

    private nonisolated static func makeSigner(_ fingerprint: String?, displayName: String?) -> [MEMessageSigner] {
        guard let fingerprint else { return [] }
        let label = displayName ?? String(fingerprint.prefix(16))
        return [MEMessageSigner(
            emailAddresses: [],
            signatureLabel: label,
            context: fingerprint.data(using: .utf8),
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
            userInfo: [NSLocalizedDescriptionKey: description],
        )
    }
}

private extension MEMessageSecurityInformation {
    static var notSecured: MEMessageSecurityInformation {
        MEMessageSecurityInformation(signers: [], isEncrypted: false, signingError: nil, encryptionError: nil)
    }
}
