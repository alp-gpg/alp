import Foundation
import MailKit

// MARK: – PGP message types

enum PGPContent {
    /// RFC 3156 multipart/encrypted
    case mime(ciphertext: Data)
    /// Inline PGP (-----BEGIN PGP MESSAGE-----)
    case inline(ciphertext: Data)
    /// Inline clearsign (-----BEGIN PGP SIGNED MESSAGE-----)
    case inlineSigned(signedBody: Data)
    /// PGP/MIME detached signature: multipart/signed
    case mimeSignature(body: Data, signature: Data)
}

// MARK: – Parser

struct PGPMessageParser {
    static let pgpMimeEncryptedType = "multipart/encrypted"
    static let pgpMimeProtocol = "application/pgp-encrypted"
    static let pgpMimeSignedType = "multipart/signed"
    static let pgpMimeSignatureProtocol = "application/pgp-signature"

    static let beginPGPMessage = "-----BEGIN PGP MESSAGE-----"
    static let beginPGPSigned = "-----BEGIN PGP SIGNED MESSAGE-----"

    /// Parse raw RFC 822 message data and return detected PGP content, if any.
    func parse(_ messageData: Data) -> PGPContent? {
        guard let text = String(data: messageData, encoding: .utf8)
            ?? String(data: messageData, encoding: .isoLatin1)
        else { return nil }

        // Check for PGP/MIME encrypted
        if looksLikePGPMIMEEncrypted(text) {
            if let cipher = extractPGPMIMECiphertext(from: messageData) {
                return .mime(ciphertext: cipher)
            }
        }

        // Check for PGP/MIME signed
        if looksLikePGPMIMESigned(text) {
            if let (body, sig) = extractPGPMIMESignature(from: messageData) {
                return .mimeSignature(body: body, signature: sig)
            }
        }

        // Inline PGP — only when the message body itself *begins* with an
        // armor block. A plain email that merely quotes
        // "-----BEGIN PGP MESSAGE-----" (a tutorial, a forwarded thread) must
        // not be treated as encrypted: that would run gpg, possibly pop
        // pinentry, and show an error banner on perfectly readable mail (§3.3).
        let body = bodyText(text)
        if body.hasPrefix(Self.beginPGPMessage) {
            if let cipher = extractInlinePGP(from: text, marker: Self.beginPGPMessage) {
                return .inline(ciphertext: cipher)
            }
        }

        // Inline clearsign
        if body.hasPrefix(Self.beginPGPSigned) {
            if let body = messageData.nilIfEmpty {
                return .inlineSigned(signedBody: body)
            }
        }

        return nil
    }

    /// The message body (everything after the first blank line that separates
    /// RFC 822 headers from body), trimmed of surrounding whitespace. Used to
    /// require that inline-PGP armor appears at the *start* of the body rather
    /// than anywhere in it.
    private func bodyText(_ text: String) -> String {
        let afterHeaders: Substring = if let r = text.range(of: "\r\n\r\n") ?? text.range(of: "\n\n") {
            text[r.upperBound...]
        } else {
            text[...]
        }
        return afterHeaders.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: – Private helpers

    private func looksLikePGPMIMEEncrypted(_ text: String) -> Bool {
        text.localizedCaseInsensitiveContains(Self.pgpMimeEncryptedType) &&
            text.localizedCaseInsensitiveContains(Self.pgpMimeProtocol)
    }

    private func looksLikePGPMIMESigned(_ text: String) -> Bool {
        text.localizedCaseInsensitiveContains(Self.pgpMimeSignedType) &&
            text.localizedCaseInsensitiveContains(Self.pgpMimeSignatureProtocol)
    }

    /// Extract the second MIME body part (the actual ciphertext) from a
    /// multipart/encrypted message. Minimal MIME parsing — enough for RFC 3156.
    private func extractPGPMIMECiphertext(from data: Data) -> Data? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        // Find boundary
        guard let boundary = extractBoundary(from: text) else { return nil }
        let parts = text.components(separatedBy: "--\(boundary)")
        // parts[0] = preamble, parts[1] = version part, parts[2] = ciphertext part
        guard parts.count >= 3 else { return nil }
        let cipherPart = parts[2]
        // Strip MIME headers from the part
        if let bodyStart = cipherPart.range(of: "\r\n\r\n") ?? cipherPart.range(of: "\n\n") {
            let body = String(cipherPart[bodyStart.upperBound...])
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return body.data(using: .utf8)
        }
        return nil
    }

    private func extractPGPMIMESignature(from data: Data) -> (Data, Data)? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        guard let boundary = extractBoundary(from: text) else { return nil }

        // RFC 3156 §5: the detached signature covers the *entire* first MIME
        // part — its headers, body, and exact CRLFs — up to (but not
        // including) the CRLF that precedes the closing boundary delimiter.
        // Any header stripping, whitespace trimming, or String round-tripping
        // here changes the hashed bytes and makes genuinely valid signatures
        // (Thunderbird, GnuPG, Proton) read as "Invalid signature". So extract
        // the part as raw bytes, byte-for-byte.
        guard let body = firstPartRawBytes(in: data, boundary: boundary) else { return nil }
        guard let sig = extractArmoredBlock(from: text, begin: "-----BEGIN PGP SIGNATURE-----",
                                            end: "-----END PGP SIGNATURE-----") else { return nil }
        return (body, sig)
    }

    /// Byte-exact bytes of the first MIME part of a multipart/signed message:
    /// everything after the CRLF that ends the first `--boundary` delimiter
    /// line, up to (but excluding) the CRLF that precedes the next `--boundary`.
    private func firstPartRawBytes(in data: Data, boundary: String) -> Data? {
        let delim = Data("--\(boundary)".utf8)
        guard let firstDelim = data.range(of: delim) else { return nil }
        // Skip to the end of the boundary delimiter line (its terminating LF).
        guard let firstLF = data.range(of: Data([0x0A]), in: firstDelim.upperBound ..< data.endIndex)
        else { return nil }
        let partStart = firstLF.upperBound
        guard let nextDelim = data.range(of: delim, in: partStart ..< data.endIndex) else { return nil }
        // Exclude the CRLF (or bare LF) immediately before the boundary — it
        // belongs to the boundary, not the signed content.
        var partEnd = nextDelim.lowerBound
        if partEnd > partStart, data[data.index(before: partEnd)] == 0x0A {
            partEnd = data.index(before: partEnd)
            if partEnd > partStart, data[data.index(before: partEnd)] == 0x0D {
                partEnd = data.index(before: partEnd)
            }
        }
        guard partEnd >= partStart else { return nil }
        return data.subdata(in: partStart ..< partEnd)
    }

    /// Extract an ASCII-armored block (e.g. the detached signature) verbatim,
    /// including its BEGIN/END lines. Robust to surrounding MIME headers and
    /// transfer-encoding artifacts on the signature part.
    private func extractArmoredBlock(from text: String, begin: String, end: String) -> Data? {
        guard let s = text.range(of: begin),
              let e = text.range(of: end, range: s.lowerBound ..< text.endIndex) else { return nil }
        return String(text[s.lowerBound ..< e.upperBound]).data(using: .utf8)
    }

    private func extractBoundary(from text: String) -> String? {
        // RFC 2045 allows boundary values to contain spaces when quoted, so we
        // must match `boundary="..."` separately from the unquoted form —
        // otherwise a boundary like `boundary="abc def"` would truncate at the
        // space and mis-identify later MIME parts.
        if let match = text.firstMatch(of: #/boundary="([^"]+)"/#) {
            return String(match.1)
        }
        if let match = text.firstMatch(of: #/boundary=([^\s;]+)/#) {
            return String(match.1)
        }
        return nil
    }

    private func extractInlinePGP(from text: String, marker: String) -> Data? {
        extractArmoredBlock(from: text, begin: marker, end: "-----END PGP MESSAGE-----")
    }
}

private extension Data {
    var nilIfEmpty: Data? {
        isEmpty ? nil : self
    }
}
