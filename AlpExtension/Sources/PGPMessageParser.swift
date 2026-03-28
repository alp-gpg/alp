import Foundation
import MailKit

// MARK: – PGP message types

enum PGPContent: Sendable {
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

struct PGPMessageParser: Sendable {
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

        // Inline PGP encrypted
        if text.contains(Self.beginPGPMessage) {
            if let cipher = extractInlinePGP(from: text, marker: Self.beginPGPMessage) {
                return .inline(ciphertext: cipher)
            }
        }

        // Inline clearsign
        if text.contains(Self.beginPGPSigned) {
            if let body = messageData.nilIfEmpty {
                return .inlineSigned(signedBody: body)
            }
        }

        return nil
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
        let parts = text.components(separatedBy: "--\(boundary)")
        guard parts.count >= 3 else { return nil }

        func partBody(_ part: String) -> Data? {
            let stripped: String
            if let r = part.range(of: "\r\n\r\n") ?? part.range(of: "\n\n") {
                stripped = String(part[r.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
            } else {
                stripped = part.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            return stripped.data(using: .utf8)
        }

        guard let body = partBody(parts[1]), let sig = partBody(parts[2]) else { return nil }
        return (body, sig)
    }

    private func extractBoundary(from text: String) -> String? {
        // Look for: boundary="..." or boundary=...
        let pattern = #/boundary="?([^"\s;]+)"?/#
        if let match = text.firstMatch(of: pattern) {
            return String(match.1)
        }
        return nil
    }

    private func extractInlinePGP(from text: String, marker: String) -> Data? {
        guard let start = text.range(of: marker) else { return nil }
        let endMarker = "-----END PGP MESSAGE-----"
        guard let end = text.range(of: endMarker, range: start.lowerBound..<text.endIndex) else {
            return nil
        }
        let pgpText = String(text[start.lowerBound..<end.upperBound])
        return pgpText.data(using: .utf8)
    }
}

private extension Data {
    var nilIfEmpty: Data? { isEmpty ? nil : self }
}
