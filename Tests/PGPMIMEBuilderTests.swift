import Foundation
import Testing

// Byte-level tests for the RFC 3156 assembly in SecurityHandler. These are the
// bytes Mail puts on the wire, and two invariants here are load-bearing:
//
//  1. Line endings must be uniformly the compose message's own. Mixing them
//     makes Mail's outgoing serializer ship an empty body (macOS 26.5) — see
//     OutgoingMIMEParser.detectEOL.
//  2. The signed part must survive assembly byte-for-byte. Those exact bytes
//     were hashed by gpg; one added or dropped octet invalidates the signature.
//
// Fixture parsing always goes through `try #require` rather than `?? Data()`:
// defaulting to empty would let a splitEnvelope regression satisfy
// `recoveredBody == body` with empty == empty, turning the most important
// assertion here into a no-op.

/// A realistic single-part compose message with `eol` terminators.
private func composeMessage(eol: String) -> Data {
    Data([
        "From: Alice <alice@example.invalid>",
        "To: Bob <bob@example.invalid>",
        "Subject: Test",
        "Message-ID: <abc123@example.invalid>",
        "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Transfer-Encoding: 7bit",
        "",
        "Hello, world.",
        "",
    ].joined(separator: eol).utf8)
}

private func armoredMessage(eol: String) -> Data {
    Data([
        "-----BEGIN PGP MESSAGE-----",
        "",
        "hQIMAzZ1example+ciphertext/payload==",
        "=aBcD",
        "-----END PGP MESSAGE-----",
        "",
    ].joined(separator: eol).utf8)
}

private func armoredSignature(eol: String) -> Data {
    Data([
        "-----BEGIN PGP SIGNATURE-----",
        "",
        "iQIzBAABCgAexample+signature/payload==",
        "=Zx91",
        "-----END PGP SIGNATURE-----",
        "",
    ].joined(separator: eol).utf8)
}

/// True when every line terminator in `data` is exactly `eol`. Both directions
/// are checked in CRLF mode — a bare LF *and* a lone CR are both failures, since
/// either one means two EOL conventions got mixed into one message.
private func usesOnly(_ eol: String, in data: Data) -> Bool {
    if eol == "\n" {
        return !data.contains(0x0D)
    }
    var previous: UInt8 = 0
    for byte in data {
        if byte == 0x0A, previous != 0x0D {
            return false
        }
        if previous == 0x0D, byte != 0x0A {
            return false
        }
        previous = byte
    }
    return previous != 0x0D
}

private func text(_ data: Data) -> String {
    // Failable initializer on purpose: every builder here must emit valid UTF-8,
    // so lossy repair would hide exactly the corruption worth failing on.
    String(bytes: data, encoding: .utf8) ?? "<not utf-8>"
}

private func trimmed(_ data: Data) -> String {
    text(data).trimmingCharacters(in: .whitespacesAndNewlines)
}

@Suite("PGP/MIME encrypted assembly")
struct PGPMIMEEncryptedTests {
    @Test
    func `round-trips through our own decoder`() throws {
        let raw = composeMessage(eol: "\r\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let ciphertext = armoredMessage(eol: "\r\n")
        let built = SecurityHandler.pgpMIMEEncrypted(
            ciphertext, envelopeHeaders: envelope.outerHeaders, eol: "\r\n",
        )
        guard case let .mime(recovered)? = PGPMessageParser().parse(built) else {
            Issue.record("built message did not parse as PGP/MIME encrypted")
            return
        }
        #expect(trimmed(recovered) == trimmed(ciphertext))
    }

    @Test
    func `keeps the routing envelope on the outer message`() throws {
        // Mail reads From/To off the outer headers to pick the sending account;
        // losing them makes the send abort on an empty recipient set (§ encode).
        let raw = composeMessage(eol: "\r\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\r\n"), envelopeHeaders: envelope.outerHeaders, eol: "\r\n",
        )
        let out = text(built)
        #expect(out.hasPrefix("From: Alice <alice@example.invalid>"))
        #expect(out.contains("To: Bob <bob@example.invalid>"))
        #expect(out.contains("Subject: Test"))
        #expect(out.contains("Message-ID: <abc123@example.invalid>"))
    }

    @Test
    func `emits exactly one MIME-Version`() throws {
        // splitEnvelope drops the original; the builder adds its own. Two of
        // them is a malformed message.
        let raw = composeMessage(eol: "\r\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\r\n"), envelopeHeaders: envelope.outerHeaders, eol: "\r\n",
        )
        #expect(text(built).components(separatedBy: "MIME-Version:").count - 1 == 1)
    }

    @Test
    func `carries the RFC 3156 protocol parameter and version part`() {
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\r\n"), envelopeHeaders: Data("Subject: x".utf8), eol: "\r\n",
        )
        let out = text(built)
        #expect(out.contains("Content-Type: multipart/encrypted"))
        #expect(out.contains("protocol=\"application/pgp-encrypted\""))
        #expect(out.contains("Content-Type: application/pgp-encrypted"))
        #expect(out.contains("Version: 1"))
    }

    @Test
    func `opens two parts and closes the multipart`() throws {
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\r\n"), envelopeHeaders: Data("Subject: x".utf8), eol: "\r\n",
        )
        let out = text(built)
        let boundary = try #require(out.firstMatch(of: #/boundary="([^"]+)"/#)?.1)
        // 2 opening delimiters + 1 closing.
        #expect(out.components(separatedBy: "--\(boundary)").count - 1 == 3)
        #expect(out.hasSuffix("--\(boundary)--\r\n"))
    }

    @Test
    func `uses CRLF throughout when the compose message is CRLF`() throws {
        let raw = composeMessage(eol: "\r\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\r\n"), envelopeHeaders: envelope.outerHeaders, eol: "\r\n",
        )
        #expect(usesOnly("\r\n", in: built))
    }

    @Test
    func `uses LF throughout when the compose message is LF`() throws {
        let raw = composeMessage(eol: "\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\n"), envelopeHeaders: envelope.outerHeaders, eol: "\n",
        )
        #expect(usesOnly("\n", in: built))
    }

    @Test
    func `normalizes CRLF ciphertext down to an LF message`() {
        // gpg's armor output is CRLF-agnostic; the builder must not smuggle a
        // foreign terminator into an LF message.
        let built = SecurityHandler.pgpMIMEEncrypted(
            armoredMessage(eol: "\r\n"), envelopeHeaders: Data("Subject: x".utf8), eol: "\n",
        )
        #expect(usesOnly("\n", in: built))
    }
}

@Suite("PGP/MIME signed assembly")
struct PGPMIMESignedTests {
    @Test
    func `preserves the signed bytes exactly`() throws {
        // The single most important assertion in this file: gpg hashed these
        // exact octets. Any re-wrapping here silently breaks every signature.
        let raw = composeMessage(eol: "\r\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let body = envelope.contentEntity
        try #require(!body.isEmpty)
        let built = SecurityHandler.pgpMIMESigned(
            body, signature: armoredSignature(eol: "\r\n"), micalg: "pgp-sha512",
            envelopeHeaders: envelope.outerHeaders, eol: "\r\n",
        )
        guard case let .mimeSignature(recoveredBody, recoveredSig)? = PGPMessageParser().parse(built) else {
            Issue.record("built message did not parse as PGP/MIME signed")
            return
        }
        #expect(recoveredBody == body)
        #expect(trimmed(recoveredSig) == trimmed(armoredSignature(eol: "\r\n")))
    }

    @Test
    func `passes micalg through instead of hardcoding it`() {
        // micalg comes from gpg's SIG_CREATED status line. A hardcoded value
        // makes verification fail the moment the user's key prefers another
        // digest, so assert two different algorithms land verbatim.
        for algorithm in ["pgp-sha512", "pgp-sha3-512"] {
            let built = SecurityHandler.pgpMIMESigned(
                Data("Content-Type: text/plain\r\n\r\nhi\r\n".utf8),
                signature: armoredSignature(eol: "\r\n"), micalg: algorithm,
                envelopeHeaders: Data("Subject: x".utf8), eol: "\r\n",
            )
            #expect(text(built).contains("micalg=\"\(algorithm)\""))
        }
    }

    @Test
    func `carries the RFC 3156 signature protocol and disposition`() {
        let built = SecurityHandler.pgpMIMESigned(
            Data("Content-Type: text/plain\r\n\r\nhi\r\n".utf8),
            signature: armoredSignature(eol: "\r\n"), micalg: "pgp-sha512",
            envelopeHeaders: Data("Subject: x".utf8), eol: "\r\n",
        )
        let out = text(built)
        #expect(out.contains("Content-Type: multipart/signed"))
        #expect(out.contains("protocol=\"application/pgp-signature\""))
        #expect(out.contains("Content-Type: application/pgp-signature; name=\"signature.asc\""))
        #expect(out.contains("Content-Disposition: attachment; filename=\"signature.asc\""))
    }

    @Test
    func `opens two parts and closes the multipart`() throws {
        let built = SecurityHandler.pgpMIMESigned(
            Data("Content-Type: text/plain\r\n\r\nhi\r\n".utf8),
            signature: armoredSignature(eol: "\r\n"), micalg: "pgp-sha512",
            envelopeHeaders: Data("Subject: x".utf8), eol: "\r\n",
        )
        let out = text(built)
        let boundary = try #require(out.firstMatch(of: #/boundary="([^"]+)"/#)?.1)
        #expect(out.components(separatedBy: "--\(boundary)").count - 1 == 3)
        #expect(out.hasSuffix("--\(boundary)--\r\n"))
    }

    @Test
    func `uses LF throughout when the compose message is LF`() throws {
        let raw = composeMessage(eol: "\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let body = OutgoingMIMEParser.normalizingEOL(envelope.contentEntity, to: "\n")
        let built = SecurityHandler.pgpMIMESigned(
            body, signature: armoredSignature(eol: "\r\n"), micalg: "pgp-sha512",
            envelopeHeaders: envelope.outerHeaders, eol: "\n",
        )
        #expect(usesOnly("\n", in: built))
    }

    @Test
    func `keeps the routing envelope on the outer message`() throws {
        let raw = composeMessage(eol: "\r\n")
        let envelope = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let built = SecurityHandler.pgpMIMESigned(
            envelope.contentEntity, signature: armoredSignature(eol: "\r\n"),
            micalg: "pgp-sha512", envelopeHeaders: envelope.outerHeaders, eol: "\r\n",
        )
        let out = text(built)
        #expect(out.hasPrefix("From: Alice <alice@example.invalid>"))
        #expect(out.contains("To: Bob <bob@example.invalid>"))
    }
}

@Suite("Inline PGP assembly")
struct InlinePGPMessageTests {
    @Test
    func `round-trips through our own decoder`() throws {
        let raw = composeMessage(eol: "\r\n")
        let parsed = try #require(OutgoingMIMEParser.split(raw))
        let ciphertext = armoredMessage(eol: "\r\n")
        let built = SecurityHandler.inlinePGPMessage(
            headers: parsed.headers, body: ciphertext, eol: "\r\n",
        )
        guard case let .inline(recovered)? = PGPMessageParser().parse(built) else {
            Issue.record("built message did not parse as inline PGP")
            return
        }
        #expect(trimmed(recovered) == trimmed(ciphertext))
    }

    @Test
    func `rewrites the content headers to plain 7bit text`() throws {
        // Armored ciphertext is literal ASCII in a text/plain part; an
        // inherited text/html Content-Type would make the recipient render the
        // armor as markup. Only 8bit is used here because split() refuses
        // quoted-printable and base64 bodies outright, so inline mode can never
        // be handed one — that fallback is covered in OutgoingMIMEParserTests.
        let raw = Data([
            "Subject: x",
            "Content-Type: text/html; charset=utf-8",
            "Content-Transfer-Encoding: 8bit",
            "",
            "<p>hi</p>",
        ].joined(separator: "\r\n").utf8)
        let parsed = try #require(OutgoingMIMEParser.split(raw))
        let built = SecurityHandler.inlinePGPMessage(
            headers: parsed.headers, body: armoredMessage(eol: "\r\n"), eol: "\r\n",
        )
        let out = text(built)
        #expect(out.contains("Content-Type: text/plain; charset=utf-8"))
        #expect(out.contains("Content-Transfer-Encoding: 7bit"))
        #expect(!out.contains("text/html"))
        #expect(!out.contains("8bit"))
        #expect(out.contains("Subject: x"))
    }

    @Test
    func `separates headers from body with exactly one blank line`() throws {
        let parsed = try #require(OutgoingMIMEParser.split(composeMessage(eol: "\r\n")))
        let built = SecurityHandler.inlinePGPMessage(
            headers: parsed.headers, body: armoredMessage(eol: "\r\n"), eol: "\r\n",
        )
        #expect(text(built).contains("7bit\r\n\r\n-----BEGIN PGP MESSAGE-----"))
    }

    @Test
    func `uses LF throughout when the compose message is LF`() throws {
        let parsed = try #require(OutgoingMIMEParser.split(composeMessage(eol: "\n")))
        let built = SecurityHandler.inlinePGPMessage(
            headers: parsed.headers, body: armoredMessage(eol: "\r\n"), eol: "\n",
        )
        #expect(usesOnly("\n", in: built))
    }
}
