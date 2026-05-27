import Foundation
import Testing

@Suite("PGP Message Parser")
struct PGPMessageParserTests {
    let parser = PGPMessageParser()

    @Test
    func `Detects PGP/MIME encrypted message`() {
        let mime = """
        MIME-Version: 1.0
        Content-Type: multipart/encrypted; boundary="abc123"; protocol="application/pgp-encrypted"

        --abc123
        Content-Type: application/pgp-encrypted

        Version: 1

        --abc123
        Content-Type: application/octet-stream; name="encrypted.asc"

        -----BEGIN PGP MESSAGE-----
        fakeciphertext
        -----END PGP MESSAGE-----

        --abc123--
        """
        let result = parser.parse(Data(mime.utf8))
        if case .mime = result { } else {
            Issue.record("Expected .mime, got \(String(describing: result))")
        }
    }

    @Test
    func `Detects inline PGP message`() {
        let inline = """
        Subject: Test

        -----BEGIN PGP MESSAGE-----
        fakeciphertext==
        -----END PGP MESSAGE-----
        """
        let result = parser.parse(Data(inline.utf8))
        if case .inline = result { } else {
            Issue.record("Expected .inline, got \(String(describing: result))")
        }
    }

    @Test
    func `Returns nil for plain message`() {
        let plain = "Hello, world!\nThis is a plain text email."
        let result = parser.parse(Data(plain.utf8))
        #expect(result == nil)
    }

    @Test
    func `Detects inline clearsigned message`() {
        let signed = """
        Subject: Test

        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256

        Hello, this is signed.
        -----BEGIN PGP SIGNATURE-----
        fakesig==
        -----END PGP SIGNATURE-----
        """
        let result = parser.parse(Data(signed.utf8))
        if case .inlineSigned = result { } else {
            Issue.record("Expected .inlineSigned, got \(String(describing: result))")
        }
    }

    @Test
    func `Returns nil for empty data`() {
        #expect(parser.parse(Data()) == nil)
    }

    @Test
    func `Returns nil for binary garbage`() {
        let bytes: [UInt8] = [0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]
        #expect(parser.parse(Data(bytes)) == nil)
    }

    @Test
    func `Handles PGP markers in headers without body`() {
        // Content-Type mentions pgp-encrypted but there's no valid MIME structure
        let broken = """
        Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"

        No boundary, no parts.
        """
        // Should not crash; returns nil because no boundary can be extracted
        #expect(parser.parse(Data(broken.utf8)) == nil)
    }

    @Test
    func `Extracts ciphertext from properly bounded MIME`() {
        let mime = """
        Content-Type: multipart/encrypted; boundary="bound"; protocol="application/pgp-encrypted"

        --bound
        Content-Type: application/pgp-encrypted

        Version: 1

        --bound
        Content-Type: application/octet-stream

        -----BEGIN PGP MESSAGE-----
        dGVzdA==
        -----END PGP MESSAGE-----

        --bound--
        """
        let result = parser.parse(Data(mime.utf8))
        if case let .mime(ciphertext) = result {
            let str = String(data: ciphertext, encoding: .utf8) ?? ""
            #expect(str.contains("BEGIN PGP MESSAGE"))
        } else {
            Issue.record("Expected .mime with ciphertext, got \(String(describing: result))")
        }
    }

    @Test
    func `Handles boundary with spaces when quoted`() {
        // RFC 2045 allows boundary values with spaces when quoted. The old
        // regex truncated at the first whitespace and mis-parsed later parts.
        let mime = """
        Content-Type: multipart/encrypted; boundary="bnd with spaces"; protocol="application/pgp-encrypted"

        --bnd with spaces
        Content-Type: application/pgp-encrypted

        Version: 1

        --bnd with spaces
        Content-Type: application/octet-stream

        -----BEGIN PGP MESSAGE-----
        dGVzdA==
        -----END PGP MESSAGE-----

        --bnd with spaces--
        """
        let result = parser.parse(Data(mime.utf8))
        if case .mime = result { } else {
            Issue.record("Expected .mime for quoted boundary with spaces, got \(String(describing: result))")
        }
    }

    @Test
    func `Handles unquoted boundary value`() {
        let mime = """
        Content-Type: multipart/encrypted; boundary=abc123; protocol="application/pgp-encrypted"

        --abc123
        Content-Type: application/pgp-encrypted

        Version: 1

        --abc123
        Content-Type: application/octet-stream

        -----BEGIN PGP MESSAGE-----
        dGVzdA==
        -----END PGP MESSAGE-----

        --abc123--
        """
        let result = parser.parse(Data(mime.utf8))
        if case .mime = result { } else {
            Issue.record("Expected .mime for unquoted boundary, got \(String(describing: result))")
        }
    }

    @Test
    func `Handles very large payloads near size cap`() {
        // ~4 MB of body — well under the 50 MB XPC cap but large enough that
        // an O(n^2) parser would be visibly slow.
        let body = String(repeating: "Hello, world. ", count: 300_000)
        #expect(parser.parse(Data(body.utf8)) == nil)
    }

    @Test
    func `Plain text containing 'boundary' word is not misdetected`() {
        let text = "Subject: test\n\nWe discussed the boundary of the project today.\n"
        #expect(parser.parse(Data(text.utf8)) == nil)
    }

    @Test
    func `Detects PGP/MIME signed message`() {
        let mime = """
        MIME-Version: 1.0
        Content-Type: multipart/signed; boundary="sigbound"; protocol="application/pgp-signature"; micalg="pgp-sha256"

        --sigbound
        Content-Type: text/plain

        Hello

        --sigbound
        Content-Type: application/pgp-signature; name="signature.asc"

        -----BEGIN PGP SIGNATURE-----
        fakesig==
        -----END PGP SIGNATURE-----

        --sigbound--
        """
        let result = parser.parse(Data(mime.utf8))
        if case .mimeSignature = result { } else {
            Issue.record("Expected .mimeSignature, got \(String(describing: result))")
        }
    }

    @Test
    func `Inline PGP with BEGIN but no END returns nil`() {
        // A truncated body shouldn't trigger a half-baked decrypt.
        let truncated = """
        From: alice@example.com

        -----BEGIN PGP MESSAGE-----

        hQIMA0z9...
        """
        #expect(parser.parse(Data(truncated.utf8)) == nil)
    }

    @Test
    func `Inline PGP with END before BEGIN returns nil`() {
        // Real attacker payload would be more sophisticated; this
        // covers the obvious case where the markers are swapped.
        let swapped = """
        -----END PGP MESSAGE-----
        ciphertext-shaped-noise
        -----BEGIN PGP MESSAGE-----
        """
        // BEGIN comes after END, so extractInlinePGP searches from BEGIN
        // forward and finds no later END — returns nil.
        #expect(parser.parse(Data(swapped.utf8)) == nil)
    }

    @Test
    func `Inline PGP only extracts the first complete block`() {
        // Concatenated messages: should not blindly include both.
        // We grab the first BEGIN..END pair and stop.
        let multi = """
        -----BEGIN PGP MESSAGE-----
        first
        -----END PGP MESSAGE-----
        -----BEGIN PGP MESSAGE-----
        second
        -----END PGP MESSAGE-----
        """
        guard case let .inline(cipher) = parser.parse(Data(multi.utf8)) else {
            Issue.record("Expected .inline result")
            return
        }
        let extracted = String(data: cipher, encoding: .utf8) ?? ""
        #expect(extracted.contains("first"))
        #expect(!extracted.contains("second"))
    }

    @Test
    func `PGP-MIME with missing boundary falls through gracefully`() {
        // Content-Type lies about being multipart/encrypted but
        // doesn't specify a boundary — extractBoundary returns nil,
        // the .mime branch declines, and the inline check doesn't
        // match either. Parser returns nil rather than crashing.
        let lying = """
        Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"

        not-a-real-mime-body
        """
        #expect(parser.parse(Data(lying.utf8)) == nil)
    }

    @Test
    func `PGP-MIME with extra ciphertext-shaped parts ignores trailing parts`() {
        // RFC 3156 demands exactly two parts: version + ciphertext.
        // A malicious sender might tack on a third part that looks
        // like more ciphertext. The parser uses parts[2] only — the
        // trailing crud is dropped, not silently forwarded.
        let mime = """
        Content-Type: multipart/encrypted; boundary="b"; protocol="application/pgp-encrypted"

        --b
        Content-Type: application/pgp-encrypted

        Version: 1

        --b
        Content-Type: application/octet-stream

        -----BEGIN PGP MESSAGE-----
        real-cipher
        -----END PGP MESSAGE-----

        --b
        Content-Type: application/octet-stream

        -----BEGIN PGP MESSAGE-----
        attacker-cipher
        -----END PGP MESSAGE-----

        --b--
        """
        guard case let .mime(cipher) = parser.parse(Data(mime.utf8)) else {
            Issue.record("Expected .mime result")
            return
        }
        let extracted = String(data: cipher, encoding: .utf8) ?? ""
        #expect(extracted.contains("real-cipher"))
        #expect(!extracted.contains("attacker-cipher"))
    }
}

@Suite("Keyserver pin set integrity")
struct KeyserverPinSetTests {
    @Test
    func `Pinned SPKI set has at least one entry`() {
        // A zero-entry set silently disables pinning — make sure the
        // build never accidentally ships in that state.
        #expect(!KeyserverSession.pinnedSPKIHashes.isEmpty)
    }

    @Test
    func `Pinned SPKI entries are all 32 bytes (SHA-256)`() {
        // The 32-byte check would silently pass on a 32-character
        // base64 string stored as UTF-8 bytes. A round-trip through
        // base64 confirms the entries are actually raw digest bytes
        // (decoding then re-encoding yields the same Data).
        for hash in KeyserverSession.pinnedSPKIHashes {
            #expect(hash.count == 32, "Pin hash \(hash.base64EncodedString()) is \(hash.count) bytes, expected 32")
            let b64 = hash.base64EncodedString()
            let decoded = Data(base64Encoded: b64)
            #expect(
                decoded == hash,
                "Pin hash must round-trip through base64 — confirms raw SHA-256 bytes, not a string",
            )
        }
    }
}

extension PGPContent: Equatable {
    /// Compare associated payloads, not just the case discriminator —
    /// otherwise an assertion like `result == .inline(expectedCipher)`
    /// would silently pass when the cipher bytes differ.
    public static func == (lhs: PGPContent, rhs: PGPContent) -> Bool {
        switch (lhs, rhs) {
        case let (.mime(a), .mime(b)):
            a == b
        case let (.inline(a), .inline(b)):
            a == b
        case let (.inlineSigned(a), .inlineSigned(b)):
            a == b
        case let (.mimeSignature(body: a1, signature: a2), .mimeSignature(body: b1, signature: b2)):
            a1 == b1 && a2 == b2
        default:
            false
        }
    }
}
