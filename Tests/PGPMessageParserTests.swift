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
}

extension PGPContent: Equatable {
    public static func == (lhs: PGPContent, rhs: PGPContent) -> Bool {
        switch (lhs, rhs) {
        case (.mime, .mime), (.inline, .inline), (.inlineSigned, .inlineSigned), (.mimeSignature, .mimeSignature):
            true
        default:
            false
        }
    }
}
