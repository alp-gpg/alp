import Testing
@testable import AlpHelper

@Suite("PGP Message Parser")
struct PGPMessageParserTests {
    let parser = PGPMessageParser()

    @Test("Detects PGP/MIME encrypted message")
    func detectsMIMEEncrypted() {
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

    @Test("Detects inline PGP message")
    func detectsInlinePGP() {
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

    @Test("Returns nil for plain message")
    func returnsNilForPlain() {
        let plain = "Hello, world!\nThis is a plain text email."
        let result = parser.parse(Data(plain.utf8))
        #expect(result == nil)
    }

    @Test("Detects PGP/MIME signed message")
    func detectsMIMESigned() {
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
