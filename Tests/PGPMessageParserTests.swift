import Foundation
import Testing

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

    @Test("Detects inline clearsigned message")
    func detectsInlineClearsigned() {
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

    @Test("Returns nil for empty data")
    func emptyData() {
        #expect(parser.parse(Data()) == nil)
    }

    @Test("Returns nil for binary garbage")
    func binaryGarbage() {
        let bytes: [UInt8] = [0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90]
        #expect(parser.parse(Data(bytes)) == nil)
    }

    @Test("Handles PGP markers in headers without body")
    func pgpMarkerInHeaderOnly() {
        // Content-Type mentions pgp-encrypted but there's no valid MIME structure
        let broken = """
        Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"

        No boundary, no parts.
        """
        // Should not crash; returns nil because no boundary can be extracted
        #expect(parser.parse(Data(broken.utf8)) == nil)
    }

    @Test("Extracts ciphertext from properly bounded MIME")
    func extractsCiphertext() {
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
        if case .mime(let ciphertext) = result {
            let str = String(data: ciphertext, encoding: .utf8) ?? ""
            #expect(str.contains("BEGIN PGP MESSAGE"))
        } else {
            Issue.record("Expected .mime with ciphertext, got \(String(describing: result))")
        }
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
