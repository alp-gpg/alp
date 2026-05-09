import Foundation
import Testing

@Suite("Autocrypt header parsing")
struct AutocryptHeaderTests {
    /// Real-shaped fixture: short fake key bytes encoded as base64. The
    /// parser doesn't care that the bytes aren't a valid OpenPGP packet —
    /// gpg validates that during import.
    private static let fakeKeyBase64 = "RmFrZUtleU1hdGVyaWFsRm9yQXV0b2NyeXB0VGVzdHM="

    @Test
    func `parses a single-line header`() {
        let raw = Data("""
        From: Alice <alice@example.com>\r
        Autocrypt: addr=alice@example.com; keydata=\(Self.fakeKeyBase64)\r
        Subject: Hi\r
        \r
        body
        """.utf8)
        let parsed = AutocryptHeader.parse(rawMessage: raw)
        #expect(parsed?.address == "alice@example.com")
        #expect(parsed?.keyData == Data(base64Encoded: Self.fakeKeyBase64))
        #expect(parsed?.preferMutual == false)
    }

    @Test
    func `unfolds keydata across continuation lines`() {
        let raw = Data("""
        From: alice@example.com\r
        Autocrypt: addr=alice@example.com; keydata=RmFrZUtleU1hdGVyaWFs\r
         Rm9yQXV0b2NyeXB0VGVzdHM=\r
        Subject: Hi\r
        \r
        """.utf8)
        let parsed = AutocryptHeader.parse(rawMessage: raw)
        #expect(parsed?.keyData == Data(base64Encoded: Self.fakeKeyBase64))
    }

    @Test
    func `captures prefer-encrypt mutual`() {
        let raw = Data(
            "From: alice@example.com\r\nAutocrypt: addr=alice@example.com; prefer-encrypt=mutual; keydata=\(Self.fakeKeyBase64)\r\n\r\n"
                .utf8,
        )
        let parsed = AutocryptHeader.parse(rawMessage: raw)
        #expect(parsed?.preferMutual == true)
    }

    @Test
    func `rejects malformed attribute pairs`() {
        let raw = Data(
            "From: a@b.co\r\nAutocrypt: addr=a@b.co; bare-attribute; keydata=\(Self.fakeKeyBase64)\r\n\r\n"
                .utf8,
        )
        #expect(AutocryptHeader.parse(rawMessage: raw) == nil)
    }

    @Test
    func `rejects unknown critical attribute`() {
        let raw = Data(
            "From: a@b.co\r\nAutocrypt: addr=a@b.co; critical=yes; keydata=\(Self.fakeKeyBase64)\r\n\r\n"
                .utf8,
        )
        #expect(AutocryptHeader.parse(rawMessage: raw) == nil)
    }

    @Test
    func `tolerates underscore-prefixed extension attributes`() {
        let raw = Data(
            "From: a@b.co\r\nAutocrypt: addr=a@b.co; _vendor=alp; keydata=\(Self.fakeKeyBase64)\r\n\r\n"
                .utf8,
        )
        #expect(AutocryptHeader.parse(rawMessage: raw) != nil)
    }

    @Test
    func `returns nil when keydata is missing`() {
        let raw = Data("From: a@b.co\r\nAutocrypt: addr=a@b.co\r\n\r\n".utf8)
        #expect(AutocryptHeader.parse(rawMessage: raw) == nil)
    }

    @Test
    func `returns nil when keydata is not valid base64`() {
        let raw = Data("From: a@b.co\r\nAutocrypt: addr=a@b.co; keydata=!!!\r\n\r\n".utf8)
        #expect(AutocryptHeader.parse(rawMessage: raw) == nil)
    }

    @Test
    func `parseAndValidate enforces matching From`() {
        let mismatch = Data(
            "From: bob@example.com\r\nAutocrypt: addr=alice@example.com; keydata=\(Self.fakeKeyBase64)\r\n\r\n"
                .utf8,
        )
        #expect(AutocryptHeader.parseAndValidate(rawMessage: mismatch) == nil)

        let match = Data(
            "From: \"Alice\" <alice@example.com>\r\nAutocrypt: addr=alice@example.com; keydata=\(Self.fakeKeyBase64)\r\n\r\n"
                .utf8,
        )
        #expect(AutocryptHeader.parseAndValidate(rawMessage: match)?.address == "alice@example.com")
    }

    @Test
    func `parseFromAddress strips display name and angle brackets`() {
        let cases: [(Data, String?)] = [
            (Data("From: Alice <alice@example.com>\r\n\r\n".utf8), "alice@example.com"),
            (Data("From: alice@example.com\r\n\r\n".utf8), "alice@example.com"),
            (Data("From: \"Quoted Name\" <qn@host.tld>\r\n\r\n".utf8), "qn@host.tld"),
            (Data("Subject: no from here\r\n\r\n".utf8), nil),
        ]
        for (raw, expected) in cases {
            #expect(AutocryptHeader.parseFromAddress(rawMessage: raw) == expected)
        }
    }
}
