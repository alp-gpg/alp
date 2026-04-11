import Foundation
import Testing

@Suite("GPGHelper input validation")
struct GPGHelperValidationTests {
    @Test("isValidFingerprint accepts 40-char hex")
    func acceptsValidFingerprint() {
        #expect(GPGHelper.isValidFingerprint("ABCDEF0123456789ABCDEF0123456789ABCDEF01"))
        #expect(GPGHelper.isValidFingerprint("abcdef0123456789abcdef0123456789abcdef01"))
    }

    @Test("isValidFingerprint rejects wrong length")
    func rejectsWrongLength() {
        #expect(!GPGHelper.isValidFingerprint(""))
        #expect(!GPGHelper.isValidFingerprint("ABCDEF"))
        #expect(!GPGHelper.isValidFingerprint(String(repeating: "A", count: 41)))
    }

    @Test("isValidFingerprint rejects non-hex characters")
    func rejectsNonHex() {
        // G is not a hex digit
        #expect(!GPGHelper.isValidFingerprint("GBCDEF0123456789ABCDEF0123456789ABCDEF01"))
        // Attempting to smuggle an argument via whitespace/flag
        #expect(!GPGHelper.isValidFingerprint("--homedir /evil/malicious/keyring/here/ab"))
        #expect(!GPGHelper.isValidFingerprint("ABCDEF0123456789ABCDEF0123456789ABCDEF 1"))
    }
}

@Suite("GPGHelper micalg parsing")
struct GPGHelperMicalgTests {
    @Test("parses pgp-sha256 from SIG_CREATED")
    func parsesSHA256() {
        let status = """
        [GNUPG:] KEY_CONSIDERED ABCDEF 0
        [GNUPG:] SIG_CREATED D 1 8 00 1700000000 ABCDEF
        [GNUPG:] END_ENCRYPTION
        """
        #expect(GPGHelper.parseMicalg(from: status) == "pgp-sha256")
    }

    @Test("parses pgp-sha512 from SIG_CREATED")
    func parsesSHA512() {
        let status = "[GNUPG:] SIG_CREATED D 22 10 00 1700000000 DEADBEEF\n"
        #expect(GPGHelper.parseMicalg(from: status) == "pgp-sha512")
    }

    @Test("returns nil when SIG_CREATED is absent")
    func returnsNilWhenMissing() {
        #expect(GPGHelper.parseMicalg(from: "[GNUPG:] KEY_CONSIDERED ABCDEF 0\n") == nil)
        #expect(GPGHelper.parseMicalg(from: "") == nil)
    }

    @Test("returns nil for unknown hash algorithm number")
    func returnsNilForUnknown() {
        // 99 is not a valid RFC 4880 hash algorithm number
        let status = "[GNUPG:] SIG_CREATED D 1 99 00 1700000000 ABCDEF\n"
        #expect(GPGHelper.parseMicalg(from: status) == nil)
    }
}
