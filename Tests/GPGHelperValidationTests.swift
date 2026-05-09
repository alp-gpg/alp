import Foundation
import Testing

@Suite("GPGHelper input validation")
struct GPGHelperValidationTests {
    @Test
    func `isValidFingerprint accepts 40-char hex`() {
        #expect(GPGHelper.isValidFingerprint("ABCDEF0123456789ABCDEF0123456789ABCDEF01"))
        #expect(GPGHelper.isValidFingerprint("abcdef0123456789abcdef0123456789abcdef01"))
    }

    @Test
    func `isValidFingerprint rejects wrong length`() {
        #expect(!GPGHelper.isValidFingerprint(""))
        #expect(!GPGHelper.isValidFingerprint("ABCDEF"))
        #expect(!GPGHelper.isValidFingerprint(String(repeating: "A", count: 41)))
    }

    @Test
    func `isValidFingerprint rejects non-hex characters`() {
        // G is not a hex digit
        #expect(!GPGHelper.isValidFingerprint("GBCDEF0123456789ABCDEF0123456789ABCDEF01"))
        // Attempting to smuggle an argument via whitespace/flag
        #expect(!GPGHelper.isValidFingerprint("--homedir /evil/malicious/keyring/here/ab"))
        #expect(!GPGHelper.isValidFingerprint("ABCDEF0123456789ABCDEF0123456789ABCDEF 1"))
    }
}

@Suite("GPGHelper key lifecycle validation")
struct GPGHelperLifecycleValidationTests {
    @Test
    func `exportPublicKey rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._exportPublicKey("--homedir /tmp/evil")
        }
        await #expect(throws: GPGError.self) {
            _ = try await helper._exportPublicKey("")
        }
    }

    @Test
    func `exportSecretKey rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._exportSecretKey("not-a-fingerprint")
        }
    }

    @Test
    func `deletePublicKey rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            try await helper._deletePublicKey("12345")
        }
    }

    @Test
    func `deleteSecretKey rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            try await helper._deleteSecretKey(String(repeating: "Z", count: 40))
        }
    }
}

@Suite("GPGHelper micalg parsing")
struct GPGHelperMicalgTests {
    @Test
    func `parses pgp-sha256 from SIG_CREATED`() {
        let status = """
        [GNUPG:] KEY_CONSIDERED ABCDEF 0
        [GNUPG:] SIG_CREATED D 1 8 00 1700000000 ABCDEF
        [GNUPG:] END_ENCRYPTION
        """
        #expect(GPGHelper.parseMicalg(from: status) == "pgp-sha256")
    }

    @Test
    func `parses pgp-sha512 from SIG_CREATED`() {
        let status = "[GNUPG:] SIG_CREATED D 22 10 00 1700000000 DEADBEEF\n"
        #expect(GPGHelper.parseMicalg(from: status) == "pgp-sha512")
    }

    @Test
    func `returns nil when SIG_CREATED is absent`() {
        #expect(GPGHelper.parseMicalg(from: "[GNUPG:] KEY_CONSIDERED ABCDEF 0\n") == nil)
        #expect(GPGHelper.parseMicalg(from: "") == nil)
    }

    @Test
    func `returns nil for unknown hash algorithm number`() {
        // 99 is not a valid RFC 4880 hash algorithm number
        let status = "[GNUPG:] SIG_CREATED D 1 99 00 1700000000 ABCDEF\n"
        #expect(GPGHelper.parseMicalg(from: status) == nil)
    }
}
