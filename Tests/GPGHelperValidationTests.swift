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

    @Test
    func `generatePrimaryKey rejects empty name`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._generatePrimaryKey(
                name: "   ", email: "x@example.com", comment: nil, expiryDays: 730,
            )
        }
    }

    @Test
    func `generatePrimaryKey rejects forbidden characters in name`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._generatePrimaryKey(
                name: "Alice <evil>", email: "a@example.com", comment: nil, expiryDays: 365,
            )
        }
    }

    @Test
    func `generatePrimaryKey rejects malformed email`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._generatePrimaryKey(
                name: "Alice", email: "not-an-email", comment: nil, expiryDays: 365,
            )
        }
    }

    @Test
    func `generatePrimaryKey rejects out-of-range expiry`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._generatePrimaryKey(
                name: "Alice", email: "a@example.com", comment: nil, expiryDays: -1,
            )
        }
        await #expect(throws: GPGError.self) {
            _ = try await helper._generatePrimaryKey(
                name: "Alice", email: "a@example.com", comment: nil, expiryDays: 36501,
            )
        }
    }
}

@Suite("GPGHelper edit-key validation")
struct GPGHelperEditKeyValidationTests {
    @Test
    func `changePassphrase rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            try await helper._changePassphrase("not-hex")
        }
    }

    @Test
    func `setExpiry rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            try await helper._setExpiry("12345", expiryDays: 365)
        }
    }

    @Test
    func `setExpiry rejects out-of-range expiry`() async {
        let helper = GPGHelper()
        let valid = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        await #expect(throws: GPGError.self) {
            try await helper._setExpiry(valid, expiryDays: -1)
        }
        await #expect(throws: GPGError.self) {
            try await helper._setExpiry(valid, expiryDays: 36501)
        }
    }

    @Test
    func `revokePrimaryKey rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            _ = try await helper._revokePrimaryKey("nope", reasonCode: 0, description: nil)
        }
    }

    @Test
    func `revokePrimaryKey rejects out-of-range reason code`() async {
        let helper = GPGHelper()
        let valid = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        await #expect(throws: GPGError.self) {
            _ = try await helper._revokePrimaryKey(valid, reasonCode: -1, description: nil)
        }
        await #expect(throws: GPGError.self) {
            _ = try await helper._revokePrimaryKey(valid, reasonCode: 99, description: nil)
        }
    }

    @Test
    func `revokePrimaryKey rejects forbidden chars in description`() async {
        let helper = GPGHelper()
        let valid = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        await #expect(throws: GPGError.self) {
            _ = try await helper._revokePrimaryKey(valid, reasonCode: 1, description: "bad <script>")
        }
    }

    @Test
    func `signKey rejects malformed target or signer fingerprint`() async {
        let helper = GPGHelper()
        let valid = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        await #expect(throws: GPGError.self) {
            try await helper._signKey(fingerprint: "nope", signer: valid, exportable: true)
        }
        await #expect(throws: GPGError.self) {
            try await helper._signKey(fingerprint: valid, signer: "nope", exportable: false)
        }
    }

    @Test
    func `setOwnerTrust rejects malformed fingerprint`() async {
        let helper = GPGHelper()
        await #expect(throws: GPGError.self) {
            try await helper._setOwnerTrust("nope", level: 4)
        }
    }

    @Test
    func `setOwnerTrust rejects out-of-range level`() async {
        let helper = GPGHelper()
        let valid = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
        await #expect(throws: GPGError.self) {
            try await helper._setOwnerTrust(valid, level: 1) // unknown is not settable
        }
        await #expect(throws: GPGError.self) {
            try await helper._setOwnerTrust(valid, level: 6)
        }
    }
}

@Suite("GPGHelper key-generation parser")
struct GPGHelperKeyGenParserTests {
    @Test
    func `parseKeyCreatedFingerprint extracts fingerprint from B line`() {
        let status = "[GNUPG:] KEY_CONSIDERED 0\n[GNUPG:] KEY_CREATED B ABCDEF0123456789ABCDEF0123456789ABCDEF01\n"
        #expect(
            GPGHelper.parseKeyCreatedFingerprint(from: status)
                == "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
        )
    }

    @Test
    func `parseKeyCreatedFingerprint returns nil when KEY_CREATED is absent`() {
        #expect(GPGHelper.parseKeyCreatedFingerprint(from: "[GNUPG:] KEY_CONSIDERED 0\n") == nil)
        #expect(GPGHelper.parseKeyCreatedFingerprint(from: "") == nil)
    }

    @Test
    func `parseKeyCreatedFingerprint rejects non-fingerprint payload`() {
        // gpg output where the third token isn't a 40-char hex fingerprint
        let status = "[GNUPG:] KEY_CREATED B not-a-fingerprint\n"
        #expect(GPGHelper.parseKeyCreatedFingerprint(from: status) == nil)
    }

    @Test
    func `isValidEmail accepts simple addresses`() {
        #expect(GPGHelper.isValidEmail("a@b.co"))
        #expect(GPGHelper.isValidEmail("user.name+tag@example.com"))
    }

    @Test
    func `isValidEmail rejects malformed addresses`() {
        #expect(!GPGHelper.isValidEmail(""))
        #expect(!GPGHelper.isValidEmail("no-at-sign"))
        #expect(!GPGHelper.isValidEmail("a@b"))
        #expect(!GPGHelper.isValidEmail("alice <a@b.co>"))
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
