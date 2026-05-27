import Foundation
import Testing

@Suite("GPG backup bundle parsing")
struct GPGHelperBackupTests {
    @Test
    func `extractOwnertrustSection returns trimmed payload`() {
        let bundle = """
        -----BEGIN PGP PUBLIC KEY BLOCK-----
        body
        -----END PGP PUBLIC KEY BLOCK-----

        # ownertrust:
        2BC83F55A4007468864C680E1B7CC8D4D4E914AA:6:
        """
        let trust = GPGHelper.extractOwnertrustSection(from: bundle)
        #expect(trust == "2BC83F55A4007468864C680E1B7CC8D4D4E914AA:6:")
    }

    @Test
    func `extractOwnertrustSection returns nil when marker missing`() {
        #expect(GPGHelper.extractOwnertrustSection(from: "no marker here") == nil)
    }

    @Test
    func `extractOwnertrustSection returns nil for empty section`() {
        #expect(GPGHelper.extractOwnertrustSection(from: "# ownertrust:\n\n") == nil)
    }

    @Test
    func `parseImportedFingerprints picks up every IMPORT_OK line`() {
        let status = """
        [GNUPG:] KEY_CONSIDERED ABCDEF0123456789ABCDEF0123456789ABCDEF01 0
        [GNUPG:] IMPORT_OK 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
        [GNUPG:] IMPORT_OK 16 2BC83F55A4007468864C680E1B7CC8D4D4E914AA
        [GNUPG:] IMPORT_RES 2 0 1 0 1 0 0 0 0 0 0 0 0 0 0
        """
        let fps = GPGHelper.parseImportedFingerprints(from: status)
        #expect(fps == [
            "ABCDEF0123456789ABCDEF0123456789ABCDEF01",
            "2BC83F55A4007468864C680E1B7CC8D4D4E914AA",
        ])
    }

    @Test
    func `parseImportedFingerprints dedupes repeats`() {
        let status = """
        [GNUPG:] IMPORT_OK 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
        [GNUPG:] IMPORT_OK 2 ABCDEF0123456789ABCDEF0123456789ABCDEF01
        """
        let fps = GPGHelper.parseImportedFingerprints(from: status)
        #expect(fps == ["ABCDEF0123456789ABCDEF0123456789ABCDEF01"])
    }

    @Test
    func `parseImportedFingerprints rejects malformed fingerprint`() {
        // 39 chars instead of 40
        let status = "[GNUPG:] IMPORT_OK 1 ABCDEF0123456789ABCDEF0123456789ABCDEF0\n"
        #expect(GPGHelper.parseImportedFingerprints(from: status).isEmpty)
    }

    @Test
    func `parseImportedFingerprints survives CRLF line endings`() {
        // Some gpg builds (Cygwin/WSL adjacent) emit CRLF on stderr.
        // The line splitter must not retain trailing \r in the
        // fingerprint slot.
        let status = "[GNUPG:] IMPORT_OK 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01\r\n"
        let fps = GPGHelper.parseImportedFingerprints(from: status)
        #expect(fps == ["ABCDEF0123456789ABCDEF0123456789ABCDEF01"])
    }

    @Test
    func `parseImportedFingerprints accepts both cases`() {
        // gpg normalizes to uppercase in practice; isValidFingerprint
        // accepts either. Don't tie the parser to one case so a
        // future gpg behavior change doesn't silently drop imports.
        let status = """
        [GNUPG:] IMPORT_OK 1 abcdef0123456789abcdef0123456789abcdef01
        [GNUPG:] IMPORT_OK 1 ABCDEF0123456789ABCDEF0123456789ABCDEF02
        """
        let fps = GPGHelper.parseImportedFingerprints(from: status)
        #expect(fps.count == 2)
    }

    @Test
    func `parseImportedFingerprints ignores noise lines`() {
        let status = """
        [GNUPG:] KEY_CONSIDERED ABCDEF0123456789ABCDEF0123456789ABCDEF01 0
        gpg: key ABCDEF01: public key "User <u@example.com>" imported
        [GNUPG:] IMPORT_OK 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
        gpg: Total number processed: 1
        gpg:               imported: 1
        [GNUPG:] IMPORT_RES 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0
        """
        let fps = GPGHelper.parseImportedFingerprints(from: status)
        #expect(fps == ["ABCDEF0123456789ABCDEF0123456789ABCDEF01"])
    }

    @Test
    func `parseImportedFingerprints returns empty on empty input`() {
        #expect(GPGHelper.parseImportedFingerprints(from: "").isEmpty)
    }

    @Test
    func `extractOwnertrustSection survives CRLF endings`() {
        let bundle = "header\r\n# ownertrust:\r\nABCDEF0123456789ABCDEF0123456789ABCDEF01:6:\r\n"
        let trust = GPGHelper.extractOwnertrustSection(from: bundle)
        #expect(trust == "ABCDEF0123456789ABCDEF0123456789ABCDEF01:6:")
    }

    @Test
    func `extractOwnertrustSection keeps multi-line trust block`() {
        // Bundle could carry trust for primary + a co-signed key. We
        // grab everything after the marker; gpg's --import-ownertrust
        // reads one fingerprint per line.
        let bundle = """
        header

        # ownertrust:
        ABCDEF0123456789ABCDEF0123456789ABCDEF01:6:
        FEDCBA9876543210FEDCBA9876543210FEDCBA98:5:
        """
        let trust = GPGHelper.extractOwnertrustSection(from: bundle)
        #expect(trust?.contains(":6:") == true)
        #expect(trust?.contains(":5:") == true)
    }
}
