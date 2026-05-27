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
}
