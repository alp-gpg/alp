import Foundation
import Testing

/// Regression tests for `signatureVerdict` — the gpg `--status-fd` parser that
/// decides whether a message is validly signed. The bug these guard against:
/// validity was previously inferred from the presence of a `VALIDSIG` line,
/// but gpg emits `VALIDSIG` for revoked- and expired-key signatures too, so a
/// forged message signed by a revoked key read as "Signature valid".
@Suite("Signature verdict parser")
struct SignatureVerdictTests {
    // A real 40-hex fingerprint and a 16-hex long key-id for fixtures.
    static let fpr = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
    static let keyid = "ABCDEF0123456789"

    @Test
    func `GOODSIG with VALIDSIG is valid and returns the 40-hex fingerprint`() async {
        let helper = await GPGHelper()
        let status = """
        [GNUPG:] GOODSIG \(Self.keyid) Alice <alice@example.com>
        [GNUPG:] VALIDSIG \(Self.fpr) 2024-01-01 1700000000 0 4 0 22 8 01 \(Self.fpr)
        [GNUPG:] TRUST_FULLY 0 pgp
        """
        let v = await helper.testSignatureVerdict(status)
        #expect(v.isValid)
        #expect(v.fingerprint == Self.fpr)
        #expect(v.displayName == "Alice <alice@example.com>")
    }

    @Test
    func `REVKEYSIG is INVALID even though VALIDSIG is present`() async {
        // The headline regression: a cryptographically-good signature made by a
        // REVOKED key. gpg emits both REVKEYSIG and VALIDSIG; we must NOT treat
        // it as valid.
        let helper = await GPGHelper()
        let status = """
        [GNUPG:] REVKEYSIG \(Self.keyid) Mallory <mallory@example.com>
        [GNUPG:] VALIDSIG \(Self.fpr) 2024-01-01 1700000000 0 4 0 22 8 01 \(Self.fpr)
        """
        let v = await helper.testSignatureVerdict(status)
        #expect(!v.isValid)
        // The signer is still surfaced so the UI can say "invalid — signed by …".
        #expect(v.displayName == "Mallory <mallory@example.com>")
    }

    @Test
    func `EXPKEYSIG (expired key) is invalid despite VALIDSIG`() async {
        let helper = await GPGHelper()
        let status = """
        [GNUPG:] EXPKEYSIG \(Self.keyid) Bob <bob@example.com>
        [GNUPG:] VALIDSIG \(Self.fpr) 2024-01-01 1700000000 0 4 0 22 8 01 \(Self.fpr)
        """
        let v = await helper.testSignatureVerdict(status)
        #expect(!v.isValid)
    }

    @Test
    func `EXPSIG (expired signature) is invalid despite VALIDSIG`() async {
        let helper = await GPGHelper()
        let status = """
        [GNUPG:] EXPSIG \(Self.keyid) Carol <carol@example.com>
        [GNUPG:] VALIDSIG \(Self.fpr) 2024-01-01 1700000000 0 4 0 22 8 01 \(Self.fpr)
        """
        let v = await helper.testSignatureVerdict(status)
        #expect(!v.isValid)
    }

    @Test
    func `BADSIG is invalid`() async {
        let helper = await GPGHelper()
        let status = "[GNUPG:] BADSIG \(Self.keyid) Dave <dave@example.com>"
        let v = await helper.testSignatureVerdict(status)
        #expect(!v.isValid)
    }

    @Test
    func `ERRSIG (unverifiable / missing key) is invalid with no signer`() async {
        let helper = await GPGHelper()
        let status = "[GNUPG:] ERRSIG \(Self.keyid) 22 8 00 1700000000 9 \(Self.fpr)"
        let v = await helper.testSignatureVerdict(status)
        #expect(!v.isValid)
        #expect(v.fingerprint == nil)
    }

    @Test
    func `unsigned input yields invalid and nil fingerprint`() async {
        let helper = await GPGHelper()
        let v = await helper.testSignatureVerdict("[GNUPG:] DECRYPTION_OKAY\n[GNUPG:] GOODMDC")
        #expect(!v.isValid)
        #expect(v.fingerprint == nil)
        #expect(v.displayName == nil)
    }

    @Test
    func `a non-40-hex VALIDSIG token is not accepted as a fingerprint`() async {
        let helper = await GPGHelper()
        // VALIDSIG must be a real 40-hex value; a short/garbage token falls back
        // to the GOODSIG key-id rather than being shown as a fingerprint.
        let status = """
        [GNUPG:] GOODSIG \(Self.keyid) Eve <eve@example.com>
        [GNUPG:] VALIDSIG not-a-fingerprint 2024-01-01 1700000000
        """
        let v = await helper.testSignatureVerdict(status)
        #expect(v.isValid)
        #expect(v.fingerprint == Self.keyid)
    }

    // MARK: – Colon-field escape decoding

    @Test
    func `decodeColonField leaves an unescaped UID untouched`() async {
        #expect(await GPGHelper.testDecodeColonField("Alice <alice@example.com>") == "Alice <alice@example.com>")
    }

    @Test
    func `decodeColonField decodes escaped colon and angle brackets`() async {
        // \x3a = ':', \x3c = '<', \x3e = '>'
        let decoded = await GPGHelper.testDecodeColonField(#"Group\x3a Team \x3cteam@example.com\x3e"#)
        #expect(decoded == "Group: Team <team@example.com>")
    }

    @Test
    func `decodeColonField reassembles multi-byte UTF-8 escapes`() async {
        // \xc3\xa9 is UTF-8 for 'é'.
        #expect(await GPGHelper.testDecodeColonField(#"Jos\xc3\xa9"#) == "José")
    }
}
