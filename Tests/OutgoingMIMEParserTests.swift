import Foundation
import Testing

@Suite("OutgoingMIMEParser splitting")
struct OutgoingMIMEParserSplitTests {
    @Test
    func `splits a typical CRLF text/plain message`() {
        let raw = Data(
            "Subject: Hello\r\nFrom: a@b.co\r\nContent-Type: text/plain\r\n\r\nBody line.\r\n".utf8,
        )
        let parsed = OutgoingMIMEParser.split(raw)
        #expect(parsed != nil)
        #expect(String(data: parsed?.body ?? Data(), encoding: .utf8) == "Body line.\r\n")
    }

    @Test
    func `handles LF-only line endings`() {
        let raw = Data("Subject: x\nContent-Type: text/plain\n\nbody".utf8)
        let parsed = OutgoingMIMEParser.split(raw)
        #expect(String(data: parsed?.body ?? Data(), encoding: .utf8) == "body")
    }

    @Test
    func `returns nil for multipart bodies`() {
        let raw = Data(
            "Subject: x\r\nContent-Type: multipart/mixed; boundary=\"X\"\r\n\r\n--X\r\n".utf8,
        )
        #expect(OutgoingMIMEParser.split(raw) == nil)
    }

    @Test
    func `returns nil for quoted-printable bodies so inline mode falls back to PGP-MIME`() {
        // §5.4: a QP body's bytes aren't the literal text; inlining them would
        // ship `caf=C3=A9`. Refuse so the caller uses PGP/MIME instead.
        let raw = Data(
            "Subject: x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9\r\n"
                .utf8,
        )
        #expect(OutgoingMIMEParser.split(raw) == nil)
    }

    @Test
    func `returns nil for base64 bodies`() {
        let raw = Data(
            "Subject: x\r\nContent-Transfer-Encoding: base64\r\n\r\nY2Fmw6k=\r\n".utf8,
        )
        #expect(OutgoingMIMEParser.split(raw) == nil)
    }

    @Test
    func `inlines 8bit bodies`() {
        let raw = Data(
            "Subject: x\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncafé\r\n"
                .utf8,
        )
        #expect(OutgoingMIMEParser.split(raw) != nil)
    }

    @Test
    func `returns nil when no header separator is present`() {
        #expect(OutgoingMIMEParser.split(Data("Subject: x\r\nNo body here".utf8)) == nil)
    }

    @Test
    func `Content-Type detection is case-insensitive`() {
        let raw = Data("subject: x\r\nCONTENT-TYPE: Multipart/Mixed\r\n\r\n".utf8)
        #expect(OutgoingMIMEParser.split(raw) == nil)
    }
}

@Suite("OutgoingMIMEParser envelope split")
struct OutgoingMIMEParserEnvelopeTests {
    private func text(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? ""
    }

    @Test
    func `envelope keeps routing headers, entity keeps content + body`() throws {
        let raw = Data(
            "To: c@d.co\r\nFrom: a@b.co\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello body\r\n"
                .utf8,
        )
        let env = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let outer = text(env.outerHeaders)
        let entity = text(env.contentEntity)

        // Envelope carries routing headers, not the content type, not MIME-Version.
        #expect(outer.contains("To: c@d.co"))
        #expect(outer.contains("From: a@b.co"))
        #expect(outer.contains("Subject: hi"))
        #expect(!outer.lowercased().contains("content-type"))
        #expect(!outer.lowercased().contains("mime-version"))

        // Entity carries the content type + body, never the envelope addresses.
        #expect(entity.contains("Content-Type: text/plain; charset=utf-8"))
        #expect(entity.contains("Hello body"))
        #expect(!entity.contains("c@d.co"))
        #expect(!entity.contains("Subject: hi"))
    }

    @Test
    func `multipart body survives as the content entity`() throws {
        let raw = Data(
            "To: c@d.co\r\nContent-Type: multipart/mixed; boundary=\"X\"\r\n\r\n--X\r\nContent-Type: text/plain\r\n\r\npart\r\n--X--\r\n"
                .utf8,
        )
        let env = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let entity = text(env.contentEntity)
        #expect(entity.contains("multipart/mixed; boundary=\"X\""))
        #expect(entity.contains("--X--"))
        #expect(text(env.outerHeaders).contains("To: c@d.co"))
    }

    @Test
    func `nil when no header separator`() {
        #expect(OutgoingMIMEParser.splitEnvelope(Data("To: x\r\nno body".utf8)) == nil)
    }
}

@Suite("OutgoingMIMEParser envelope merge (decode path)")
struct OutgoingMIMEParserMergeTests {
    @Test
    func `LF-only original merges with LF splices, not mixed EOL`() throws {
        let lfOriginal = Data(
            "To: c@d.co\nSubject: hi\nMIME-Version: 1.0\nContent-Type: multipart/encrypted; boundary=\"X\"\n\n--X\n(parts)\n--X--\n"
                .utf8,
        )
        let entity = Data("Content-Type: text/plain\n\nhello\n".utf8)
        let merged = OutgoingMIMEParser.mergingEnvelope(of: lfOriginal, withEntity: entity)
        let text = try #require(String(bytes: merged, encoding: .utf8))
        #expect(!text.contains("\r\n"), "no CRLF may leak into an LF message")
        #expect(text.contains("\nMIME-Version: 1.0\n"))
    }

    /// The encrypted message as Mail hands it to decode — full envelope plus
    /// the multipart/encrypted framing.
    private let original = Data(
        "To: c@d.co\r\nFrom: a@b.co\r\nSubject: hi\r\nMessage-ID: <1@local>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; boundary=\"X\"; protocol=\"application/pgp-encrypted\"\r\n\r\n--X\r\n(parts)\r\n--X--\r\n"
            .utf8,
    )

    private func text(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? ""
    }

    @Test
    func `re-attaches envelope to a decrypted content entity`() {
        let entity = Data("Content-Type: text/plain; charset=utf-8\r\n\r\nSecret body\r\n".utf8)
        let out = text(OutgoingMIMEParser.mergingEnvelope(of: original, withEntity: entity))
        // Envelope Mail's indexer needs — sender, recipient, subject, message-id.
        #expect(out.contains("To: c@d.co"))
        #expect(out.contains("From: a@b.co"))
        #expect(out.contains("Subject: hi"))
        #expect(out.contains("Message-ID: <1@local>"))
        // Exactly one MIME-Version, the entity's content type, no encrypted framing.
        #expect(out.components(separatedBy: "MIME-Version:").count == 2)
        #expect(out.contains("Content-Type: text/plain; charset=utf-8"))
        #expect(!out.contains("multipart/encrypted"))
        // Header block ends before the body — the entity's own blank line.
        #expect(out.contains("charset=utf-8\r\n\r\nSecret body"))
    }

    @Test
    func `wraps bare inline plaintext as text-plain`() {
        let out = text(OutgoingMIMEParser.mergingEnvelope(
            of: original, withEntity: Data("Just the decrypted words.\r\n".utf8),
        ))
        #expect(out.contains("To: c@d.co"))
        #expect(out.contains("Content-Type: text/plain; charset=utf-8\r\n\r\nJust the decrypted words."))
    }

    @Test
    func `passes through an entity that is already a full message`() {
        let full = Data("From: legacy@e.co\r\nTo: c@d.co\r\nSubject: old\r\n\r\nbody\r\n".utf8)
        let out = OutgoingMIMEParser.mergingEnvelope(of: original, withEntity: full)
        #expect(out == full)
    }

    @Test
    func `returns entity unchanged when original has no header separator`() {
        let entity = Data("Content-Type: text/plain\r\n\r\nx".utf8)
        #expect(OutgoingMIMEParser.mergingEnvelope(of: Data("garbage".utf8), withEntity: entity) == entity)
    }
}

@Suite("OutgoingMIMEParser Bcc stripping")
struct OutgoingMIMEParserBccTests {
    private func text(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? ""
    }

    @Test
    func `strips Bcc header, preserves other headers and body`() {
        let raw = Data("From: a@b.co\r\nTo: c@d.co\r\nBcc: secret@e.co\r\nSubject: hi\r\n\r\nBody café\r\n".utf8)
        let out = text(OutgoingMIMEParser.removingHeader("Bcc", from: raw))
        #expect(!out.contains("secret@e.co"))
        #expect(!out.lowercased().contains("bcc:"))
        #expect(out.contains("From: a@b.co"))
        #expect(out.contains("To: c@d.co"))
        #expect(out.contains("Subject: hi"))
        #expect(out.contains("Body café"))
    }

    @Test
    func `Bcc stripping is case-insensitive`() {
        let raw = Data("To: c@d.co\r\nBCC: secret@e.co\r\n\r\nbody".utf8)
        let out = text(OutgoingMIMEParser.removingHeader("Bcc", from: raw))
        #expect(!out.contains("secret@e.co"))
    }

    @Test
    func `strips folded Bcc continuation lines`() {
        let raw = Data("To: c@d.co\r\nBcc: one@e.co,\r\n two@e.co,\r\n\tthree@e.co\r\nSubject: hi\r\n\r\nbody".utf8)
        let out = text(OutgoingMIMEParser.removingHeader("Bcc", from: raw))
        #expect(!out.contains("one@e.co"))
        #expect(!out.contains("two@e.co"))
        #expect(!out.contains("three@e.co"))
        #expect(out.contains("Subject: hi"))
        #expect(out.contains("To: c@d.co"))
    }

    @Test
    func `leaves a Bcc-looking line in the body untouched`() {
        let raw = Data("To: c@d.co\r\n\r\nNotes:\r\nBcc: this is body text, not a header\r\n".utf8)
        let out = text(OutgoingMIMEParser.removingHeader("Bcc", from: raw))
        #expect(out.contains("Bcc: this is body text"))
    }

    @Test
    func `no-op when there is no Bcc header`() {
        let raw = Data("From: a@b.co\r\nTo: c@d.co\r\n\r\nbody".utf8)
        let out = OutgoingMIMEParser.removingHeader("Bcc", from: raw)
        #expect(out == raw)
    }
}

@Suite("OutgoingMIMEParser header rewrite")
struct OutgoingMIMEParserRewriteTests {
    @Test
    func `replaces Content-Type and adds Content-Transfer-Encoding`() {
        let headers = Data(
            "Subject: Hi\r\nFrom: a@b.co\r\nContent-Type: text/html; charset=us-ascii\r\nContent-Transfer-Encoding: quoted-printable"
                .utf8,
        )
        let out = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers, eol: "\r\n")
        let text = String(data: out, encoding: .utf8) ?? ""
        #expect(text.contains("Subject: Hi"))
        #expect(text.contains("From: a@b.co"))
        #expect(!text.lowercased().contains("text/html"))
        #expect(!text.lowercased().contains("quoted-printable"))
        #expect(text.contains("Content-Type: text/plain; charset=utf-8"))
        #expect(text.contains("Content-Transfer-Encoding: 7bit"))
    }

    @Test
    func `drops folded continuation lines belonging to a removed header`() {
        let headers = Data(
            "Subject: Hi\r\nContent-Type: text/html;\r\n charset=us-ascii;\r\n format=flowed\r\nFrom: a@b.co".utf8,
        )
        let out = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers, eol: "\r\n")
        let text = String(data: out, encoding: .utf8) ?? ""
        #expect(!text.contains("text/html"))
        #expect(!text.contains("format=flowed"))
        #expect(text.contains("Subject: Hi"))
        #expect(text.contains("From: a@b.co"))
    }

    @Test
    func `preserves other headers unchanged`() {
        let headers = Data(
            "Subject: Hi\r\nMessage-ID: <1234@local>\r\nDate: now\r\n".utf8,
        )
        let out = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers, eol: "\r\n")
        let text = String(data: out, encoding: .utf8) ?? ""
        #expect(text.contains("Message-ID: <1234@local>"))
        #expect(text.contains("Date: now"))
        #expect(text.contains("Content-Type: text/plain; charset=utf-8"))
    }
}

@Suite("OutgoingMIMEParser EOL handling (encode path)")
struct OutgoingMIMEParserEOLTests {
    private let crlf = "\r\n"
    private let lf = "\n"

    @Test
    func `detects CRLF, LF, and defaults to CRLF without newlines`() {
        #expect(OutgoingMIMEParser.detectEOL(in: Data("To: x\r\nSubject: y\r\n\r\nbody".utf8)) == crlf)
        #expect(OutgoingMIMEParser.detectEOL(in: Data("To: x\nSubject: y\n\nbody".utf8)) == lf)
        #expect(OutgoingMIMEParser.detectEOL(in: Data("no newline at all".utf8)) == crlf)
        #expect(OutgoingMIMEParser.detectEOL(in: Data()) == crlf)
    }

    @Test
    func `mixed EOLs follow the header terminator`() {
        // CRLF headers over an LF body — the serializer parses headers first,
        // so the header EOL decides.
        #expect(OutgoingMIMEParser.detectEOL(in: Data("To: x\r\nSubject: y\r\n\r\nline\nline\n".utf8)) == crlf)
        #expect(OutgoingMIMEParser.detectEOL(in: Data("To: x\nSubject: y\n\nline\r\n".utf8)) == lf)
    }

    @Test
    func `normalizes CRLF to LF and LF to CRLF, ensuring a trailing terminator`() {
        let mixed = Data("a\r\nb\nc".utf8)
        #expect(OutgoingMIMEParser.normalizingEOL(mixed, to: lf) == Data("a\nb\nc\n".utf8))
        #expect(OutgoingMIMEParser.normalizingEOL(mixed, to: crlf) == Data("a\r\nb\r\nc\r\n".utf8))
        // Already-normalized input round-trips unchanged (idempotent).
        let canonical = Data("a\r\nb\r\n".utf8)
        #expect(OutgoingMIMEParser.normalizingEOL(canonical, to: crlf) == canonical)
    }

    @Test
    func `preserves non-UTF8 bytes and lone carriage returns`() {
        // 0xFF makes the data invalid UTF-8; a String round-trip would drop or
        // mangle it. A lone CR not followed by LF belongs to its line.
        let data = Data([0x61, 0xFF, 0x0D, 0x62, 0x0A, 0x63]) // "a<FF><CR>b\nc"
        let normalized = OutgoingMIMEParser.normalizingEOL(data, to: "\r\n")
        #expect(normalized == Data([0x61, 0xFF, 0x0D, 0x62, 0x0D, 0x0A, 0x63, 0x0D, 0x0A]))
    }

    @Test
    func `LF-only message keeps LF through splitEnvelope`() throws {
        let raw = Data("To: c@d.co\nSubject: hi\nContent-Type: text/plain\n\nBody\n".utf8)
        let env = try #require(OutgoingMIMEParser.splitEnvelope(raw))
        let outer = try #require(String(bytes: env.outerHeaders, encoding: .utf8))
        let entity = try #require(String(bytes: env.contentEntity, encoding: .utf8))
        #expect(!outer.contains("\r\n"))
        #expect(!entity.contains("\r\n"))
        #expect(entity.hasPrefix("Content-Type: text/plain\n\n"))
    }
}
