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
        let out = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers)
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
        let out = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers)
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
        let out = OutgoingMIMEParser.rewriteContentTypeHeaders(in: headers)
        let text = String(data: out, encoding: .utf8) ?? ""
        #expect(text.contains("Message-ID: <1234@local>"))
        #expect(text.contains("Date: now"))
        #expect(text.contains("Content-Type: text/plain; charset=utf-8"))
    }
}
