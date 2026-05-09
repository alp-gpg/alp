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
    func `returns nil when no header separator is present`() {
        #expect(OutgoingMIMEParser.split(Data("Subject: x\r\nNo body here".utf8)) == nil)
    }

    @Test
    func `Content-Type detection is case-insensitive`() {
        let raw = Data("subject: x\r\nCONTENT-TYPE: Multipart/Mixed\r\n\r\n".utf8)
        #expect(OutgoingMIMEParser.split(raw) == nil)
    }
}

@Suite("OutgoingMIMEParser header rewrite")
struct OutgoingMIMEParserRewriteTests {
    @Test
    func `replaces Content-Type and adds Content-Transfer-Encoding`() {
        let headers = Data(
            "Subject: Hi\r\nFrom: a@b.co\r\nContent-Type: text/html; charset=us-ascii\r\nContent-Transfer-Encoding: quoted-printable".utf8,
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
