import Foundation

/// Splits an outgoing RFC 822 message into its header block and a single-part
/// text body so the body can be replaced with armored PGP for inline mode.
///
/// Returns nil for messages that aren't safe to inline:
///   * No `\r\n\r\n` (or `\n\n`) header/body separator.
///   * Multipart bodies (Content-Type: multipart/*) — attachments would be
///     dropped if we replaced the body wholesale.
///
/// The caller falls back to PGP/MIME when this parser returns nil.
enum OutgoingMIMEParser {
    struct Parsed {
        /// Header block, **without** the trailing CRLF/LF separator. Caller
        /// supplies the new separator after rewriting Content-Type headers.
        let headers: Data
        /// Body bytes after the header separator. UTF-8 encoded plain text.
        let body: Data
    }

    static func split(_ data: Data) -> Parsed? {
        guard let (headerEnd, bodyStart) = findHeaderBoundary(in: data) else {
            return nil
        }
        let headers = data.subdata(in: 0 ..< headerEnd)
        let body = data.subdata(in: bodyStart ..< data.count)

        guard !isMultipart(headers: headers) else { return nil }

        return Parsed(headers: headers, body: body)
    }

    /// Returns (endOfHeaders, startOfBody) byte indices, or nil when no
    /// CRLFCRLF / LFLF separator is found.
    static func findHeaderBoundary(in data: Data) -> (Int, Int)? {
        let bytes = [UInt8](data)
        let crlfCRLF: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        let lfLF: [UInt8] = [0x0A, 0x0A]
        if let range = bytes.firstRange(of: crlfCRLF) {
            return (range.lowerBound, range.upperBound)
        }
        if let range = bytes.firstRange(of: lfLF) {
            return (range.lowerBound, range.upperBound)
        }
        return nil
    }

    /// Case-insensitive check for a `Content-Type: multipart/*` header in the
    /// header block. Matches across CRLF or LF folded headers.
    static func isMultipart(headers: Data) -> Bool {
        guard let text = String(data: headers, encoding: .utf8)
            ?? String(data: headers, encoding: .isoLatin1)
        else { return false }
        for line in text.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces).lowercased()
            if trimmed.hasPrefix("content-type:"), trimmed.contains("multipart/") {
                return true
            }
        }
        return false
    }

    /// Removes any existing `Content-Type` and `Content-Transfer-Encoding`
    /// headers from the header block and appends the inline-PGP defaults
    /// (`text/plain; charset=utf-8`, `7bit`). The caller is responsible for
    /// adding the trailing CRLFCRLF separator before the new body.
    static func rewriteContentTypeHeaders(in headers: Data) -> Data {
        let rawText: String
        if let utf8 = String(data: headers, encoding: .utf8) {
            rawText = utf8
        } else if let latin = String(data: headers, encoding: .isoLatin1) {
            rawText = latin
        } else {
            return headers
        }

        // Split on CRLF if present, otherwise on LF; we don't care about
        // round-tripping the exact line terminator because we re-emit CRLF.
        let separator = rawText.contains("\r\n") ? "\r\n" : "\n"
        let lines = rawText.components(separatedBy: separator)

        var keptLines: [String] = []
        keptLines.reserveCapacity(lines.count)
        var skippingFolded = false
        for line in lines {
            // RFC 5322 folded continuation lines start with whitespace; they
            // belong to the previous header. Drop them when we drop the header.
            if line.first == " " || line.first == "\t" {
                if skippingFolded { continue }
                keptLines.append(line)
                continue
            }
            skippingFolded = false

            let lower = line.lowercased()
            if lower.hasPrefix("content-type:")
                || lower.hasPrefix("content-transfer-encoding:")
            {
                skippingFolded = true
                continue
            }
            keptLines.append(line)
        }

        keptLines.append("Content-Type: text/plain; charset=utf-8")
        keptLines.append("Content-Transfer-Encoding: 7bit")
        return Data(keptLines.joined(separator: "\r\n").utf8)
    }
}

private extension [UInt8] {
    /// Linear scan; outgoing RFC 822 headers are typically a few KB so big-O
    /// optimisation isn't worth the complexity of Boyer-Moore.
    func firstRange(of needle: [UInt8]) -> Range<Int>? {
        guard !needle.isEmpty, needle.count <= count else { return nil }
        let limit = count - needle.count
        var i = 0
        while i <= limit {
            if self[i] == needle[0], Array(self[i ..< i + needle.count]) == needle {
                return i ..< (i + needle.count)
            }
            i += 1
        }
        return nil
    }
}
