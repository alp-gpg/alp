import Foundation

/// Parses an `Autocrypt:` header out of an RFC 822 message so the receive
/// path can auto-import a sender's public key on the very first email.
///
/// Spec: <https://autocrypt.org/level1.html>. Minimal subset Alp uses:
///   * `addr` (required) — the sender's email; must match the message's
///     From address before the key is imported.
///   * `keydata` (required) — base64-encoded OpenPGP transferable public
///     key. May be folded across multiple lines per RFC 5322; whitespace
///     inside the value is stripped before decoding.
///   * `prefer-encrypt` (optional) — `mutual` is the only value the spec
///     defines; we capture it for future use even though we don't act on
///     it yet.
///
/// Anything else (`_-prefixed` extensions, unknown attributes) is ignored.
/// A header that lists the same attribute twice is rejected as malformed
/// per the spec.
enum AutocryptHeader {
    struct Header: Equatable {
        let address: String
        let keyData: Data
        let preferMutual: Bool
    }

    /// Returns the parsed header if the message has an Autocrypt header
    /// AND the From address matches its `addr` attribute. Returns nil for
    /// every other case so the caller can treat nil as "do nothing".
    static func parseAndValidate(rawMessage: Data) -> Header? {
        guard let header = parse(rawMessage: rawMessage) else { return nil }
        guard let from = parseFromAddress(rawMessage: rawMessage) else { return nil }
        guard from.lowercased() == header.address.lowercased() else { return nil }
        return header
    }

    /// Parses the Autocrypt header from a raw RFC 822 message. Returns nil
    /// when the header is missing, malformed, or specifies an attribute
    /// twice.
    static func parse(rawMessage: Data) -> Header? {
        guard let block = headerBlock(of: rawMessage) else { return nil }
        guard let line = unfoldedHeader(named: "Autocrypt", in: block) else {
            return nil
        }
        return parseValue(line)
    }

    /// Pulls the bare email out of the From header. Returns nil if the
    /// header is missing or unparseable. Strips display-name prefixes,
    /// angle brackets, and surrounding whitespace.
    static func parseFromAddress(rawMessage: Data) -> String? {
        guard let block = headerBlock(of: rawMessage) else { return nil }
        guard let line = unfoldedHeader(named: "From", in: block) else { return nil }
        // Trim "From:" prefix and outer whitespace.
        let value = line.dropFirst("From:".count).trimmingCharacters(in: .whitespaces)
        // "Display Name <user@example.com>" → user@example.com
        if let lt = value.firstIndex(of: "<"),
           let gt = value.lastIndex(of: ">"),
           lt < gt
        {
            return String(value[value.index(after: lt) ..< gt])
                .trimmingCharacters(in: .whitespaces)
        }
        // Bare "user@example.com"
        return value.isEmpty ? nil : value
    }

    // MARK: – Private helpers

    /// Returns the substring before the header/body separator, or nil when
    /// the input has no separator.
    private static func headerBlock(of data: Data) -> String? {
        let bytes = [UInt8](data)
        let crlfCRLF: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        let lfLF: [UInt8] = [0x0A, 0x0A]
        let end: Int
        if let range = firstRange(of: crlfCRLF, in: bytes) {
            end = range.lowerBound
        } else if let range = firstRange(of: lfLF, in: bytes) {
            end = range.lowerBound
        } else {
            return String(data: data, encoding: .utf8)
                ?? String(data: data, encoding: .isoLatin1)
        }
        let head = data.subdata(in: 0 ..< end)
        return String(data: head, encoding: .utf8)
            ?? String(data: head, encoding: .isoLatin1)
    }

    /// Joins folded continuation lines (RFC 5322 §2.2.3) back into a single
    /// logical header line, then returns the first one matching `name`
    /// (case-insensitive). The returned string keeps the `Name:` prefix so
    /// callers know what they got.
    private static func unfoldedHeader(named name: String, in block: String) -> String? {
        let separator = block.contains("\r\n") ? "\r\n" : "\n"
        var unfolded: [String] = []
        for line in block.components(separatedBy: separator) {
            if line.first == " " || line.first == "\t" {
                if !unfolded.isEmpty {
                    unfolded[unfolded.count - 1].append(line)
                }
            } else {
                unfolded.append(line)
            }
        }
        let lowerName = name.lowercased()
        return unfolded.first { line in
            line.lowercased().hasPrefix(lowerName + ":")
        }
    }

    private static func parseValue(_ rawLine: String) -> Header? {
        // Strip "Autocrypt:" prefix.
        let value = rawLine.dropFirst("Autocrypt:".count).trimmingCharacters(in: .whitespaces)
        // Per spec, whitespace inside the keydata is meaningless. Strip it
        // all, then split on `;`.
        let compact = value.filter { !$0.isWhitespace }

        var addr: String?
        var keyDataBase64: String?
        var preferMutual = false
        for attr in compact.split(separator: ";") {
            let parts = attr.split(separator: "=", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return nil } // malformed
            let key = parts[0].lowercased()
            let val = parts[1]
            switch key {
            case "addr":
                if addr != nil { return nil } // duplicate
                addr = val
            case "keydata":
                if keyDataBase64 != nil { return nil }
                keyDataBase64 = val
            case "prefer-encrypt":
                preferMutual = (val.lowercased() == "mutual")
            default:
                if !key.hasPrefix("_") { return nil } // unknown critical attr
            }
        }
        guard let address = addr, let base64 = keyDataBase64 else { return nil }
        guard let decoded = Data(base64Encoded: base64),
              !decoded.isEmpty
        else { return nil }
        return Header(address: address, keyData: decoded, preferMutual: preferMutual)
    }

    private static func firstRange(of needle: [UInt8], in haystack: [UInt8]) -> Range<Int>? {
        guard !needle.isEmpty, needle.count <= haystack.count else { return nil }
        let limit = haystack.count - needle.count
        var i = 0
        while i <= limit {
            if haystack[i] == needle[0],
               Array(haystack[i ..< i + needle.count]) == needle
            {
                return i ..< (i + needle.count)
            }
            i += 1
        }
        return nil
    }
}
