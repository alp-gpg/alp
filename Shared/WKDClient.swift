import CommonCrypto
import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp", category: "WKD")

/// Web Key Directory lookup per draft-koch-openpgp-webkey-service.
///
/// Two URL forms exist:
///   * Advanced: `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<zbase32(SHA1(localpart))>`
///   * Direct:   `https://<domain>/.well-known/openpgpkey/hu/<zbase32(SHA1(localpart))>`
///
/// We try the advanced URL first because it is what the spec recommends and
/// what most providers (proton.me, gnupg.org, gmx.de) implement. The direct
/// URL is checked only when advanced returns 4xx so we can support legacy
/// installations that haven't moved to the subdomain.
///
/// Servers respond with **binary** OpenPGP key material (no ASCII armor). The
/// helper's `importKey` accepts both forms — gpg auto-detects.
enum WKDClient {
    /// Maximum response size accepted from a WKD endpoint (1 MB). Keys are
    /// rarely > 50 KB; the cap is defense against an evil host streaming
    /// gigabytes into the helper.
    static let maxResponseBytes: Int64 = 1 * 1024 * 1024

    enum Error: Swift.Error, LocalizedError {
        case malformedEmail
        case notFound
        case responseTooLarge
        case httpError(Int)
        case networkError(Swift.Error)

        var errorDescription: String? {
            switch self {
            case .malformedEmail: String(localized: "Invalid email address.")
            case .notFound: String(localized: "No WKD key published for this address.")
            case .responseTooLarge: String(localized: "WKD response was unexpectedly large; refusing to import.")
            case let .httpError(code): String(localized: "WKD server returned HTTP \(code).")
            case let .networkError(inner): inner.localizedDescription
            }
        }
    }

    /// Fetch the binary OpenPGP key data for `email` via WKD, trying advanced
    /// then direct URL variants. Returns the raw key bytes ready to feed into
    /// the helper's `importKey` or `previewKey`.
    static func fetch(
        email: String,
        session: URLSession = .makeWKDSession(),
    ) async throws -> Data {
        guard let parts = parseEmail(email) else {
            throw Error.malformedEmail
        }
        let (localpart, domain) = parts
        let hash = zbase32(sha1(Data(localpart.lowercased().utf8)))

        let queryEncoded = localpart.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? localpart
        let advanced = "https://openpgpkey.\(domain)/.well-known/openpgpkey/\(domain)/hu/\(hash)?l=\(queryEncoded)"
        let direct = "https://\(domain)/.well-known/openpgpkey/hu/\(hash)?l=\(queryEncoded)"

        for urlString in [advanced, direct] {
            guard let url = URL(string: urlString), url.scheme == "https" else { continue }
            do {
                return try await fetchOne(url: url, session: session)
            } catch Error.notFound {
                continue // try the next variant
            } catch let Error.httpError(code) where (400 ... 499).contains(code) {
                continue
            }
        }
        throw Error.notFound
    }

    private static func fetchOne(url: URL, session: URLSession) async throws -> Data {
        do {
            let (data, response) = try await session.data(from: url)
            if let http = response as? HTTPURLResponse {
                if http.statusCode == 404 { throw Error.notFound }
                guard (200 ... 299).contains(http.statusCode) else {
                    throw Error.httpError(http.statusCode)
                }
            }
            guard data.count <= Int(maxResponseBytes) else {
                throw Error.responseTooLarge
            }
            return data
        } catch let e as Error {
            throw e
        } catch {
            let host = url.host ?? "?"
            // host is the correspondent's email domain and the error text may
            // carry detail — keep both .private so they're redacted in shareable
            // `log show` output (e.g. bug reports). The URLError code stays
            // public for triage (offline vs timeout vs DNS).
            let code = (error as? URLError)?.code.rawValue ?? -1
            log
                .warning(
                    "WKD fetch \(host, privacy: .private) failed (URLError \(code, privacy: .public)): \(error.localizedDescription, privacy: .private)",
                )
            throw Error.networkError(error)
        }
    }

    /// Splits `local@domain` into `(local, lowercase-domain)`. Returns nil
    /// when the address has no `@`, has whitespace, or has an empty side.
    static func parseEmail(_ email: String) -> (String, String)? {
        let trimmed = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.contains(where: { $0.isWhitespace || $0 == "<" || $0 == ">" }) else {
            return nil
        }
        guard let atIndex = trimmed.firstIndex(of: "@") else { return nil }
        let local = String(trimmed[..<atIndex])
        let domain = String(trimmed[trimmed.index(after: atIndex)...]).lowercased()
        guard !local.isEmpty, !domain.isEmpty, domain.contains(".") else { return nil }
        return (local, domain)
    }

    static func sha1(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        _ = data.withUnsafeBytes { ptr in
            CC_SHA1(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }

    /// zbase32 encoding (alphabet: ybndrfg8ejkmcpqxot1uwisza345h769) per
    /// the WKD draft. SHA1 is 20 bytes = 160 bits = 32 zbase32 characters.
    static func zbase32(_ data: Data) -> String {
        let alphabet: [Character] = Array("ybndrfg8ejkmcpqxot1uwisza345h769")
        var bits: UInt64 = 0
        var bitCount = 0
        var output = String()
        output.reserveCapacity((data.count * 8 + 4) / 5)
        for byte in data {
            bits = (bits << 8) | UInt64(byte)
            bitCount += 8
            while bitCount >= 5 {
                bitCount -= 5
                let idx = Int((bits >> UInt64(bitCount)) & 0x1F)
                output.append(alphabet[idx])
            }
        }
        if bitCount > 0 {
            let idx = Int((bits << UInt64(5 - bitCount)) & 0x1F)
            output.append(alphabet[idx])
        }
        return output
    }
}

extension URLSession {
    /// Ephemeral session with strict ATS for WKD lookups. We cannot pin
    /// certificates because the WKD universe is the open web — pinning would
    /// only help if every domain shared a CA, which they don't.
    static func makeWKDSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        return URLSession(configuration: config)
    }
}
