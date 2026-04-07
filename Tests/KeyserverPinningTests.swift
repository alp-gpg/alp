import Foundation
import Testing

struct KeyserverPinningTests {
    /// Connects to keys.openpgp.org and verifies that at least one certificate
    /// in the chain matches a pinned SPKI hash. Fails with actionable output
    /// if the server's certificate chain has rotated to an unpinned intermediate.
    @Test
    func `Server certificate chain contains a pinned intermediate`() async throws {
        let url = try #require(URL(string: "https://keys.openpgp.org"))
        let collector = CertificateCollector()
        let session = URLSession(configuration: .ephemeral, delegate: collector, delegateQueue: nil)

        // A simple HEAD request is enough to trigger the TLS handshake.
        let (_, response) = try await session.data(for: URLRequest(url: url))
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            Issue.record("Keyserver returned non-200; can't verify pins")
            return
        }

        let chainHashes = collector.spkiHashes
        #expect(!chainHashes.isEmpty, "No SPKI hashes collected — TLS delegate not called?")

        let pinnedSet = KeyserverSession.pinnedSPKIHashes
        #expect(!pinnedSet.isEmpty, "pinnedSPKIHashes is empty — pinning is disabled")

        let matched = !chainHashes.filter { pinnedSet.contains($0) }.isEmpty

        if !matched {
            let chainBase64 = chainHashes.map { $0.base64EncodedString() }
            Issue.record("""
            Certificate pin mismatch for keys.openpgp.org!
            None of the server's SPKI hashes match a pinned value.

            Server chain SPKI hashes (base64):
            \(chainBase64.enumerated().map { "  [\($0.offset)] \($0.element)" }.joined(separator: "\n"))

            Update pinnedSPKIHashes in Shared/KeyserverSession.swift with the new intermediate hash.
            """)
        }
    }
}

/// URLSession delegate that collects SPKI SHA-256 hashes from the server's certificate chain.
private final class CertificateCollector: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var _hashes: [Data] = []

    var spkiHashes: [Data] {
        lock.withLock { _hashes }
    }

    func urlSession(
        _: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            return (.performDefaultHandling, nil)
        }

        var hashes: [Data] = []
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            for cert in chain {
                if let key = SecCertificateCopyKey(cert) {
                    var error: Unmanaged<CFError>?
                    if let keyData = SecKeyCopyExternalRepresentation(key, &error) as Data? {
                        hashes.append(sha256(keyData))
                    }
                }
            }
        }

        lock.withLock { _hashes = hashes }
        return (.performDefaultHandling, nil)
    }

    private func sha256(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: 32)
        data.withUnsafeBytes { ptr in
            CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }
}

import CommonCrypto
