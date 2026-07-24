import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp", category: "KeyserverPinning")

/// URLSession configured with certificate pinning for keys.openpgp.org.
/// On pin mismatch, falls back to standard TLS and posts a notification
/// so the UI can warn the user.
enum KeyserverSession {
    /// The pinned host.
    static let host = "keys.openpgp.org"

    /// Posted on the main actor when a keyserver connection succeeds but
    /// no certificate in the chain matches a pinned hash. The UI should
    /// surface a non-blocking warning. Object is the mismatched host (String).
    static let pinningDegradedNotification = Notification.Name("app.alp.Alp.keyserverPinningDegraded")

    /// App-group key for the "Strict Pinning" toggle. When true, a pin
    /// mismatch cancels the TLS handshake instead of falling back to ATS.
    /// Default is off so first-run / users behind MITM-proxies are not
    /// silently broken — opt-in for high-risk environments.
    static let strictPinningDefaultsKey = "strictKeyserverPinning"

    /// Reads the strict-pinning toggle from the shared app group so both the
    /// main app and the Mail extension honor the same setting.
    static var isStrictPinningEnabled: Bool {
        UserDefaults(suiteName: BuildConfig.appGroup)?
            .bool(forKey: strictPinningDefaultsKey) ?? false
    }

    /// SHA-256 hashes of public key data (SecKeyCopyExternalRepresentation) for
    /// Let's Encrypt intermediates serving keys.openpgp.org.
    /// Pinning intermediates (not the leaf) so 90-day LE renewals don't break.
    ///
    /// When the KeyserverPinningTests canary fails, it prints the current chain
    /// hashes — update the intermediate (index [1]) hash here.
    static let pinnedSPKIHashes: Set<Data> = {
        let base64Hashes = [
            // Let's Encrypt E7 intermediate (current, 2026-04-02)
            "rkie3IcdRKBv2qLlYHQEeMKcAIAQdrQNm5/0EJq3AqE=",
            // ISRG Root X2 (LE ECDSA root — stable, long-lived)
            "9Fk6HgfMnM7/vtnBHcUhg1b3gU2bIpSd50XmKZkMbGA=",
        ]
        return Set(base64Hashes.compactMap { Data(base64Encoded: $0) })
    }()

    /// Shared session with pinning delegate. Falls back to standard TLS on pin mismatch.
    static let shared: URLSession = {
        let delegate = PinningDelegate()
        return URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
    }()
}

private final class PinningDelegate: NSObject, URLSessionDelegate, Sendable {
    /// Only post the degraded notification once per process to avoid spamming.
    private let hasNotified = OSAllocatedUnfairLock(initialState: false)

    func urlSession(
        _: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == KeyserverSession.host,
              let trust = challenge.protectionSpace.serverTrust
        else {
            return (.performDefaultHandling, nil)
        }

        // If no pins configured, fall back to standard ATS validation.
        guard !KeyserverSession.pinnedSPKIHashes.isEmpty else {
            return (.performDefaultHandling, nil)
        }

        // Evaluate the trust chain first.
        var cfError: CFError?
        guard SecTrustEvaluateWithError(trust, &cfError) else {
            return (.cancelAuthenticationChallenge, nil)
        }

        // Check each certificate in the chain for a matching hash.
        if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
            for cert in chain {
                if let publicKey = SecCertificateCopyKey(cert) {
                    var error: Unmanaged<CFError>?
                    if let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
                        let hash = SHA256.hash(keyData)
                        if KeyserverSession.pinnedSPKIHashes.contains(hash) {
                            return (.useCredential, URLCredential(trust: trust))
                        }
                    }
                }
            }
        }

        // Pin mismatch. In strict mode, cancel outright. Otherwise fall back
        // to standard ATS validation and notify the UI so the user is warned.
        let strict = KeyserverSession.isStrictPinningEnabled
        if strict {
            log.error("Certificate pin mismatch for \(KeyserverSession.host) — strict pinning enabled, cancelling")
        } else {
            log.warning("Certificate pin mismatch for \(KeyserverSession.host) — falling back to standard TLS")
        }

        let shouldNotify = hasNotified.withLock { notified -> Bool in
            if notified {
                return false
            }
            notified = true
            return true
        }
        if shouldNotify {
            Task { @MainActor in
                NotificationCenter.default.post(
                    name: KeyserverSession.pinningDegradedNotification,
                    object: KeyserverSession.host,
                )
            }
        }

        return strict ? (.cancelAuthenticationChallenge, nil) : (.performDefaultHandling, nil)
    }
}

/// Minimal SHA-256 using CommonCrypto (available on all Apple platforms without extra imports).
private enum SHA256 {
    static func hash(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: 32)
        _ = data.withUnsafeBytes { ptr in
            CC_SHA256(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }
}

import CommonCrypto
