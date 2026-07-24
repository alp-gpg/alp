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
    /// the chain serving keys.openpgp.org. Pinning above the leaf so 90-day LE
    /// renewals don't break; three levels deep so a rotation at any single
    /// level still matches another pin.
    ///
    /// When the KeyserverPinningTests canary fails
    /// (`TEST_RUNNER_ALP_RUN_NETWORK_TESTS=1`), it prints the current chain
    /// hashes. Before pinning a new value, verify the certificate against an
    /// authoritative source (https://letsencrypt.org/certs/) — do NOT pin
    /// whatever the network serves. The 2026-07 rotation revealed the previous
    /// "ISRG Root X2" pin had been mis-computed and never matched the real X2
    /// key, so the intended rotation resilience silently didn't exist.
    static let pinnedSPKIHashes: Set<Data> = {
        let base64Hashes = [
            // Let's Encrypt YE2 intermediate (current, verified 2026-07-24)
            "uVnyjs8i8IbTN0j/dhQYuoLYVYfhIa0bczhBt2SP4GQ=",
            // ISRG Root YE (new ISRG root, cross-signed by X2; survives
            // intermediate rotation within the YE hierarchy)
            "o8gmWo6hTNA1Y/ybI8g6rlbzT1YElMY4ivrLbjg5fyE=",
            // ISRG Root X2 — verified against letsencrypt.org/certs/isrg-root-x2.pem
            // (SHA-256 cert fingerprint 69:72:9B:8E:…:CB:14:70)
            "+QHt0j1IgBr88CsiSG197KRsbAlprQDohcvoe1Za45Y=",
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
