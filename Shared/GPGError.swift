import Foundation

enum GPGError: Error {
    case gpgNotFound
    case processError(exitCode: Int32, stderr: String)
    case noSigningKey
    case missingKeys([String])
    case decryptionFailed(String)
    case verificationFailed(String)
    case xpcUnavailable
    case encodingError(String)
    case importRejected(String)
}

extension GPGError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .gpgNotFound:
            String(localized: "gpg binary not found. Install with: brew install gnupg")
        case let .processError(code, stderr):
            GPGError.friendlyProcessError(code: code, stderr: stderr)
        case .noSigningKey:
            String(localized: "No secret key available for signing.")
        case let .missingKeys(emails):
            String(localized: "No public key for: \(emails.joined(separator: ", "))")
        case let .decryptionFailed(detail):
            String(localized: "Decryption failed: \(detail)")
        case let .verificationFailed(detail):
            String(localized: "Signature verification failed: \(detail)")
        case .xpcUnavailable:
            String(localized: "GPG helper service is not running. Open Alp and install the helper.")
        case let .encodingError(detail):
            String(localized: "Message encoding error: \(detail)")
        case let .importRejected(detail):
            String(localized: "gpg refused to import the key: \(detail)")
        }
    }

    /// Map the common gpg failure modes to plain guidance for the target
    /// audience; fall back to the raw stderr (still useful to experts) for
    /// anything unrecognized (§5.6).
    private static func friendlyProcessError(code: Int32, stderr: String) -> String {
        let lower = stderr.lowercased()
        if lower.contains("no secret key") {
            return String(localized: "No matching secret key is available for this operation.")
        }
        if lower.contains("bad passphrase") || lower.contains("no passphrase") {
            return String(localized: "Wrong or missing passphrase. Try again.")
        }
        if lower.contains("no pinentry") || (lower.contains("pinentry") && lower.contains("not")) {
            return String(localized: "Couldn't show the passphrase prompt. Reinstall the Alp helper from Settings.")
        }
        if lower.contains("no public key") || lower.contains("unusable public key") {
            return String(localized: "No usable public key for one or more recipients.")
        }
        if lower.contains("decryption failed") || lower.contains("no secret key found") {
            return String(localized: "This message can't be decrypted with your keys.")
        }
        let trimmed = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty
            ? String(localized: "gpg failed with code \(code).")
            : String(localized: "gpg failed (code \(code)): \(trimmed)")
    }
}

extension GPGError {
    var asNSError: NSError {
        NSError(
            domain: "app.alp.Alp.GPGError",
            code: nsErrorCode,
            userInfo: [NSLocalizedDescriptionKey: errorDescription ?? "Unknown error"],
        )
    }

    private var nsErrorCode: Int {
        switch self {
        case .gpgNotFound: 1
        case .processError: 2
        case .noSigningKey: 3
        case .missingKeys: 4
        case .decryptionFailed: 5
        case .verificationFailed: 6
        case .xpcUnavailable: 7
        case .encodingError: 8
        case .importRejected: 9
        }
    }
}
