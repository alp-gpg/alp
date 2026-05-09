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
            String(localized: "gpg exited with code \(code): \(stderr)")
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
}

extension GPGError {
    /// User-friendly description that maps common gpg stderr patterns to actionable messages.
    var userFacingDescription: String {
        switch self {
        case let .processError(_, stderr):
            let lower = stderr.lowercased()
            if lower.contains("no secret key") {
                return String(
                    localized: "No secret key found for decryption. The message may have been encrypted to a different key.",
                )
            }
            if lower.contains("no public key") {
                return String(localized: "Recipient's public key not found in your keyring.")
            }
            if lower.contains("unusable public key") || lower.contains("unusable secret key") {
                return String(localized: "The key is expired or revoked and cannot be used.")
            }
            if lower.contains("bad passphrase") || lower.contains("bad password") {
                return String(localized: "Incorrect passphrase. Check your pinentry-mac configuration.")
            }
            if lower.contains("no pinentry") || lower.contains("problem with the agent") {
                return String(
                    localized: "Could not prompt for passphrase. Verify pinentry-mac is configured in ~/.gnupg/gpg-agent.conf.",
                )
            }
            if lower.contains("not acceptable") || lower.contains("compliance") {
                return String(localized: "The key does not meet the required trust or policy level.")
            }
            return errorDescription ?? String(localized: "GPG operation failed.")
        default:
            return errorDescription ?? String(localized: "Unknown GPG error.")
        }
    }

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
