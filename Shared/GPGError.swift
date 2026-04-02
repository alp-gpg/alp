import Foundation

enum GPGError: Error, Sendable {
    case gpgNotFound
    case processError(exitCode: Int32, stderr: String)
    case noSigningKey
    case missingKeys([String])
    case decryptionFailed(String)
    case verificationFailed(String)
    case xpcUnavailable
    case encodingError(String)
}

extension GPGError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .gpgNotFound:
            "gpg binary not found. Install with: brew install gnupg"
        case let .processError(code, stderr):
            "gpg exited with code \(code): \(stderr)"
        case .noSigningKey:
            "No secret key available for signing."
        case let .missingKeys(emails):
            "No public key for: \(emails.joined(separator: ", "))"
        case let .decryptionFailed(detail):
            "Decryption failed: \(detail)"
        case let .verificationFailed(detail):
            "Signature verification failed: \(detail)"
        case .xpcUnavailable:
            "GPG helper service is not running. Open Alp and install the helper."
        case let .encodingError(detail):
            "Message encoding error: \(detail)"
        }
    }
}

extension GPGError {
    var asNSError: NSError {
        NSError(
            domain: "app.alp.Alp.GPGError",
            code: nsErrorCode,
            userInfo: [NSLocalizedDescriptionKey: errorDescription ?? "Unknown error"]
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
        }
    }
}
