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
