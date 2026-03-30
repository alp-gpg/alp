import Foundation

// NSObject-compatible for XPC; reply blocks must be @Sendable.
// Added to both AlpExtension and AlpHelper targets.
@objc protocol GPGHelperProtocol: NSObjectProtocol {
    func encrypt(
        data: Data,
        recipientFingerprints: [String],
        signingFingerprint: String?,
        reply: @escaping @Sendable (Data?, NSError?) -> Void
    )

    /// reply: (plaintext, signerFingerprint?, signerDisplayName?, error?)
    func decrypt(
        data: Data,
        reply: @escaping @Sendable (Data?, String?, String?, NSError?) -> Void
    )

    func sign(
        data: Data,
        signingFingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void
    )

    /// reply: (valid, signerFingerprint?, signerDisplayName?, error?)
    func verify(
        data: Data,
        signatureData: Data?,
        reply: @escaping @Sendable (Bool, String?, String?, NSError?) -> Void
    )

    /// reply: JSON-encoded [GPGKeyInfo] or error
    func listSecretKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void)

    /// All public keys with hasSecretKey flag set when a matching secret key exists.
    /// reply: JSON-encoded [GPGKeyInfo] or error
    func listAllKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void)

    /// Parse armored key data without importing. reply: JSON-encoded [GPGKeyInfo] or error
    func previewKey(armoredKey: Data, reply: @escaping @Sendable ([Data]?, NSError?) -> Void)

    /// Import armored key data into the local keyring. reply: error? (nil = success)
    func importKey(armoredKey: Data, reply: @escaping @Sendable (NSError?) -> Void)

    /// reply: (found, fingerprint?, error?)
    func publicKeyExists(
        email: String,
        reply: @escaping @Sendable (Bool, String?, NSError?) -> Void
    )
}
