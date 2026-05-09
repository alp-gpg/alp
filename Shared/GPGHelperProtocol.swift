import Foundation

/// NSObject-compatible for XPC; reply blocks must be @Sendable.
/// Added to both AlpExtension and AlpHelper targets.
@objc protocol GPGHelperProtocol: NSObjectProtocol {
    func encrypt(
        data: Data,
        recipientFingerprints: [String],
        signingFingerprint: String?,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    )

    /// reply: (plaintext, signerFingerprint?, signerDisplayName?, error?)
    func decrypt(
        data: Data,
        reply: @escaping @Sendable (Data?, String?, String?, NSError?) -> Void,
    )

    /// reply: (signature, micalgHashAlgorithm?, error?)
    /// `micalgHashAlgorithm` is the RFC 3156 hash name (e.g. "pgp-sha256", "pgp-sha512")
    /// parsed from gpg's SIG_CREATED status line.
    func sign(
        data: Data,
        signingFingerprint: String,
        reply: @escaping @Sendable (Data?, String?, NSError?) -> Void,
    )

    /// reply: (valid, signerFingerprint?, signerDisplayName?, error?)
    func verify(
        data: Data,
        signatureData: Data?,
        reply: @escaping @Sendable (Bool, String?, String?, NSError?) -> Void,
    )

    /// reply: JSON-encoded [GPGKeyInfo] or error
    func listSecretKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void)

    /// All public keys with hasSecretKey flag set when a matching secret key exists.
    /// reply: JSON-encoded [GPGKeyInfo] or error
    func listAllKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void)

    /// Parse armored key data without importing. reply: JSON-encoded [GPGKeyInfo] or error
    func previewKey(armoredKey: Data, reply: @escaping @Sendable ([Data]?, NSError?) -> Void)

    /// reply: (jsonEncodedGPGImportResult?, error?)
    func importKey(armoredKey: Data, reply: @escaping @Sendable (Data?, NSError?) -> Void)

    /// reply: (found, fingerprint?, error?)
    func publicKeyExists(
        email: String,
        reply: @escaping @Sendable (Bool, String?, NSError?) -> Void,
    )

    /// Check GPG environment health. reply: JSON-encoded GPGHealthStatus or error
    func checkHealth(reply: @escaping @Sendable (Data?, NSError?) -> Void)

    /// Export a public key as ASCII-armored data (`gpg --armor --export FP`).
    /// reply: (armoredKey?, error?)
    func exportPublicKey(
        fingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    )

    /// Export a secret key as ASCII-armored data (`gpg --armor --export-secret-keys FP`).
    /// gpg-agent will prompt for the passphrase via the user's pinentry.
    /// reply: (armoredKey?, error?)
    func exportSecretKey(
        fingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    )

    /// Remove a public key (and any matching secret key) from the local keyring
    /// (`gpg --batch --yes --delete-keys FP`). Caller must confirm in the UI.
    /// reply: (error?) — error is nil on success.
    func deletePublicKey(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Remove only the secret half of a key pair, leaving the public key in place
    /// (`gpg --batch --yes --delete-secret-keys FP`). Caller must confirm in the UI.
    /// reply: (error?) — error is nil on success.
    func deleteSecretKey(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    )
}
