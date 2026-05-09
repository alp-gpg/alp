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

    /// Inline ASCII-armored signature wrapping the body in
    /// `-----BEGIN PGP SIGNED MESSAGE-----` markers (`gpg --clearsign`).
    /// Use for inline-PGP outgoing messages where recipients expect to read
    /// the body as readable text.
    /// reply: (clearsignedData?, error?)
    func clearsign(
        data: Data,
        signingFingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
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

    /// Run `gpg --card-status --with-colons` and return a parsed
    /// `GPGCardStatus`. The reply data is nil when no card is present;
    /// the error path is reserved for genuine helper failures.
    func cardStatus(reply: @escaping @Sendable (Data?, NSError?) -> Void)

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

    /// Generate a new Ed25519 sign + Cv25519 encrypt primary/subkey pair using
    /// `gpg --quick-gen-key`. gpg-agent will prompt for the passphrase via the
    /// user's configured pinentry; the helper does not collect or proxy it.
    ///
    /// - name: real name (≤ 100 chars, no `<>()` or control characters).
    /// - email: RFC 5322-ish address (5..254 chars).
    /// - comment: optional UID comment (same constraints as name).
    /// - expiryDays: 0 for "never", otherwise 1..36500.
    ///
    /// reply: (newFingerprint?, error?)
    func generatePrimaryKey(
        name: String,
        email: String,
        comment: String?,
        expiryDays: Int,
        reply: @escaping @Sendable (String?, NSError?) -> Void,
    )

    /// Change the passphrase on a secret key (`gpg --edit-key FP passwd save`).
    /// gpg-agent prompts for the current and new passphrases via pinentry —
    /// the helper feeds only menu commands, never the passphrase itself.
    /// reply: (error?) — error is nil on success.
    func changePassphrase(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Set or extend the expiry of a primary key in days from now.
    /// `expiryDays` of 0 means "never expires"; otherwise 1..36500.
    /// Drives `gpg --edit-key FP expire <days> save`.
    /// reply: (error?) — error is nil on success.
    func setExpiry(
        fingerprint: String,
        expiryDays: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Certify a public key with one of *our* secret keys (`gpg --quick-sign-key`
    /// or `--quick-lsign-key`). When `exportable` is true, the signature can
    /// be uploaded to keyservers and shared. When false, the certification
    /// stays local — useful when you want to mark someone's key as trusted
    /// for your own decisions without making a public claim.
    /// reply: (error?) — error is nil on success.
    func signKey(
        fingerprint: String,
        signerFingerprint: String,
        exportable: Bool,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Set the local ownertrust value for a key via `gpg --import-ownertrust`.
    /// `level` follows gpg's numeric encoding: 2=never, 3=marginal, 4=full,
    /// 5=ultimate. The `unknown` level (1) is the implicit default — call
    /// this only with 2..5.
    /// reply: (error?) — error is nil on success.
    func setOwnerTrust(
        fingerprint: String,
        level: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Generate a revocation certificate via `gpg --gen-revoke` and import it
    /// immediately, marking the local key as revoked.
    /// `reasonCode` follows RFC 4880 §5.2.3.23: 0=no reason, 1=compromised,
    /// 2=superseded, 3=no longer used. `description` is optional, ≤ 200 chars,
    /// single-line, no `<>()` or control characters.
    /// reply: (armoredRevocationCert?, error?). The caller should offer to save
    /// the returned cert to disk so the user retains an offline backup.
    func revokePrimaryKey(
        fingerprint: String,
        reasonCode: Int,
        description: String?,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    )
}
