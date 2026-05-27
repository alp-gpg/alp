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

    /// Decrypt a file in-place via gpg streaming — avoids the 50 MB XPC
    /// payload limit. Both paths must be absolute; `outputPath` must
    /// differ from `inputPath` so a malformed call can't clobber the
    /// ciphertext. The helper reads `inputPath` and writes plaintext to
    /// `outputPath`; gpg-agent prompts for the passphrase via pinentry.
    /// reply: (signerFingerprint?, signerDisplayName?, error?)
    func decryptFile(
        inputPath: String,
        outputPath: String,
        reply: @escaping @Sendable (String?, String?, NSError?) -> Void,
    )

    /// Verify a signature file. When `signaturePath` is nil, `inputPath`
    /// is expected to be a clearsigned or armored signature wrapping its
    /// own data. When `signaturePath` is non-nil, it points at a detached
    /// signature and `inputPath` is the data being verified.
    /// reply: (valid, signerFingerprint?, signerDisplayName?, error?)
    func verifyFile(
        inputPath: String,
        signaturePath: String?,
        reply: @escaping @Sendable (Bool, String?, String?, NSError?) -> Void,
    )

    /// Produce an ASCII-armored detached signature for `inputPath`,
    /// writing the .asc/.sig blob to `outputPath`. Both paths absolute,
    /// must differ. gpg-agent prompts via pinentry for the signer's
    /// passphrase. reply: (error?)
    func signFile(
        inputPath: String,
        outputPath: String,
        signingFingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Encrypt `inputPath` to one or more recipients (optionally also
    /// signing) and write the binary OpenPGP packet to `outputPath`. Both
    /// paths absolute, must differ. Each recipient and the signer (when
    /// present) must be a 40-char hex fingerprint.
    /// reply: (error?)
    func encryptFile(
        inputPath: String,
        outputPath: String,
        recipientFingerprints: [String],
        signingFingerprint: String?,
        reply: @escaping @Sendable (NSError?) -> Void,
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

    /// Drive `gpg --card-edit` → `passwd` → option 1 to change the
    /// OpenPGP user PIN. gpg-agent prompts the user via pinentry for the
    /// current PIN and then the new PIN twice; the helper never sees the
    /// PIN material. reply: (error?)
    func changeCardPIN(reply: @escaping @Sendable (NSError?) -> Void)

    /// Reads the `pinentry-program` line from `~/.gnupg/gpg-agent.conf`.
    /// reply: (currentProgramPath?, isAlp, error?) where `isAlp` is
    /// true when the configured path points at our shim.
    func pinentryConfigStatus(
        reply: @escaping @Sendable (String?, Bool, NSError?) -> Void,
    )

    /// Install the Alp pinentry shim and point gpg-agent at it.
    /// `bundlePath` is the absolute path to the running Alp.app bundle so
    /// the shim can `exec` `<bundle>/Contents/Helpers/AlpPinentry`.
    /// gpg-agent is restarted via `gpgconf --kill gpg-agent` before the
    /// reply.
    func installAlpPinentry(
        bundlePath: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Remove the `pinentry-program` line from `gpg-agent.conf` and
    /// restart gpg-agent so it falls back to its default pinentry
    /// search. The shim script is left in place for later re-enable.
    func uninstallAlpPinentry(reply: @escaping @Sendable (NSError?) -> Void)

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

    /// Add a new subkey to an existing primary key via
    /// `gpg --quick-add-key FP <algo> <usage> <expire>`. `algoTag` selects
    /// the curve + role: "ed25519/sign", "cv25519/encr", "ed25519/auth".
    /// reply: (error?) — error is nil on success.
    func addSubkey(
        fingerprint: String,
        algoTag: String,
        expiryDays: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Revoke a single subkey while leaving the primary and other subkeys
    /// alone (`gpg --edit-key FP key <n> revkey save`). `subkeyIndex` is
    /// 1-based — 1 means the first subkey in listing order.
    /// `reasonCode` follows RFC 4880 §5.2.3.23: 0=no reason, 1=superseded,
    /// 2=compromised, 3=no longer used.
    /// reply: (error?) — error is nil on success.
    func revokeSubkey(
        fingerprint: String,
        subkeyIndex: Int,
        reasonCode: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Permanently delete a subkey (`gpg --edit-key FP key <n> delkey save`).
    /// Use `revokeSubkey` instead unless the goal is genuine cleanup —
    /// deletion strips the subkey from the local keyring without producing
    /// a revocation that other people can see. 1-based index.
    /// reply: (error?) — error is nil on success.
    func deleteSubkey(
        fingerprint: String,
        subkeyIndex: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Bulk-delete subkeys in one `--edit-key` session so gpg-agent only
    /// prompts for the passphrase once. Indices are 1-based to match
    /// gpg's `key <n>` command. Empty input is a no-op.
    /// reply: (error?) — error is nil on success.
    func deleteSubkeys(
        fingerprint: String,
        subkeyIndices: [NSNumber],
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Append a new User ID to an existing primary key
    /// (`gpg --edit-key FP adduid save`). gpg-agent prompts for the
    /// passphrase via pinentry. Validation rules match `generatePrimaryKey`.
    /// reply: (error?) — error is nil on success.
    func addUserID(
        fingerprint: String,
        name: String,
        email: String,
        comment: String?,
        reply: @escaping @Sendable (NSError?) -> Void,
    )

    /// Revoke an existing UID by its 1-based index
    /// (`gpg --edit-key FP uid <n> revuid save`). Used to retire a stale
    /// email without nuking the whole key.
    /// reply: (error?) — error is nil on success.
    func revokeUserID(
        fingerprint: String,
        uidIndex: Int,
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
