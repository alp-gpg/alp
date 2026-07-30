import Foundation
import Testing

// Executes the key-lifecycle helper methods against a real gpg. Until now these
// were only argument-validated, never run.
//
// What this actually guards: most of them drive gpg's *interactive* edit-key
// menu through --command-fd with a hardcoded transcript, e.g.
// "key 2\nrevkey\ny\n0\n\ny\nsave\n". Those transcripts encode the exact
// prompt sequence of one gpg version. When Homebrew moves gnupg and a prompt is
// added, removed or reordered, gpg still exits 0 — it just saves nothing, or
// acts on the wrong subkey. Nothing in the argument-validation tests can see
// that. So every assertion below re-reads the keyring afterwards and checks the
// change actually landed; a silent no-op has to fail.
//
// Gated on the hermetic keyring: these operations revoke and delete keys, so
// they must never run against a developer's real keyring. scripts/test.sh sets
// the variable after pointing $HOME at a scratch directory.

private let hermeticKeyring = ProcessInfo.processInfo.environment["ALP_HERMETIC_KEYRING"] == "1"

/// Runs the gpg CLI directly, out of band from the helper. Used to mint
/// disposable keys and to read raw colon listings — deliberately not going
/// through GPGHelper, so a parser bug there cannot mask a failed mutation.
@discardableResult
private func gpgCLI(_ arguments: [String]) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["gpg"] + arguments
    var environment = ProcessInfo.processInfo.environment
    environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/opt/local/bin:/usr/bin:/bin"
    process.environment = environment
    let out = Pipe()
    process.standardOutput = out
    process.standardError = Pipe()
    try process.run()
    let data = out.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return String(bytes: data, encoding: .utf8) ?? ""
}

/// Creates a passphrase-less disposable key and returns its fingerprint.
/// Passphrase-less is required, not convenient: a protected key routes every
/// edit through gpg-agent into pinentry and blocks on a human.
private func mintDisposableKey(email: String) async throws -> String {
    try gpgCLI([
        "--batch", "--yes", "--passphrase", "",
        "--quick-gen-key", "Lifecycle Test <\(email)>", "default", "default", "never",
    ])
    let keys = try await GPGHelper()._listAllKeys()
    let key = try #require(
        keys.first { $0.userIDs.contains { $0.contains(email) } },
        "disposable key \(email) was not created",
    )
    return key.fingerprint
}

private func reload(_ fingerprint: String) async throws -> GPGKeyInfo {
    let keys = try await GPGHelper()._listAllKeys()
    return try #require(keys.first { $0.fingerprint == fingerprint }, "key vanished from the keyring")
}

/// Raw colon listing for one key. Field 2 carries the validity flag, where
/// "r" means revoked — the ground truth for "did the revoke actually save".
private func colonListing(_ fingerprint: String) throws -> String {
    try gpgCLI(["--list-keys", "--with-colons", fingerprint])
}

@Suite(
    "GPG key lifecycle",
    .enabled(if: hermeticKeyring, "requires the scratch keyring — run scripts/test.sh"),
    .serialized,
)
struct GPGKeyLifecycleTests {
    @Test
    func `generates an Ed25519 primary key and parses its fingerprint from KEY_CREATED`() async throws {
        let fingerprint = try await GPGHelper()._generatePrimaryKey(
            name: "Generated Lifecycle", email: "generated-lifecycle@alp.invalid",
            comment: nil, expiryDays: 0,
        )

        // reload proves the parsed fingerprint denotes a key that actually
        // exists — a KEY_CREATED mis-parse would hand back garbage here.
        let key = try await reload(fingerprint)
        #expect(key.userIDs.contains { $0.contains("generated-lifecycle@alp.invalid") })
        // `future-default` is what backs the UI's "Ed25519 + Cv25519" label;
        // the curve names are colon-delimited fields in the listing.
        let listing = try colonListing(fingerprint)
        #expect(listing.contains(":ed25519:"))
        #expect(listing.contains(":cv25519:"))
    }

    @Test
    func `adds a user ID and revokes it`() async throws {
        let fingerprint = try await mintDisposableKey(email: "uid-lifecycle@alp.invalid")
        let helper = GPGHelper()
        #expect(try await reload(fingerprint).userIDs.count == 1)

        try await helper._addUserID(
            fingerprint: fingerprint,
            name: "Second Identity",
            email: "second-uid@alp.invalid",
            comment: nil,
        )
        let withSecond = try await reload(fingerprint)
        #expect(withSecond.userIDs.count == 2)
        #expect(withSecond.userIDs.contains { $0.contains("second-uid@alp.invalid") })

        // uid 2 is the one just added. gpg exits 0 whether or not revuid's
        // prompt sequence still matches, so check the listing, not the exit.
        try await helper._revokeUserID(fingerprint, uidIndex: 2)
        #expect(try colonListing(fingerprint).contains("uid:r:"))
    }

    @Test
    func `adds a subkey, then revokes and deletes it`() async throws {
        let fingerprint = try await mintDisposableKey(email: "subkey-lifecycle@alp.invalid")
        let helper = GPGHelper()
        let initialCount = try await reload(fingerprint).subkeys.count

        try await helper._addSubkey(fingerprint: fingerprint, algoTag: "ed25519/sign", expiryDays: 30)
        #expect(try await reload(fingerprint).subkeys.count == initialCount + 1)

        // key 2 = the subkey just added (gpg's `key <n>` is 1-based on subkeys).
        try await helper._revokeSubkey(fingerprint, subkeyIndex: 2, reasonCode: 0)
        #expect(try colonListing(fingerprint).contains("sub:r:"))

        try await helper._deleteSubkey(fingerprint, subkeyIndex: 2)
        #expect(try await reload(fingerprint).subkeys.count == initialCount)
    }

    @Test
    func `deletes several subkeys in one batch`() async throws {
        let fingerprint = try await mintDisposableKey(email: "batch-delete-lifecycle@alp.invalid")
        let helper = GPGHelper()
        let initialCount = try await reload(fingerprint).subkeys.count

        try await helper._addSubkey(fingerprint: fingerprint, algoTag: "ed25519/sign", expiryDays: 0)
        try await helper._addSubkey(fingerprint: fingerprint, algoTag: "ed25519/auth", expiryDays: 0)
        #expect(try await reload(fingerprint).subkeys.count == initialCount + 2)

        // One transcript stacks several `key <n>` selections before a single
        // delkey. A drifted prompt sequence could delete only the last
        // selection and still exit 0, so the count is the assertion.
        try await helper._deleteSubkeys(fingerprint, subkeyIndices: [initialCount + 1, initialCount + 2])
        #expect(try await reload(fingerprint).subkeys.count == initialCount)
    }

    @Test
    func `sets an expiry on a key created to never expire`() async throws {
        let fingerprint = try await mintDisposableKey(email: "expiry-lifecycle@alp.invalid")
        #expect(try await reload(fingerprint).expiryDate == nil)

        try await GPGHelper()._setExpiry(fingerprint, expiryDays: 90)

        let expiry = try #require(try await reload(fingerprint).expiryDate, "expiry did not save")
        let daysOut = expiry.timeIntervalSinceNow / 86400
        #expect(daysOut > 88 && daysOut < 92)
    }

    @Test
    func `writes owner trust into the trust database`() async throws {
        let fingerprint = try await mintDisposableKey(email: "trust-lifecycle@alp.invalid")

        try await GPGHelper()._setOwnerTrust(fingerprint, level: 5)

        // Read the trustdb back out rather than trusting the colon listing's
        // derived validity column, which also folds in signatures.
        let exported = try gpgCLI(["--export-ownertrust"])
        #expect(exported.contains("\(fingerprint):5:"))
    }

    @Test
    func `signs one key with another`() async throws {
        let target = try await mintDisposableKey(email: "signed-lifecycle@alp.invalid")
        let signer = try await mintDisposableKey(email: "signer-lifecycle@alp.invalid")

        try await GPGHelper()._signKey(fingerprint: target, signer: signer, exportable: true)

        // A certification from the signer must now appear on the target.
        let signatures = try gpgCLI(["--list-sigs", "--with-colons", target])
        #expect(signatures.contains(String(signer.suffix(16))))
    }

    @Test
    func `produces an armored revocation certificate without revoking the key`() async throws {
        let fingerprint = try await mintDisposableKey(email: "revcert-lifecycle@alp.invalid")

        let certificate = try await GPGHelper()._generateRevocationCert(fingerprint: fingerprint)

        let armor = String(bytes: certificate, encoding: .utf8) ?? ""
        #expect(armor.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        #expect(armor.contains("-----END PGP PUBLIC KEY BLOCK-----"))
        // _generateRevocationCert must not import what it generates — that is
        // _revokePrimaryKey's job, and conflating them would revoke a key the
        // user only wanted a backup certificate for.
        #expect(try !colonListing(fingerprint).contains("pub:r:"))
    }

    @Test
    func `backs up a key and restores it after deletion`() async throws {
        let fingerprint = try await mintDisposableKey(email: "backup-lifecycle@alp.invalid")
        let helper = GPGHelper()
        // Explicit ownertrust so the bundle carries a trust section and the
        // restore path's --import-ownertrust branch executes.
        try await helper._setOwnerTrust(fingerprint, level: 4)

        // The stub pinentry answers the symmetric-wrap passphrase prompt —
        // the same prompt a user would see.
        let bundle = try await helper._backupKey(fingerprint: fingerprint)
        #expect(String(bytes: bundle, encoding: .utf8)?
            .contains("-----BEGIN PGP MESSAGE-----") == true)

        let bundleURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("alp-backup-roundtrip.asc")
        try bundle.write(to: bundleURL)
        defer { try? FileManager.default.removeItem(at: bundleURL) }

        try gpgCLI(["--batch", "--yes", "--delete-secret-and-public-key", fingerprint])
        #expect(try !gpgCLI(["--list-keys", "--with-colons"]).contains(fingerprint))

        let imported = try await helper._restoreBackup(bundlePath: bundleURL.path)
        #expect(imported.contains(fingerprint))

        let restored = try await reload(fingerprint)
        #expect(restored.hasSecretKey)
        // The bundle also carries a revocation certificate. gpg's colon guard
        // on --gen-revoke output must keep --import from applying it — a
        // restore that resurrects the key already revoked would be data loss.
        #expect(try !colonListing(fingerprint).contains("pub:r:"))
    }

    @Test
    func `revokes a primary key with no description`() async throws {
        // Regression: the transcript used to emit the empty description as its
        // own line *plus* the terminating blank. gpg answered "Is this okay?"
        // with the extra blank, re-asked for the reason code, and died on EOF —
        // leaving the key unrevoked while the UI's default path reported an
        // opaque failure. Both description branches are covered because they
        // produce different transcripts.
        let fingerprint = try await mintDisposableKey(email: "revoke-lifecycle@alp.invalid")
        #expect(try !colonListing(fingerprint).contains("pub:r:"))

        let certificate = try await GPGHelper()._revokePrimaryKey(
            fingerprint, reasonCode: 0, description: nil,
        )

        #expect(!certificate.isEmpty)
        // Unlike _generateRevocationCert this one imports, so the local key
        // must now read as revoked.
        #expect(try colonListing(fingerprint).contains("pub:r:"))
    }

    @Test
    func `revokes a primary key with a description`() async throws {
        let fingerprint = try await mintDisposableKey(email: "revoke-desc-lifecycle@alp.invalid")

        let certificate = try await GPGHelper()._revokePrimaryKey(
            fingerprint, reasonCode: 1, description: "Key superseded",
        )

        #expect(!certificate.isEmpty)
        #expect(try colonListing(fingerprint).contains("pub:r:"))
    }
}
