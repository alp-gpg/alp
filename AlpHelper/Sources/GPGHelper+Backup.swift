import Foundation

/// Key backup bundle assembly. Lives in its own file because the
/// orchestration here is feature-distinct from the rest of the helper
/// and we want the main `GPGHelper.swift` to stay readable.
///
/// Backup layout (UTF-8 text, then symmetric-encrypted as a whole):
///
///   # Alp key backup
///   # Fingerprint: <40 hex>
///   # Created: <ISO 8601>
///   # Restore: `gpg --decrypt <file> | gpg --import` then
///   #   `gpg --import-ownertrust <(gpg --decrypt <file>)`
///
///   -----BEGIN PGP PUBLIC KEY BLOCK-----   (primary public)
///   ...
///   -----BEGIN PGP PRIVATE KEY BLOCK-----  (secret)
///   ...
///   :-----BEGIN PGP PUBLIC KEY BLOCK-----  (revocation cert, colon-guarded)
///   ...
///   # ownertrust:
///   <fp>:<level>:
///
/// gpg's `--import` reads multiple armored blocks from a single stream,
/// so restore is `gpg --decrypt … | gpg --import` plus a separate
/// `gpg --import-ownertrust` pass on the trailing trust line. The
/// revocation cert's colon guard (gpg's own openpgp-revocs.d convention)
/// keeps that import from revoking the key being restored.
extension GPGHelper {
    func _backupKey(fingerprint: String) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        // 1. Public key
        let pub = try await _exportPublicKey(fingerprint)
        // 2. Secret key — gpg-agent prompts via pinentry for the
        //    secret-key passphrase. We never see it.
        let sec = try await _exportSecretKey(fingerprint)
        // 3. Fresh revocation certificate. Reason 0 ("no reason"), no
        //    description; the user can regenerate a more specific one
        //    later if they actually need to revoke. We do not import
        //    the cert — the point of a backup is to capture the
        //    *possibility* of revocation without changing local state.
        let revoke = try await _generateRevocationCert(fingerprint: fingerprint)
        // 4. Ownertrust line for this key (if any).
        let trust = try await _exportOwnertrust(for: fingerprint)

        let isoFormatter = ISO8601DateFormatter()
        isoFormatter.formatOptions = [.withInternetDateTime]
        var sections: [String] = []
        sections.append("""
        # Alp key backup
        # Fingerprint: \(fingerprint)
        # Created: \(isoFormatter.string(from: Date()))
        # Restore: pipe `gpg --decrypt <file>` through `gpg --import`,
        #   then feed the ownertrust block at the end of this bundle to
        #   `gpg --import-ownertrust`.
        """)
        if let pubText = String(data: pub, encoding: .utf8) {
            sections.append(pubText)
        }
        if let secText = String(data: sec, encoding: .utf8) {
            sections.append(secText)
        }
        if let revokeText = String(data: revoke, encoding: .utf8) {
            // Colon-guard the BEGIN line, exactly like gpg's own
            // openpgp-revocs.d files: the armor scanner then never opens the
            // block, so restoring this bundle cannot import the certificate
            // and revoke the key it just resurrected. Removing the colon
            // re-arms it.
            sections.append("""
            # Revocation certificate. Guarded against accidental import —
            # to actually revoke this key, remove the leading ':' and run
            # `gpg --import` on this block alone.
            \(revokeText.replacingOccurrences(
                of: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
                with: ":-----BEGIN PGP PUBLIC KEY BLOCK-----",
            ))
            """)
        }
        if !trust.isEmpty {
            sections.append("# ownertrust:\n\(trust)")
        }
        let plaintext = sections.joined(separator: "\n")

        // 5. Wrap in a passphrase-protected symmetric envelope. Skip
        //    `--batch` so gpg-agent can drive pinentry to collect the
        //    archive passphrase. AES-256 matches gpg's modern default
        //    but pinning it here keeps the bundle decryptable across
        //    gpg versions that change defaults.
        //
        //    On gpg ≥ 2.3 we pass `--force-ocb` (alias `--force-aead`) so
        //    the outer layer uses OCB AEAD instead of RFC 4880 CFB —
        //    giving tamper detection at the cipher layer. A bare `--aead`
        //    is NOT that option: gpg reads it as an abbreviation of
        //    `--aead-algo`, which takes an argument, and exits 2 with
        //    "missing argument" — failing every backup. gpg < 2.3 falls
        //    back to CFB (still passphrase-protected; packet validation
        //    still catches most tampering).
        var args = [
            "--yes", "--armor",
            "--symmetric", "--cipher-algo", "AES256",
            "--output", "-",
        ]
        if let version = try? await gpgVersion(), compareVersion(version, isAtLeast: "2.3") {
            args.append("--force-ocb")
        }
        return try await runGPG(args, input: Data(plaintext.utf8))
    }

    /// Generate-only revocation certificate. Unlike `_revokePrimaryKey`
    /// this does NOT pipe the resulting cert back through `--import`,
    /// so the user's local key remains unrevoked. Reason 0 / no
    /// description — appropriate for a "future revoke" cert kept in a
    /// backup bundle.
    ///
    /// `--no-tty` is load-bearing: without it, `gpg --gen-revoke`
    /// tries to write its menu prompts to /dev/tty even when fed via
    /// `--command-fd 0`, which fails inside the helper process where
    /// no controlling terminal is attached (errno: "Device not
    /// configured"). The `--command-fd`/`--status-fd` pair carries
    /// every interaction we need.
    func _generateRevocationCert(fingerprint: String) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        let commands = "y\n0\n\ny\n"
        let args = [
            "--no-tty",
            "--armor", "--command-fd", "0", "--status-fd", "2",
            "--gen-revoke", fingerprint,
        ]
        return try await runGPG(args, input: Data(commands.utf8))
    }

    /// Filter `gpg --export-ownertrust` output down to lines matching
    /// the target fingerprint. Returns "" when the key has no explicit
    /// ownertrust (gpg's default state).
    private func _exportOwnertrust(for fingerprint: String) async throws -> String {
        let out = try await runGPG(["--export-ownertrust"])
        let text = String(data: out, encoding: .utf8) ?? ""
        return text.components(separatedBy: "\n")
            .filter { $0.hasPrefix(fingerprint + ":") }
            .joined(separator: "\n")
    }

    /// Restore the inverse of `_backupKey`. The bundle path must be
    /// absolute and readable; gpg-agent collects the archive
    /// passphrase via pinentry. Returns the fingerprints reported on
    /// gpg's `IMPORT_OK` status lines.
    func _restoreBackup(bundlePath: String) async throws -> [String] {
        try Self.validateFileOpPaths(
            inputPath: bundlePath, outputPath: nil, requireInputExists: true,
        )
        // 1. Decrypt — no `--batch` so pinentry can prompt for the
        //    archive passphrase. `--output -` so we get the plaintext
        //    in-process rather than spilling it to disk. `--max-output`
        //    bounds a decompression-bomb backup (parity with `_decrypt`).
        let plaintext = try await runGPG(
            ["--yes", "--decrypt", "--max-output", String(Self.maxDecryptOutput),
             "--output", "-", "--", bundlePath],
        )

        // 2. Import every armored block in the plaintext. gpg reads
        //    multiple PGP blocks from a single stream, so one call is
        //    sufficient for primary + secret + revoke cert.
        let (_, importStderr, importExit) = try await runGPGRaw(
            ["--batch", "--yes", "--status-fd", "2", "--import"],
            input: plaintext,
        )
        let importStatus = String(data: importStderr, encoding: .utf8) ?? ""
        guard importExit == 0 else {
            throw GPGError.processError(exitCode: importExit, stderr: importStatus)
        }

        // 3. Re-apply ownertrust if the bundle carried it. Missing is
        //    fine — the user never set explicit trust on this key.
        if let text = String(data: plaintext, encoding: .utf8),
           let trustText = Self.extractOwnertrustSection(from: text)
        {
            _ = try? await runGPG(
                ["--batch", "--yes", "--import-ownertrust"],
                input: Data(trustText.utf8),
            )
        }

        // 4. Pull every unique fingerprint out of the IMPORT_OK lines.
        return Self.parseImportedFingerprints(from: importStatus)
    }

    /// Return the ownertrust payload that follows the
    /// `# ownertrust:` marker in a backup bundle, or nil when the
    /// marker is missing or the section is empty/whitespace-only.
    static func extractOwnertrustSection(from text: String) -> String? {
        guard let marker = text.range(of: "# ownertrust:") else { return nil }
        let trustText = text[marker.upperBound...]
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return trustText.isEmpty ? nil : trustText
    }

    /// Pull every unique 40-hex fingerprint out of gpg's `IMPORT_OK`
    /// status lines, preserving emission order.
    static func parseImportedFingerprints(from statusText: String) -> [String] {
        var seen = Set<String>()
        var fingerprints: [String] = []
        for line in statusText.components(separatedBy: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let idx = parts.firstIndex(of: "IMPORT_OK"), parts.count > idx + 2 else { continue }
            let fp = parts[idx + 2]
            guard isValidFingerprint(fp), seen.insert(fp).inserted else { continue }
            fingerprints.append(fp)
        }
        return fingerprints
    }

    // MARK: – nonisolated XPC bridges

    nonisolated func backupKey(
        fingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        Task {
            do {
                let bundle = try await self._backupKey(fingerprint: fingerprint)
                reply(bundle, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func restoreBackup(
        bundlePath: String,
        reply: @escaping @Sendable ([String]?, NSError?) -> Void,
    ) {
        Task {
            do {
                let fps = try await self._restoreBackup(bundlePath: bundlePath)
                reply(fps, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }
}
