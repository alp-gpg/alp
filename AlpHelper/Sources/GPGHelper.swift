import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp.helper", category: "GPGHelper")

/// Unsandboxed actor that drives the gpg(1) binary.
///
/// All Process launches inherit the user's environment so gpg-agent socket,
/// GNUPGHOME, and pinentry-mac are resolved automatically.
actor GPGHelper: NSObject, GPGHelperProtocol {
    private let gpgPath: String

    /// Maximum message payload accepted over XPC (50 MB).
    private static let maxPayloadSize = 50 * 1024 * 1024
    /// Maximum recipients per encrypt call.
    static let maxRecipients = 100

    /// RFC 4880 full fingerprints are 40 hex chars. Reject anything else before
    /// passing to gpg so a malicious caller cannot smuggle flags like
    /// `--homedir /evil` through the --recipient / --local-user arguments.
    static func isValidFingerprint(_ value: String) -> Bool {
        guard value.count == 40 else { return false }
        return value.allSatisfy(\.isHexDigit)
    }

    /// Validation for file-op paths sent over XPC. Rejects relative paths,
    /// empty strings, and embedded null bytes. We do not resolve symlinks
    /// or canonicalize — the caller (a Services menu invocation) hands us
    /// a user-selected URL whose path is already absolute.
    static func isValidAbsolutePath(_ value: String) -> Bool {
        guard !value.isEmpty else { return false }
        guard value.hasPrefix("/") else { return false }
        return !value.contains("\0")
    }

    override init() {
        gpgPath = GPGHelper.detectGPGPath()
        super.init()
    }

    /// Allowlist of environment variables forwarded to gpg.
    /// Prevents GNUPGHOME redirection and DYLD_INSERT_LIBRARIES injection.
    private static func sanitizedEnvironment() -> [String: String] {
        let inherited = ProcessInfo.processInfo.environment
        let allowed = ["HOME", "USER", "LANG", "LC_ALL", "LC_CTYPE", "DISPLAY", "GPG_TTY",
                       "DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK", "TERM"]
        var env: [String: String] = [:]
        for key in allowed {
            if let val = inherited[key] { env[key] = val }
        }
        env["HOME"] = env["HOME"] ?? NSHomeDirectory()
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/opt/local/bin:/nix/var/nix/profiles/default/bin:/usr/local/MacGPG2/bin:/usr/bin:/bin"
        return env
    }

    // MARK: – GPG binary detection

    private static func detectGPGPath() -> String {
        let candidates = [
            "/opt/homebrew/bin/gpg", // Homebrew (Apple Silicon)
            "/usr/local/bin/gpg", // Homebrew (Intel) / manual install
            "/opt/local/bin/gpg", // MacPorts
            "/nix/var/nix/profiles/default/bin/gpg", // Nix
            "/usr/local/MacGPG2/bin/gpg", // GPG Suite (GPGTools)
        ]
        // No fallback to bare "gpg": Process.run with a relative path fails on
        // macOS, and isExecutableFile against "gpg" always returns false.
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) } ?? ""
    }

    // MARK: – Core runner

    /// Raw runner returning stdout, stderr, and exit code without throwing on non-zero exit.
    func runGPGRaw(_ args: [String],
                   input: Data? = nil) async throws -> (stdout: Data, stderr: Data, exitCode: Int32)
    {
        guard !gpgPath.isEmpty, FileManager.default.isExecutableFile(atPath: gpgPath) else {
            throw GPGError.gpgNotFound
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: gpgPath)
        process.arguments = args
        process.environment = Self.sanitizedEnvironment()

        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe

        if let input {
            let stdinPipe = Pipe()
            process.standardInput = stdinPipe
            try process.run()
            stdinPipe.fileHandleForWriting.write(input)
            stdinPipe.fileHandleForWriting.closeFile()
        } else {
            try process.run()
        }

        // Read both pipes concurrently to avoid deadlock when either pipe's
        // OS buffer (~64 KB) fills while the other is still being written.
        let stderrQueue = DispatchQueue(label: "app.alp.Alp.stderr-reader")
        nonisolated(unsafe) var stderrData = Data()
        stderrQueue.async { stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile() }
        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        stderrQueue.sync {} // barrier — wait for stderr read to finish

        process.waitUntilExit()
        return (stdoutData, stderrData, process.terminationStatus)
    }

    /// Convenience that throws on non-zero exit.
    func runGPG(_ args: [String], input: Data? = nil) async throws -> Data {
        let (stdout, stderr, exitCode) = try await runGPGRaw(args, input: input)
        guard exitCode == 0 else {
            let errText = String(data: stderr, encoding: .utf8) ?? ""
            throw GPGError.processError(exitCode: exitCode, stderr: errText)
        }
        return stdout
    }

    // MARK: – Protocol implementations (async internals)

    func _encrypt(
        _ data: Data,
        _ recipients: [String],
        _ signer: String?,
    ) async throws -> Data {
        if let signer, !Self.isValidFingerprint(signer) {
            throw GPGError.encodingError("invalid signer fingerprint")
        }
        for fp in recipients {
            guard Self.isValidFingerprint(fp) else {
                throw GPGError.encodingError("invalid recipient fingerprint")
            }
        }
        var args = [
            "--batch", "--yes", "--armor",
            "--trust-model", "tofu+pgp",
            "--encrypt",
        ]
        if let signer {
            args += ["--sign", "--local-user", signer]
        }
        for fp in recipients {
            args += ["--recipient", fp]
        }
        args += ["--output", "-"]
        return try await runGPG(args, input: data)
    }

    func _decrypt(_ data: Data) async throws -> (Data, String?, String?) {
        let args = ["--yes", "--decrypt", "--status-fd", "2", "--output", "-"]
        // We need stderr for the status output (signer fingerprint), stdout for plaintext.
        // Run with a custom setup to capture both separately.
        return try await runGPGWithStatus(args, input: data)
    }

    /// Returns (signature, micalgHashName). micalg is derived from the SIG_CREATED
    /// status line so the outgoing PGP/MIME header matches the actual hash algorithm
    /// (RFC 3156 §5). Falls back to "pgp-sha256" if the status line is missing.
    func _sign(_ data: Data, signer: String) async throws -> (Data, String) {
        guard Self.isValidFingerprint(signer) else {
            throw GPGError.encodingError("invalid signer fingerprint")
        }
        let args = [
            "--batch", "--yes", "--armor",
            "--status-fd", "2",
            "--detach-sign", "--local-user", signer,
            "--output", "-",
        ]
        let (stdout, stderr, exitCode) = try await runGPGRaw(args, input: data)
        guard exitCode == 0 else {
            let errText = String(data: stderr, encoding: .utf8) ?? ""
            throw GPGError.processError(exitCode: exitCode, stderr: errText)
        }
        let stderrText = String(data: stderr, encoding: .utf8) ?? ""
        let micalg = Self.parseMicalg(from: stderrText) ?? "pgp-sha256"
        return (stdout, micalg)
    }

    func _clearsign(_ data: Data, signer: String) async throws -> Data {
        guard Self.isValidFingerprint(signer) else {
            throw GPGError.encodingError("invalid signer fingerprint")
        }
        let args = [
            "--batch", "--yes", "--armor",
            "--clearsign", "--local-user", signer,
            "--output", "-",
        ]
        return try await runGPG(args, input: data)
    }

    /// Parses the RFC 4880 hash algorithm number from gpg's SIG_CREATED status line
    /// and maps it to the RFC 3156 micalg name. Format:
    ///   [GNUPG:] SIG_CREATED <type> <pubkey_algo> <hash_algo> <class> <timestamp> <keyfpr>
    static func parseMicalg(from statusText: String) -> String? {
        for line in statusText.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: " ")
            guard let idx = parts.firstIndex(of: "SIG_CREATED"),
                  parts.count > idx + 3,
                  let algoNum = Int(parts[idx + 3])
            else { continue }
            switch algoNum {
            case 2: return "pgp-sha1"
            case 8: return "pgp-sha256"
            case 9: return "pgp-sha384"
            case 10: return "pgp-sha512"
            case 11: return "pgp-sha224"
            default: return nil
            }
        }
        return nil
    }

    /// Parses gpg's `IMPORT_OK <reason> <fingerprint>` status line.
    ///
    /// Returns the **first** IMPORT_OK line encountered. For bundle imports
    /// that emit multiple IMPORT_OK lines, callers should invoke gpg per-key
    /// if they need per-key results. Returns nil when no IMPORT_OK line is
    /// present (e.g., gpg emitted IMPORT_PROBLEM instead) — callers should
    /// treat nil as a parse failure and inspect stderr directly.
    static func parseImportResult(from statusText: String) -> GPGImportResult? {
        for rawLine in statusText.components(separatedBy: "\n") {
            let line = rawLine.trimmingCharacters(in: .init(charactersIn: "\r"))
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let idx = parts.firstIndex(of: "IMPORT_OK"),
                  parts.count > idx + 2,
                  let reason = Int(parts[idx + 1])
            else { continue }
            let fingerprint = parts[idx + 2]
            guard fingerprint.count == 40, fingerprint.allSatisfy(\.isHexDigit) else { continue }
            // Bits ≥ 16 (e.g., 16 = contains secret key, 32 = contains sub secret)
            // are intentionally ignored; Alp only imports public key material.
            return GPGImportResult(
                fingerprint: fingerprint,
                newKey: reason & 1 != 0,
                newUserIDs: reason & 2 != 0,
                updatedSignatures: reason & 4 != 0,
                newSubkeys: reason & 8 != 0,
            )
        }
        return nil
    }

    func _verify(_ data: Data, signature: Data?) async throws -> (Bool, String?, String?) {
        // gpg --verify exits non-zero for bad/untrusted signatures, which is a
        // valid result (not an error). Use runGPGRaw and parse status output
        // regardless of exit code. Status goes to stderr via --status-fd 2.
        if let signature {
            let sigURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString + ".asc")
            // Create with 0600 so another local user cannot read the signature
            // during the verify window.
            guard FileManager.default.createFile(
                atPath: sigURL.path,
                contents: signature,
                attributes: [.posixPermissions: 0o600],
            ) else {
                throw GPGError.encodingError("could not write signature tempfile")
            }
            defer {
                do {
                    try FileManager.default.removeItem(at: sigURL)
                } catch {
                    log
                        .error(
                            "Failed to remove signature tempfile \(sigURL.path, privacy: .public): \(error.localizedDescription, privacy: .public)",
                        )
                }
            }
            let args = ["--batch", "--verify", "--status-fd", "2", sigURL.path, "-"]
            let (_, stderr, _) = try await runGPGRaw(args, input: data)
            let statusText = String(data: stderr, encoding: .utf8) ?? ""
            let (fp, name) = extractSignerInfo(from: statusText)
            return (fp != nil, fp, name)
        } else {
            let args = ["--batch", "--verify", "--status-fd", "2"]
            let (_, stderr, _) = try await runGPGRaw(args, input: data)
            let statusText = String(data: stderr, encoding: .utf8) ?? ""
            let (fp, name) = extractSignerInfo(from: statusText)
            return (fp != nil, fp, name)
        }
    }

    func _listSecretKeys() async throws -> [GPGKeyInfo] {
        let args = ["--list-secret-keys", "--with-colons", "--with-fingerprint"]
        let output = try await runGPG(args)
        let text = String(data: output, encoding: .utf8) ?? ""
        return parseColonKeyListing(text)
    }

    func _listAllKeys() async throws -> [GPGKeyInfo] {
        let pubOut = try await runGPG(["--list-keys", "--with-colons", "--with-fingerprint"])
        var keys = parseColonKeyListing(String(data: pubOut, encoding: .utf8) ?? "")
        // Cross-reference with secret keys to set hasSecretKey. Mutating
        // hasSecretKey in place preserves every other field — earlier
        // versions rebuilt each GPGKeyInfo via the minimal init and silently
        // dropped subkeys / ownerTrustCode / creationDate / algorithm.
        if let secOut = try? await runGPG(["--list-secret-keys", "--with-colons", "--with-fingerprint"]) {
            let secFPs = Set(parseColonKeyListing(String(data: secOut, encoding: .utf8) ?? "").map(\.fingerprint))
            for index in keys.indices {
                keys[index].hasSecretKey = secFPs.contains(keys[index].fingerprint)
            }
        }
        return keys
    }

    func _previewKey(_ armoredKey: Data) async throws -> [GPGKeyInfo] {
        // --show-keys reads key material without importing it (GnuPG ≥ 2.2.14)
        let args = ["--batch", "--show-keys", "--with-colons", "--with-fingerprint", "-"]
        let out = try await runGPG(args, input: armoredKey)
        return parseColonKeyListing(String(data: out, encoding: .utf8) ?? "")
    }

    func _importKey(_ armoredKey: Data) async throws -> GPGImportResult {
        let args = ["--batch", "--yes", "--status-fd", "2", "--import"]
        let (_, stderr, exitCode) = try await runGPGRaw(args, input: armoredKey)
        let stderrText = String(data: stderr, encoding: .utf8) ?? ""
        guard exitCode == 0 else {
            throw GPGError.processError(exitCode: exitCode, stderr: stderrText)
        }
        // parseImportResult returns nil when IMPORT_OK is missing (e.g., gpg
        // emitted IMPORT_PROBLEM instead). Treat that as a genuine failure —
        // the caller shouldn't see a silent success.
        guard let result = Self.parseImportResult(from: stderrText) else {
            throw GPGError.importRejected(stderrText)
        }
        return result
    }

    func _exportPublicKey(_ fingerprint: String) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        let args = ["--batch", "--yes", "--armor", "--export", fingerprint]
        return try await runGPG(args)
    }

    func _exportSecretKey(_ fingerprint: String) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        // gpg-agent will trigger pinentry on the user's session for the
        // passphrase. We do not need stdin input here.
        let args = ["--armor", "--export-secret-keys", fingerprint]
        return try await runGPG(args)
    }

    func _deletePublicKey(_ fingerprint: String) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        // gpg refuses --delete-keys on a key that still has a secret half;
        // remove the secret first so the public delete cannot leave a half-pair
        // dangling. _deleteSecretKey is a no-op when there is no secret key.
        try? await _deleteSecretKey(fingerprint)
        let args = ["--batch", "--yes", "--delete-keys", fingerprint]
        _ = try await runGPG(args)
    }

    func _deleteSecretKey(_ fingerprint: String) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        let args = ["--batch", "--yes", "--delete-secret-keys", fingerprint]
        _ = try await runGPG(args)
    }

    func _generatePrimaryKey(
        name: String,
        email: String,
        comment: String?,
        expiryDays: Int,
    ) async throws -> String {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1 ... 100).contains(trimmedName.count),
              Self.isValidUserIDComponent(trimmedName)
        else {
            throw GPGError.encodingError("name must be 1..100 chars without <>() or control characters")
        }
        let trimmedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isValidEmail(trimmedEmail) else {
            throw GPGError.encodingError("invalid email")
        }
        let trimmedComment = comment?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let trimmedComment, !trimmedComment.isEmpty {
            guard trimmedComment.count <= 100, Self.isValidUserIDComponent(trimmedComment) else {
                throw GPGError.encodingError("comment must be ≤ 100 chars without <>() or control characters")
            }
        }
        guard (0 ... 36500).contains(expiryDays) else {
            throw GPGError.encodingError("expiryDays must be 0..36500")
        }

        let userID = if let trimmedComment, !trimmedComment.isEmpty {
            "\(trimmedName) (\(trimmedComment)) <\(trimmedEmail)>"
        } else {
            "\(trimmedName) <\(trimmedEmail)>"
        }
        let expire = expiryDays == 0 ? "0" : "\(expiryDays)d"

        // `--quick-gen-key` with both algo args = "default" produces an Ed25519
        // sign primary plus a Cv25519 encrypt subkey on gpg ≥ 2.4. Older 2.2/2.3
        // builds default to RSA — version is checked elsewhere by the health
        // check. gpg-agent handles passphrase pinentry; we only read status.
        let args = [
            "--batch", "--status-fd", "2",
            "--quick-gen-key", userID, "default", "default", expire,
        ]
        let (_, stderr, exitCode) = try await runGPGRaw(args)
        let stderrText = String(data: stderr, encoding: .utf8) ?? ""
        guard exitCode == 0 else {
            throw GPGError.processError(exitCode: exitCode, stderr: stderrText)
        }
        guard let fingerprint = Self.parseKeyCreatedFingerprint(from: stderrText) else {
            throw GPGError.processError(exitCode: 0, stderr: "no KEY_CREATED line in: \(stderrText)")
        }
        return fingerprint
    }

    /// Algorithm tags accepted by `_addSubkey`. Mapped to gpg's
    /// `--quick-add-key` algorithm + usage syntax internally.
    static let allowedSubkeyAlgoTags: Set<String> = [
        "ed25519/sign",
        "cv25519/encr",
        "ed25519/auth",
    ]

    func _addSubkey(
        fingerprint: String,
        algoTag: String,
        expiryDays: Int,
    ) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard Self.allowedSubkeyAlgoTags.contains(algoTag) else {
            throw GPGError.encodingError("unsupported subkey algorithm tag")
        }
        guard (0 ... 36500).contains(expiryDays) else {
            throw GPGError.encodingError("expiryDays must be 0..36500")
        }
        // algoTag is "<curve>/<usage>"; gpg accepts that exact shape.
        let parts = algoTag.split(separator: "/", maxSplits: 1).map(String.init)
        guard parts.count == 2 else {
            throw GPGError.encodingError("malformed algoTag")
        }
        let expire = expiryDays == 0 ? "0" : "\(expiryDays)d"
        let args = [
            "--batch", "--status-fd", "2",
            "--quick-add-key", fingerprint, parts[0], parts[1], expire,
        ]
        _ = try await runGPG(args)
    }

    func _revokeSubkey(
        _ fingerprint: String,
        subkeyIndex: Int,
        reasonCode: Int,
    ) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard subkeyIndex >= 1, subkeyIndex <= 50 else {
            throw GPGError.encodingError("subkeyIndex must be a positive number ≤ 50")
        }
        guard (0 ... 3).contains(reasonCode) else {
            throw GPGError.encodingError("reasonCode must be 0..3")
        }
        // gpg's `key <n>` command is 1-based on subkeys, so we feed the
        // user's index unchanged. revkey then prompts: y → reason code →
        // empty description → y final confirm → save.
        let commands = "key \(subkeyIndex)\nrevkey\ny\n\(reasonCode)\n\ny\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _deleteSubkey(
        _ fingerprint: String,
        subkeyIndex: Int,
    ) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard subkeyIndex >= 1, subkeyIndex <= 50 else {
            throw GPGError.encodingError("subkeyIndex must be a positive number ≤ 50")
        }
        // delkey: select subkey, delkey, y to confirm, save.
        let commands = "key \(subkeyIndex)\ndelkey\ny\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _deleteSubkeys(
        _ fingerprint: String,
        subkeyIndices: [Int],
    ) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard !subkeyIndices.isEmpty else { return }
        for index in subkeyIndices {
            guard index >= 1, index <= 50 else {
                throw GPGError.encodingError("subkey indices must be 1..50")
            }
        }
        // gpg --edit-key: each `key <n>` selects an additional subkey;
        // delkey then removes every selected subkey in one go. y confirms,
        // save persists. Single pinentry prompt for the whole batch.
        let selectLines = subkeyIndices.map { "key \($0)" }.joined(separator: "\n")
        let commands = "\(selectLines)\ndelkey\ny\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _addUserID(
        fingerprint: String,
        name: String,
        email: String,
        comment: String?,
    ) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1 ... 100).contains(trimmedName.count),
              Self.isValidUserIDComponent(trimmedName)
        else {
            throw GPGError.encodingError("invalid name")
        }
        let trimmedEmail = email.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isValidEmail(trimmedEmail) else {
            throw GPGError.encodingError("invalid email")
        }
        let trimmedComment = comment?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !trimmedComment.isEmpty {
            guard trimmedComment.count <= 100, Self.isValidUserIDComponent(trimmedComment) else {
                throw GPGError.encodingError("invalid comment")
            }
        }
        // adduid menu: name → email → comment → O (okay) → save.
        let commands = "adduid\n\(trimmedName)\n\(trimmedEmail)\n\(trimmedComment)\nO\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _revokeUserID(_ fingerprint: String, uidIndex: Int) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard uidIndex >= 1, uidIndex <= 50 else {
            throw GPGError.encodingError("uidIndex must be a positive number ≤ 50")
        }
        // uid <n> selects, revuid revokes, y confirms, 4 = "User ID is no
        // longer valid" reason code, empty description, y final confirm,
        // save persists. The reason number tracks RFC 4880 §5.2.3.23 too —
        // 4 maps to "user id no longer valid" in gpg's revuid prompt.
        let commands = "uid \(uidIndex)\nrevuid\ny\n4\n\ny\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _signKey(
        fingerprint: String,
        signer: String,
        exportable: Bool,
    ) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid target fingerprint")
        }
        guard Self.isValidFingerprint(signer) else {
            throw GPGError.encodingError("invalid signer fingerprint")
        }
        // --quick-sign-key produces an exportable cert; --quick-lsign-key a
        // local non-exportable one. gpg-agent prompts via pinentry for the
        // signer's passphrase as usual.
        let subcommand = exportable ? "--quick-sign-key" : "--quick-lsign-key"
        let args = [
            "--batch", "--yes", "--status-fd", "2",
            "--local-user", signer,
            subcommand, fingerprint,
        ]
        _ = try await runGPG(args)
    }

    func _setOwnerTrust(_ fingerprint: String, level: Int) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard (2 ... 5).contains(level) else {
            throw GPGError.encodingError("trust level must be 2..5")
        }
        // `--import-ownertrust` reads `<fingerprint>:<level>:` lines from
        // stdin. This is the documented non-interactive path; the
        // alternative (`--edit-key trust`) is menu-driven.
        let payload = "\(fingerprint):\(level):\n"
        let args = ["--batch", "--yes", "--import-ownertrust"]
        _ = try await runGPG(args, input: Data(payload.utf8))
    }

    func _changePassphrase(_ fingerprint: String) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        // `passwd` triggers gpg-agent → pinentry for both the current and the
        // new passphrases. `--command-fd` only carries the menu commands; the
        // passphrases themselves never traverse the helper.
        let commands = "passwd\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _setExpiry(_ fingerprint: String, expiryDays: Int) async throws {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard (0 ... 36500).contains(expiryDays) else {
            throw GPGError.encodingError("expiryDays must be 0..36500")
        }
        let expireArg = expiryDays == 0 ? "0" : "\(expiryDays)d"
        let commands = "expire\n\(expireArg)\nsave\n"
        let args = [
            "--command-fd", "0", "--status-fd", "2",
            "--edit-key", fingerprint,
        ]
        _ = try await runGPG(args, input: Data(commands.utf8))
    }

    func _revokePrimaryKey(
        _ fingerprint: String,
        reasonCode: Int,
        description: String?,
    ) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        guard (0 ... 3).contains(reasonCode) else {
            throw GPGError.encodingError("reasonCode must be 0..3")
        }
        let trimmedDescription = description?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let trimmedDescription, !trimmedDescription.isEmpty {
            guard trimmedDescription.count <= 200, Self.isValidUserIDComponent(trimmedDescription) else {
                throw GPGError.encodingError("invalid description")
            }
        }
        // gpg --gen-revoke prompts via --command-fd:
        //   y           → confirm "Create a revocation certificate for this key?"
        //   <code>      → reason code (0..3)
        //   <desc>      → description (optional single line)
        //   <empty>     → terminate description
        //   y           → confirm "Is this okay?"
        let descLine = trimmedDescription ?? ""
        let commands = "y\n\(reasonCode)\n\(descLine)\n\ny\n"
        let args = [
            "--armor", "--command-fd", "0", "--status-fd", "2",
            "--gen-revoke", fingerprint,
        ]
        let cert = try await runGPG(args, input: Data(commands.utf8))

        // Importing the freshly-generated cert flips the local key's revoke
        // state. We return the armored cert so the UI can also offer to save
        // it to disk for offline backup.
        let importArgs = ["--batch", "--yes", "--import"]
        _ = try await runGPG(importArgs, input: cert)
        return cert
    }

    static func isValidUserIDComponent(_ value: String) -> Bool {
        for scalar in value.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7F { return false }
            if scalar == "<" || scalar == ">" || scalar == "(" || scalar == ")" {
                return false
            }
        }
        return true
    }

    static func isValidEmail(_ value: String) -> Bool {
        guard (5 ... 254).contains(value.count) else { return false }
        guard value.firstMatch(of: #/^[^\s<>()@]+@[^\s<>()@]+\.[^\s<>()@]+$/#) != nil else {
            return false
        }
        return true
    }

    /// Parses the new key's fingerprint from gpg's `KEY_CREATED` status line.
    /// Format: `[GNUPG:] KEY_CREATED <type> <fingerprint> [handle]`.
    /// Type is `B` (both primary+sub), `P` (primary only), or `S` (sub).
    static func parseKeyCreatedFingerprint(from statusText: String) -> String? {
        for rawLine in statusText.components(separatedBy: "\n") {
            let parts = rawLine.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let idx = parts.firstIndex(of: "KEY_CREATED"),
                  parts.count > idx + 2
            else { continue }
            let fingerprint = parts[idx + 2]
            if fingerprint.count == 40, fingerprint.allSatisfy(\.isHexDigit) {
                return fingerprint
            }
        }
        return nil
    }

    func _publicKeyExists(email: String) async throws -> (Bool, String?) {
        let args = ["--list-keys", "--with-colons", "--", email]
        do {
            let output = try await runGPG(args)
            let text = String(data: output, encoding: .utf8) ?? ""
            let keys = parseColonKeyListing(text)
            return (!keys.isEmpty, keys.first?.fingerprint)
        } catch GPGError.processError {
            return (false, nil)
        }
    }

    // MARK: – Health check

    // MARK: – Pinentry installer

    /// Stable path the shim script lives at. gpg-agent.conf points here
    /// so app moves don't break the reference.
    static var pinentryShimPath: String {
        let home = NSHomeDirectory()
        return "\(home)/Library/Application Support/Alp/pinentry"
    }

    private static var gpgAgentConfPath: String {
        "\(NSHomeDirectory())/.gnupg/gpg-agent.conf"
    }

    /// Reads the current `pinentry-program` line from gpg-agent.conf.
    /// Returns nil when the file or directive is missing.
    func _readPinentryProgram() -> String? {
        guard let text = try? String(contentsOfFile: Self.gpgAgentConfPath, encoding: .utf8) else {
            return nil
        }
        for line in text.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("pinentry-program") {
                let parts = trimmed.split(separator: " ", maxSplits: 1)
                if parts.count == 2 {
                    return String(parts[1]).trimmingCharacters(in: .whitespaces)
                }
            }
        }
        return nil
    }

    /// True when `pinentry-program` already points at our shim.
    func _isAlpPinentryConfigured() -> Bool {
        _readPinentryProgram() == Self.pinentryShimPath
    }

    /// Writes the shim script (POSIX shell, Spotlight-resolves the app
    /// bundle so app moves don't break the reference), edits
    /// gpg-agent.conf, and restarts gpg-agent.
    func _installAlpPinentry(bundlePath: String) async throws {
        let shimContent = """
        #!/bin/sh
        # Alp Pinentry shim. gpg-agent invokes this; we resolve the current
        # Alp.app bundle via Spotlight (so app moves keep working) and
        # exec its embedded AlpPinentry binary.
        APP_BUNDLE="\(bundlePath)"
        if [ ! -x "$APP_BUNDLE/Contents/Helpers/AlpPinentry" ]; then
            FOUND=$(/usr/bin/mdfind 'kMDItemCFBundleIdentifier == "app.alp.Alp"' | head -1)
            if [ -n "$FOUND" ]; then
                APP_BUNDLE="$FOUND"
            fi
        fi
        exec "$APP_BUNDLE/Contents/Helpers/AlpPinentry" "$@"
        """
        let shimPath = Self.pinentryShimPath
        let shimDir = (shimPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: shimDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700],
        )
        try shimContent.write(toFile: shimPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: shimPath,
        )
        try Self.upsertPinentryProgram(shimPath)
        try await Self.restartGpgAgent()
    }

    /// Strip the `pinentry-program` line and restart gpg-agent. Leaves
    /// the shim file in place for re-enable.
    func _uninstallAlpPinentry() async throws {
        try Self.removePinentryProgram()
        try await Self.restartGpgAgent()
    }

    /// Adds or replaces the `pinentry-program` directive in
    /// gpg-agent.conf. Creates the file if it doesn't exist.
    private static func upsertPinentryProgram(_ path: String) throws {
        let conf = gpgAgentConfPath
        let confDir = (conf as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(
            atPath: confDir,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700],
        )
        let existing = (try? String(contentsOfFile: conf, encoding: .utf8)) ?? ""
        var lines = existing.components(separatedBy: "\n")
        var replaced = false
        for index in lines.indices {
            let trimmed = lines[index].trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("pinentry-program") {
                lines[index] = "pinentry-program \(path)"
                replaced = true
                break
            }
        }
        if !replaced {
            // Drop trailing blank line, then append + restore one.
            while lines.last == "" {
                lines.removeLast()
            }
            lines.append("pinentry-program \(path)")
            lines.append("")
        }
        try lines.joined(separator: "\n").write(
            toFile: conf, atomically: true, encoding: .utf8,
        )
    }

    private static func removePinentryProgram() throws {
        let conf = gpgAgentConfPath
        guard let existing = try? String(contentsOfFile: conf, encoding: .utf8) else {
            return
        }
        let lines = existing.components(separatedBy: "\n").filter { line in
            !line.trimmingCharacters(in: .whitespaces).hasPrefix("pinentry-program")
        }
        try lines.joined(separator: "\n").write(
            toFile: conf, atomically: true, encoding: .utf8,
        )
    }

    private static func restartGpgAgent() async throws {
        // `gpgconf --kill gpg-agent` is the documented way to force a
        // reload of gpg-agent.conf. The next gpg invocation respawns it.
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["gpgconf", "--kill", "gpg-agent"]
        process.environment = sanitizedEnvironment()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        process.waitUntilExit()
        // We don't check exit status — gpgconf returns non-zero when
        // gpg-agent isn't running, which is fine: the next gpg call
        // will spawn a fresh one with the new conf.
    }

    /// Returns nil when no card is present rather than throwing — the UI
    /// uses presence as a hide/show signal, so a "no card" outcome is
    /// expected and not an error condition.
    func _cardStatus() async -> GPGCardStatus? {
        let args = ["--card-status", "--with-colons"]
        guard let result = try? await runGPGRaw(args), result.exitCode == 0 else {
            return nil
        }
        guard let text = String(data: result.stdout, encoding: .utf8) else { return nil }
        let parsed = Self.parseCardStatusColons(text)
        return parsed.isPresent ? parsed : nil
    }

    /// Parses the colon-prefixed output of `gpg --card-status --with-colons`.
    /// Public on the type so tests can exercise it without invoking gpg.
    static func parseCardStatusColons(_ text: String) -> GPGCardStatus {
        var manufacturer: String?
        var serial: String?
        var cardholder: String?
        var version: String?
        var pinRetries: [Int] = []
        var fingerprints: [String] = ["", "", ""]
        var algorithms: [String] = ["", "", ""]

        for rawLine in text.components(separatedBy: "\n") {
            let parts = rawLine.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard let key = parts.first else { continue }
            switch key {
            case "vendor":
                // vendor:<id>:<name>:
                if parts.count >= 3, !parts[2].isEmpty { manufacturer = parts[2] }
            case "serial":
                if parts.count >= 2, !parts[1].isEmpty { serial = parts[1] }
            case "name":
                if parts.count >= 2, !parts[1].isEmpty {
                    cardholder = parts[1].replacingOccurrences(of: "<<", with: " ")
                }
            case "version":
                // 0303 → "3.3"
                if parts.count >= 2, !parts[1].isEmpty {
                    version = formatCardVersion(parts[1])
                }
            case "pinretry":
                // pinretry:<user>:<reset>:<admin>:::
                pinRetries = parts.dropFirst().compactMap { Int($0) }
            case "fpr":
                // fpr:<sig>:<dec>:<auth>:::
                let raw = Array(parts.dropFirst().prefix(3))
                for (i, fp) in raw.enumerated() where i < 3 {
                    fingerprints[i] = fp
                }
            case "keyattr":
                // keyattr:<slot>:<algoId>:<bits-or-curve>:...
                if parts.count >= 4, let slot = Int(parts[1]), (1 ... 3).contains(slot) {
                    algorithms[slot - 1] = formatKeyAttr(algoId: parts[2], curveOrBits: parts[3])
                }
            default:
                continue
            }
        }

        return GPGCardStatus(
            manufacturer: manufacturer,
            serial: serial,
            cardholderName: cardholder,
            version: version,
            pinRetriesLeft: pinRetries,
            keyFingerprints: fingerprints,
            keyAlgorithms: algorithms,
        )
    }

    private static func formatCardVersion(_ raw: String) -> String {
        // gpg pads to 4 hex chars: "0303" → "3.3", "0304" → "3.4".
        let padded = raw.count == 4 ? raw : raw.padding(toLength: 4, withPad: "0", startingAt: 0)
        let major = Int(padded.prefix(2)) ?? 0
        let minor = Int(padded.suffix(2)) ?? 0
        return "\(major).\(minor)"
    }

    private static func formatKeyAttr(algoId: String, curveOrBits: String) -> String {
        // RFC 4880 algorithm IDs the card status surface ever produces.
        switch Int(algoId) {
        case 1: curveOrBits.isEmpty ? "RSA" : "RSA \(curveOrBits)"
        case 18, 19, 22:
            curveOrBits.capitalized.isEmpty ? "ECC" : curveOrBits.capitalized
        default:
            curveOrBits
        }
    }

    func _checkHealth() async -> GPGHealthStatus {
        var status = GPGHealthStatus()

        // 1. GPG binary
        let path = gpgPath
        let found = !path.isEmpty && FileManager.default.isExecutableFile(atPath: path)
        status.gpgPath = found ? path : nil

        // 2. Version
        if found, let versionData = try? await runGPGRaw(["--version"]).stdout,
           let versionText = String(data: versionData, encoding: .utf8)
        {
            // First line: "gpg (GnuPG) 2.4.7"
            if let firstLine = versionText.components(separatedBy: "\n").first,
               let match = firstLine.range(of: #"\d+\.\d+(\.\d+)?"#, options: .regularExpression)
            {
                let ver = String(firstLine[match])
                status.gpgVersion = ver
                status.versionSufficient = compareVersion(ver, isAtLeast: "2.2.14")
            }
        }

        // sanitizedEnvironment() deliberately drops GNUPGHOME, so gpg always
        // resolves its home to ~/.gnupg. Mirror that here — reading the current
        // process's GNUPGHOME would report success against a different keyring
        // than gpg actually uses.
        let gnupgHome = NSHomeDirectory() + "/.gnupg"

        // 3. gpg-agent
        if found {
            let agentCheck = try? await runProcess("/usr/bin/env", args: ["gpgconf", "--check-programs"])
            if let data = agentCheck, let text = String(data: data, encoding: .utf8) {
                status.agentRunning = text.contains("gpg-agent") && !text.contains(":0:")
            }
            // Fallback: just check the socket exists
            if !status.agentRunning {
                let socketPath = gnupgHome + "/S.gpg-agent"
                status.agentRunning = FileManager.default.fileExists(atPath: socketPath)
            }
        }

        // 4. pinentry-mac
        let agentConf = gnupgHome + "/gpg-agent.conf"
        if let confText = try? String(contentsOfFile: agentConf, encoding: .utf8) {
            for line in confText.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("pinentry-program") {
                    let parts = trimmed.components(separatedBy: .whitespaces)
                    if parts.count >= 2 {
                        status.pinentryPath = parts[1]
                        // Accept any GUI pinentry (pinentry-mac, pinentry-gnome3, pinentry-qt, etc.)
                        status.pinentryConfigured = FileManager.default.isExecutableFile(atPath: parts[1])
                    }
                }
            }
        }

        // 5. Secret keys
        if found, let keys = try? await _listSecretKeys() {
            status.hasSecretKeys = !keys.isEmpty
            status.secretKeyCount = keys.count
        }

        // 6. TOFU trust model support
        if found {
            // gpg --with-colons --trust-model tofu+pgp --list-keys returns 0 if supported
            let tofuResult = try? await runGPGRaw([
                "--batch",
                "--trust-model",
                "tofu+pgp",
                "--list-keys",
                "--with-colons",
            ])
            status.tofuSupported = tofuResult?.exitCode == 0
        }

        return status
    }

    /// Simple semver comparison: "2.4.7" isAtLeast "2.2.14" → true
    private func compareVersion(_ version: String, isAtLeast minimum: String) -> Bool {
        let v = version.split(separator: ".").compactMap { Int($0) }
        let m = minimum.split(separator: ".").compactMap { Int($0) }
        for i in 0 ..< max(v.count, m.count) {
            let a = i < v.count ? v[i] : 0
            let b = i < m.count ? m[i] : 0
            if a > b { return true }
            if a < b { return false }
        }
        return true // equal
    }

    /// Run an arbitrary process and return stdout.
    private func runProcess(_ path: String, args: [String]) async throws -> Data {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        process.environment = Self.sanitizedEnvironment()
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return data
    }

    // MARK: – Helpers

    /// Run gpg and capture stdout (plaintext) while parsing status-fd on stderr (signer info).
    private func runGPGWithStatus(
        _ args: [String], input: Data? = nil,
    ) async throws -> (Data, String?, String?) {
        let (stdout, stderr, exitCode) = try await runGPGRaw(args, input: input)
        let stderrText = String(data: stderr, encoding: .utf8) ?? ""

        guard exitCode == 0 else {
            throw GPGError.processError(exitCode: exitCode, stderr: stderrText)
        }

        let (fp, name) = extractSignerInfo(from: stderrText)
        return (stdout, fp, name)
    }

    /// Parses gpg status output for VALIDSIG (40-char fingerprint) and GOODSIG (display name).
    /// GOODSIG format: [GNUPG:] GOODSIG <keyid> <Name <email>>
    /// VALIDSIG format: [GNUPG:] VALIDSIG <fingerprint> <date> ...
    func extractSignerInfo(from statusText: String) -> (fingerprint: String?, displayName: String?) {
        var fingerprint: String?
        var displayName: String?
        for line in statusText.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: " ")
            if let idx = parts.firstIndex(of: "VALIDSIG"), parts.count > idx + 1 {
                fingerprint = parts[idx + 1]
            }
            if let idx = parts.firstIndex(of: "GOODSIG"), parts.count > idx + 2 {
                let name = parts[(idx + 2)...].joined(separator: " ")
                    .trimmingCharacters(in: .whitespaces)
                if !name.isEmpty { displayName = name }
                if fingerprint == nil { fingerprint = parts[idx + 1] } // key ID fallback
            }
        }
        return (fingerprint, displayName)
    }

    private func parseColonKeyListing(_ text: String) -> [GPGKeyInfo] {
        var keys: [GPGKeyInfo] = []

        var primaryFingerprint: String?
        var primaryUIDs: [String] = []
        var primaryCapabilities = ""
        var primaryExpiry: Date?
        var primaryOwnerTrust: String?
        var primaryCreated: Date?
        var primaryAlgorithm: String?
        var subkeys: [GPGSubkey] = []

        // Staging area for the subkey we're currently filling in. We can't
        // build the final `GPGSubkey` until its `fpr` line arrives because
        // the subkey's full fingerprint appears on a subsequent record.
        struct PendingSubkey {
            var fingerprint: String = ""
            var capabilities: String = ""
            var expiry: Date?
            var algorithm: String?
            var isRevoked: Bool = false
        }
        var pendingSubkey: PendingSubkey?

        func flushSubkey() {
            guard let pending = pendingSubkey, !pending.fingerprint.isEmpty else {
                pendingSubkey = nil
                return
            }
            subkeys.append(GPGSubkey(
                fingerprint: pending.fingerprint,
                capabilities: pending.capabilities,
                expiryDate: pending.expiry,
                algorithm: pending.algorithm,
                isRevoked: pending.isRevoked,
            ))
            pendingSubkey = nil
        }

        func flushPrimary() {
            flushSubkey()
            guard let fp = primaryFingerprint, !fp.isEmpty else { return }
            keys.append(GPGKeyInfo(
                fingerprint: fp,
                userIDs: primaryUIDs,
                capabilities: primaryCapabilities,
                expiryDate: primaryExpiry,
                subkeys: subkeys,
                ownerTrustCode: primaryOwnerTrust,
                creationDate: primaryCreated,
                algorithm: primaryAlgorithm,
            ))
            primaryFingerprint = nil
            primaryUIDs = []
            primaryCapabilities = ""
            primaryExpiry = nil
            primaryOwnerTrust = nil
            primaryCreated = nil
            primaryAlgorithm = nil
            subkeys = []
        }

        for raw in text.components(separatedBy: "\n") {
            let fields = raw.trimmingCharacters(in: .init(charactersIn: "\r"))
                .components(separatedBy: ":")
            guard let recordType = fields.first, !recordType.isEmpty else { continue }

            if recordType.hasPrefix("pub") || recordType.hasPrefix("sec") {
                flushPrimary()
                primaryCapabilities = fields.count > 11 ? fields[11] : ""
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    primaryExpiry = Date(timeIntervalSince1970: ts)
                } else {
                    primaryExpiry = nil
                }
                // Field 9 of the pub colon record is the ownertrust code.
                if fields.count > 8, !fields[8].isEmpty {
                    primaryOwnerTrust = fields[8]
                } else {
                    primaryOwnerTrust = nil
                }
                // Field 6 (creation timestamp) and the bits/algo/curve
                // triple feed the inspector view's metadata block.
                if fields.count > 5, let ts = TimeInterval(fields[5]), ts > 0 {
                    primaryCreated = Date(timeIntervalSince1970: ts)
                } else {
                    primaryCreated = nil
                }
                primaryAlgorithm = Self.formatAlgorithm(
                    id: fields.count > 3 ? fields[3] : "",
                    bits: fields.count > 2 ? fields[2] : "",
                    curve: fields.count > 16 ? fields[16] : "",
                )
            } else if recordType.hasPrefix("sub") || recordType.hasPrefix("ssb") {
                flushSubkey()
                var pending = PendingSubkey()
                pending.isRevoked = fields.count > 1 && fields[1] == "r"
                pending.capabilities = fields.count > 11 ? fields[11] : ""
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    pending.expiry = Date(timeIntervalSince1970: ts)
                }
                pending.algorithm = Self.formatAlgorithm(
                    id: fields.count > 3 ? fields[3] : "",
                    bits: fields.count > 2 ? fields[2] : "",
                    curve: fields.count > 16 ? fields[16] : "",
                )
                pendingSubkey = pending
            } else if recordType == "fpr" {
                if pendingSubkey != nil {
                    if fields.count > 9 { pendingSubkey?.fingerprint = fields[9] }
                } else if primaryFingerprint == nil, fields.count > 9 {
                    primaryFingerprint = fields[9]
                }
            } else if recordType == "uid" {
                if fields.count > 9, !fields[9].isEmpty {
                    primaryUIDs.append(fields[9])
                }
            }
        }
        flushPrimary()
        return keys
    }

    /// Maps gpg's numeric algorithm id + bit size + curve name to a
    /// human-readable label, e.g. "RSA 3072" or "Ed25519".
    ///
    /// Algorithm ids come from RFC 4880 + gpg extensions:
    ///   1 = RSA, 16 = ElGamal, 17 = DSA, 18 = ECDH, 19 = ECDSA, 22 = EdDSA.
    static func formatAlgorithm(id: String, bits: String, curve: String) -> String? {
        guard let algoId = Int(id) else { return nil }
        let name: String
        switch algoId {
        case 1: name = "RSA"
        case 16: name = "ElGamal"
        case 17: name = "DSA"
        case 18: name = "ECDH"
        case 19: name = "ECDSA"
        case 22: name = "EdDSA"
        default: return nil
        }
        // ECC keys prefer the curve name when it's present — "Ed25519" is
        // more useful than "EdDSA 255".
        if [18, 19, 22].contains(algoId), !curve.isEmpty {
            return curve.capitalized
        }
        if !bits.isEmpty { return "\(name) \(bits)" }
        return name
    }

    // MARK: – nonisolated XPC bridge methods

    nonisolated func encrypt(
        data: Data,
        recipientFingerprints: [String],
        signingFingerprint: String?,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(nil, GPGError.encodingError("payload too large").asNSError); return
        }
        guard recipientFingerprints.count <= Self.maxRecipients else {
            reply(nil, GPGError.encodingError("too many recipients").asNSError); return
        }
        Task {
            do {
                let result = try await self._encrypt(data, recipientFingerprints, signingFingerprint)
                reply(result, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func decrypt(
        data: Data,
        reply: @escaping @Sendable (Data?, String?, String?, NSError?) -> Void,
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(nil, nil, nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let (plain, signer, signerName) = try await self._decrypt(data)
                reply(plain, signer, signerName, nil)
            } catch let e as GPGError {
                reply(nil, nil, nil, e.asNSError)
            } catch {
                reply(nil, nil, nil, error as NSError)
            }
        }
    }

    nonisolated func sign(
        data: Data,
        signingFingerprint: String,
        reply: @escaping @Sendable (Data?, String?, NSError?) -> Void,
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(nil, nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let (sig, micalg) = try await self._sign(data, signer: signingFingerprint)
                reply(sig, micalg, nil)
            } catch let e as GPGError {
                reply(nil, nil, e.asNSError)
            } catch {
                reply(nil, nil, error as NSError)
            }
        }
    }

    nonisolated func clearsign(
        data: Data,
        signingFingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let signed = try await self._clearsign(data, signer: signingFingerprint)
                reply(signed, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func verify(
        data: Data,
        signatureData: Data?,
        reply: @escaping @Sendable (Bool, String?, String?, NSError?) -> Void,
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(false, nil, nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let (valid, signer, signerName) = try await self._verify(data, signature: signatureData)
                reply(valid, signer, signerName, nil)
            } catch let e as GPGError {
                reply(false, nil, nil, e.asNSError)
            } catch {
                reply(false, nil, nil, error as NSError)
            }
        }
    }

    nonisolated func listSecretKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void) {
        Task {
            do {
                let keys = try await self._listSecretKeys()
                let encoded = try keys.map { try JSONEncoder().encode($0) }
                reply(encoded, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func listAllKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void) {
        Task {
            do {
                let keys = try await self._listAllKeys()
                let encoded = try keys.map { try JSONEncoder().encode($0) }
                reply(encoded, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func previewKey(
        armoredKey: Data,
        reply: @escaping @Sendable ([Data]?, NSError?) -> Void,
    ) {
        guard armoredKey.count <= Self.maxPayloadSize else {
            reply(nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let keys = try await self._previewKey(armoredKey)
                let encoded = try keys.map { try JSONEncoder().encode($0) }
                reply(encoded, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func importKey(
        armoredKey: Data,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        guard armoredKey.count <= Self.maxPayloadSize else {
            reply(nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let result = try await self._importKey(armoredKey)
                let encoded = try JSONEncoder().encode(result)
                reply(encoded, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func publicKeyExists(
        email: String,
        reply: @escaping @Sendable (Bool, String?, NSError?) -> Void,
    ) {
        guard email.count <= 254 else {
            reply(false, nil, GPGError.encodingError("email too long").asNSError); return
        }
        Task {
            do {
                let (found, fp) = try await self._publicKeyExists(email: email)
                reply(found, fp, nil)
            } catch let e as GPGError {
                reply(false, nil, e.asNSError)
            } catch {
                reply(false, nil, error as NSError)
            }
        }
    }

    nonisolated func checkHealth(reply: @escaping @Sendable (Data?, NSError?) -> Void) {
        Task {
            let status = await self._checkHealth()
            do {
                let data = try JSONEncoder().encode(status)
                reply(data, nil)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func pinentryConfigStatus(
        reply: @escaping @Sendable (String?, Bool, NSError?) -> Void,
    ) {
        Task {
            let path = await self._readPinentryProgram()
            let isAlp = await self._isAlpPinentryConfigured()
            reply(path, isAlp, nil)
        }
    }

    nonisolated func installAlpPinentry(
        bundlePath: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._installAlpPinentry(bundlePath: bundlePath)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func uninstallAlpPinentry(reply: @escaping @Sendable (NSError?) -> Void) {
        Task {
            do {
                try await self._uninstallAlpPinentry()
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func cardStatus(reply: @escaping @Sendable (Data?, NSError?) -> Void) {
        Task {
            guard let status = await self._cardStatus() else {
                reply(nil, nil) // no card present — not an error
                return
            }
            do {
                try reply(JSONEncoder().encode(status), nil)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func exportPublicKey(
        fingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        Task {
            do {
                let armored = try await self._exportPublicKey(fingerprint)
                reply(armored, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func exportSecretKey(
        fingerprint: String,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        Task {
            do {
                let armored = try await self._exportSecretKey(fingerprint)
                reply(armored, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func deletePublicKey(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._deletePublicKey(fingerprint)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func deleteSecretKey(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._deleteSecretKey(fingerprint)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func generatePrimaryKey(
        name: String,
        email: String,
        comment: String?,
        expiryDays: Int,
        reply: @escaping @Sendable (String?, NSError?) -> Void,
    ) {
        Task {
            do {
                let fp = try await self._generatePrimaryKey(
                    name: name,
                    email: email,
                    comment: comment,
                    expiryDays: expiryDays,
                )
                reply(fp, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }

    nonisolated func addSubkey(
        fingerprint: String,
        algoTag: String,
        expiryDays: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._addSubkey(
                    fingerprint: fingerprint,
                    algoTag: algoTag,
                    expiryDays: expiryDays,
                )
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func revokeSubkey(
        fingerprint: String,
        subkeyIndex: Int,
        reasonCode: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._revokeSubkey(
                    fingerprint,
                    subkeyIndex: subkeyIndex,
                    reasonCode: reasonCode,
                )
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func deleteSubkey(
        fingerprint: String,
        subkeyIndex: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._deleteSubkey(fingerprint, subkeyIndex: subkeyIndex)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func deleteSubkeys(
        fingerprint: String,
        subkeyIndices: [NSNumber],
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                let ints = subkeyIndices.map(\.intValue)
                try await self._deleteSubkeys(fingerprint, subkeyIndices: ints)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func addUserID(
        fingerprint: String,
        name: String,
        email: String,
        comment: String?,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._addUserID(
                    fingerprint: fingerprint,
                    name: name,
                    email: email,
                    comment: comment,
                )
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func revokeUserID(
        fingerprint: String,
        uidIndex: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._revokeUserID(fingerprint, uidIndex: uidIndex)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func signKey(
        fingerprint: String,
        signerFingerprint: String,
        exportable: Bool,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._signKey(
                    fingerprint: fingerprint,
                    signer: signerFingerprint,
                    exportable: exportable,
                )
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func setOwnerTrust(
        fingerprint: String,
        level: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._setOwnerTrust(fingerprint, level: level)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func changePassphrase(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._changePassphrase(fingerprint)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func setExpiry(
        fingerprint: String,
        expiryDays: Int,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._setExpiry(fingerprint, expiryDays: expiryDays)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func revokePrimaryKey(
        fingerprint: String,
        reasonCode: Int,
        description: String?,
        reply: @escaping @Sendable (Data?, NSError?) -> Void,
    ) {
        Task {
            do {
                let cert = try await self._revokePrimaryKey(
                    fingerprint,
                    reasonCode: reasonCode,
                    description: description,
                )
                reply(cert, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }
}

#if DEBUG
    extension GPGHelper {
        /// Test-only hook into the colon listing parser. Kept inside `#if DEBUG`
        /// so it does not ship in Release builds.
        func testParseColonKeyListing(_ text: String) -> [GPGKeyInfo] {
            parseColonKeyListing(text)
        }
    }
#endif
