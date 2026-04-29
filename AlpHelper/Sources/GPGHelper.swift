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
    private static let maxRecipients = 100

    /// RFC 4880 full fingerprints are 40 hex chars. Reject anything else before
    /// passing to gpg so a malicious caller cannot smuggle flags like
    /// `--homedir /evil` through the --recipient / --local-user arguments.
    static func isValidFingerprint(_ value: String) -> Bool {
        guard value.count == 40 else { return false }
        return value.allSatisfy { $0.isHexDigit }
    }

    override init() {
        self.gpgPath = GPGHelper.detectGPGPath()
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
            "/opt/homebrew/bin/gpg",              // Homebrew (Apple Silicon)
            "/usr/local/bin/gpg",                 // Homebrew (Intel) / manual install
            "/opt/local/bin/gpg",                 // MacPorts
            "/nix/var/nix/profiles/default/bin/gpg", // Nix
            "/usr/local/MacGPG2/bin/gpg",         // GPG Suite (GPGTools)
        ]
        // No fallback to bare "gpg": Process.run with a relative path fails on
        // macOS, and isExecutableFile against "gpg" always returns false.
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) } ?? ""
    }

    // MARK: – Core runner

    /// Raw runner returning stdout, stderr, and exit code without throwing on non-zero exit.
    private func runGPGRaw(_ args: [String], input: Data? = nil) async throws -> (stdout: Data, stderr: Data, exitCode: Int32) {
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
    private func runGPG(_ args: [String], input: Data? = nil) async throws -> Data {
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
        _ signer: String?
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
        let plain = try await runGPGWithStatus(args, input: data)
        return plain
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
                newSubkeys: reason & 8 != 0
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
                attributes: [.posixPermissions: 0o600]
            ) else {
                throw GPGError.encodingError("could not write signature tempfile")
            }
            defer {
                do {
                    try FileManager.default.removeItem(at: sigURL)
                } catch {
                    log.error("Failed to remove signature tempfile \(sigURL.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
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
        // Cross-reference with secret keys to set hasSecretKey
        if let secOut = try? await runGPG(["--list-secret-keys", "--with-colons", "--with-fingerprint"]) {
            let secFPs = Set(parseColonKeyListing(String(data: secOut, encoding: .utf8) ?? "").map { $0.fingerprint })
            keys = keys.map { k in
                GPGKeyInfo(fingerprint: k.fingerprint, userIDs: k.userIDs, capabilities: k.capabilities, hasSecretKey: secFPs.contains(k.fingerprint), expiryDate: k.expiryDate)
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

    /// Test-only helper — **not** exposed via GPGHelperProtocol. Exists solely
    /// to let `XPCRoundtripTests` round-trip real armored key material through
    /// the import bridge without hard-coding test fixtures. Safe against
    /// argument injection via the `isValidFingerprint` check.
    func _export(_ fingerprint: String) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        let args = ["--batch", "--yes", "--armor", "--export", fingerprint]
        return try await runGPG(args)
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

    func _checkHealth() async -> GPGHealthStatus {
        var status = GPGHealthStatus()

        // 1. GPG binary
        let path = gpgPath
        let found = !path.isEmpty && FileManager.default.isExecutableFile(atPath: path)
        status.gpgPath = found ? path : nil

        // 2. Version
        if found, let versionData = try? await runGPGRaw(["--version"]).stdout,
           let versionText = String(data: versionData, encoding: .utf8) {
            // First line: "gpg (GnuPG) 2.4.7"
            if let firstLine = versionText.components(separatedBy: "\n").first,
               let match = firstLine.range(of: #"\d+\.\d+(\.\d+)?"#, options: .regularExpression) {
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
            let tofuResult = try? await runGPGRaw(["--batch", "--trust-model", "tofu+pgp", "--list-keys", "--with-colons"])
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
        _ args: [String], input: Data? = nil
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
    private func extractSignerInfo(from statusText: String) -> (fingerprint: String?, displayName: String?) {
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
                if fingerprint == nil { fingerprint = parts[idx + 1] }  // key ID fallback
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
        var subkeys: [GPGSubkey] = []

        /// Staging area for the subkey we're currently filling in. We can't
        /// build the final `GPGSubkey` until its `fpr` line arrives because
        /// the subkey's full fingerprint appears on a subsequent record.
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
                isRevoked: pending.isRevoked
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
                subkeys: subkeys
            ))
            primaryFingerprint = nil
            primaryUIDs = []
            primaryCapabilities = ""
            primaryExpiry = nil
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
                    curve: fields.count > 16 ? fields[16] : ""
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
        case 1:  name = "RSA"
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
        reply: @escaping @Sendable (Data?, NSError?) -> Void
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
        reply: @escaping @Sendable (Data?, String?, String?, NSError?) -> Void
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
        reply: @escaping @Sendable (Data?, String?, NSError?) -> Void
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

    nonisolated func verify(
        data: Data,
        signatureData: Data?,
        reply: @escaping @Sendable (Bool, String?, String?, NSError?) -> Void
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
        reply: @escaping @Sendable ([Data]?, NSError?) -> Void
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
        reply: @escaping @Sendable (Data?, NSError?) -> Void
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
        reply: @escaping @Sendable (Bool, String?, NSError?) -> Void
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
                reply(nil, (error as NSError))
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
