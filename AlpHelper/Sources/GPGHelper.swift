import Foundation

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
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
            ?? "gpg"  // last resort: rely on PATH
    }

    // MARK: – Core runner

    /// Raw runner returning stdout, stderr, and exit code without throwing on non-zero exit.
    private func runGPGRaw(_ args: [String], input: Data? = nil) async throws -> (stdout: Data, stderr: Data, exitCode: Int32) {
        guard gpgPath != "gpg" || FileManager.default.isExecutableFile(atPath: gpgPath) else {
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
        let stderrQueue = DispatchQueue(label: "\(BuildConfig.bundlePrefix).alp.stderr-reader")
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

    func _sign(_ data: Data, signer: String) async throws -> Data {
        let args = [
            "--batch", "--yes", "--armor",
            "--detach-sign", "--local-user", signer,
            "--output", "-",
        ]
        return try await runGPG(args, input: data)
    }

    func _verify(_ data: Data, signature: Data?) async throws -> (Bool, String?, String?) {
        // gpg --verify exits non-zero for bad/untrusted signatures, which is a
        // valid result (not an error). Use runGPGRaw and parse status output
        // regardless of exit code. Status goes to stderr via --status-fd 2.
        if let signature {
            let sigURL = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString + ".asc")
            try signature.write(to: sigURL)
            defer { try? FileManager.default.removeItem(at: sigURL) }
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

    func _importKey(_ armoredKey: Data) async throws {
        _ = try await runGPG(["--batch", "--yes", "--import"], input: armoredKey)
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
        let found = path != "gpg" && FileManager.default.isExecutableFile(atPath: path)
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

        // 3. gpg-agent
        if found {
            let agentCheck = try? await runProcess("/usr/bin/env", args: ["gpgconf", "--check-programs"])
            if let data = agentCheck, let text = String(data: data, encoding: .utf8) {
                status.agentRunning = text.contains("gpg-agent") && !text.contains(":0:")
            }
            // Fallback: just check the socket exists
            if !status.agentRunning {
                let gnupgHome = ProcessInfo.processInfo.environment["GNUPGHOME"]
                    ?? (NSHomeDirectory() + "/.gnupg")
                let socketPath = gnupgHome + "/S.gpg-agent"
                status.agentRunning = FileManager.default.fileExists(atPath: socketPath)
            }
        }

        // 4. pinentry-mac
        let gnupgHome = ProcessInfo.processInfo.environment["GNUPGHOME"]
            ?? (NSHomeDirectory() + "/.gnupg")
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
        var currentFingerprint: String?
        var currentUIDs: [String] = []
        var currentCapabilities = ""
        var currentExpiryDate: Date?
        // Tracks whether the current fpr/uid line belongs to a subkey rather than
        // the primary key. GPG emits sub/ssb variants (sub#, ssb>, ssb#) for
        // smartcard/stub keys; primary key variants are pub, sec, sec#, sec>.
        var inSubkey = false

        func flush() {
            guard let fp = currentFingerprint, !fp.isEmpty else { return }
            keys.append(GPGKeyInfo(
                fingerprint: fp,
                userIDs: currentUIDs,
                capabilities: currentCapabilities,
                expiryDate: currentExpiryDate
            ))
        }

        for raw in text.components(separatedBy: "\n") {
            // Trim \r so the parser is robust against \r\n line endings.
            let fields = raw.trimmingCharacters(in: .init(charactersIn: "\r"))
                            .components(separatedBy: ":")
            guard let recordType = fields.first, !recordType.isEmpty else { continue }

            if recordType.hasPrefix("pub") || recordType.hasPrefix("sec") {
                // New primary key block — flush the previous one and reset.
                flush()
                currentFingerprint = nil
                currentUIDs = []
                currentCapabilities = fields.count > 11 ? fields[11] : ""
                // Field 6 is the expiry Unix timestamp (empty string = no expiry).
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    currentExpiryDate = Date(timeIntervalSince1970: ts)
                } else {
                    currentExpiryDate = nil
                }
                inSubkey = false
            } else if recordType.hasPrefix("sub") || recordType.hasPrefix("ssb") {
                // Entering a subkey block; subsequent fpr records belong to the subkey.
                inSubkey = true
            } else if recordType == "fpr" {
                if !inSubkey, currentFingerprint == nil, fields.count > 9 {
                    currentFingerprint = fields[9]
                }
            } else if recordType == "uid" {
                if fields.count > 9, !fields[9].isEmpty {
                    currentUIDs.append(fields[9])
                }
            }
        }
        flush()
        return keys
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
        reply: @escaping @Sendable (Data?, NSError?) -> Void
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let sig = try await self._sign(data, signer: signingFingerprint)
                reply(sig, nil)
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
        reply: @escaping @Sendable (NSError?) -> Void
    ) {
        guard armoredKey.count <= Self.maxPayloadSize else {
            reply(GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                try await self._importKey(armoredKey)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
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
