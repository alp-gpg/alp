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
        env["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        return env
    }

    // MARK: – GPG binary detection

    private static func detectGPGPath() -> String {
        let candidates = [
            "/opt/homebrew/bin/gpg",     // brew install gnupg (Apple Silicon)
            "/usr/local/bin/gpg",        // brew install gnupg (Intel)
            "/usr/local/MacGPG2/bin/gpg", // GPGTools fallback
            "/usr/bin/gpg",              // system fallback
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
        let stderrQueue = DispatchQueue(label: "com.CXM87Z432P.alp.stderr-reader")
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

    func _decrypt(_ data: Data) async throws -> (Data, String?) {
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

    func _verify(_ data: Data, signature: Data?) async throws -> (Bool, String?) {
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
            let fp = extractGoodSig(from: statusText)
            return (fp != nil, fp)
        } else {
            let args = ["--batch", "--verify", "--status-fd", "2"]
            let (_, stderr, _) = try await runGPGRaw(args, input: data)
            let statusText = String(data: stderr, encoding: .utf8) ?? ""
            let fp = extractGoodSig(from: statusText)
            return (fp != nil, fp)
        }
    }

    func _listSecretKeys() async throws -> [GPGKeyInfo] {
        let args = ["--list-secret-keys", "--with-colons", "--with-fingerprint"]
        let output = try await runGPG(args)
        let text = String(data: output, encoding: .utf8) ?? ""
        return parseColonKeyListing(text)
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

    // MARK: – Helpers

    /// Run gpg and capture stdout (plaintext) while parsing status-fd on stderr (signer info).
    private func runGPGWithStatus(
        _ args: [String], input: Data? = nil
    ) async throws -> (Data, String?) {
        let (stdout, stderr, exitCode) = try await runGPGRaw(args, input: input)
        let stderrText = String(data: stderr, encoding: .utf8) ?? ""

        guard exitCode == 0 else {
            throw GPGError.processError(exitCode: exitCode, stderr: stderrText)
        }

        let signer = extractGoodSig(from: stderrText)
        return (stdout, signer)
    }

    private func extractGoodSig(from statusText: String) -> String? {
        for line in statusText.components(separatedBy: "\n") {
            if line.contains("[GNUPG:] GOODSIG") || line.contains("[GNUPG:] VALIDSIG") {
                let parts = line.components(separatedBy: " ")
                if let idx = parts.firstIndex(of: "VALIDSIG"), parts.count > idx + 1 {
                    return parts[idx + 1]
                }
                if let idx = parts.firstIndex(of: "GOODSIG"), parts.count > idx + 1 {
                    return parts[idx + 1]
                }
            }
        }
        return nil
    }

    private func parseColonKeyListing(_ text: String) -> [GPGKeyInfo] {
        var keys: [GPGKeyInfo] = []
        var currentFingerprint: String?
        var currentUIDs: [String] = []
        var currentCapabilities = ""

        func flush() {
            guard let fp = currentFingerprint, !fp.isEmpty else { return }
            keys.append(GPGKeyInfo(
                fingerprint: fp,
                userIDs: currentUIDs,
                capabilities: currentCapabilities
            ))
        }

        for line in text.components(separatedBy: "\n") {
            let fields = line.components(separatedBy: ":")
            guard !fields.isEmpty else { continue }
            switch fields[0] {
            case "pub", "sec":
                flush()
                currentFingerprint = nil
                currentUIDs = []
                currentCapabilities = fields.count > 11 ? fields[11] : ""
            case "fpr":
                if currentFingerprint == nil {
                    currentFingerprint = fields.count > 9 ? fields[9] : nil
                }
            case "uid":
                if fields.count > 9, !fields[9].isEmpty {
                    currentUIDs.append(fields[9])
                }
            default:
                break
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
        reply: @escaping @Sendable (Data?, String?, NSError?) -> Void
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(nil, nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let (plain, signer) = try await self._decrypt(data)
                reply(plain, signer, nil)
            } catch let e as GPGError {
                reply(nil, nil, e.asNSError)
            } catch {
                reply(nil, nil, error as NSError)
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
        reply: @escaping @Sendable (Bool, String?, NSError?) -> Void
    ) {
        guard data.count <= Self.maxPayloadSize else {
            reply(false, nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let (valid, signer) = try await self._verify(data, signature: signatureData)
                reply(valid, signer, nil)
            } catch let e as GPGError {
                reply(false, nil, e.asNSError)
            } catch {
                reply(false, nil, error as NSError)
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
}
