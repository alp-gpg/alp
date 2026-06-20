import Foundation

/// File-level gpg operations (encrypt / decrypt / sign / verify against a
/// path instead of an in-memory `Data`). Lives in its own file so the
/// main `GPGHelper.swift` stays under SwiftLint's file_length limit. All
/// methods stream gpg via `--output <path>` so the XPC payload stays
/// constant regardless of file size.
extension GPGHelper {
    /// Decrypt a file on disk. Streams through gpg via `--output <out>`
    /// and a trailing `<in>` argument, so memory use is independent of
    /// file size. Returns the signer info parsed from `--status-fd 2`
    /// (nil when the ciphertext was unsigned).
    func _decryptFile(
        inputPath: String,
        outputPath: String,
    ) async throws -> (String?, String?) {
        try Self.validateFileOpPaths(inputPath: inputPath, outputPath: outputPath, requireInputExists: true)
        let args = [
            "--yes", "--status-fd", "2",
            "--decrypt",
            "--output", outputPath,
            "--", inputPath,
        ]
        let (_, stderr, exitCode) = try await runGPGRaw(args)
        let statusText = String(data: stderr, encoding: .utf8) ?? ""
        guard exitCode == 0 else {
            throw GPGError.processError(exitCode: exitCode, stderr: statusText)
        }
        let (fp, name) = extractSignerInfo(from: statusText)
        return (fp, name)
    }

    /// Verify a signature on disk. When `signaturePath` is nil, gpg is
    /// asked to verify the file in isolation — that covers clearsigned
    /// documents and standalone armored signatures. When non-nil, gpg
    /// is given the signature first and the data file second, which is
    /// the standard detached-signature flow.
    func _verifyFile(
        inputPath: String,
        signaturePath: String?,
    ) async throws -> (Bool, String?, String?, String?) {
        try Self.validateFileOpPaths(inputPath: inputPath, outputPath: nil, requireInputExists: true)
        var args = ["--batch", "--verify", "--status-fd", "2"]
        if let signaturePath {
            guard Self.isValidAbsolutePath(signaturePath),
                  FileManager.default.isReadableFile(atPath: signaturePath)
            else {
                throw GPGError.encodingError("invalid signature path")
            }
            args.append(contentsOf: ["--", signaturePath, inputPath])
        } else {
            args.append(contentsOf: ["--", inputPath])
        }
        // gpg --verify exits non-zero for bad/untrusted signatures, which is
        // a valid outcome rather than a hard error. Mirror _verify(data:).
        let (_, stderr, _) = try await runGPGRaw(args)
        let statusText = String(data: stderr, encoding: .utf8) ?? ""
        let (fp, name) = extractSignerInfo(from: statusText)
        let trust = Self.parseTrustLevel(from: statusText)
        return (fp != nil, fp, name, trust)
    }

    /// Map gpg's `TRUST_*` status line to a lowercase label. Returns nil
    /// when no trust line is present (e.g. unsigned input or gpg refused
    /// to evaluate trust). The return values match `OwnerTrust`'s title
    /// vocabulary in lowercase form.
    static func parseTrustLevel(from statusText: String) -> String? {
        for line in statusText.components(separatedBy: "\n") {
            let parts = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let tag = parts.first(where: { $0.hasPrefix("TRUST_") }) else { continue }
            switch tag {
            case "TRUST_ULTIMATE": return "ultimate"
            case "TRUST_FULLY": return "fully"
            case "TRUST_MARGINAL": return "marginal"
            case "TRUST_NEVER": return "never"
            case "TRUST_UNDEFINED": return "undefined"
            default: return nil
            }
        }
        return nil
    }

    /// ASCII-armored detached signature for the file at `inputPath`,
    /// written to `outputPath`. Detached because that's the only useful
    /// shape for file signing — clearsign is text-only and inline sign
    /// rewrites the document.
    func _signFile(
        inputPath: String,
        outputPath: String,
        signer: String,
    ) async throws {
        guard Self.isValidFingerprint(signer) else {
            throw GPGError.encodingError("invalid signer fingerprint")
        }
        try Self.validateFileOpPaths(inputPath: inputPath, outputPath: outputPath, requireInputExists: true)
        let args = [
            "--batch", "--yes", "--armor",
            "--status-fd", "2",
            "--detach-sign", "--local-user", signer,
            "--output", outputPath,
            "--", inputPath,
        ]
        _ = try await runGPG(args)
    }

    /// Encrypt the file at `inputPath` to one or more recipient fingerprints.
    /// Binary OpenPGP output (no `--armor`) because file encryption is the
    /// one workflow where armor's 33% size penalty is rarely worth paying.
    /// Output suffix should be `.gpg` by convention; that's the caller's
    /// responsibility, not ours.
    func _encryptFile(
        inputPath: String,
        outputPath: String,
        recipients: [String],
        signer: String?,
    ) async throws {
        guard !recipients.isEmpty else {
            throw GPGError.encodingError("no recipients")
        }
        guard recipients.count <= Self.maxRecipients else {
            throw GPGError.encodingError("too many recipients")
        }
        for fp in recipients {
            guard Self.isValidFingerprint(fp) else {
                throw GPGError.encodingError("invalid recipient fingerprint")
            }
        }
        if let signer, !Self.isValidFingerprint(signer) {
            throw GPGError.encodingError("invalid signer fingerprint")
        }
        try Self.validateFileOpPaths(inputPath: inputPath, outputPath: outputPath, requireInputExists: true)
        var args = [
            "--batch", "--yes",
            "--trust-model", "tofu+pgp",
            "--encrypt",
        ]
        if let signer {
            args += ["--sign", "--local-user", signer]
        }
        for fp in recipients {
            args += ["--recipient", fp]
        }
        args += ["--output", outputPath, "--", inputPath]
        _ = try await runGPG(args)
    }

    /// Shared input/output validation for the file-ops surface.
    /// `outputPath == nil` skips the output checks for verify, which has
    /// no output file. `requireInputExists` is on for everything except
    /// future stream-from-stdin variants.
    static func validateFileOpPaths(
        inputPath: String,
        outputPath: String?,
        requireInputExists: Bool,
    ) throws {
        guard isValidAbsolutePath(inputPath) else {
            throw GPGError.encodingError("invalid input path")
        }
        if requireInputExists {
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: inputPath, isDirectory: &isDir), !isDir.boolValue else {
                throw GPGError.encodingError("input file not found")
            }
        }
        if let outputPath {
            guard isValidAbsolutePath(outputPath) else {
                throw GPGError.encodingError("invalid output path")
            }
            // Refuse to clobber the source by accident. Compare both the raw
            // strings and their canonicalized (symlink-resolved) forms so a
            // symlinked output path can't alias the input and overwrite it
            // (§2.7).
            guard outputPath != inputPath else {
                throw GPGError.encodingError("input and output paths must differ")
            }
            let resolvedOut = (outputPath as NSString).resolvingSymlinksInPath
            let resolvedIn = (inputPath as NSString).resolvingSymlinksInPath
            guard resolvedOut != resolvedIn else {
                throw GPGError.encodingError("input and output paths resolve to the same file")
            }
            // Output parent directory must exist + be writable. We don't
            // create it: the caller picked the location via NSSavePanel.
            let parent = (outputPath as NSString).deletingLastPathComponent
            guard FileManager.default.isWritableFile(atPath: parent) else {
                throw GPGError.encodingError("output directory not writable")
            }
        }
    }

    // MARK: – nonisolated XPC bridges

    nonisolated func decryptFile(
        inputPath: String,
        outputPath: String,
        reply: @escaping @Sendable (String?, String?, NSError?) -> Void,
    ) {
        Task {
            do {
                let (signer, signerName) = try await self._decryptFile(
                    inputPath: inputPath,
                    outputPath: outputPath,
                )
                reply(signer, signerName, nil)
            } catch let e as GPGError {
                reply(nil, nil, e.asNSError)
            } catch {
                reply(nil, nil, error as NSError)
            }
        }
    }

    nonisolated func verifyFile(
        inputPath: String,
        signaturePath: String?,
        reply: @escaping @Sendable (Bool, String?, String?, String?, NSError?) -> Void,
    ) {
        Task {
            do {
                let (valid, signer, signerName, trust) = try await self._verifyFile(
                    inputPath: inputPath,
                    signaturePath: signaturePath,
                )
                reply(valid, signer, signerName, trust, nil)
            } catch let e as GPGError {
                reply(false, nil, nil, nil, e.asNSError)
            } catch {
                reply(false, nil, nil, nil, error as NSError)
            }
        }
    }

    nonisolated func signFile(
        inputPath: String,
        outputPath: String,
        signingFingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._signFile(
                    inputPath: inputPath,
                    outputPath: outputPath,
                    signer: signingFingerprint,
                )
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func encryptFile(
        inputPath: String,
        outputPath: String,
        recipientFingerprints: [String],
        signingFingerprint: String?,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._encryptFile(
                    inputPath: inputPath,
                    outputPath: outputPath,
                    recipients: recipientFingerprints,
                    signer: signingFingerprint,
                )
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }
}
