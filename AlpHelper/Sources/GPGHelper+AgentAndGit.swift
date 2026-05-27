import Foundation

/// gpg-agent + git-config sidecar operations. Split from `GPGHelper.swift`
/// so the main actor body stays under SwiftLint's type_body_length limit.
extension GPGHelper {
    /// Flush gpg-agent's cached passphrases. We use `reloadagent` rather
    /// than `KILLAGENT` so the agent stays running but drops the cache;
    /// the next gpg operation prompts again via pinentry.
    func _clearAgentCache() async throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["gpg-connect-agent", "reloadagent", "/bye"]
        process.environment = Self.sanitizedEnvironment()
        let stderrPipe = Pipe()
        process.standardOutput = Pipe()
        process.standardError = stderrPipe
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let stderrText = String(
                data: stderrPipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8,
            ) ?? ""
            throw GPGError.processError(exitCode: process.terminationStatus, stderr: stderrText)
        }
    }

    /// Read the current git signing config out of `~/.gitconfig`. We
    /// shell to `git config --global --get` instead of parsing the file
    /// ourselves so includeIf / conditional includes resolve identically
    /// to what `git` itself would see. Both keys are optional.
    func _gitSigningStatus() async -> (signingKey: String?, commitGpgsign: Bool) {
        let key = await (try? Self.runGit(["config", "--global", "--get", "user.signingkey"]))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let gpgsign = await (try? Self.runGit(["config", "--global", "--get", "commit.gpgsign"]))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (
            (key?.isEmpty == false) ? key : nil,
            gpgsign == "true",
        )
    }

    /// Write `user.signingkey` and `commit.gpgsign = true` into the
    /// global git config. Passing an empty string unsets both keys —
    /// the inverse operation for users who want to stop signing.
    func _setGitSigning(fingerprint: String) async throws {
        let trimmed = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            _ = try? await Self.runGit(["config", "--global", "--unset", "user.signingkey"])
            _ = try? await Self.runGit(["config", "--global", "--unset", "commit.gpgsign"])
            return
        }
        guard Self.isValidFingerprint(trimmed) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        _ = try await Self.runGit(["config", "--global", "user.signingkey", trimmed])
        _ = try await Self.runGit(["config", "--global", "commit.gpgsign", "true"])
    }

    /// Locate git via `/usr/bin/env` so the user's PATH (Homebrew, Xcode,
    /// /usr/bin) wins. Same allowlisted environment as gpg invocations,
    /// so neither GNUPGHOME nor DYLD_INSERT_LIBRARIES propagates.
    static func runGit(_ args: [String]) async throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["git"] + args
        process.environment = sanitizedEnvironment()
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        // `git config --get` exits 1 when the key is missing; treat that
        // as an empty result, not a thrown error.
        if process.terminationStatus != 0, !args.contains("--get") {
            throw GPGError.processError(
                exitCode: process.terminationStatus,
                stderr: String(data: errData, encoding: .utf8) ?? "",
            )
        }
        return String(data: data, encoding: .utf8) ?? ""
    }

    // MARK: – nonisolated XPC bridges

    nonisolated func clearAgentCache(reply: @escaping @Sendable (NSError?) -> Void) {
        Task {
            do {
                try await self._clearAgentCache()
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }

    nonisolated func gitSigningStatus(
        reply: @escaping @Sendable (String?, Bool, NSError?) -> Void,
    ) {
        Task {
            let (key, gpgsign) = await self._gitSigningStatus()
            reply(key, gpgsign, nil)
        }
    }

    nonisolated func setGitSigning(
        fingerprint: String,
        reply: @escaping @Sendable (NSError?) -> Void,
    ) {
        Task {
            do {
                try await self._setGitSigning(fingerprint: fingerprint)
                reply(nil)
            } catch let e as GPGError {
                reply(e.asNSError)
            } catch {
                reply(error as NSError)
            }
        }
    }
}
