import Foundation
import Testing

// Smoke tests against the *installed* AlpHelper over a real NSXPCConnection.
// Everything else in Tests/ calls GPGHelper in-process; nothing there would
// notice if launchd stopped registering the agent, if the code-signing
// requirement stopped matching, or if SMAppService changed behaviour under a
// new macOS. That is what this suite is for — run it first after an OS upgrade.
//
// This target is hosted in Alp.app (see Project.swift) because the helper only
// accepts clients identified as `app.alp.Alp` or `app.alp.Alp.extension`
// (BuildConfig.clientRequirement). A standalone test bundle is rejected by the
// system before any reply is delivered, so hosting is not cosmetic.

/// Opt-in rather than auto-detected. Probing for "is a helper installed" would
/// have to treat an unreachable helper as "not installed" and skip — but a
/// helper that is installed and *stops answering* is exactly the regression this
/// suite exists to catch, and NSXPCConnection reports absence and rejection
/// identically. So: you assert a helper is there by setting the variable, and
/// anything short of a working round trip is a failure.
///
/// The `TEST_RUNNER_` prefix is not optional: xcodebuild strips it and forwards
/// the rest to the test process, and a plain `ALP_LIVE_XPC=1` never arrives —
/// the suite then skips and reports green, the exact false negative above.
///
///   TEST_RUNNER_ALP_LIVE_XPC=1 xcodebuild test -workspace Alp.xcworkspace \
///       -scheme AlpXPCTests -destination 'platform=macOS'
///
private let liveXPCEnabled = ProcessInfo.processInfo.environment["ALP_LIVE_XPC"] == "1"

/// Runs the gpg CLI in the test host — Alp.app, which is unsandboxed on
/// purpose (see Alp.entitlements), so Process is available. Used only to mint
/// and remove the disposable key for the decrypt test; everything being
/// smoked still goes through the helper.
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

@Suite(
    "Live helper XPC",
    .enabled(if: liveXPCEnabled, "set ALP_LIVE_XPC=1 with Alp installed and its helper running"),
    .serialized,
)
struct LiveHelperSmokeTests {
    /// One connection per test: reconnecting is part of what's being smoked.
    private func health() async throws -> GPGHealthStatus {
        try await HelperConnection().call { proxy, resume in
            proxy.checkHealth { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(Result { try JSONDecoder().decode(GPGHealthStatus.self, from: data) })
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }

    @Test
    func `the helper answers over real XPC`() async throws {
        // Reaching a decoded reply at all proves the whole stack: launchd
        // resolved the mach service, the helper accepted our code-signing
        // identity, and the NSXPCInterface whitelist passed the reply back.
        let status = try await health()
        #expect(status.gpgPath?.isEmpty == false)
        #expect(status.gpgVersion?.isEmpty == false)
        #expect(status.versionSufficient)
    }

    @Test
    func `gpg-agent is alive behind the helper`() async throws {
        let status = try await health()
        #expect(status.agentRunning)
    }

    @Test
    func `arguments and non-trivial replies marshal both ways`() async throws {
        // An address that cannot resolve: exercises a String argument plus a
        // three-value reply block without depending on the local keyring.
        let (found, fingerprint): (Bool, String?) = try await HelperConnection().call { proxy, resume in
            proxy.publicKeyExists(email: "nobody@alp.invalid") { found, fingerprint, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success((found, fingerprint)))
                }
            }
        }
        #expect(!found)
        #expect(fingerprint == nil)
    }

    @Test
    func `encrypts to a local secret key across the process boundary`() async throws {
        let status = try await health()
        try #require(status.hasSecretKeys, "no secret key in the keyring — nothing to encrypt to")

        let keys: [GPGKeyInfo] = try await HelperConnection().call { proxy, resume in
            proxy.listAllKeys { dataList, error in
                if let error {
                    resume(.failure(error))
                } else {
                    resume(.success((dataList ?? []).compactMap {
                        try? JSONDecoder().decode(GPGKeyInfo.self, from: $0)
                    }))
                }
            }
        }
        let target = try #require(
            keys.first { $0.hasSecretKey && !$0.isExpired },
            "no usable secret key",
        )

        let plaintext = Data("alp live xpc smoke".utf8)
        let ciphertext: Data = try await HelperConnection().call { proxy, resume in
            proxy.encrypt(data: plaintext, recipientFingerprints: [target.fingerprint],
                          signingFingerprint: nil)
            { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
        let armor = String(bytes: ciphertext, encoding: .utf8)
        #expect(armor?.hasPrefix("-----BEGIN PGP MESSAGE-----") == true)
        #expect(ciphertext.count > plaintext.count)
    }

    @Test
    func `decrypts across the process boundary with a disposable key`() async throws {
        // Decrypting to the *user's* key would block on pinentry, so the real
        // keyring briefly gains a passphrase-less throwaway key instead —
        // gpg-agent then never needs a human. Minted and removed via the CLI,
        // out of band from the helper being smoked. The UUID keeps a leftover
        // from an aborted earlier run from shadowing this one's fingerprint.
        let email = "live-smoke-\(UUID().uuidString.prefix(8).lowercased())@alp.invalid"
        try gpgCLI([
            "--batch", "--yes", "--passphrase", "",
            "--quick-gen-key", "Alp Live Smoke <\(email)>", "default", "default", "never",
        ])
        let listing = try gpgCLI(["--list-keys", "--with-colons", email])
        let fingerprint = try #require(
            listing.split(separator: "\n").first { $0.hasPrefix("fpr:") }
                .map { String($0.split(separator: ":").last ?? "") },
            "disposable key was not created",
        )
        // `--yes` advises gpg-agent not to ask for delete confirmation, so
        // cleanup cannot pop a dialog even on failure paths.
        defer {
            _ = try? gpgCLI(["--batch", "--yes", "--delete-secret-and-public-key", fingerprint])
        }

        let plaintext = Data("alp live xpc decrypt smoke".utf8)
        let ciphertext: Data = try await HelperConnection().call { proxy, resume in
            proxy.encrypt(data: plaintext, recipientFingerprints: [fingerprint],
                          signingFingerprint: nil)
            { data, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }

        let decrypted: Data = try await HelperConnection().call { proxy, resume in
            proxy.decrypt(data: ciphertext) { data, _, _, error in
                if let error {
                    resume(.failure(error))
                } else if let data {
                    resume(.success(data))
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
        #expect(decrypted == plaintext)
    }
}
