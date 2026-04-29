import Foundation

/// Result of a GPG environment health check. Each field represents
/// a capability or configuration that Alp requires to function.
struct GPGHealthStatus: Codable {
    /// Path to the detected gpg binary, or nil if not found.
    var gpgPath: String?
    /// Detected GnuPG version string (e.g. "2.4.7").
    var gpgVersion: String?
    /// True if version is ≥ 2.2.14 (required for --show-keys).
    var versionSufficient: Bool = false
    /// True if gpg-agent is reachable.
    var agentRunning: Bool = false
    /// True if pinentry-mac (or compatible GUI pinentry) is configured.
    var pinentryConfigured: Bool = false
    /// The configured pinentry program path, if any.
    var pinentryPath: String?
    /// True if at least one secret key exists in the keyring.
    var hasSecretKeys: Bool = false
    /// Number of secret keys found.
    var secretKeyCount: Int = 0
    /// True if the tofu+pgp trust model is supported.
    var tofuSupported: Bool = false

    /// True when all checks pass and Alp can operate normally.
    var allPassed: Bool {
        gpgPath != nil
            && versionSufficient
            && agentRunning
            && pinentryConfigured
            && hasSecretKeys
            && tofuSupported
    }

    /// Human-readable issues for display in the UI.
    var issues: [String] {
        var result: [String] = []
        if gpgPath == nil {
            result.append("GnuPG not found. Install with: brew install gnupg")
        } else if !versionSufficient {
            result.append("GnuPG \(gpgVersion ?? "?") is too old. Version 2.2.14 or later is required.")
        }
        if !agentRunning {
            result.append("gpg-agent is not running. Run: gpgconf --launch gpg-agent")
        }
        if !pinentryConfigured {
            result.append("pinentry-mac is not configured in ~/.gnupg/gpg-agent.conf")
        }
        if !hasSecretKeys {
            result.append("No secret keys found. Import or generate a key with: gpg --full-generate-key")
        }
        if !tofuSupported {
            result.append("Trust model tofu+pgp is not supported by this GnuPG build.")
        }
        return result
    }
}
