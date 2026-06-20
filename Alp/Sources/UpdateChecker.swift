import CryptoKit
import Foundation
import Observation
import os.log

private let log = Logger(subsystem: "app.alp.Alp", category: "UpdateChecker")

/// Notification-only updater — the replacement for Sparkle.
///
/// Fetches a signed `release.json` manifest, verifies an Ed25519 signature over
/// the **raw JSON bytes** (never a re-serialized copy), and on a newer version
/// shows the user a sheet pointing at the download page. There is deliberately
/// **no privileged install path**: the user downloads the notarized DMG and
/// Gatekeeper enforces install authenticity. A compromised feed or signing key
/// can at worst show a false notification pointing at a binary that must still
/// pass Gatekeeper and the documented Team-ID check.
@Observable @MainActor
final class UpdateChecker {
    /// The release manifest served at the feed URL.
    struct Release: Codable, Equatable {
        /// Marketing version, e.g. "1.2.3" (compared semantically).
        let version: String
        /// Minimum macOS version required, e.g. "26.0".
        let minOS: String
        /// Download page (opened in the browser; not fetched directly).
        let url: String
        /// SHA-256 of the DMG, shown so the user can verify their download.
        let sha256: String
        /// Human-readable release notes.
        let notes: String
    }

    enum CheckResult: Equatable {
        case upToDate
        case updateAvailable(Release)
        case failed(String)
    }

    var latestResult: CheckResult?
    var isChecking = false
    /// True while a check the user explicitly triggered is running, so the UI
    /// can surface "you're up to date" rather than staying silent.
    var lastCheckWasManual = false

    private let publicKeyBase64: String
    private let feedURL: URL?
    private let currentVersion: String
    private let currentOS: OperatingSystemVersion
    private let session: URLSession

    /// Production initializer: reads config from the app bundle.
    init() {
        let info = Bundle.main.infoDictionary ?? [:]
        publicKeyBase64 = info["AlpUpdatePublicKey"] as? String ?? ""
        feedURL = (info["AlpUpdateFeedURL"] as? String).flatMap(URL.init(string:))
        currentVersion = info["CFBundleShortVersionString"] as? String ?? "0"
        currentOS = ProcessInfo.processInfo.operatingSystemVersion
        session = URLSession(configuration: .ephemeral)
    }

    /// Test/injection initializer.
    init(
        publicKeyBase64: String,
        feedURL: URL?,
        currentVersion: String,
        currentOS: OperatingSystemVersion,
        session: URLSession = URLSession(configuration: .ephemeral),
    ) {
        self.publicKeyBase64 = publicKeyBase64
        self.feedURL = feedURL
        self.currentVersion = currentVersion
        self.currentOS = currentOS
        self.session = session
    }

    // MARK: – Pure, testable core

    /// Verify an Ed25519 signature (base64 of 64 raw bytes) over `manifest`
    /// using a public key (base64 of 32 raw bytes). Any malformed input fails
    /// closed.
    static func verify(manifest: Data, signatureBase64: String, publicKeyBase64: String) -> Bool {
        guard let keyData = Data(base64Encoded: publicKeyBase64.trimmingCharacters(in: .whitespacesAndNewlines)),
              let sigData = Data(base64Encoded: signatureBase64.trimmingCharacters(in: .whitespacesAndNewlines)),
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: keyData)
        else { return false }
        return key.isValidSignature(sigData, for: manifest)
    }

    static func decode(_ data: Data) -> Release? {
        try? JSONDecoder().decode(Release.self, from: data)
    }

    /// True when `lhs` is a strictly newer dotted version than `rhs`. Missing
    /// components count as 0, so "1.2" < "1.2.1". Non-numeric junk sorts as 0,
    /// which is the safe (no-update) direction.
    static func isVersion(_ lhs: String, newerThan rhs: String) -> Bool {
        let a = lhs.split(separator: ".").map { Int($0) ?? 0 }
        let b = rhs.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0 ..< max(a.count, b.count) {
            let l = i < a.count ? a[i] : 0
            let r = i < b.count ? b[i] : 0
            if l != r { return l > r }
        }
        return false
    }

    static func osMeets(_ minOS: String, current: OperatingSystemVersion) -> Bool {
        let parts = minOS.split(separator: ".").map { Int($0) ?? 0 }
        let major = parts.count > 0 ? parts[0] : 0
        let minor = parts.count > 1 ? parts[1] : 0
        let patch = parts.count > 2 ? parts[2] : 0
        let target = OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: patch)
        if current.majorVersion != target.majorVersion { return current.majorVersion > target.majorVersion }
        if current.minorVersion != target.minorVersion { return current.minorVersion > target.minorVersion }
        return current.patchVersion >= target.patchVersion
    }

    /// The decision the rest of the flow turns on. Pulled out so it's testable
    /// without networking: verify the signature, decode, reject downgrades and
    /// replays (only a strictly-newer version is offered), and reject releases
    /// that need a newer macOS than the user runs.
    func evaluate(manifest: Data, signatureBase64: String) -> CheckResult {
        guard Self.verify(manifest: manifest, signatureBase64: signatureBase64, publicKeyBase64: publicKeyBase64) else {
            return .failed("Update signature could not be verified.")
        }
        guard let release = Self.decode(manifest) else {
            return .failed("Update manifest was malformed.")
        }
        guard Self.isAllowedDownloadURL(release.url) else {
            return .failed("Update manifest points at an unexpected download URL.")
        }
        guard Self.isVersion(release.version, newerThan: currentVersion) else {
            return .upToDate
        }
        guard Self.osMeets(release.minOS, current: currentOS) else {
            return .upToDate // newer version exists but needs a newer macOS
        }
        return .updateAvailable(release)
    }

    /// Defense-in-depth: even with a valid Ed25519 signature, constrain the
    /// download URL to HTTPS on the official hosts. A compromised signing key
    /// could otherwise redirect to a phishing page.
    static func isAllowedDownloadURL(_ urlString: String) -> Bool {
        guard let url = URL(string: urlString),
              url.scheme == "https",
              let host = url.host?.lowercased()
        else { return false }
        return host == "github.com"
            || host == "alp-gpg.github.io"
            || host.hasSuffix(".github.com")
            || host.hasSuffix(".github.io")
    }

    // MARK: – Network

    /// Fetch `release.json` + `release.json.sig` and evaluate. `manual` flags a
    /// user-triggered check so the UI can confirm "up to date".
    func check(manual: Bool) async {
        guard let feedURL else { return }
        isChecking = true
        lastCheckWasManual = manual
        defer { isChecking = false }
        let sigURL = feedURL.appendingPathExtension("sig")
        do {
            let (manifest, _) = try await session.data(from: feedURL)
            let (sigBytes, _) = try await session.data(from: sigURL)
            let signature = String(bytes: sigBytes, encoding: .utf8) ?? ""
            let result = evaluate(manifest: manifest, signatureBase64: signature)
            if case let .updateAvailable(release) = result, skippedVersion == release.version {
                latestResult = .upToDate // user chose to skip this version
            } else {
                latestResult = result
            }
        } catch {
            log.error("Update check failed: \(error.localizedDescription, privacy: .public)")
            latestResult = .failed("Couldn't reach the update server.")
        }
    }

    // MARK: – Skip-this-version

    private static let skippedKey = "AlpSkippedUpdateVersion"

    var skippedVersion: String? {
        get { UserDefaults.standard.string(forKey: Self.skippedKey) }
        set { UserDefaults.standard.set(newValue, forKey: Self.skippedKey) }
    }

    func skip(_ release: Release) {
        skippedVersion = release.version
        latestResult = .upToDate
    }

    // MARK: – Scheduling

    @ObservationIgnored private var scheduled: Task<Void, Never>?

    /// Check on launch and roughly daily while opted in. Plain GET, no
    /// identifying data; intervals are jittered so checks don't synchronize
    /// across the install base.
    func startAutomaticChecks() {
        scheduled?.cancel()
        scheduled = Task { [weak self] in
            // Small startup delay (0–15 min) so launches don't thundering-herd.
            try? await Task.sleep(for: .seconds(Double.random(in: 0 ... 900)))
            while !Task.isCancelled {
                await self?.check(manual: false)
                // Re-check ~daily, ± 1 h so the install base doesn't synchronize.
                try? await Task.sleep(for: .seconds(24 * 3600 + Double.random(in: -3600 ... 3600)))
            }
        }
    }

    func stopAutomaticChecks() {
        scheduled?.cancel()
        scheduled = nil
    }
}
