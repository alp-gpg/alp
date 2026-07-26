import Foundation
import Observation
import ServiceManagement

@Observable @MainActor
final class SettingsViewModel {
    /// Mirror writes into the app group so the sandboxed extension can read them.
    private static let groupDefaults = UserDefaults(suiteName: BuildConfig.appGroup)

    // MARK: – Setup

    /// True when helper is running, GPG is healthy, extension has been seen, and a signing key is picked.
    var setupComplete: Bool {
        helperStatus == .enabled
            && healthStatus?.allPassed == true
            && extensionLastSeen != nil
            && defaultSignerFingerprint != nil
    }

    /// Last time the Mail extension wrote a heartbeat to the app group.
    var extensionLastSeen: Date? {
        Self.groupDefaults?.object(forKey: "extensionLastSeen") as? Date
    }

    /// True if the extension heartbeat is present and less than 24 hours old.
    var extensionRecentlySeen: Bool {
        guard let seen = extensionLastSeen else { return false }
        return seen.timeIntervalSinceNow > -86400
    }

    // MARK: – Pinning

    /// True when a keyserver connection succeeded but no certificate pin matched.
    var pinningDegraded = false

    /// Retained token for the pinning-degraded observer so it is registered
    /// exactly once and removed on teardown. `load()` can run again when the
    /// settings view re-appears, which would otherwise stack duplicate
    /// observers (and the block-based token would be unrecoverable).
    /// `@ObservationIgnored` (internal bookkeeping, not UI state) + nonisolated
    /// so `deinit` — which is nonisolated on a @MainActor class — can read it to
    /// remove the observer. Written only on the main actor (in `load()`) and
    /// read only from `deinit`, when no other reference survives, so the two
    /// accesses can never race.
    @ObservationIgnored private nonisolated(unsafe) var pinningObserver: NSObjectProtocol?

    /// In-flight per-key keyserver presence checks, retained so a fresh refresh
    /// or an uninstall can cancel the previous batch instead of leaving N
    /// unbounded network tasks racing writes into `keyserverStatus`.
    private var keyserverChecks: [Task<Void, Never>] = []

    deinit {
        if let pinningObserver {
            NotificationCenter.default.removeObserver(pinningObserver)
        }
    }

    // MARK: – Keys

    /// All keys in the local public keyring, with hasSecretKey set where a secret key exists.
    var allKeys: [GPGKeyInfo] = []
    /// Subset of allKeys that have a secret key — used by the signing key picker.
    var secretKeys: [GPGKeyInfo] = []

    enum KeyserverStatus { case checking, found, notFound, unreachable }
    /// keys.openpgp.org lookup status keyed by fingerprint.
    var keyserverStatus: [String: KeyserverStatus] = [:]

    var isLoadingKeys = false

    /// Set when the last key load failed (helper/XPC error). The Keys view shows
    /// an error + Retry instead of the misleading "No Keys Found — Generate a
    /// new pair…" state, which reads as data loss to a user with existing keys
    /// and invites generating a duplicate (§3.2).
    var keysLoadError: String?

    /// Returns the primary keys that should be shown given the "Show expired"
    /// toggle state. A primary is hidden only when its *own* expiry has
    /// passed; subkeys expiring independently do not hide their parent.
    func filteredKeys(showExpired: Bool) -> [GPGKeyInfo] {
        guard !showExpired else { return allKeys }
        return allKeys.filter { !$0.isExpired }
    }

    /// Count of expired primary keys Alp can plausibly refresh from
    /// keys.openpgp.org — drives the banner in KeySettingsView. With presence
    /// checks on, only keys confirmed published; with checks off (the default)
    /// publish status is unknown, so count every expired key and let the
    /// refresh attempts discover which are published.
    var expiredPublishedCount: Int {
        allKeys.count(where: { key in
            key.isExpired &&
                (!keyserverPresenceChecks || keyserverStatus[key.fingerprint] == .found)
        })
    }

    /// Shared across the Keys settings view's banner + per-row actions.
    @ObservationIgnored
    private(set) var expiredRefresher = ExpiredKeyRefresher()

    // MARK: – Compose defaults (stored so @Observable tracks mutations for Picker bindings)

    var defaultSignerFingerprint: String? = UserDefaults.standard.string(forKey: "defaultSignerFingerprint") {
        didSet {
            UserDefaults.standard.set(defaultSignerFingerprint, forKey: "defaultSignerFingerprint")
            Self.groupDefaults?.set(defaultSignerFingerprint, forKey: "defaultSignerFingerprint")
        }
    }

    /// When ON, the user's own key is added as a recipient on every encrypted
    /// message so their Sent items stay readable. Defaults ON — the common
    /// "I can't read my own sent encrypted mail" complaint for naive PGP setups.
    var encryptToSelf: Bool = UserDefaults.standard
        .object(forKey: BuildConfig.DefaultsKey.encryptToSelf) as? Bool ?? true
    {
        didSet {
            UserDefaults.standard.set(encryptToSelf, forKey: BuildConfig.DefaultsKey.encryptToSelf)
            Self.groupDefaults?.set(encryptToSelf, forKey: BuildConfig.DefaultsKey.encryptToSelf)
        }
    }

    /// When ON, Alp HEAD-requests keys.openpgp.org for each key on load to
    /// show publish status. That discloses the whole contact-key graph to the
    /// keyserver, so it is OPT-IN (default off) — the README promises
    /// keyserver traffic only on explicit user action (§5.7).
    var keyserverPresenceChecks: Bool = UserDefaults.standard
        .object(forKey: "keyserverPresenceChecks") as? Bool ?? false
    {
        didSet {
            UserDefaults.standard.set(keyserverPresenceChecks, forKey: "keyserverPresenceChecks")
            Self.groupDefaults?.set(keyserverPresenceChecks, forKey: "keyserverPresenceChecks")
        }
    }

    // MARK: – Health

    var healthStatus: GPGHealthStatus?
    var isCheckingHealth = false
    /// True when health was previously OK but the latest check failed.
    var helperUnresponsive = false
    private var healthCheckTask: Task<Void, Never>?

    // MARK: – Pinentry

    /// Latest pinentry configuration read from `~/.gnupg/gpg-agent.conf`.
    /// Settings shows / hides the "Use Alp Pinentry" suggestion based
    /// on whether `isAlpPinentry` is true.
    var pinentryConfig: HelperXPCClient.PinentryConfig?

    func refreshPinentryConfig() async {
        do {
            pinentryConfig = try await HelperXPCClient.shared.pinentryConfigStatus()
        } catch {
            pinentryConfig = nil
        }
    }

    func installAlpPinentry() async {
        do {
            let bundlePath = Bundle.main.bundlePath
            try await HelperXPCClient.shared.installAlpPinentry(bundlePath: bundlePath)
            await refreshPinentryConfig()
            await refreshHealth()
        } catch {
            helperError = error.localizedDescription
        }
    }

    func uninstallAlpPinentry() async {
        do {
            try await HelperXPCClient.shared.uninstallAlpPinentry()
            await refreshPinentryConfig()
            await refreshHealth()
        } catch {
            helperError = error.localizedDescription
        }
    }

    func refreshHealth() async {
        isCheckingHealth = true
        defer { isCheckingHealth = false }
        let previouslyHealthy = healthStatus?.allPassed == true
        do {
            healthStatus = try await HelperXPCClient.shared.checkHealth()
            helperUnresponsive = false
        } catch {
            healthStatus = nil
            if previouslyHealthy {
                helperUnresponsive = true
            }
        }
    }

    func startPeriodicHealthCheck() {
        healthCheckTask?.cancel()
        healthCheckTask = Task {
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(300))
                guard !Task.isCancelled else { break }
                await refreshHealth()
            }
        }
    }

    func stopPeriodicHealthCheck() {
        healthCheckTask?.cancel()
        healthCheckTask = nil
    }

    // MARK: – Helper

    var helperStatus: SMAppService.Status = .notRegistered
    var helperError: String?

    func load() async {
        helperStatus = helperService.status
        if pinningObserver == nil {
            pinningObserver = NotificationCenter.default.addObserver(
                forName: KeyserverSession.pinningDegradedNotification,
                object: nil, queue: nil,
            ) { [weak self] _ in
                Task { @MainActor in
                    self?.pinningDegraded = true
                }
            }
        }
        if helperStatus == .enabled {
            await refreshKeys()
            await refreshHealth()
            await refreshPinentryConfig()
        }
    }

    func refreshKeys() async {
        isLoadingKeys = true
        keyserverStatus = [:]
        // Cancel any presence checks still running from a previous refresh so
        // their late writes can't repopulate the status map we just cleared.
        keyserverChecks.forEach { $0.cancel() }
        keyserverChecks = []
        defer { isLoadingKeys = false }
        do {
            let keys = try await HelperXPCClient.shared.listAllKeys()
            allKeys = keys
            secretKeys = keys.filter(\.hasSecretKey)
            keysLoadError = nil
            // Fire off keyserver checks concurrently — each updates keyserverStatus
            // as it finishes. Skipped when the user opted out of presence checks.
            if keyserverPresenceChecks {
                keyserverChecks = keys.map { key in
                    Task { await self.checkKeyserver(fingerprint: key.fingerprint) }
                }
            }
        } catch {
            // Don't wipe a previously loaded keyring on a transient error —
            // surface the failure and let the user retry (§3.2).
            keysLoadError = error.localizedDescription
        }
    }

    func installHelper() {
        helperError = nil
        do {
            try HelperInstaller.install()
            helperStatus = helperService.status
            Task {
                try? await Task.sleep(for: .milliseconds(500))
                await refreshKeys()
                await refreshHealth()
                // Without this, the "Use Alp Pinentry" section never appears
                // after a fresh install — pinentryConfig stays nil until the
                // next app launch. Every other path to .enabled refreshes it.
                await refreshPinentryConfig()
            }
        } catch {
            helperError = error.localizedDescription
        }
    }

    func uninstallHelper() {
        helperError = nil
        do {
            try HelperInstaller.uninstall()
            helperStatus = helperService.status
            keyserverChecks.forEach { $0.cancel() }
            keyserverChecks = []
            allKeys = []
            secretKeys = []
            keyserverStatus = [:]
        } catch {
            helperError = error.localizedDescription
        }
    }

    // MARK: – Private

    private func checkKeyserver(fingerprint: String) async {
        keyserverStatus[fingerprint] = .checking
        let fp = fingerprint.uppercased()
        guard let url = URL(string: "https://keys.openpgp.org/vks/v1/by-fingerprint/\(fp)"),
              url.scheme == "https"
        else {
            keyserverStatus[fingerprint] = .unreachable; return
        }
        do {
            var req = URLRequest(url: url)
            req.httpMethod = "HEAD"
            let (_, response) = try await KeyserverSession.shared.data(for: req)
            // A cancelled batch (refresh/uninstall) must not write a stale
            // result back into the freshly-cleared status map.
            guard !Task.isCancelled else { return }
            if let http = response as? HTTPURLResponse {
                keyserverStatus[fingerprint] = http.statusCode == 200 ? .found : .notFound
            } else {
                keyserverStatus[fingerprint] = .unreachable
            }
        } catch {
            guard !Task.isCancelled else { return }
            keyserverStatus[fingerprint] = .unreachable
        }
    }

    private var helperService: SMAppService {
        SMAppService.agent(plistName: BuildConfig.helperPlistName)
    }
}
