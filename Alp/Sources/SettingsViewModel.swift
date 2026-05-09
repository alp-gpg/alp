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

    // MARK: – Keys

    /// All keys in the local public keyring, with hasSecretKey set where a secret key exists.
    var allKeys: [GPGKeyInfo] = []
    /// Subset of allKeys that have a secret key — used by the signing key picker.
    var secretKeys: [GPGKeyInfo] = []

    enum KeyserverStatus { case checking, found, notFound, unreachable }
    /// keys.openpgp.org lookup status keyed by fingerprint.
    var keyserverStatus: [String: KeyserverStatus] = [:]

    var isLoadingKeys = false

    /// Returns the primary keys that should be shown given the "Show expired"
    /// toggle state. A primary is hidden only when its *own* expiry has
    /// passed; subkeys expiring independently do not hide their parent.
    func filteredKeys(showExpired: Bool) -> [GPGKeyInfo] {
        guard !showExpired else { return allKeys }
        return allKeys.filter { !$0.isExpired }
    }

    /// Count of expired primary keys that are published on keys.openpgp.org —
    /// i.e. the ones Alp can plausibly refresh. Used to drive the banner in
    /// KeySettingsView.
    var expiredPublishedCount: Int {
        allKeys.count(where: { key in
            key.isExpired && keyserverStatus[key.fingerprint] == .found
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

    var signByDefault: Bool = UserDefaults.standard.object(forKey: "signByDefault") as? Bool ?? false {
        didSet {
            UserDefaults.standard.set(signByDefault, forKey: "signByDefault")
            Self.groupDefaults?.set(signByDefault, forKey: "signByDefault")
        }
    }

    var encryptByDefault: Bool = UserDefaults.standard.bool(forKey: "encryptByDefault") {
        didSet {
            UserDefaults.standard.set(encryptByDefault, forKey: "encryptByDefault")
            Self.groupDefaults?.set(encryptByDefault, forKey: "encryptByDefault")
        }
    }

    // MARK: – Health

    var healthStatus: GPGHealthStatus?
    var isCheckingHealth = false
    /// True when health was previously OK but the latest check failed.
    var helperUnresponsive = false
    private var healthCheckTask: Task<Void, Never>?

    // MARK: – Smartcard

    /// Most recent smartcard read; nil when no card is inserted or the
    /// helper hasn't been queried yet. The General settings view hides
    /// the Smartcard section based on this value.
    var cardStatus: GPGCardStatus?

    func refreshCardStatus() async {
        do {
            cardStatus = try await HelperXPCClient.shared.cardStatus()
        } catch {
            cardStatus = nil
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
            if previouslyHealthy { helperUnresponsive = true }
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

    /// Non-error user feedback for the most recent key import. Shown as a
    /// transient summary in the Keys section.
    ///
    /// **Lifecycle:** set by the import flow on success, consumed by the UI
    /// when displayed, and **must be cleared by the UI layer after display**
    /// (e.g., on the next user interaction or after a short timeout) to
    /// avoid a stale toast reappearing on view re-render. No one currently
    /// reads this — UI wiring arrives with the Keys list hierarchy rework.
    var lastImportSummary: String?

    func load() async {
        #if DEBUG
            // Don't assume helper is running — check if we can actually reach it.
            // The user must click "Install Helper" to bootstrap via launchctl.
            helperStatus = .notRegistered
        #else
            helperStatus = helperService.status
        #endif
        NotificationCenter.default.addObserver(
            forName: KeyserverSession.pinningDegradedNotification,
            object: nil, queue: nil,
        ) { [weak self] _ in
            Task { @MainActor in
                self?.pinningDegraded = true
            }
        }
        if helperStatus == .enabled {
            await refreshKeys()
            await refreshHealth()
            await refreshCardStatus()
        }
    }

    func refreshKeys() async {
        isLoadingKeys = true
        keyserverStatus = [:]
        defer { isLoadingKeys = false }
        do {
            let keys = try await HelperXPCClient.shared.listAllKeys()
            allKeys = keys
            secretKeys = keys.filter(\.hasSecretKey)
            // Fire off keyserver checks concurrently — each updates keyserverStatus as it finishes.
            for key in keys {
                Task { await self.checkKeyserver(fingerprint: key.fingerprint) }
            }
        } catch {
            allKeys = []
            secretKeys = []
        }
    }

    func installHelper() {
        helperError = nil
        do {
            try HelperInstaller.install()
            #if DEBUG
                helperStatus = .enabled
            #else
                helperStatus = helperService.status
            #endif
            Task {
                try? await Task.sleep(for: .milliseconds(500))
                await refreshKeys()
                await refreshHealth()
            }
        } catch {
            helperError = error.localizedDescription
        }
    }

    func uninstallHelper() {
        helperError = nil
        do {
            try HelperInstaller.uninstall()
            #if DEBUG
                helperStatus = .notRegistered
            #else
                helperStatus = helperService.status
            #endif
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
            if let http = response as? HTTPURLResponse {
                keyserverStatus[fingerprint] = http.statusCode == 200 ? .found : .notFound
            } else {
                keyserverStatus[fingerprint] = .unreachable
            }
        } catch {
            keyserverStatus[fingerprint] = .unreachable
        }
    }

    private var helperService: SMAppService {
        SMAppService.agent(plistName: BuildConfig.helperPlistName)
    }
}
