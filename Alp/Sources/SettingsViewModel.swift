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

    /// Surface for the most recent card-edit failure. Cleared on every
    /// successful refresh so stale messages don't linger.
    var cardError: String?

    func refreshCardStatus() async {
        do {
            cardStatus = try await HelperXPCClient.shared.cardStatus()
            cardError = nil
        } catch {
            cardStatus = nil
            cardError = nil
        }
    }

    /// Triggers the smartcard user-PIN change flow via the helper. The
    /// helper drives `gpg --card-edit` while gpg-agent prompts the user
    /// via pinentry for the old and new PINs. After the flow finishes
    /// we refresh card status so the visible PIN-retries count reflects
    /// any change.
    func changeCardPIN() async {
        cardError = nil
        do {
            try await HelperXPCClient.shared.changeCardPIN()
        } catch {
            cardError = error.localizedDescription
        }
        await refreshCardStatus()
    }

    /// Sibling of `changeCardPIN` for the admin PIN.
    func changeCardAdminPIN() async {
        cardError = nil
        do {
            try await HelperXPCClient.shared.changeCardAdminPIN()
        } catch {
            cardError = error.localizedDescription
        }
        await refreshCardStatus()
    }

    // MARK: – gpg-agent cache

    /// Surface for the most recent passphrase-cache clear failure.
    var agentCacheError: String?

    func clearAgentCache() async {
        agentCacheError = nil
        do {
            try await HelperXPCClient.shared.clearAgentCache()
        } catch {
            agentCacheError = error.localizedDescription
        }
    }

    // MARK: – Git commit signing

    var gitSigningStatus: HelperXPCClient.GitSigningStatus?
    var gitSigningError: String?

    func refreshGitSigningStatus() async {
        do {
            gitSigningStatus = try await HelperXPCClient.shared.gitSigningStatus()
            gitSigningError = nil
        } catch {
            gitSigningStatus = nil
            gitSigningError = error.localizedDescription
        }
    }

    func applyDefaultSignerToGit() async {
        guard let fp = UserDefaults.standard.string(forKey: "defaultSignerFingerprint") else {
            gitSigningError = "No default signing key — pick one in Settings → Keys first."
            return
        }
        await applyGitSigning(fingerprint: fp)
    }

    func disableGitSigning() async {
        await applyGitSigning(fingerprint: "")
    }

    private func applyGitSigning(fingerprint: String) async {
        gitSigningError = nil
        do {
            try await HelperXPCClient.shared.setGitSigning(fingerprint: fingerprint)
        } catch {
            gitSigningError = error.localizedDescription
        }
        await refreshGitSigningStatus()
    }

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
            await refreshPinentryConfig()
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
