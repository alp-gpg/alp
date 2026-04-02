import Foundation
import Observation
import ServiceManagement

@Observable @MainActor
final class SettingsViewModel {
    // Mirror writes into the app group so the sandboxed extension can read them.
    private static let groupDefaults = UserDefaults(suiteName: "group.com.CXM87Z432P.alp")

    // MARK: – Keys

    /// All keys in the local public keyring, with hasSecretKey set where a secret key exists.
    var allKeys: [GPGKeyInfo] = []
    /// Subset of allKeys that have a secret key — used by the signing key picker.
    var secretKeys: [GPGKeyInfo] = []

    enum KeyserverStatus: Sendable { case checking, found, notFound, unreachable }
    /// keys.openpgp.org lookup status keyed by fingerprint.
    var keyserverStatus: [String: KeyserverStatus] = [:]

    var isLoadingKeys = false

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

    func refreshHealth() async {
        isCheckingHealth = true
        defer { isCheckingHealth = false }
        do {
            healthStatus = try await HelperXPCClient.shared.checkHealth()
        } catch {
            healthStatus = nil
        }
    }

    // MARK: – Helper

    var helperStatus: SMAppService.Status = .notRegistered
    var helperError: String?

    func load() async {
        helperStatus = helperService.status
        await refreshKeys()
        await refreshHealth()
    }

    func refreshKeys() async {
        isLoadingKeys = true
        keyserverStatus = [:]
        defer { isLoadingKeys = false }
        do {
            let keys = try await HelperXPCClient.shared.listAllKeys()
            allKeys = keys
            secretKeys = keys.filter { $0.hasSecretKey }
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
            try helperService.register()
            helperStatus = helperService.status
            Task {
                // Give launchd a moment to start the daemon before the first XPC call.
                try? await Task.sleep(for: .milliseconds(800))
                await refreshKeys()
            }
        } catch {
            helperError = error.localizedDescription
        }
    }

    func uninstallHelper() {
        helperError = nil
        do {
            try helperService.unregister()
            helperStatus = helperService.status
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
            let (_, response) = try await URLSession.shared.data(for: req)
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
        SMAppService.agent(plistName: "com.CXM87Z432P.alp.helper.plist")
    }
}
