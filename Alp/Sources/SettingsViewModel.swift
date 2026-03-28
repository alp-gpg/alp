import Observation
import ServiceManagement

@Observable @MainActor
final class SettingsViewModel {
    var secretKeys: [GPGKeyInfo] = []
    var defaultSignerFingerprint: String? {
        get { UserDefaults.standard.string(forKey: "defaultSignerFingerprint") }
        set { UserDefaults.standard.set(newValue, forKey: "defaultSignerFingerprint") }
    }
    var signByDefault: Bool {
        get { UserDefaults.standard.bool(forKey: "signByDefault") }
        set { UserDefaults.standard.set(newValue, forKey: "signByDefault") }
    }
    var encryptByDefault: Bool {
        get { UserDefaults.standard.bool(forKey: "encryptByDefault") }
        set { UserDefaults.standard.set(newValue, forKey: "encryptByDefault") }
    }

    var helperStatus: SMAppService.Status = .notRegistered
    var helperError: String?
    var isLoadingKeys = false

    func load() async {
        helperStatus = helperService.status
        await refreshKeys()
    }

    func refreshKeys() async {
        isLoadingKeys = true
        defer { isLoadingKeys = false }
        // AlpHelper runs in a separate process; connect via XPC
        // For the main app we use a direct XPC call through a lightweight client.
        do {
            let keys = try await HelperXPCClient.shared.listSecretKeys()
            secretKeys = keys
        } catch {
            secretKeys = []
        }
    }

    func installHelper() {
        helperError = nil
        do {
            try helperService.register()
            helperStatus = helperService.status
        } catch {
            helperError = error.localizedDescription
        }
    }

    func uninstallHelper() {
        helperError = nil
        do {
            try helperService.unregister()
            helperStatus = helperService.status
        } catch {
            helperError = error.localizedDescription
        }
    }

    private var helperService: SMAppService {
        SMAppService.agent(plistName: "com.CXM87Z432P.alp.helper.plist")
    }
}
