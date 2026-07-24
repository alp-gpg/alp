import Foundation
import Testing

// .serialized: two tests below toggle the shared `keyserverPresenceChecks`
// standard-defaults key that SettingsViewModel reads at init.
@Suite("Keys view model filter", .serialized)
@MainActor
struct KeysViewModelFilterTests {
    private func makeKey(
        fp: String,
        expired: Bool = false,
        published: Bool = false,
        store: SettingsViewModel,
    ) -> GPGKeyInfo {
        let expiry: Date? = expired ? Date(timeIntervalSince1970: 1) : nil
        if published {
            store.keyserverStatus[fp] = .found
        }
        return GPGKeyInfo(
            fingerprint: fp, userIDs: ["User <x@y>"],
            capabilities: "scESC",
            hasSecretKey: false, expiryDate: expiry, subkeys: [],
        )
    }

    @Test
    func `filteredKeys(showExpired: false) hides expired primaries`() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: false, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, store: vm),
        ]
        let visible = vm.filteredKeys(showExpired: false)
        #expect(visible.count == 1)
        #expect(visible.first?.fingerprint == String(repeating: "A", count: 40))
    }

    @Test
    func `filteredKeys(showExpired: true) returns everything`() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: false, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, store: vm),
        ]
        #expect(vm.filteredKeys(showExpired: true).count == 2)
    }

    @Test
    func `expiredPublishedCount counts only published expired primaries when checks are on`() {
        // Seed the standard-defaults key SettingsViewModel reads at init;
        // setting the property post-init would didSet-write the real app group.
        UserDefaults.standard.set(true, forKey: "keyserverPresenceChecks")
        defer { UserDefaults.standard.removeObject(forKey: "keyserverPresenceChecks") }
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: true, published: true, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, published: false, store: vm),
            makeKey(fp: String(repeating: "C", count: 40), expired: false, published: true, store: vm),
        ]
        #expect(vm.expiredPublishedCount == 1)
    }

    @Test
    func `expiredPublishedCount counts every expired primary when checks are off`() {
        // Default (checks off): publish status is unknown, so all expired keys
        // are refresh candidates — the banner/batch path must not go dead.
        UserDefaults.standard.removeObject(forKey: "keyserverPresenceChecks")
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: true, published: true, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, published: false, store: vm),
            makeKey(fp: String(repeating: "C", count: 40), expired: false, published: true, store: vm),
        ]
        #expect(vm.expiredPublishedCount == 2)
    }
}
