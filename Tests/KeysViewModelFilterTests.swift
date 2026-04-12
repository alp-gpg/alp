import Foundation
import Testing

@Suite("Keys view model filter")
@MainActor
struct KeysViewModelFilterTests {
    private func makeKey(
        fp: String,
        expired: Bool = false,
        published: Bool = false,
        store: SettingsViewModel
    ) -> GPGKeyInfo {
        let expiry: Date? = expired ? Date(timeIntervalSince1970: 1) : nil
        if published {
            store.keyserverStatus[fp] = .found
        }
        return GPGKeyInfo(
            fingerprint: fp, userIDs: ["User <x@y>"],
            capabilities: "scESC",
            hasSecretKey: false, expiryDate: expiry, subkeys: []
        )
    }

    @Test("filteredKeys(showExpired: false) hides expired primaries")
    func hidesExpired() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: false, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, store: vm),
        ]
        let visible = vm.filteredKeys(showExpired: false)
        #expect(visible.count == 1)
        #expect(visible.first?.fingerprint == String(repeating: "A", count: 40))
    }

    @Test("filteredKeys(showExpired: true) returns everything")
    func showsAll() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: false, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, store: vm),
        ]
        #expect(vm.filteredKeys(showExpired: true).count == 2)
    }

    @Test("expiredPublishedCount counts only published expired primaries")
    func publishedExpiredCount() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: true, published: true, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, published: false, store: vm),
            makeKey(fp: String(repeating: "C", count: 40), expired: false, published: true, store: vm),
        ]
        #expect(vm.expiredPublishedCount == 1)
    }
}
