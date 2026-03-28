import SwiftUI

struct GeneralSettingsView: View {
    @Bindable var vm: SettingsViewModel

    var body: some View {
        Form {
            Section("Compose Defaults") {
                Toggle("Sign messages by default", isOn: $vm.signByDefault)
                Toggle("Encrypt messages by default", isOn: $vm.encryptByDefault)
            }

            if !vm.secretKeys.isEmpty {
                Section("Default Signing Key") {
                    Picker("Key", selection: $vm.defaultSignerFingerprint) {
                        Text("None").tag(String?.none)
                        ForEach(vm.secretKeys) { key in
                            Text(key.displayName)
                                .tag(Optional(key.fingerprint))
                        }
                    }
                }
            }
        }
        .formStyle(.grouped)
        .navigationTitle("General")
    }
}
