import SwiftUI

struct KeySettingsView: View {
    @Bindable var vm: SettingsViewModel

    var body: some View {
        VStack {
            if vm.isLoadingKeys {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if vm.secretKeys.isEmpty {
                ContentUnavailableView(
                    "No Secret Keys",
                    systemImage: "key.slash",
                    description: Text("No GPG secret keys were found. Install gnupg and import or generate a key.")
                )
            } else {
                Table(vm.secretKeys) {
                    TableColumn("Fingerprint", value: \.fingerprint)
                    TableColumn("User ID") { key in
                        Text(key.displayName)
                    }
                    TableColumn("Capabilities", value: \.capabilities)
                }
            }
        }
        .toolbar {
            ToolbarItem {
                Button("Refresh", systemImage: "arrow.clockwise") {
                    Task { await vm.refreshKeys() }
                }
            }
        }
        .navigationTitle("Keys")
    }
}
