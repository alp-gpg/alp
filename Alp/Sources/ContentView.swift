import SwiftUI

enum SettingsSection: Hashable {
    case general, keys, helper
}

struct ContentView: View {
    @State private var selection: SettingsSection? = .general
    @State private var vm = SettingsViewModel()

    var body: some View {
        NavigationSplitView {
            List(selection: $selection) {
                Label("General", systemImage: "gear")
                    .tag(SettingsSection.general)
                Label("Keys", systemImage: "key.fill")
                    .tag(SettingsSection.keys)
                Label("Helper", systemImage: "wrench.and.screwdriver")
                    .tag(SettingsSection.helper)
            }
            .navigationTitle("Alp")
            .listStyle(.sidebar)
        } detail: {
            switch selection ?? .general {
            case .general:
                GeneralSettingsView(vm: vm)
            case .keys:
                KeySettingsView(vm: vm)
            case .helper:
                HelperStatusView(vm: vm)
            }
        }
        .frame(minWidth: 520, minHeight: 360)
        .task {
            await vm.load()
            vm.startPeriodicHealthCheck()
            // Guide user to the first unresolved problem.
            if vm.helperStatus != .enabled {
                selection = .helper
            }
        }
        .onDisappear {
            vm.stopPeriodicHealthCheck()
        }
    }
}
