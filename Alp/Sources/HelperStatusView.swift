import SwiftUI
import ServiceManagement

struct HelperStatusView: View {
    @Bindable var vm: SettingsViewModel

    var body: some View {
        Form {
            Section("Helper Daemon") {
                LabeledContent("Status") {
                    statusBadge
                }

                if let error = vm.helperError {
                    Text(error)
                        .foregroundStyle(.red)
                        .font(.callout)
                }

                HStack {
                    Button("Install Helper") {
                        vm.installHelper()
                    }
                    .disabled(vm.helperStatus == .enabled)

                    Button("Uninstall Helper") {
                        vm.uninstallHelper()
                    }
                    .disabled(vm.helperStatus != .enabled)
                }
            }

            Section("About") {
                Text("The Alp helper runs as a background daemon outside the sandbox so it can invoke the gpg binary. It only accepts connections from the Alp extension (same Team ID).")
                    .foregroundStyle(.secondary)
                    .font(.callout)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("Helper")
    }

    @ViewBuilder
    private var statusBadge: some View {
        switch vm.helperStatus {
        case .enabled:
            Label("Running", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .requiresApproval:
            Label("Requires Approval", systemImage: "exclamationmark.circle.fill")
                .foregroundStyle(.orange)
        case .notRegistered:
            Label("Not Installed", systemImage: "xmark.circle.fill")
                .foregroundStyle(.secondary)
        default:
            Label("Unknown", systemImage: "questionmark.circle")
                .foregroundStyle(.secondary)
        }
    }
}
