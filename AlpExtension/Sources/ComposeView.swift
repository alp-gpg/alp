import SwiftUI
import MailKit

struct ComposeView: View {
    @Bindable var vm: ComposeViewModel

    var body: some View {
        HStack(spacing: 12) {
            Toggle(isOn: $vm.shouldSign) {
                Label("Sign", systemImage: "signature")
                    .symbolEffect(.bounce, value: vm.shouldSign)
            }
            .toggleStyle(.button)
            .tint(.blue)

            Toggle(isOn: $vm.shouldEncrypt) {
                Label("Encrypt", systemImage: "lock.fill")
                    .symbolEffect(.variableColor, value: vm.shouldEncrypt)
            }
            .toggleStyle(.button)
            .tint(.green)
            .disabled(!vm.canEncrypt)

            if !vm.missingKeyEmails.isEmpty {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .help("No public key for: \(vm.missingKeyEmails.joined(separator: ", "))")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .glassEffect(.regular, in: .capsule)
        .task { await vm.refresh() }
        .onChange(of: vm.shouldSign) { _, _ in syncStore() }
        .onChange(of: vm.shouldEncrypt) { _, _ in syncStore() }
        .onChange(of: vm.selectedSignerFingerprint) { _, _ in syncStore() }
    }

    @MainActor
    private func syncStore() {
        Task { await vm.refresh() }
    }
}
