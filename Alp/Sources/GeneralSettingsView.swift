import SwiftUI

struct GeneralSettingsView: View {
    @Bindable var vm: SettingsViewModel

    var body: some View {
        Form {
            Section("GPG Environment") {
                if vm.isCheckingHealth {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Checking GPG setup…")
                            .foregroundStyle(.secondary)
                    }
                } else if let health = vm.healthStatus {
                    healthRows(health)
                } else if vm.helperStatus != .enabled {
                    Label("Install the helper to check GPG status.", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } else {
                    Label("Could not connect to helper.", systemImage: "xmark.circle")
                        .foregroundStyle(.red)
                }
            }

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

    @ViewBuilder
    private func healthRows(_ health: GPGHealthStatus) -> some View {
        checkRow("GnuPG", passed: health.gpgPath != nil, detail: health.gpgPath.map { path in
            "\(path) (\(health.gpgVersion ?? "?"))"
        })
        checkRow("Version ≥ 2.2.14", passed: health.versionSufficient)
        checkRow("gpg-agent", passed: health.agentRunning)
        checkRow("pinentry", passed: health.pinentryConfigured, detail: health.pinentryPath)
        checkRow("Secret keys", passed: health.hasSecretKeys, detail: health.hasSecretKeys ? "\(health.secretKeyCount) found" : nil)
        checkRow("Trust model (tofu+pgp)", passed: health.tofuSupported)

        if !health.issues.isEmpty {
            ForEach(health.issues, id: \.self) { issue in
                Label(issue, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .font(.callout)
            }
        }

        Button {
            Task { await vm.refreshHealth() }
        } label: {
            Label("Recheck", systemImage: "arrow.clockwise")
        }
    }

    private func checkRow(_ title: String, passed: Bool, detail: String? = nil) -> some View {
        LabeledContent(title) {
            HStack(spacing: 6) {
                if let detail {
                    Text(detail)
                        .foregroundStyle(.secondary)
                        .font(.callout)
                }
                Image(systemName: passed ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundStyle(passed ? .green : .red)
            }
        }
    }
}
