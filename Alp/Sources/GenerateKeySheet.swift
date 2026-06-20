import SwiftUI

/// Sheet for generating a new Ed25519 + Cv25519 primary/subkey pair.
/// gpg-agent prompts for the passphrase via the user's pinentry while the
/// sheet shows a progress indicator.
struct GenerateKeySheet: View {
    @Bindable var vm: SettingsViewModel
    @Environment(\.dismiss) private var dismiss

    @State private var name: String = ""
    @State private var email: String = ""
    @State private var comment: String = ""
    @State private var expirySelection: ExpiryOption = .twoYears
    @State private var isGenerating = false
    @State private var errorMessage: String?

    private enum ExpiryOption: String, CaseIterable, Identifiable {
        case ninetyDays
        case oneYear
        case twoYears
        case fourYears
        case never

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .ninetyDays: "90 days"
            case .oneYear: "1 year"
            case .twoYears: "2 years"
            case .fourYears: "4 years"
            case .never: "Never"
            }
        }

        var days: Int {
            switch self {
            case .ninetyDays: 90
            case .oneYear: 365
            case .twoYears: 730
            case .fourYears: 1460
            case .never: 0
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Generate New Key")
                .font(.title2.weight(.semibold))

            Form {
                TextField("Name", text: $name)
                    .textContentType(.name)
                    .disabled(isGenerating)

                TextField("Email", text: $email)
                    .textContentType(.emailAddress)
                    .disabled(isGenerating)

                TextField("Comment (optional)", text: $comment)
                    .disabled(isGenerating)

                Picker("Expires", selection: $expirySelection) {
                    ForEach(ExpiryOption.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }
                .disabled(isGenerating)
            }
            .formStyle(.grouped)

            Text(
                "Generates an Ed25519 signing primary with a Cv25519 encryption subkey. Pinentry will ask for a new passphrase (with a confirm field) to protect this key. Pick something strong and back it up — a forgotten passphrase cannot be recovered.",
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if isGenerating {
                    ProgressView().controlSize(.small)
                    Text("Waiting for pinentry…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isGenerating)
                Button("Generate") { Task { await generate() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(!canSubmit || isGenerating)
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 500)
    }

    private var canSubmit: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
            && !email.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func generate() async {
        errorMessage = nil
        isGenerating = true
        defer { isGenerating = false }
        let trimmedComment = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let fingerprint = try await HelperXPCClient.shared.generatePrimaryKey(
                name: name,
                email: email,
                comment: trimmedComment.isEmpty ? nil : trimmedComment,
                expiryDays: expirySelection.days,
            )
            await vm.refreshKeys()
            // Default new key to the signer slot if none is selected.
            if vm.defaultSignerFingerprint == nil {
                vm.defaultSignerFingerprint = fingerprint
            }
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
