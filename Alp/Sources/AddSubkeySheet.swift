import SwiftUI

/// Add a fresh subkey to an existing primary. Used to rotate the
/// encryption subkey periodically without throwing the primary away —
/// the long-lived primary keeps its sigs, certifications, and ownertrust.
struct AddSubkeySheet: View {
    let key: GPGKeyInfo
    let onAdded: () async -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var algoTag: AlgoTag = .encryptCv25519
    @State private var expiry: ExpiryOption = .twoYears
    @State private var isWorking = false
    @State private var errorMessage: String?

    /// Subset gpg's `--quick-add-key` accepts on Curve25519 hardware. RSA
    /// is intentionally absent — modern key-generation guidance has moved
    /// off it and adding it here would invite users to ship slow keys.
    enum AlgoTag: String, CaseIterable, Identifiable {
        case signEd25519 = "ed25519/sign"
        case encryptCv25519 = "cv25519/encr"
        case authEd25519 = "ed25519/auth"

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .signEd25519: "Sign (Ed25519)"
            case .encryptCv25519: "Encrypt (Cv25519)"
            case .authEd25519: "Authenticate (Ed25519)"
            }
        }
    }

    private enum ExpiryOption: String, CaseIterable, Identifiable {
        case oneYear, twoYears, fourYears, never

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .oneYear: "1 year"
            case .twoYears: "2 years"
            case .fourYears: "4 years"
            case .never: "Never"
            }
        }

        var days: Int {
            switch self {
            case .oneYear: 365
            case .twoYears: 730
            case .fourYears: 1460
            case .never: 0
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add Subkey")
                .font(.title2.weight(.semibold))
            Text(key.displayName)
                .font(.callout)
                .foregroundStyle(.secondary)

            Form {
                Picker("Purpose", selection: $algoTag) {
                    ForEach(AlgoTag.allCases) { tag in
                        Text(tag.title).tag(tag)
                    }
                }
                .disabled(isWorking)

                Picker("Expires", selection: $expiry) {
                    ForEach(ExpiryOption.allCases) { option in
                        Text(option.title).tag(option)
                    }
                }
                .disabled(isWorking)
            }
            .formStyle(.grouped)

            Text(
                "Adds a fresh subkey under the existing primary. gpg-agent prompts for the primary key's passphrase via pinentry.",
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
                if isWorking {
                    ProgressView().controlSize(.small)
                    Text("Waiting for pinentry…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isWorking)
                Button("Add Subkey") { Task { await add() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking)
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 520)
    }

    private func add() async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        do {
            try await HelperXPCClient.shared.addSubkey(
                fingerprint: key.fingerprint,
                algoTag: algoTag.rawValue,
                expiryDays: expiry.days,
            )
            await onAdded()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
