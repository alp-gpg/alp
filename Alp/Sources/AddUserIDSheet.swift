import SwiftUI

/// Append a new User ID (name + email + optional comment) to an existing
/// primary key. The helper drives `gpg --edit-key adduid save`; gpg-agent
/// prompts for the passphrase via pinentry while the sheet shows progress.
struct AddUserIDSheet: View {
    let key: GPGKeyInfo
    let onAdded: () async -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var name: String = ""
    @State private var email: String = ""
    @State private var comment: String = ""
    @State private var isWorking = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add User ID")
                .font(.title2.weight(.semibold))
            Text(key.displayName)
                .font(.callout)
                .foregroundStyle(.secondary)

            Form {
                TextField("Name", text: $name)
                    .textContentType(.name)
                    .disabled(isWorking)
                TextField("Email", text: $email)
                    .textContentType(.emailAddress)
                    .disabled(isWorking)
                TextField("Comment (optional)", text: $comment)
                    .disabled(isWorking)
            }
            .formStyle(.grouped)

            Text("gpg-agent will prompt for the passphrase via pinentry.")
                .font(.caption)
                .foregroundStyle(.secondary)

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
                Button("Add UID") { Task { await add() } }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
                    .disabled(isWorking || !canSubmit)
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 500)
    }

    private var canSubmit: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty
            && !email.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private func add() async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }
        let trimmedComment = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            try await HelperXPCClient.shared.addUserID(
                fingerprint: key.fingerprint,
                name: name,
                email: email,
                comment: trimmedComment.isEmpty ? nil : trimmedComment,
            )
            await onAdded()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
