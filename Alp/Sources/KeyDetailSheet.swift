import SwiftUI

/// Read-only inspector for a primary key. Surfaces every field the colon
/// parser captures — fingerprint, creation date, expiry, algorithm,
/// capabilities, ownertrust, every UID, and every subkey — without making
/// the Keys table row itself any wider.
struct KeyDetailSheet: View {
    let key: GPGKeyInfo
    /// Called when the user picks "Revoke" on a UID. The argument is the
    /// 1-based UID index gpg expects on its `uid <n>` edit-key command.
    let onRevokeUID: (_ uidIndex: Int) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var uidIndexPendingRevoke: Int?

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    overviewSection
                    if !key.userIDs.isEmpty {
                        userIDsSection
                    }
                    if !key.subkeys.isEmpty {
                        subkeysSection
                    }
                }
                .padding(20)
            }

            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .padding(16)
        }
        .frame(minWidth: 540, idealWidth: 620, minHeight: 420, idealHeight: 540)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: key.hasSecretKey ? "key.fill" : "key")
                .font(.title)
                .foregroundStyle(key.hasSecretKey ? .primary : .secondary)
            VStack(alignment: .leading, spacing: 4) {
                Text(key.shortName)
                    .font(.title2.weight(.semibold))
                Text(key.hasSecretKey ? "Public + secret key" : "Public key only")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let trust = OwnerTrust(rawCode: key.ownerTrustCode) {
                Text(trust.title)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(.quaternary, in: .capsule)
            }
        }
        .padding(20)
    }

    private var overviewSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Overview")
                .font(.headline)
            metadataGrid([
                ("Fingerprint", formattedFingerprint(key.fingerprint)),
                ("Algorithm", key.algorithm ?? "—"),
                ("Capabilities", capabilitiesDescription(key.capabilities)),
                ("Created", key.creationDate.map(Self.dateFormatter.string(from:)) ?? "—"),
                ("Expires", key.expiryDate.map(Self.dateFormatter.string(from:)) ?? "Never"),
            ])
        }
    }

    private var userIDsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("User IDs")
                .font(.headline)
            ForEach(Array(key.userIDs.enumerated()), id: \.offset) { offset, uid in
                HStack(alignment: .top) {
                    Image(systemName: "person.text.rectangle")
                        .foregroundStyle(.secondary)
                    Text(uid)
                        .textSelection(.enabled)
                        .font(.callout)
                    Spacer()
                    if key.hasSecretKey, key.userIDs.count > 1 {
                        Menu {
                            Button("Revoke this UID…", role: .destructive) {
                                // gpg uses 1-based UID indices.
                                uidIndexPendingRevoke = offset + 1
                            }
                        } label: {
                            Image(systemName: "ellipsis.circle")
                                .foregroundStyle(.secondary)
                        }
                        .menuStyle(.borderlessButton)
                        .fixedSize()
                        .help("UID actions")
                    }
                }
            }
            if key.hasSecretKey, key.userIDs.count <= 1 {
                Text("A key needs at least two UIDs before any can be revoked.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .alert(
            "Revoke this UID?",
            isPresented: Binding(
                get: { uidIndexPendingRevoke != nil },
                set: { if !$0 { uidIndexPendingRevoke = nil } },
            ),
        ) {
            Button("Revoke", role: .destructive) {
                if let idx = uidIndexPendingRevoke {
                    Task {
                        await onRevokeUID(idx)
                        uidIndexPendingRevoke = nil
                    }
                }
            }
            Button("Cancel", role: .cancel) {
                uidIndexPendingRevoke = nil
            }
        } message: {
            Text(
                "Revoking marks this User ID as no longer valid. The other UIDs on the key stay active. This cannot be undone.",
            )
        }
    }

    private var subkeysSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Subkeys")
                .font(.headline)
            ForEach(key.subkeys) { sub in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Image(systemName: "key")
                            .foregroundStyle(sub.isRevoked ? .red : .secondary)
                        Text(formattedFingerprint(sub.fingerprint))
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .strikethrough(sub.isRevoked)
                        if sub.isRevoked {
                            Text("revoked")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.red)
                        }
                    }
                    HStack(spacing: 16) {
                        if let algorithm = sub.algorithm {
                            metadataPair("Algorithm", algorithm)
                        }
                        metadataPair("Capabilities", capabilitiesDescription(sub.capabilities))
                        metadataPair(
                            "Expires",
                            sub.expiryDate.map(Self.dateFormatter.string(from:)) ?? "Never",
                        )
                    }
                }
                .padding(.vertical, 4)
            }
        }
    }

    private func metadataGrid(_ pairs: [(String, String)]) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(pairs, id: \.0) { label, value in
                HStack(alignment: .top) {
                    Text(label)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .frame(width: 110, alignment: .leading)
                    Text(value)
                        .font(.callout.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
    }

    private func metadataPair(_ label: String, _ value: String) -> some View {
        HStack(spacing: 4) {
            Text(label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    /// `0x1234 5678 90AB CDEF 1234 5678 90AB CDEF 1234 5678` — ten 4-char
    /// blocks, easy to compare by eye.
    private func formattedFingerprint(_ fingerprint: String) -> String {
        let upper = fingerprint.uppercased()
        guard upper.count == 40 else { return upper }
        let chunks = stride(from: 0, to: 40, by: 4).map { i -> String in
            let start = upper.index(upper.startIndex, offsetBy: i)
            let end = upper.index(start, offsetBy: 4)
            return String(upper[start ..< end])
        }
        return chunks.joined(separator: " ")
    }

    /// Translates gpg's compact capability flag string ("scESC", "e", …)
    /// into a human-readable list. Upper-case letters mark primary-key
    /// capabilities (gpg convention); lower-case mark subkey capabilities.
    private func capabilitiesDescription(_ caps: String) -> String {
        let order: [(Character, String)] = [
            ("c", "Certify"),
            ("s", "Sign"),
            ("e", "Encrypt"),
            ("a", "Authenticate"),
        ]
        let lower = caps.lowercased()
        let names = order.compactMap { lower.contains($0.0) ? $0.1 : nil }
        if names.isEmpty { return "—" }
        return names.joined(separator: " · ")
    }
}
