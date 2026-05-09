import SwiftUI

/// Read-only inspector for a primary key. Surfaces every field the colon
/// parser captures — fingerprint, creation date, expiry, algorithm,
/// capabilities, ownertrust, every UID, and every subkey — without making
/// the Keys table row itself any wider.
struct KeyDetailSheet: View {
    let key: GPGKeyInfo

    @Environment(\.dismiss) private var dismiss

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
            ForEach(key.userIDs, id: \.self) { uid in
                HStack(alignment: .top) {
                    Image(systemName: "person.text.rectangle")
                        .foregroundStyle(.secondary)
                    Text(uid)
                        .textSelection(.enabled)
                        .font(.callout)
                }
            }
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
