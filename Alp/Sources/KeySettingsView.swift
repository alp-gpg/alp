import SwiftUI

struct KeySettingsView: View {
    @Bindable var vm: SettingsViewModel
    /// Column-header sort state. KeyPathComparator works with plain Swift structs;
    /// SortDescriptor requires an NSObject root and won't compile for GPGKeyInfo.
    @State private var sortOrder: [KeyPathComparator<GPGKeyInfo>] = []

    /// Sorted view of allKeys. Applies the user's column sort, with pub+sec as a
    /// stable tie-break so it always floats to the top within equal-valued groups.
    private var sortedKeys: [GPGKeyInfo] {
        vm.allKeys.sorted { a, b in
            for comparator in sortOrder {
                switch comparator.compare(a, b) {
                case .orderedAscending:  return true
                case .orderedDescending: return false
                case .orderedSame:       continue
                }
            }
            // Default / tie-break: pub+sec before pub-only, then alphabetical.
            if a.hasSecretKey != b.hasSecretKey { return a.hasSecretKey }
            return a.displayName.localizedCompare(b.displayName) == .orderedAscending
        }
    }

    var body: some View {
        VStack {
            if vm.isLoadingKeys {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if vm.allKeys.isEmpty {
                ContentUnavailableView(
                    "No Keys Found",
                    systemImage: "key.slash",
                    description: Text("No GPG keys were found. Install gnupg and import or generate a key pair.")
                )
            } else {
                Table(sortedKeys, sortOrder: $sortOrder) {
                    // Type column: not header-sortable; ordering is guaranteed by the
                    // pub+sec tie-break in sortedKeys regardless of active sort column.
                    TableColumn("Type") { key in
                        KeyTypeLabel(hasSecretKey: key.hasSecretKey)
                    }
                    .width(70)

                    TableColumn("User ID", value: \.displayName) { key in
                        Text(key.displayName)
                            .lineLimit(1)
                    }

                    TableColumn("Fingerprint", value: \.shortFingerprint) { key in
                        Text(key.shortFingerprint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    .width(120)

                    TableColumn("Expires") { key in
                        ExpiryLabel(date: key.expiryDate)
                    }
                    .width(100)

                    TableColumn("keys.openpgp.org") { key in
                        KeyserverStatusLabel(status: vm.keyserverStatus[key.fingerprint])
                    }
                    .width(140)
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

private struct KeyTypeLabel: View {
    let hasSecretKey: Bool

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: hasSecretKey ? "key.fill" : "key")
                .foregroundStyle(hasSecretKey ? .primary : .secondary)
            Text(hasSecretKey ? "pub+sec" : "pub")
                .font(.caption2)
                .foregroundStyle(hasSecretKey ? .primary : .secondary)
        }
    }
}

private struct ExpiryLabel: View {
    let date: Date?

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .none
        return f
    }()

    var body: some View {
        if let date {
            let expired = date < Date.now
            Text(Self.formatter.string(from: date))
                .font(.caption)
                .foregroundStyle(expired ? .red : .secondary)
        } else {
            Text("Never")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct KeyserverStatusLabel: View {
    let status: SettingsViewModel.KeyserverStatus?

    var body: some View {
        switch status {
        case nil, .checking:
            ProgressView().controlSize(.mini)
        case .found:
            Label("Published", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.caption)
        case .notFound:
            Label("Not found", systemImage: "xmark.circle")
                .foregroundStyle(.secondary)
                .font(.caption)
        case .unreachable:
            Label("Unreachable", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
                .font(.caption)
        }
    }
}
