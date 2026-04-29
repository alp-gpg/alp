import SwiftUI
import UniformTypeIdentifiers

struct KeySettingsView: View {
    @Bindable var vm: SettingsViewModel
    @AppStorage("showExpiredKeys") private var showExpired = false
    @AppStorage("autoRefreshExpiredOnShow") private var autoRefresh = false

    /// Primary rows built from filtered keys, sorted with pub+sec first.
    private var primaryRows: [KeyRow] {
        let filtered = vm.filteredKeys(showExpired: showExpired)
        let sorted = filtered.sorted { lhs, rhs in
            if lhs.hasSecretKey != rhs.hasSecretKey { return lhs.hasSecretKey }
            return lhs.displayName.localizedCompare(rhs.displayName) == .orderedAscending
        }
        return sorted.map { .primary($0) }
    }

    var body: some View {
        VStack {
            if vm.isLoadingKeys {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if vm.allKeys.isEmpty {
                ContentUnavailableView {
                    Label("No Keys Found", systemImage: "key.slash")
                } description: {
                    Text("No GPG keys were found.")
                } actions: {
                    Button("Import Key File…") { importKeyFromFile() }
                    Text("or generate one in Terminal:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("gpg --full-generate-key")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            } else {
                VStack(spacing: 0) {
                    if showExpired, vm.expiredPublishedCount > 0 {
                        ExpiredKeysBanner(
                            expiredPublishedCount: vm.expiredPublishedCount,
                            isRunning: vm.expiredRefresher.isRunning,
                            onCheckNow: { startBatchRefresh() },
                            onCancel: { vm.expiredRefresher.cancel() },
                        )
                    }
                    Table(of: KeyRow.self) {
                        TableColumn("Type") { row in
                            HStack(spacing: 4) {
                                KeyRowTypeLabel(row: row)
                                rowStateBadge(for: row)
                            }
                            .contextMenu { contextMenu(for: row) }
                        }
                        .width(90)

                        TableColumn("User ID") { row in
                            Text(row.displayName)
                                .lineLimit(1)
                                .strikethrough(row.isRevoked || row.isExpired)
                        }

                        TableColumn("Capabilities") { row in
                            HStack(spacing: 4) {
                                ForEach(row.capabilityIcons, id: \.self) { sym in
                                    Image(systemName: sym)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .width(80)

                        TableColumn("Fingerprint") { row in
                            Text(row.shortFingerprint)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        .width(160)

                        TableColumn("Expires") { row in
                            ExpiryLabel(date: row.expiryDate)
                        }
                        .width(100)

                        TableColumn("keys.openpgp.org") { row in
                            if case let .primary(key) = row {
                                KeyserverStatusLabel(status: vm.keyserverStatus[key.fingerprint])
                            }
                        }
                        .width(140)
                    } rows: {
                        ForEach(primaryRows) { primaryRow in
                            if let children = primaryRow.children {
                                DisclosureTableRow(primaryRow) {
                                    ForEach(children) { child in
                                        TableRow(child)
                                    }
                                }
                            } else {
                                TableRow(primaryRow)
                            }
                        }
                    }
                }
                .onChange(of: showExpired) { _, newValue in
                    if newValue, autoRefresh, vm.expiredPublishedCount > 0 {
                        startBatchRefresh()
                    }
                }
            }
        }
        .toolbar {
            ToolbarItem {
                Button("Import Key…", systemImage: "square.and.arrow.down") {
                    importKeyFromFile()
                }
            }
            ToolbarItem {
                Button("Reload", systemImage: "arrow.clockwise") {
                    Task { await vm.refreshKeys() }
                }
                .help("Re-read keys from the local keyring")
            }
            ToolbarItem {
                Toggle(isOn: $showExpired) {
                    Label(showExpired ? "Hide expired" : "Show all",
                          systemImage: showExpired ? "eye.slash" : "eye")
                }
                .toggleStyle(.button)
                .help(showExpired ? "Hide expired keys" : "Show expired keys")
            }
        }
        .navigationTitle("Keys")
    }

    private func startBatchRefresh() {
        let candidates = vm.allKeys.filter { key in
            key.isExpired && vm.keyserverStatus[key.fingerprint] == .found
        }
        vm.expiredRefresher.start(keys: candidates)
    }

    @ViewBuilder
    private func contextMenu(for row: KeyRow) -> some View {
        switch row {
        case let .primary(key):
            Button("Copy fingerprint") { copyToPasteboard(key.fingerprint) }
            Button("Refresh from keyserver") {
                Task { await refreshSingle(fingerprint: key.fingerprint) }
            }
            .disabled(vm.keyserverStatus[key.fingerprint] != .found)
            Button("Reveal on keys.openpgp.org…") { openKeyserverPage(for: key.fingerprint) }
        case let .subkey(sub, _):
            Button("Copy fingerprint") { copyToPasteboard(sub.fingerprint) }
        }
    }

    @ViewBuilder
    private func rowStateBadge(for row: KeyRow) -> some View {
        if case let .primary(key) = row {
            switch vm.expiredRefresher.rowState[key.fingerprint] {
            case .fetching:
                ProgressView().controlSize(.mini)
            case let .failed(message):
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.red)
                    .help(message)
            default:
                EmptyView()
            }
        }
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }

    private func openKeyserverPage(for fingerprint: String) {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "keys.openpgp.org"
        components.percentEncodedPath = "/pks/lookup"
        components.queryItems = [
            .init(name: "op", value: "get"),
            .init(name: "search", value: "0x" + fingerprint),
        ]
        guard let url = components.url else { return }
        NSWorkspace.shared.open(url)
    }

    private func refreshSingle(fingerprint: String) async {
        let service = KeyserverRefreshService()
        do {
            _ = try await service.refresh(fingerprint: fingerprint)
            await vm.refreshKeys()
        } catch {
            vm.helperError = error.localizedDescription
        }
    }

    private func importKeyFromFile() {
        let panel = NSOpenPanel()
        panel.title = "Import GPG Key"
        panel.allowedContentTypes = ["asc", "gpg", "pgp", "key"]
            .compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do {
                let data = try Data(contentsOf: url)
                let result = try await HelperXPCClient.shared.importKey(data)
                vm.lastImportSummary = result.userFacingSummary
                await vm.refreshKeys()
            } catch {
                vm.helperError = error.localizedDescription
            }
        }
    }
}

private struct KeyTypeLabel: View {
    let hasSecretKey: Bool
    var isExpired: Bool = false

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: hasSecretKey ? "key.fill" : "key")
                .foregroundStyle(isExpired ? .red : (hasSecretKey ? .primary : .secondary))
            Text(isExpired ? "EXPIRED" : (hasSecretKey ? "pub+sec" : "pub"))
                .font(.caption2)
                .foregroundStyle(isExpired ? .red : (hasSecretKey ? .primary : .secondary))
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(isExpired ? "Expired key" : (hasSecretKey ? "Public and secret key" : "Public key only"))
    }
}

private struct KeyRowTypeLabel: View {
    let row: KeyRow
    var body: some View {
        switch row {
        case let .primary(key):
            KeyTypeLabel(hasSecretKey: key.hasSecretKey, isExpired: key.isExpired)
        case let .subkey(sub, _):
            HStack(spacing: 4) {
                Image(systemName: "key")
                    .foregroundStyle(.secondary)
                Text(sub.isRevoked ? "REVOKED" : "sub")
                    .font(.caption2)
                    .foregroundStyle(sub.isRevoked ? .red : .secondary)
                    .strikethrough(sub.isRevoked)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(sub.isRevoked ? "Revoked subkey" : "Subkey")
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
                .accessibilityLabel(expired ? "Expired \(Self.formatter.string(from: date))" :
                    "Expires \(Self.formatter.string(from: date))")
        } else {
            Text("Never")
                .font(.caption)
                .foregroundStyle(.secondary)
                .accessibilityLabel("Never expires")
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
                .accessibilityLabel("Published on keyserver")
        case .notFound:
            Label("Not found", systemImage: "xmark.circle")
                .foregroundStyle(.secondary)
                .font(.caption)
                .accessibilityLabel("Not found on keyserver")
        case .unreachable:
            Label("Unreachable", systemImage: "exclamationmark.triangle")
                .foregroundStyle(.orange)
                .font(.caption)
                .accessibilityLabel("Keyserver unreachable")
        }
    }
}
