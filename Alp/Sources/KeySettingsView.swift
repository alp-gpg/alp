import SwiftUI
import UniformTypeIdentifiers

struct KeySettingsView: View {
    @Bindable var vm: SettingsViewModel
    @AppStorage("showExpiredKeys") private var showExpired = false
    @AppStorage("autoRefreshExpiredOnShow") private var autoRefresh = false

    @State private var searchQuery: String = ""
    @State private var selection: KeyRow.ID?
    @State private var showingGenerateSheet = false
    @State private var keyForSetExpiry: GPGKeyInfo?
    @State private var keyForRevoke: GPGKeyInfo?
    @State private var keyToDelete: KeyDeletionRequest?
    @State private var keyForUpload: GPGKeyInfo?
    @State private var keyForCertify: GPGKeyInfo?
    @State private var keyForDetail: GPGKeyInfo?
    @State private var keyForAddUID: GPGKeyInfo?
    @State private var keyForAddSubkey: GPGKeyInfo?
    @State private var actionError: String?

    /// Pairs a key with the kind of delete the user requested so the confirm
    /// alert and the RPC dispatch agree.
    fileprivate struct KeyDeletionRequest: Identifiable {
        let key: GPGKeyInfo
        let secretOnly: Bool
        var id: String {
            "\(key.fingerprint)-\(secretOnly)"
        }
    }

    /// Primary rows built from filtered keys, sorted with pub+sec first.
    private var primaryRows: [KeyRow] {
        let filtered = vm.filteredKeys(showExpired: showExpired)
        let searched = Self.matching(query: searchQuery, in: filtered)
        let sorted = searched.sorted { lhs, rhs in
            if lhs.hasSecretKey != rhs.hasSecretKey {
                return lhs.hasSecretKey
            }
            return lhs.displayName.localizedCompare(rhs.displayName) == .orderedAscending
        }
        return sorted.map { .primary($0) }
    }

    /// Resolves a Table selection id back to its KeyRow. Walks both
    /// primary rows and their children so subkey selections work too.
    private func row(for id: KeyRow.ID) -> KeyRow? {
        for row in primaryRows {
            if row.id == id {
                return row
            }
            if let children = row.children {
                for child in children where child.id == id {
                    return child
                }
            }
        }
        return nil
    }

    /// Case-insensitive substring match against display name, every UID
    /// email, the primary fingerprint, and any subkey fingerprint. Empty
    /// query returns every key. `nonisolated` so unit tests can call it
    /// without hopping the main actor; SwiftUI `View` is implicitly
    /// `@MainActor` otherwise.
    nonisolated static func matching(query: String, in keys: [GPGKeyInfo]) -> [GPGKeyInfo] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return keys }
        return keys.filter { key in
            if key.fingerprint.lowercased().contains(trimmed) {
                return true
            }
            if key.displayName.lowercased().contains(trimmed) {
                return true
            }
            if key.emails.contains(where: { $0.contains(trimmed) }) {
                return true
            }
            return key.subkeys.contains { $0.fingerprint.lowercased().contains(trimmed) }
        }
    }

    var body: some View {
        VStack {
            if vm.isLoadingKeys {
                ProgressView("Loading keys…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let loadError = vm.keysLoadError, vm.allKeys.isEmpty {
                // A helper/XPC error must not masquerade as "No Keys Found" —
                // that reads as data loss and invites a duplicate key (§3.2).
                ContentUnavailableView {
                    Label("Couldn't Load Keys", systemImage: "exclamationmark.triangle")
                } description: {
                    Text(loadError)
                } actions: {
                    Button("Retry") { Task { await vm.refreshKeys() } }
                        .buttonStyle(.borderedProminent)
                }
            } else if vm.allKeys.isEmpty {
                ContentUnavailableView {
                    Label("No Keys Found", systemImage: "key.slash")
                } description: {
                    Text("Generate a new Ed25519 + Cv25519 pair, or import an existing armored key file.")
                } actions: {
                    Button("Generate Key…") { showingGenerateSheet = true }
                        .buttonStyle(.borderedProminent)
                    Button("Import Key File…") { importKeyFromFile() }
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
                    Table(of: KeyRow.self, selection: $selection) {
                        TableColumn("Type") { row in
                            HStack(spacing: 4) {
                                KeyRowTypeLabel(row: row)
                                rowStateBadge(for: row)
                            }
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

                        TableColumn("Trust") { row in
                            if case let .primary(key) = row,
                               let trust = OwnerTrust(rawCode: key.ownerTrustCode)
                            {
                                TrustPill(trust: trust)
                            }
                        }
                        .width(90)

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
                            // Presence checks are opt-in; without them a nil
                            // status means "unchecked", not "in flight" — show
                            // a dash, not an eternal spinner.
                            if case let .primary(key) = row {
                                if vm.keyserverPresenceChecks {
                                    KeyserverStatusLabel(status: vm.keyserverStatus[key.fingerprint])
                                } else {
                                    Text("—")
                                        .foregroundStyle(.tertiary)
                                        .accessibilityLabel("Publish status not checked")
                                }
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
                    .contextMenu(forSelectionType: KeyRow.ID.self) { ids in
                        if let id = ids.first, let r = row(for: id) {
                            contextMenu(for: r)
                        }
                    } primaryAction: { ids in
                        if let id = ids.first, let r = row(for: id) {
                            primaryAction(for: r)
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
            // `.titleAndIcon` on every label so users see what each
            // toolbar control does without having to hover for the
            // tooltip. macOS otherwise renders these icon-only.
            ToolbarItem {
                Button {
                    showingGenerateSheet = true
                } label: {
                    Label("Generate", systemImage: "key.horizontal")
                        .labelStyle(.titleAndIcon)
                }
                .help("Generate a new Ed25519 + Cv25519 key pair")
            }
            ToolbarItem {
                Button {
                    importKeyFromFile()
                } label: {
                    Label("Import", systemImage: "square.and.arrow.down")
                        .labelStyle(.titleAndIcon)
                }
                .help("Import an armored or binary public key from disk")
            }
            ToolbarItem {
                Button {
                    restoreBackupFromFile()
                } label: {
                    Label("Restore Backup", systemImage: "tray.and.arrow.down")
                        .labelStyle(.titleAndIcon)
                }
                .help("Restore a key bundle previously produced by Back Up Key…")
            }
            ToolbarItem {
                Button {
                    Task { await vm.refreshKeys() }
                } label: {
                    Label("Reload", systemImage: "arrow.clockwise")
                        .labelStyle(.titleAndIcon)
                }
                .help("Re-read keys from the local keyring")
            }
            ToolbarItem {
                Toggle(isOn: $showExpired) {
                    Label(
                        showExpired ? "Hide expired" : "Show all",
                        systemImage: showExpired ? "eye.slash" : "eye",
                    )
                    .labelStyle(.titleAndIcon)
                }
                .toggleStyle(.button)
                .help(showExpired ? "Hide expired keys" : "Show expired keys")
            }
        }
        .sheet(isPresented: $showingGenerateSheet) {
            GenerateKeySheet(vm: vm)
        }
        .sheet(item: $keyForSetExpiry) { key in
            SetExpirySheet(key: key) { days in
                await runHelperAction("Set expiry") {
                    try await HelperXPCClient.shared.setExpiry(
                        fingerprint: key.fingerprint, expiryDays: days,
                    )
                    await vm.refreshKeys()
                }
            }
        }
        .sheet(item: $keyForRevoke) { key in
            RevokeKeySheet(key: key) { reasonCode, description in
                await runHelperAction("Revoke key") {
                    let cert = try await HelperXPCClient.shared.revokePrimaryKey(
                        fingerprint: key.fingerprint,
                        reasonCode: reasonCode,
                        description: description,
                    )
                    await saveExportedKey(cert, suggested: "\(key.fingerprint)-revoke.asc")
                    await vm.refreshKeys()
                }
            }
        }
        .sheet(item: $keyForUpload) { key in
            PublishKeySheet(key: key)
        }
        .sheet(item: $keyForDetail) { key in
            KeyDetailSheet(
                key: key,
                onRevokeUID: { uidIndex in
                    await runHelperAction("Revoke UID") {
                        try await HelperXPCClient.shared.revokeUserID(
                            fingerprint: key.fingerprint, uidIndex: uidIndex,
                        )
                        await vm.refreshKeys()
                    }
                },
                onRevokeSubkey: { subkeyIndex in
                    await runHelperAction("Revoke subkey") {
                        try await HelperXPCClient.shared.revokeSubkey(
                            fingerprint: key.fingerprint,
                            subkeyIndex: subkeyIndex,
                            reasonCode: 1, // 1 = key superseded; safest default
                        )
                        await vm.refreshKeys()
                    }
                },
                onDeleteSubkey: { subkeyIndex in
                    await runHelperAction("Delete subkey") {
                        try await HelperXPCClient.shared.deleteSubkey(
                            fingerprint: key.fingerprint,
                            subkeyIndex: subkeyIndex,
                        )
                        await vm.refreshKeys()
                    }
                },
                onCleanupSubkeys: { indices in
                    await runHelperAction("Clean up subkeys") {
                        try await HelperXPCClient.shared.deleteSubkeys(
                            fingerprint: key.fingerprint,
                            subkeyIndices: indices,
                        )
                        await vm.refreshKeys()
                    }
                },
            )
        }
        .sheet(item: $keyForAddUID) { key in
            AddUserIDSheet(key: key) {
                await vm.refreshKeys()
            }
        }
        .sheet(item: $keyForAddSubkey) { key in
            AddSubkeySheet(key: key) {
                await vm.refreshKeys()
            }
        }
        .sheet(item: $keyForCertify) { key in
            CertifyKeySheet(key: key, signers: vm.secretKeys) { signerFP, exportable in
                await runHelperAction("Certify key") {
                    try await HelperXPCClient.shared.signKey(
                        fingerprint: key.fingerprint,
                        signer: signerFP,
                        exportable: exportable,
                    )
                    await vm.refreshKeys()
                }
            }
        }
        .alert(
            Text(keyToDelete?.secretOnly == true ? "Delete Secret Key Only?" : "Delete Key?"),
            isPresented: deleteConfirmBinding,
            presenting: keyToDelete,
        ) { request in
            Button("Delete", role: .destructive) { Task { await deleteKey(request) } }
            Button("Cancel", role: .cancel) {}
        } message: { request in
            Text(request.secretOnly
                ? "Removes the secret half of \(request.key.displayName). The public key stays in the keyring. This cannot be undone."
                :
                "Removes both the secret and public halves of \(request.key.displayName) from the local keyring. This cannot be undone.")
        }
        .alert("Operation failed", isPresented: actionErrorBinding) {
            Button("OK", role: .cancel) { actionError = nil }
        } message: {
            Text(actionError ?? "")
        }
        .navigationTitle("Keys")
        .searchable(text: $searchQuery, placement: .toolbar, prompt: "Search keys")
    }

    private var actionErrorBinding: Binding<Bool> {
        Binding(get: { actionError != nil }, set: {
            if !$0 {
                actionError = nil
            }
        })
    }

    private var deleteConfirmBinding: Binding<Bool> {
        Binding(get: { keyToDelete != nil }, set: {
            if !$0 {
                keyToDelete = nil
            }
        })
    }

    private func startBatchRefresh() {
        let candidates = vm.allKeys.filter { key in
            key.isExpired && vm.keyserverStatus[key.fingerprint] == .found
        }
        vm.expiredRefresher.start(keys: candidates)
    }

    /// Triggered by double-click or Enter on a selected row. Opens the
    /// detail inspector for primaries; for subkeys, opens the parent's
    /// inspector — the parent is where every subkey-level action lives.
    private func primaryAction(for row: KeyRow) {
        switch row {
        case let .primary(key):
            keyForDetail = key
        case let .subkey(_, parentFingerprint):
            if let parent = vm.allKeys.first(where: { $0.fingerprint == parentFingerprint }) {
                keyForDetail = parent
            }
        }
    }

    @ViewBuilder
    private func contextMenu(for row: KeyRow) -> some View {
        switch row {
        case let .primary(key):
            Button("Show Details…") { keyForDetail = key }
            Button("Copy fingerprint") { copyToPasteboard(key.fingerprint) }
            Button("Refresh from keyserver") {
                Task { await refreshSingle(fingerprint: key.fingerprint) }
            }
            // With presence checks off we don't know the publish status —
            // allow the attempt (it's an explicit user action) instead of
            // permanently disabling refresh.
            .disabled(vm.keyserverPresenceChecks && vm.keyserverStatus[key.fingerprint] != .found)
            Button("Reveal on keys.openpgp.org…") { openKeyserverPage(for: key.fingerprint) }

            Divider()

            Button("Export Public Key…") { exportPublicKey(for: key) }
            if key.hasSecretKey {
                Button("Export Secret Key…") { exportSecretKey(for: key) }
                Button("Back Up Key…") { backUpKey(for: key) }
                Button("Change Passphrase…") { changePassphrase(for: key) }
            }
            Button("Set Expiry…") { keyForSetExpiry = key }

            if !vm.secretKeys.isEmpty {
                Button("Certify…") { keyForCertify = key }
                Menu("Set Trust") {
                    ForEach(OwnerTrustLevel.userVisible, id: \.rawValue) { level in
                        Button(level.title) {
                            Task {
                                await runHelperAction("Set trust") {
                                    try await HelperXPCClient.shared.setOwnerTrust(
                                        fingerprint: key.fingerprint, level: level.rawValue,
                                    )
                                    await vm.refreshKeys()
                                }
                            }
                        }
                    }
                }
            }

            if key.hasSecretKey {
                Button("Add User ID…") { keyForAddUID = key }
                Button("Add Subkey…") { keyForAddSubkey = key }
                // Generate-only: saves an offline revocation cert WITHOUT
                // revoking — the standard "make a backup after key creation"
                // workflow. Separate from the destructive "Revoke Key…" below
                // so the safe action is no longer mislabeled as the dangerous
                // one (§5.1).
                Button("Generate Revocation Certificate…") { generateRevocationCert(for: key) }
                Button("Publish to keys.openpgp.org…") { keyForUpload = key }
            }

            Divider()

            if key.hasSecretKey {
                Button("Revoke Key…", role: .destructive) { keyForRevoke = key }
                Button("Delete Secret Key Only…", role: .destructive) {
                    keyToDelete = .init(key: key, secretOnly: true)
                }
            }
            Button("Delete Key…", role: .destructive) {
                keyToDelete = .init(key: key, secretOnly: false)
            }
        case let .subkey(sub, parentFingerprint):
            Button("Copy fingerprint") { copyToPasteboard(sub.fingerprint) }
            if let parent = vm.allKeys.first(where: { $0.fingerprint == parentFingerprint }) {
                Button("Show Details on Primary…") { keyForDetail = parent }
            }
        }
    }

    @ViewBuilder
    private func rowStateBadge(for row: KeyRow) -> some View {
        if case let .primary(key) = row {
            switch vm.expiredRefresher.rowState[key.fingerprint] {
            case .fetching:
                ProgressView().controlSize(.mini)
            case .updated:
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .help("Refreshed from keyserver — newer key data imported.")
            case .alreadyCurrent:
                Image(systemName: "checkmark.circle")
                    .foregroundStyle(.secondary)
                    .help("Already up to date on the keyserver.")
            case .notPublished:
                Image(systemName: "icloud.slash")
                    .foregroundStyle(.secondary)
                    .help("Not published on keys.openpgp.org — nothing to refresh.")
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
        await runHelperAction("Refresh from keyserver") {
            _ = try await KeyserverRefreshService().refresh(fingerprint: fingerprint)
            await vm.refreshKeys()
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
            await runHelperAction("Import key") {
                let data = try Data(contentsOf: url)
                _ = try await HelperXPCClient.shared.importKey(data)
                await vm.refreshKeys()
            }
        }
    }

    private func restoreBackupFromFile() {
        let panel = NSOpenPanel()
        panel.title = "Restore Alp Backup"
        panel.allowedContentTypes = ["asc"].compactMap { UTType(filenameExtension: $0) }
        panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }

        // Pre-flight alert: tell the user exactly which passphrase
        // they need (the archive passphrase from backup time, not
        // their key passphrase).
        let intro = NSAlert()
        intro.alertStyle = .informational
        intro.messageText = "Restore “\(url.lastPathComponent)”"
        intro.informativeText = """
        You'll be prompted for the archive passphrase you set when this backup was created — not your key passphrase.

        After unlocking, Alp imports every key in the bundle and replays the ownertrust.
        """
        intro.addButton(withTitle: "Continue")
        intro.addButton(withTitle: "Cancel")
        guard intro.runModal() == .alertFirstButtonReturn else { return }

        Task {
            await runHelperAction("Restore backup") {
                // Pinentry collects the archive passphrase. Helper
                // imports every armored block + replays ownertrust.
                let imported = try await HelperXPCClient.shared.restoreBackup(
                    bundlePath: url.path,
                )
                await vm.refreshKeys()
                if imported.isEmpty {
                    actionError = "Backup restored, but no new keys reported."
                }
            }
        }
    }

    // MARK: – Lifecycle action helpers

    private func exportPublicKey(for key: GPGKeyInfo) {
        Task {
            await runHelperAction("Export public key") {
                let armored = try await HelperXPCClient.shared.exportPublicKey(
                    fingerprint: key.fingerprint,
                )
                await saveExportedKey(armored, suggested: "\(key.fingerprint)-public.asc")
            }
        }
    }

    private func exportSecretKey(for key: GPGKeyInfo) {
        // Secret keys decrypt everything the user has ever received
        // with this key. Pause for a clear "yes, I know" before the
        // file lands on disk — and steer users toward Back Up Key…
        // when that's actually what they want.
        let intro = NSAlert()
        intro.alertStyle = .warning
        intro.messageText = "Export secret key for “\(key.shortName)”?"
        intro.informativeText = """
        Anyone with this file plus your passphrase can decrypt every message ever sent to this key. Treat it like a password — never email it, never sync it to a public cloud folder.

        For a long-term offline backup, use Back Up Key… instead. That bundles the secret key, a fresh revocation cert, and your ownertrust in one AES-256 wrapped file.
        """
        intro.addButton(withTitle: "Continue")
        intro.addButton(withTitle: "Cancel")
        guard intro.runModal() == .alertFirstButtonReturn else { return }

        Task {
            await runHelperAction("Export secret key") {
                let armored = try await HelperXPCClient.shared.exportSecretKey(
                    fingerprint: key.fingerprint,
                )
                await saveExportedKey(armored, suggested: "\(key.fingerprint)-secret.asc")
            }
        }
    }

    private func backUpKey(for key: GPGKeyInfo) {
        // Pre-flight alert: the helper triggers two pinentry prompts
        // in sequence and they look superficially identical. Explain
        // up front what the user will be asked for, what they're
        // expected to type, and why. Without this the second prompt
        // can read as "didn't gpg already take my passphrase?".
        let intro = NSAlert()
        intro.alertStyle = .informational
        intro.messageText = "Back Up “\(key.shortName)”"
        intro.informativeText = """
        You'll see two passphrase prompts in a row:

        1. Your existing key passphrase — so gpg can read the secret material.
        2. A new archive passphrase — Alp uses this to AES-256 wrap the backup file.

        Write the archive passphrase down. Without it you cannot restore the backup. Alp never sees either passphrase.
        """
        intro.addButton(withTitle: "Continue")
        intro.addButton(withTitle: "Cancel")
        guard intro.runModal() == .alertFirstButtonReturn else { return }

        Task {
            await runHelperAction("Back up key") {
                // The helper drives two pinentry prompts in sequence:
                // one for the secret-key passphrase (to export), one
                // for the archive passphrase (to symmetric-encrypt the
                // bundle). The plaintext bundle never reaches us — by
                // the time the bytes return, they're already AES-256
                // wrapped.
                let bundle = try await HelperXPCClient.shared.backupKey(
                    fingerprint: key.fingerprint,
                )
                let datestamp = Date.now.formatted(.iso8601.year().month().day())
                await saveExportedKey(
                    bundle,
                    suggested: "alp-backup-\(key.shortName)-\(datestamp).asc",
                )
            }
        }
    }

    private func changePassphrase(for key: GPGKeyInfo) {
        // Pre-flight: same two-prompt confusion as Back Up Key.
        // gpg-agent asks for the current passphrase, then a new one
        // (with confirmation when AlpPinentry honors SETREPEAT).
        let intro = NSAlert()
        intro.alertStyle = .informational
        intro.messageText = "Change passphrase for “\(key.shortName)”"
        intro.informativeText = """
        You'll see two prompts:

        1. The current passphrase for this key.
        2. The new passphrase (with a confirm field).

        Alp never sees either — gpg-agent talks to pinentry directly. If you forget the new passphrase there is no recovery.
        """
        intro.addButton(withTitle: "Continue")
        intro.addButton(withTitle: "Cancel")
        guard intro.runModal() == .alertFirstButtonReturn else { return }

        Task {
            await runHelperAction("Change passphrase") {
                try await HelperXPCClient.shared.changePassphrase(fingerprint: key.fingerprint)
            }
        }
    }

    private func deleteKey(_ request: KeyDeletionRequest) async {
        await runHelperAction(request.secretOnly ? "Delete secret key" : "Delete key") {
            if request.secretOnly {
                try await HelperXPCClient.shared.deleteSecretKey(fingerprint: request.key.fingerprint)
            } else {
                try await HelperXPCClient.shared.deletePublicKey(fingerprint: request.key.fingerprint)
            }
            await vm.refreshKeys()
        }
    }

    /// Wraps any helper RPC with a uniform error surface so a failed call
    /// shows the system alert instead of silently swallowing the throw.
    private func runHelperAction(_ label: String, _ work: @escaping () async throws -> Void) async {
        do {
            try await work()
        } catch {
            actionError = "\(label) failed: \(error.localizedDescription)"
        }
    }

    /// Generate-only revocation cert: produces the cert and saves it to disk
    /// without touching the local key's validity (§5.1).
    private func generateRevocationCert(for key: GPGKeyInfo) {
        Task {
            await runHelperAction("Generate revocation certificate") {
                let cert = try await HelperXPCClient.shared.generateRevocationCertificate(
                    fingerprint: key.fingerprint,
                )
                await saveExportedKey(cert, suggested: "\(key.fingerprint)-revoke.asc")
            }
        }
    }

    @MainActor
    private func saveExportedKey(_ armored: Data, suggested filename: String) async {
        let panel = NSSavePanel()
        panel.title = "Save Exported Key"
        panel.nameFieldStringValue = filename
        panel.allowedContentTypes = [UTType(filenameExtension: "asc")].compactMap(\.self)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            // 0600: secret-key material, backup bundles, and revocation certs
            // are owner-only. Atomic write then explicit chmod — String.write
            // does not guarantee the umask doesn't leave these group/world
            // readable on a misconfigured machine.
            try armored.write(to: url, options: [.atomic])
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path,
            )
        } catch {
            // If the write landed but the chmod failed, the file is sitting at
            // umask permissions with secret-key material in it. Remove it so a
            // "could not write" error never leaves group/world-readable secrets
            // behind.
            try? FileManager.default.removeItem(at: url)
            actionError = "Could not write exported key: \(error.localizedDescription)"
        }
    }
}

// MARK: – OwnerTrust levels

/// gpg's `--import-ownertrust` numeric encoding (RFC 4880 §5.2.3.13). Only
/// the values a user explicitly picks (never / marginal / full / ultimate)
/// are exposed; "unknown" is the implicit default and "undefined" is set
/// programmatically when keys are imported.
enum OwnerTrustLevel: Int, CaseIterable {
    case never = 2
    case marginal = 3
    case full = 4
    case ultimate = 5

    static let userVisible: [OwnerTrustLevel] = [.never, .marginal, .full, .ultimate]

    var title: String {
        switch self {
        case .never: "Never"
        case .marginal: "Marginal"
        case .full: "Full"
        case .ultimate: "Ultimate"
        }
    }
}

// MARK: – Certify Key Sheet

private struct CertifyKeySheet: View {
    let key: GPGKeyInfo
    let signers: [GPGKeyInfo]
    let onConfirm: (_ signerFingerprint: String, _ exportable: Bool) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var signerFingerprint: String?
    @State private var exportable = true
    @State private var isWorking = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Certify Key")
                .font(.title2.weight(.semibold))
            Text(key.displayName)
                .font(.callout)
                .foregroundStyle(.secondary)

            Form {
                Picker("Sign with", selection: $signerFingerprint) {
                    Text("Choose…").tag(String?.none)
                    ForEach(signers) { signer in
                        Text(signer.displayName).tag(Optional(signer.fingerprint))
                    }
                }
                .disabled(isWorking)

                Toggle("Exportable certification", isOn: $exportable)
                    .disabled(isWorking)
            }
            .formStyle(.grouped)

            Text(
                exportable
                    ? "An exportable certification can be uploaded to keyservers and shared with others — use it when you've verified the key out-of-band and want to vouch for it publicly."
                    :
                    "A local certification stays on this Mac. gpg uses it for trust decisions but it is never shared. Pick this if you trust the key for your own use without making a public claim.",
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

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
                Button("Certify") {
                    Task {
                        guard let fp = signerFingerprint else { return }
                        isWorking = true
                        defer { isWorking = false }
                        await onConfirm(fp, exportable)
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(isWorking || signerFingerprint == nil)
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 520)
    }
}

// MARK: – Set Expiry Sheet

private struct SetExpirySheet: View {
    let key: GPGKeyInfo
    let onConfirm: (Int) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var selection: ExpiryOption = .twoYears
    @State private var isWorking = false

    private enum ExpiryOption: String, CaseIterable, Identifiable {
        case oneYear, twoYears, fourYears, never
        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .oneYear: "1 year from now"
            case .twoYears: "2 years from now"
            case .fourYears: "4 years from now"
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
            Text("Set Expiry")
                .font(.title2.weight(.semibold))
            Text(key.displayName)
                .font(.callout)
                .foregroundStyle(.secondary)

            Picker("New expiry", selection: $selection) {
                ForEach(ExpiryOption.allCases) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.inline)
            .labelsHidden()
            .disabled(isWorking)

            Text("gpg-agent will prompt for the passphrase via pinentry.")
                .font(.caption)
                .foregroundStyle(.secondary)

            HStack {
                if isWorking {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isWorking)
                Button("Update Expiry") {
                    Task {
                        isWorking = true
                        defer { isWorking = false }
                        await onConfirm(selection.days)
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(isWorking)
            }
        }
        .padding(20)
        .frame(minWidth: 420, idealWidth: 460)
    }
}

// MARK: – Revoke Key Sheet

private struct RevokeKeySheet: View {
    let key: GPGKeyInfo
    let onConfirm: (Int, String?) async -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var reason: RevocationReason = .superseded
    @State private var description: String = ""
    @State private var isWorking = false

    private enum RevocationReason: Int, CaseIterable, Identifiable {
        case noReason = 0
        case compromised = 1
        case superseded = 2
        case noLongerUsed = 3

        var id: Int {
            rawValue
        }

        var title: String {
            switch self {
            case .noReason: "No reason specified"
            case .compromised: "Key has been compromised"
            case .superseded: "Key is superseded"
            case .noLongerUsed: "Key is no longer used"
            }
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Revoke Key")
                .font(.title2.weight(.semibold))
            Text(key.displayName)
                .font(.callout)
                .foregroundStyle(.secondary)

            Picker("Reason", selection: $reason) {
                ForEach(RevocationReason.allCases) { r in
                    Text(r.title).tag(r)
                }
            }
            .pickerStyle(.menu)
            .disabled(isWorking)

            TextField("Description (optional)", text: $description, axis: .vertical)
                .lineLimit(3, reservesSpace: true)
                .disabled(isWorking)

            Text(
                "Revoking marks this key as no longer valid for signing or encryption. The certificate will also be saved to disk for offline backup. This cannot be undone.",
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            HStack {
                if isWorking {
                    ProgressView().controlSize(.small)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(isWorking)
                Button("Revoke") {
                    Task {
                        isWorking = true
                        defer { isWorking = false }
                        let trimmed = description.trimmingCharacters(in: .whitespacesAndNewlines)
                        await onConfirm(reason.rawValue, trimmed.isEmpty ? nil : trimmed)
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(isWorking)
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 500)
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

/// Compact trust display for the Keys table. Color follows the same logic
/// that drives Set Trust: green for full/ultimate, orange for marginal,
/// red for never, secondary for unknown.
private struct TrustPill: View {
    let trust: OwnerTrust

    var body: some View {
        Text(trust.title)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.15), in: .capsule)
            .foregroundStyle(color)
            .accessibilityLabel("Owner trust: \(trust.title)")
    }

    private var color: Color {
        switch trust {
        case .full, .ultimate: .green
        case .marginal: .orange
        case .never: .red
        case .unknown: .secondary
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
