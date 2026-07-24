import SwiftUI

struct GeneralSettingsView: View {
    @Bindable var vm: SettingsViewModel
    @Environment(UpdateChecker.self) private var updateChecker

    @State private var showingGPGInstaller = false

    var body: some View {
        Form {
            if !vm.setupComplete {
                setupChecklist
            } else {
                Section("Setup") {
                    Label("All set — Alp is ready to use.", systemImage: "checkmark.seal.fill")
                        .foregroundStyle(.green)
                }
            }

            if vm.helperUnresponsive {
                Section {
                    Label(
                        "The GPG helper stopped responding. Keyserver lookups and GPG operations may fail.",
                        systemImage: "exclamationmark.triangle.fill",
                    )
                    .foregroundStyle(.red)
                    .font(.callout)
                    Button("Reinstall Helper") { vm.installHelper() }
                }
            }

            keysSection

            if vm.pinningDegraded {
                Section {
                    Label(
                        "Keyserver certificate pinning could not be verified. Key lookups are still encrypted (TLS) but the expected certificate has changed. Update Alp when a new version is available.",
                        systemImage: "exclamationmark.shield",
                    )
                    .foregroundStyle(.orange)
                    .font(.callout)
                }
            }

            Section("Keyserver Security") {
                Toggle(isOn: $strictKeyserverPinning) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Strict certificate pinning")
                        Text(
                            "Block keyserver connections when the pinned certificate does not match. Recommended for high-risk environments; may break key lookups if the pinned certificate rotates before Alp is updated.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
                Toggle(isOn: $vm.keyserverPresenceChecks) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Check keys.openpgp.org for each key")
                        Text(
                            "Shows whether each key is published. Turning this off keeps your full contact-key list private — Alp won't query the keyserver on every load.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
            }

            Section("Updates") {
                Toggle(isOn: $automaticUpdateChecks) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text("Automatically check for updates")
                            Image(systemName: "shield.lefthalf.filled")
                                .foregroundStyle(.green)
                                .help("Recommended for security")
                        }
                        Text(
                            "Strongly recommended. Off by default because a security tool should not phone home without consent. Turning this on lets Alp pull cert-pin rotations and helper bug fixes from alp-gpg.github.io as soon as they ship. Alp only notifies you — it never installs anything itself; you download the notarized DMG yourself.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
                .onChange(of: automaticUpdateChecks) { _, on in
                    if on {
                        updateChecker.startAutomaticChecks()
                    } else {
                        updateChecker.stopAutomaticChecks()
                    }
                }

                updateStatusView

                Button {
                    Task { await updateChecker.check(manual: true) }
                } label: {
                    Text(updateChecker.isChecking ? "Checking…" : "Check Now")
                }
                .disabled(updateChecker.isChecking)
            }

            if vm.helperStatus == .enabled, let config = vm.pinentryConfig {
                pinentrySection(config)
            }

            Section("Privacy Limitations") {
                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Drafts are not encrypted")
                            .font(.callout.weight(.semibold))
                        Text(
                            "Mail saves draft messages to the server while you type. Alp only encrypts at send, so drafts reach IMAP/iCloud in plaintext. For any account where you use PGP, disable \"Store drafts on server\" in Mail → Settings → Accounts → Mailbox Behaviors.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "doc.text.magnifyingglass")
                        .foregroundStyle(.orange)
                }

                Label {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Subject lines are not encrypted")
                            .font(.callout.weight(.semibold))
                        Text(
                            "PGP/MIME (RFC 3156) encrypts the message body but not the Subject header. Mail servers and anyone with access to message metadata can read it. Keep sensitive details out of the subject line.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "envelope.badge")
                        .foregroundStyle(.orange)
                }
            }

            Section("Compose Defaults") {
                Toggle("Encrypt to my own key", isOn: $vm.encryptToSelf)
                    .help("Adds your own key as a recipient so you can read your sent encrypted mail.")
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
                    if let fp = vm.defaultSignerFingerprint,
                       let key = vm.secretKeys.first(where: { $0.fingerprint == fp }),
                       key.isExpired
                    {
                        Label(
                            "Selected signing key is expired. Recipients may reject your signature.",
                            systemImage: "exclamationmark.triangle.fill",
                        )
                        .foregroundStyle(.red)
                        .font(.callout)
                    }
                }
            }

            aboutSection
        }
        .formStyle(.grouped)
        .navigationTitle("General")
        .sheet(isPresented: $showingGPGInstaller) {
            GPGInstallerSheet { Task { await vm.refreshHealth() } }
        }
    }

    // MARK: – About

    private var aboutSection: some View {
        Section {
            HStack {
                Text("Alp")
                if Self.isBeta {
                    Text("BETA")
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.orange, in: Capsule())
                }
                Spacer()
                Text("Version \(Self.appVersion)")
                    .foregroundStyle(.secondary)
            }
        } footer: {
            if Self.isBeta {
                Text(
                    "Beta software. Alp handles your private keys and passphrases — keep independent backups and report problems at github.com/alp-gpg/alp/issues.",
                )
            }
        }
    }

    private static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
    }

    /// Pre-1.0 releases are betas; the badge self-removes once a 1.x ships.
    private static var isBeta: Bool {
        (Int(appVersion.split(separator: ".").first ?? "") ?? 0) < 1
    }

    // MARK: – Keys

    private var keysSection: some View {
        GroupBox("Keys") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle(isOn: $autoRefreshExpiredOnShow) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Automatically check keyserver when showing expired keys")
                        Text(
                            "When enabled, Alp will fetch updates from keys.openpgp.org whenever you reveal expired keys. Uses a pinned TLS connection.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(8)
        }
    }

    @AppStorage("autoRefreshExpiredOnShow") private var autoRefreshExpiredOnShow = false

    /// Pinentry section: surfaces the current `gpg-agent.conf` value
    /// and offers a one-click switch to Alp's bundled native pinentry.
    /// Removes the brew dependency on `pinentry-mac` for users who
    /// install it.
    private func pinentrySection(_ config: HelperXPCClient.PinentryConfig) -> some View {
        Section("Pinentry") {
            if config.isAlpPinentry {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Using Alp's built-in pinentry")
                        Text("gpg-agent will prompt for passphrases through Alp.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }
                Button("Stop using Alp Pinentry") {
                    Task { await vm.uninstallAlpPinentry() }
                }
                .controlSize(.small)
            } else {
                VStack(alignment: .leading, spacing: 4) {
                    if let path = config.configuredPath {
                        LabeledContent("Current") {
                            Text(path)
                                .font(.caption.monospaced())
                                .textSelection(.enabled)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } else {
                        Text(
                            "gpg-agent has no `pinentry-program` directive — it falls back to a default search path that often picks the curses pinentry, which can't prompt from a background daemon.",
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    }
                    Text(
                        "Switching to Alp's built-in pinentry removes the need for `brew install pinentry-mac` and gives Alp control over the prompt UI.",
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
                }
                Button("Use Alp Pinentry") {
                    Task { await vm.installAlpPinentry() }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)
            }
        }
    }

    @AppStorage(KeyserverSession.strictPinningDefaultsKey, store: UserDefaults(suiteName: BuildConfig.appGroup))
    private var strictKeyserverPinning = false

    /// Opt-in for the notification-only updater's background checks.
    @AppStorage("AlpAutomaticUpdateChecks") private var automaticUpdateChecks = false

    /// Renders the latest update-check outcome under the Updates toggle.
    @ViewBuilder
    private var updateStatusView: some View {
        switch updateChecker.latestResult {
        case let .updateAvailable(release):
            VStack(alignment: .leading, spacing: 6) {
                Label("Version \(release.version) is available", systemImage: "arrow.down.circle.fill")
                    .foregroundStyle(.blue)
                if !release.notes.isEmpty {
                    Text(release.notes).font(.caption).foregroundStyle(.secondary)
                }
                Text("SHA-256: \(release.sha256)")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                HStack {
                    if let url = URL(string: release.url) {
                        Button("Open Download Page") { NSWorkspace.shared.open(url) }
                            .buttonStyle(.borderedProminent)
                    }
                    Button("Skip This Version") { updateChecker.skip(release) }
                }
                Text("Installed with Homebrew? Run `brew upgrade --cask alp` instead of downloading.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        case .upToDate:
            if updateChecker.lastCheckWasManual {
                Label("You're up to date.", systemImage: "checkmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case let .failed(message):
            Label(message, systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(.orange)
        case nil:
            EmptyView()
        }
    }

    // MARK: – Setup Checklist

    @ViewBuilder
    private var setupChecklist: some View {
        Section("Setup") {
            // Step 1: Helper
            setupRow(
                "Install Helper",
                passed: vm.helperStatus == .enabled,
                detail: helperDetail,
            ) {
                helperAction
            }

            if let error = vm.helperError {
                Text(error)
                    .foregroundStyle(.red)
                    .font(.callout)
            }

            // Step 2: GPG Environment
            if vm.helperStatus == .enabled {
                setupRow(
                    "GPG Environment",
                    passed: vm.healthStatus?.allPassed == true,
                    detail: gpgDetail,
                ) {
                    gpgAction
                }
            }

            // Step 3: Mail Extension
            if vm.helperStatus == .enabled {
                setupRow(
                    "Enable Mail Extension",
                    passed: vm.extensionRecentlySeen,
                    detail: vm.extensionRecentlySeen ? "Active" : "Not detected",
                ) {
                    if !vm.extensionRecentlySeen {
                        Button("Open Mail Extensions Settings") {
                            if let url = URL(string: "x-apple.systempreferences:com.apple.ExtensionsPreferences") {
                                NSWorkspace.shared.open(url)
                            }
                        }
                    }
                }
            }

            // Step 4: Signing Key
            if vm.helperStatus == .enabled, !vm.secretKeys.isEmpty {
                setupRow(
                    "Choose Signing Key",
                    passed: vm.defaultSignerFingerprint != nil,
                    detail: vm.defaultSignerFingerprint != nil
                        ?
                        (vm.secretKeys.first { $0.fingerprint == vm.defaultSignerFingerprint }?
                            .shortName ?? "Selected")
                        : "Not selected",
                ) {
                    if vm.defaultSignerFingerprint == nil {
                        Picker("Key", selection: $vm.defaultSignerFingerprint) {
                            Text("Select a key…").tag(String?.none)
                            ForEach(vm.secretKeys) { key in
                                Text(key.displayName).tag(Optional(key.fingerprint))
                            }
                        }
                        .labelsHidden()
                    }
                }
            }
        }

        // Collapsible GPG health details
        if vm.helperStatus == .enabled, let health = vm.healthStatus, !health.allPassed {
            Section("GPG Details") {
                healthRows(health)
            }
        }
    }

    private var helperDetail: String {
        switch vm.helperStatus {
        case .enabled: "Running"
        case .requiresApproval: "Needs approval in System Settings"
        case .notRegistered: "Not installed"
        default: "Unknown"
        }
    }

    @ViewBuilder
    private var helperAction: some View {
        switch vm.helperStatus {
        case .notRegistered:
            Button("Install") { vm.installHelper() }
        case .requiresApproval:
            Button("Open Login Items") {
                if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                    NSWorkspace.shared.open(url)
                }
            }
        default:
            EmptyView()
        }
    }

    private var gpgDetail: String {
        if vm.isCheckingHealth {
            return "Checking…"
        }
        guard let health = vm.healthStatus else {
            return "Could not connect to helper"
        }
        return health.allPassed ? "All checks passed" : "\(health.issues.count) issue(s)"
    }

    @ViewBuilder
    private var gpgAction: some View {
        if vm.healthStatus?.gpgPath == nil, vm.helperStatus == .enabled, !vm.isCheckingHealth {
            // gpg is not installed at all — offer concrete install paths
            // instead of the generic "Recheck" button which leads nowhere.
            Button("Install GnuPG…") { showingGPGInstaller = true }
        } else if vm.healthStatus?.allPassed != true {
            Button("Recheck") {
                Task { await vm.refreshHealth() }
            }
        }
    }

    // MARK: – Setup Row

    private func setupRow(
        _ title: String,
        passed: Bool,
        detail: String,
        @ViewBuilder action: () -> some View,
    ) -> some View {
        HStack {
            Image(systemName: passed ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(passed ? .green : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            action()
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(passed ? "complete" : "incomplete"), \(detail)")
    }

    // MARK: – Health Rows

    @ViewBuilder
    private func healthRows(_ health: GPGHealthStatus) -> some View {
        checkRow("GnuPG", passed: health.gpgPath != nil, detail: health.gpgPath.map { path in
            "\(path) (\(health.gpgVersion ?? "?"))"
        })
        checkRow("Version ≥ 2.2.14", passed: health.versionSufficient)
        checkRow("gpg-agent", passed: health.agentRunning)
        checkRow("pinentry", passed: health.pinentryConfigured, detail: health.pinentryPath)
        checkRow(
            "Secret keys",
            passed: health.hasSecretKeys,
            detail: health.hasSecretKeys ? "\(health.secretKeyCount) found" : nil,
        )
        checkRow("Trust model (tofu+pgp)", passed: health.tofuSupported)

        if !health.issues.isEmpty {
            ForEach(health.issues, id: \.self) { issue in
                Label(issue, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                    .font(.callout)
            }
        }

        if !health.warnings.isEmpty {
            ForEach(health.warnings, id: \.self) { warning in
                Label(warning, systemImage: "info.circle")
                    .foregroundStyle(.secondary)
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
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(passed ? "passed" : "failed")\(detail.map { ", \($0)" } ?? "")")
    }
}
