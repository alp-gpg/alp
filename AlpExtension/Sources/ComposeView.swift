import MailKit
import SwiftUI

struct ComposeView: View {
    @Bindable var vm: ComposeViewModel
    @State private var showingMissingKeys = false
    @State private var showingPrivacyTips = false

    var body: some View {
        HStack(spacing: 8) {
            Toggle(isOn: $vm.shouldSign) {
                Label("Sign", systemImage: "signature")
                    .symbolEffect(.bounce, value: vm.shouldSign)
            }
            .toggleStyle(.button)
            .tint(.blue)
            .disabled(!vm.canSign)
            .keyboardShortcut("s", modifiers: [.shift, .command])
            .help(vm.canSign ? "Sign message (⇧⌘S)" : "No signing key. Add a secret key in Alp → General.")
            .accessibilityLabel("Sign message")
            .accessibilityValue(vm.shouldSign ? "On" : "Off")

            if vm.shouldSign, vm.availableSecretKeys.count > 1 {
                keyPickerMenu
            }

            Divider().frame(height: 16).opacity(0.5)

            Toggle(isOn: $vm.shouldEncrypt) {
                Label("Encrypt", systemImage: "lock.fill")
                    .symbolEffect(.variableColor, value: vm.shouldEncrypt)
            }
            .toggleStyle(.button)
            .tint(.green)
            .disabled(!vm.canEncrypt)
            .keyboardShortcut("e", modifiers: [.shift, .command])
            .help(vm.canEncrypt ? "Encrypt message (⇧⌘E)" : encryptTooltip)
            .accessibilityLabel("Encrypt message")
            .accessibilityValue(vm.shouldEncrypt ? "On" : "Off")

            if !vm.shouldSign, !vm.shouldEncrypt, vm.missingKeyEmails.isEmpty {
                Text("Plaintext")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            if !vm.missingKeyEmails.isEmpty {
                Button {
                    showingMissingKeys.toggle()
                } label: {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
                .buttonStyle(.plain)
                .help("Missing keys for \(vm.missingKeyEmails.count) recipient(s) — click for details")
                .accessibilityLabel("Missing keys warning")
                .accessibilityHint("Missing public keys for \(vm.missingKeyEmails.count) recipients")
                .popover(isPresented: $showingMissingKeys, arrowEdge: .bottom) {
                    MissingKeysView(emails: vm.missingKeyEmails) {
                        await vm.refresh()
                    }
                }
            }

            if vm.shouldEncrypt || vm.shouldSign {
                Toggle(isOn: $vm.useInlinePGP) {
                    Text("Inline")
                        .font(.caption)
                }
                .toggleStyle(.button)
                .controlSize(.mini)
                .keyboardShortcut("i", modifiers: [.shift, .command])
                .help(
                    "Send as inline ASCII-armor (RFC 4880) for legacy recipients. Falls back to PGP/MIME for messages with attachments. ⇧⌘I",
                )
                .accessibilityLabel("Inline PGP")
                .accessibilityValue(vm.useInlinePGP ? "On" : "Off")
            }

            if vm.shouldEncrypt {
                Button {
                    showingPrivacyTips.toggle()
                } label: {
                    Image(systemName: "info.circle")
                        .foregroundStyle(.secondary)
                }
                .buttonStyle(.plain)
                .help("Privacy limits of PGP encryption — click for details")
                .accessibilityLabel("Encryption privacy notes")
                .popover(isPresented: $showingPrivacyTips, arrowEdge: .bottom) {
                    PrivacyTipsView()
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .glassEffect(.regular, in: .capsule)
        .task { await vm.refresh() }
        .onChange(of: vm.shouldSign) { _, _ in vm.syncStateToStore() }
        .onChange(of: vm.shouldEncrypt) { _, _ in vm.syncStateToStore() }
        .onChange(of: vm.selectedSignerFingerprint) { _, _ in vm.syncStateToStore() }
        .onChange(of: vm.useInlinePGP) { _, _ in vm.syncStateToStore() }
    }

    private var encryptTooltip: String {
        if vm.canEncrypt { return "" }
        if !vm.missingKeyEmails.isEmpty {
            return "Missing public keys for \(vm.missingKeyEmails.count) recipient(s)"
        }
        return "Add recipients to enable encryption"
    }

    private var keyPickerMenu: some View {
        Menu {
            ForEach(vm.availableSecretKeys) { key in
                Button {
                    vm.selectedSignerFingerprint = key.fingerprint
                } label: {
                    if vm.selectedSignerFingerprint == key.fingerprint {
                        Label(key.shortName, systemImage: "checkmark")
                    } else {
                        Text(key.shortName)
                    }
                }
            }
        } label: {
            HStack(spacing: 2) {
                Text(vm.selectedKey?.shortName ?? "Key")
                    .font(.caption)
                    .lineLimit(1)
                Image(systemName: "chevron.up.chevron.down")
                    .font(.caption2)
            }
            .foregroundStyle(.secondary)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }
}

// MARK: – Privacy tips popover

private struct PrivacyTipsView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("What encryption does not protect", systemImage: "info.circle.fill")
                .font(.headline)
                .foregroundStyle(.blue)

            VStack(alignment: .leading, spacing: 4) {
                Label("Subject lines are visible", systemImage: "envelope.badge")
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(
                    "PGP/MIME does not encrypt the Subject header. Mail servers in transit can read it — keep sensitive details out of the subject.",
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 4) {
                Label("Drafts may be uploaded in plaintext", systemImage: "doc.text.magnifyingglass")
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(
                    "Mail saves drafts to the server as you type. Encryption only happens at send. Disable \"Store drafts on server\" for accounts you use with PGP — Mail → Settings → Accounts → Mailbox Behaviors.",
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding()
        .frame(minWidth: 320, maxWidth: 420)
    }
}

// MARK: – Missing keys popover

private struct MissingKeysView: View {
    let emails: [String]
    let onImported: () async -> Void

    @State private var states: [String: RowState] = [:]

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Missing Public Keys", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)

            Text("Encryption is disabled until all recipients have public keys.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            ForEach(emails, id: \.self) { email in
                EmailRow(email: email, state: states[email] ?? .idle) { action in
                    await handle(action, for: email)
                }
            }
        }
        .padding()
        .frame(minWidth: 300, maxWidth: 420)
    }

    private func handle(_ action: EmailRow.Action, for email: String) async {
        switch action {
        case .copy:
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(email, forType: .string)

        case .findKey:
            states[email] = .searching
            do {
                let armoredKey = try await KeyserverClient.fetch(email: email)
                let preview = await (try? GPGXPCClient.shared.previewKey(armoredKey)) ?? []
                states[email] = .found(armoredKey: armoredKey, preview: preview)
            } catch KeyserverClient.Error.notFound {
                states[email] = .notFound
            } catch {
                states[email] = .searchError(error.localizedDescription)
            }

        case let .import(armoredKey):
            states[email] = .importing
            do {
                _ = try await GPGXPCClient.shared.importKey(armoredKey)
                states[email] = .imported
                await onImported()
            } catch {
                states[email] = .importError(error.localizedDescription)
            }

        case .reset:
            states[email] = .idle
        }
    }
}

private enum RowState {
    case idle
    case searching
    case found(armoredKey: Data, preview: [GPGKeyInfo])
    case notFound
    case searchError(String)
    case importing
    case imported
    case importError(String)
}

private struct EmailRow: View {
    enum Action { case copy, findKey, `import`(Data), reset }

    let email: String
    let state: RowState
    let perform: (Action) async -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(email)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                Spacer()
                controls
            }
            detail
        }
    }

    @ViewBuilder
    private var controls: some View {
        switch state {
        case .idle:
            HStack(spacing: 6) {
                Button("Copy") { Task { await perform(.copy) } }
                    .buttonStyle(.borderless).font(.caption).foregroundStyle(.secondary)
                Button("Find Key") { Task { await perform(.findKey) } }
                    .buttonStyle(.bordered).controlSize(.mini).font(.caption)
            }
        case .searching, .importing:
            ProgressView().controlSize(.mini)
        case let .found(key, _):
            HStack(spacing: 6) {
                Button("Cancel") { Task { await perform(.reset) } }
                    .buttonStyle(.borderless).controlSize(.mini).font(.caption)
                Button("Import") { Task { await perform(.import(key)) } }
                    .buttonStyle(.borderedProminent).controlSize(.mini).font(.caption)
            }
        case .imported:
            Label("Imported", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green).font(.caption)
        case .notFound, .searchError, .importError:
            Button("Retry") { Task { await perform(.reset) } }
                .buttonStyle(.borderless).controlSize(.mini).font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch state {
        case let .found(_, preview):
            if let key = preview.first {
                VStack(alignment: .leading, spacing: 2) {
                    Text(key.displayName)
                        .font(.caption).foregroundStyle(.primary)
                    Text(key.shortFingerprint)
                        .font(.caption2.monospaced()).foregroundStyle(.secondary)
                }
                .padding(.leading, 4)
            }
        case .notFound:
            Text("No key found on keys.openpgp.org")
                .font(.caption).foregroundStyle(.secondary)
        case let .searchError(msg):
            Text(msg).font(.caption).foregroundStyle(.red)
        case let .importError(msg):
            Text(msg).font(.caption).foregroundStyle(.red)
        default:
            EmptyView()
        }
    }
}

// MARK: – Keyserver HTTP client

private enum KeyserverClient {
    enum Error: Swift.Error, LocalizedError {
        case notFound
        case httpError(Int)
        case networkError(Swift.Error)

        var errorDescription: String? {
            switch self {
            case .notFound:
                return "No key found on keys.openpgp.org"
            case let .httpError(code):
                return "Keyserver returned error \(code)"
            case let .networkError(inner):
                let nsError = inner as NSError
                switch nsError.code {
                case NSURLErrorNotConnectedToInternet, NSURLErrorNetworkConnectionLost:
                    return "No internet connection"
                case NSURLErrorTimedOut, NSURLErrorCannotConnectToHost, NSURLErrorCannotFindHost:
                    return "Keyserver unreachable — keys.openpgp.org may be down"
                case NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot:
                    return "Keyserver certificate error — connection blocked for safety"
                default:
                    return nsError.localizedDescription
                }
            }
        }
    }

    static func fetch(email: String) async throws -> Data {
        // Sources are tried in priority order; first hit wins. The order
        // is: pinned keys.openpgp.org → WKD (advanced + direct) → Proton's
        // PKS endpoint → the HKPS pool. Each hop falls through on
        // `notFound`; the rest of the network errors propagate so users
        // see actionable messages instead of silent failure.
        var lastNetworkError: Swift.Error?
        for source in fallbackOrder {
            do {
                return try await source.fetch(email)
            } catch Error.notFound {
                continue
            } catch let Error.networkError(inner) {
                lastNetworkError = inner
                continue
            } catch let Error.httpError(code) where (400 ... 499).contains(code) {
                continue
            }
        }
        if let lastNetworkError {
            throw Error.networkError(lastNetworkError)
        }
        throw Error.notFound
    }

    /// Each fallback is independent; failure surfaces as one of the
    /// canonical `Error` cases so the outer dispatcher can decide whether
    /// to keep trying.
    struct Source {
        let label: String
        let fetch: @Sendable (_ email: String) async throws -> Data
    }

    private static var fallbackOrder: [Source] {
        [
            Source(label: "keys.openpgp.org", fetch: fetchOpenPGPDirectory),
            Source(label: "WKD", fetch: fetchWKD),
            Source(label: "proton.me", fetch: fetchProton),
            Source(label: "HKPS pool", fetch: fetchHKPSPool),
        ]
    }

    private static let openSession: URLSession = .makeWKDSession()

    private static func fetchWKD(email: String) async throws -> Data {
        do {
            return try await WKDClient.fetch(email: email)
        } catch WKDClient.Error.notFound, WKDClient.Error.malformedEmail {
            throw Error.notFound
        } catch let WKDClient.Error.networkError(inner) {
            throw Error.networkError(inner)
        } catch let WKDClient.Error.httpError(code) {
            throw Error.httpError(code)
        } catch WKDClient.Error.responseTooLarge {
            throw Error.httpError(0)
        }
    }

    private static func fetchProton(email: String) async throws -> Data {
        try await fetchPKSLookup(host: "api.protonmail.ch", email: email, session: openSession)
    }

    private static func fetchHKPSPool(email: String) async throws -> Data {
        try await fetchPKSLookup(host: "keyserver.ubuntu.com", email: email, session: openSession)
    }

    private static func fetchPKSLookup(
        host: String,
        email: String,
        session: URLSession,
    ) async throws -> Data {
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.path = "/pks/lookup"
        components.queryItems = [
            URLQueryItem(name: "op", value: "get"),
            URLQueryItem(name: "options", value: "mr"),
            URLQueryItem(name: "search", value: email),
        ]
        guard let url = components.url, url.scheme == "https" else {
            throw Error.notFound
        }
        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(from: url)
        } catch {
            throw Error.networkError(error)
        }
        guard let http = response as? HTTPURLResponse else { throw Error.notFound }
        switch http.statusCode {
        case 200:
            // Some PKS hosts return 200 with an HTML "no key found" page.
            // The `mr` (machine-readable) option asks for a raw armored
            // body; if it's not armored, treat as notFound rather than
            // attempting to import HTML as a key.
            let prefix = data.prefix(64)
            guard prefix.contains("-----BEGIN PGP".utf8.first ?? 0),
                  let head = String(data: prefix, encoding: .utf8),
                  head.contains("-----BEGIN PGP")
            else {
                throw Error.notFound
            }
            return data
        case 404:
            throw Error.notFound
        default:
            throw Error.httpError(http.statusCode)
        }
    }

    private static func fetchOpenPGPDirectory(email: String) async throws -> Data {
        // Build with URLComponents so scheme and host are fixed — a crafted
        // email cannot introduce a new host or additional path segments.
        guard let encoded = email.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) else {
            throw Error.notFound
        }
        var components = URLComponents()
        components.scheme = "https"
        components.host = "keys.openpgp.org"
        components.percentEncodedPath = "/vks/v1/by-email/" + encoded
        guard let url = components.url, url.scheme == "https" else {
            throw Error.notFound
        }

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await KeyserverSession.shared.data(from: url)
        } catch {
            throw Error.networkError(error)
        }

        guard let http = response as? HTTPURLResponse else { throw Error.notFound }
        switch http.statusCode {
        case 200: return data
        case 404: throw Error.notFound
        default: throw Error.httpError(http.statusCode)
        }
    }
}
