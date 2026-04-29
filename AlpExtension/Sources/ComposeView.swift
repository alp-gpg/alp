import MailKit
import SwiftUI

struct ComposeView: View {
    @Bindable var vm: ComposeViewModel
    @State private var showingMissingKeys = false

    var body: some View {
        HStack(spacing: 8) {
            Toggle(isOn: $vm.shouldSign) {
                Label("Sign", systemImage: "signature")
                    .symbolEffect(.bounce, value: vm.shouldSign)
            }
            .toggleStyle(.button)
            .tint(.blue)
            .disabled(!vm.canSign)
            .help(vm.canSign ? "" : "No signing key. Add a secret key in Alp → General.")
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
            .help(encryptTooltip)
            .accessibilityLabel("Encrypt message")
            .accessibilityValue(vm.shouldEncrypt ? "On" : "Off")

            if !vm.shouldSign, !vm.shouldEncrypt, vm.missingKeyEmails.isEmpty {
                Text("No GPG")
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
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .glassEffect(.regular, in: .capsule)
        .task { await vm.refresh() }
        .onChange(of: vm.shouldSign) { _, _ in vm.syncStateToStore() }
        .onChange(of: vm.shouldEncrypt) { _, _ in vm.syncStateToStore() }
        .onChange(of: vm.selectedSignerFingerprint) { _, _ in vm.syncStateToStore() }
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
