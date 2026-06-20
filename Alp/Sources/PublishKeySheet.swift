import SwiftUI

/// Publishes a public key to keys.openpgp.org and surfaces the per-UID
/// verification status the server returns. The user has to click links in
/// each verification mail before the key is publicly served — this sheet
/// just kicks the process off and shows what to expect next.
struct PublishKeySheet: View {
    let key: GPGKeyInfo

    @Environment(\.dismiss) private var dismiss
    @State private var phase: Phase = .idle
    @State private var errorMessage: String?

    private enum Phase: Equatable {
        case idle
        case uploading
        case completed(KeyserverUploader.UploadResult)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Publish to keys.openpgp.org", systemImage: "icloud.and.arrow.up")
                .font(.title2.weight(.semibold))

            Text(key.displayName)
                .font(.callout)
                .foregroundStyle(.secondary)

            switch phase {
            case .idle, .uploading:
                explainerSection
            case let .completed(result):
                statusSection(result: result)
            }

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack {
                if case .uploading = phase {
                    ProgressView().controlSize(.small)
                    Text("Uploading…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if case .completed = phase {
                    Button("Done") { dismiss() }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("Cancel") { dismiss() }
                        .keyboardShortcut(.cancelAction)
                        .disabled(phase == .uploading)
                    Button("Publish") { Task { await upload() } }
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                        .disabled(phase == .uploading)
                }
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 520)
    }

    private var explainerSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(
                "Alp will export the public half of this key and POST it to keys.openpgp.org over a certificate-pinned TLS connection. The server replies with a per-UID verification status; you'll get a confirmation email at each address listed below.",
            )
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)

            if !key.emails.isEmpty {
                Text("Verification mail will be sent to:")
                    .font(.caption.weight(.semibold))
                    .padding(.top, 4)
                ForEach(key.emails, id: \.self) { addr in
                    Label(addr, systemImage: "envelope")
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                }
            }

            Text(
                "Click the link in each verification mail to make the address publicly searchable. Until then keys.openpgp.org will only serve the key by fingerprint, not by email.",
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 4)
        }
    }

    private func statusSection(result: KeyserverUploader.UploadResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Upload accepted", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
                .font(.callout.weight(.semibold))
            Text("Verification mail has been sent to each address. Click the link inside to publish that UID.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            ForEach(result.addressStatus.sorted(by: { $0.key < $1.key }), id: \.key) { entry in
                HStack {
                    Image(systemName: icon(for: entry.value))
                        .foregroundStyle(color(for: entry.value))
                    Text(entry.key)
                        .font(.caption.monospaced())
                    Spacer()
                    Text(entry.value)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func icon(for status: String) -> String {
        switch status {
        case "published": "checkmark.circle.fill"
        case "revoked": "xmark.octagon.fill"
        case "pending": "clock"
        default: "envelope.badge"
        }
    }

    private func color(for status: String) -> Color {
        switch status {
        case "published": .green
        case "revoked": .red
        case "pending": .orange
        default: .secondary
        }
    }

    private func upload() async {
        errorMessage = nil
        phase = .uploading
        do {
            let armored = try await HelperXPCClient.shared.exportPublicKey(
                fingerprint: key.fingerprint,
            )
            let result = try await KeyserverUploader.upload(armoredKey: armored)
            // Ask VKS to send verification mail for every UID with a real
            // address. Skip UIDs missing an angle-bracketed email.
            let addresses = key.emails
            if !addresses.isEmpty {
                try await KeyserverUploader.requestVerify(
                    token: result.token, addresses: addresses,
                )
            }
            phase = .completed(result)
        } catch {
            errorMessage = error.localizedDescription
            phase = .idle
        }
    }
}
