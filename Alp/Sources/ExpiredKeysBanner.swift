import SwiftUI

struct ExpiredKeysBanner: View {
    let expiredPublishedCount: Int
    let isRunning: Bool
    let onCheckNow: () -> Void
    let onCancel: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: isRunning ? "hourglass" : "exclamationmark.triangle.fill")
                .foregroundStyle(isRunning ? .blue : .orange)
                .font(.title3)

            if isRunning {
                Text("Checking \(expiredPublishedCount) expired keys on keys.openpgp.org…")
                    .font(.callout)
                Spacer()
                Button("Cancel", action: onCancel)
                    .keyboardShortcut(.cancelAction)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(expiredPublishedCount) expired keys")
                        .font(.callout.bold())
                    Text("Alp can check keys.openpgp.org for updates.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Check now", action: onCheckNow)
                    .help(
                        "Sends each expired key's fingerprint to keys.openpgp.org over a certificate-pinned TLS connection.",
                    )
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.yellow.opacity(0.15)),
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(.orange.opacity(0.35), lineWidth: 1),
        )
        .padding(.horizontal)
        .padding(.top, 8)
    }
}
