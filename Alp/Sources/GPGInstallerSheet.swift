import AppKit
import SwiftUI

/// Sheet presented from the Setup checklist when the helper reports that gpg
/// is not installed. Offers two paths so the user is never left at a dead
/// end: a Homebrew one-liner (preferred when brew is detected) and a link to
/// gnupg.org's official installer for users who avoid Homebrew.
struct GPGInstallerSheet: View {
    let onDismissOrRecheck: () -> Void

    @Environment(\.dismiss) private var dismiss

    private static let downloadURL: URL = {
        guard let url = URL(string: "https://gnupg.org/download/") else {
            preconditionFailure("hardcoded URL is malformed")
        }
        return url
    }()

    private static let brewPath: String? = {
        let candidates = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Install GnuPG", systemImage: "shippingbox")
                .font(.title2.weight(.semibold))

            Text(
                "Alp drives the system `gpg` binary. macOS doesn't ship one, so a one-time install is required before the rest of the setup checklist can complete.",
            )
            .font(.callout)
            .foregroundStyle(.primary)
            .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 12) {
                if Self.brewPath != nil {
                    homebrewSection
                    Divider()
                }
                downloadSection
                if Self.brewPath == nil {
                    Divider()
                    Text(
                        "Already have a package manager? Install `gnupg` and `pinentry-mac` from MacPorts or Nix and Alp will detect them automatically.",
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack {
                Spacer()
                Button("Done") {
                    onDismissOrRecheck()
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(minWidth: 460, idealWidth: 520)
    }

    private var homebrewSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Install via Homebrew", systemImage: "terminal")
                .font(.callout.weight(.semibold))
            Text(
                "Recommended — also installs `pinentry-mac` so Alp can prompt for passphrases without dropping into Terminal.",
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                Text("brew install gnupg pinentry-mac")
                    .font(.caption.monospaced())
                    .padding(6)
                    .background(.quaternary, in: .rect(cornerRadius: 4))
                    .textSelection(.enabled)

                Spacer()

                Button("Copy") { copyToPasteboard("brew install gnupg pinentry-mac") }
                    .controlSize(.small)
                Button("Open Terminal") { openTerminal() }
                    .controlSize(.small)
                    .buttonStyle(.borderless)
            }
        }
    }

    private func openTerminal() {
        let url = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
        NSWorkspace.shared.open(url)
    }

    private var downloadSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("Download from gnupg.org", systemImage: "globe")
                .font(.callout.weight(.semibold))
            Text(
                "Official installer maintained by the GnuPG team. After installing, return here and tap Recheck on the GPG Environment row.",
            )
            .font(.caption)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            Button("Open gnupg.org/download") {
                NSWorkspace.shared.open(Self.downloadURL)
            }
            .controlSize(.small)
        }
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}
