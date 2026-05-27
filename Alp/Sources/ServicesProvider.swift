import AppKit
import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp", category: "Services")

/// Provides macOS Services menu entries:
///   * Decrypt with Alp
///   * Verify with Alp
///   * Sign with Alp
///
/// All entries operate on the current text selection: read it from the
/// pasteboard, route through the helper, write the result back. No new
/// windows or sheets — that's the point of Services. Errors surface via a
/// `NSUserNotification`-style banner and a returned `NSString` describing
/// the failure so the user is never silently dropped.
///
/// Encryption is intentionally absent: it requires a recipient list, which
/// is incompatible with the zero-UI Services contract. Use compose for that.
@MainActor
final class ServicesProvider: NSObject {
    static let shared = ServicesProvider()

    /// Wires this provider into AppKit's Services system. Call once from
    /// app startup; Services menu items declared in Info.plist resolve their
    /// `NSPortName` to the registered provider.
    func register() {
        NSApp.servicesProvider = self
        NSUpdateDynamicServices()
    }

    // MARK: – Service entry points

    //
    // The Services protocol passes the pasteboard, an opaque user-data
    // string, and an outparam for an error message. Returning a non-nil
    // error pointer surfaces a small system alert; otherwise the result
    // overwrites the original selection.

    @objc func decryptSelection(
        _ pboard: NSPasteboard,
        userData _: String?,
        error: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        runService(
            input: pboard,
            errorOut: error,
            label: "Decrypt",
        ) { data in
            let (plain, _, _) = try await HelperXPCClient.shared.decrypt(data)
            return plain
        }
    }

    @objc func verifySelection(
        _ pboard: NSPasteboard,
        userData _: String?,
        error: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        runService(input: pboard, errorOut: error, label: "Verify") { data in
            let (valid, signer, name) = try await HelperXPCClient.shared.verify(data)
            // Replace the selection with a one-line status banner. The
            // caller can paste it next to the original message or discard
            // it; we do not rewrite the source selection silently because
            // the user almost certainly wants to keep the signed text.
            let who = name ?? signer ?? "unknown signer"
            let summary = valid ? "✓ Signature valid — \(who)" : "✗ Signature invalid — \(who)"
            return Data(summary.utf8)
        }
    }

    @objc func signSelection(
        _ pboard: NSPasteboard,
        userData _: String?,
        error: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        runService(input: pboard, errorOut: error, label: "Sign") { data in
            guard let signer = UserDefaults.standard.string(forKey: "defaultSignerFingerprint") else {
                throw GPGError.noSigningKey
            }
            return try await HelperXPCClient.shared.clearsign(data, signer: signer)
        }
    }

    // MARK: – File Services

    //
    // File entry points are fire-and-forget: AppKit hands us a file-URL
    // pasteboard, we read it, then drive the rest of the flow ourselves
    // (save panel, helper call, completion alert). The Services error
    // pointer is no use for async results, so we deliberately ignore it
    // and surface every outcome through NSAlert instead.

    @objc nonisolated func decryptFile(
        _ pboard: NSPasteboard,
        userData _: String?,
        error _: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        // NSPasteboard is not Sendable. Read the user-selected file URL
        // synchronously here, then dispatch the rest of the flow onto
        // the main actor with only Sendable values crossing.
        let input = readFirstFileURL(from: pboard)
        Task { @MainActor in
            guard let input else {
                presentAlert(title: "Decrypt File", message: "No file selected.")
                return
            }
            NSApp.activate(ignoringOtherApps: true)
            guard let output = promptSave(
                title: "Save decrypted file",
                defaultName: strippedEncryptedExtensionName(for: input),
                relativeTo: input,
            ) else { return }
            do {
                let (signer, signerName) = try await HelperXPCClient.shared.decryptFile(
                    inputPath: input.path,
                    outputPath: output.path,
                )
                let who = signerName ?? signer
                let suffix = who.map { " (signed by \($0))" } ?? ""
                presentAlert(
                    title: "Decrypted",
                    message: "\(output.lastPathComponent)\(suffix)",
                    reveal: output,
                )
            } catch {
                presentAlert(title: "Decrypt failed", message: error.localizedDescription)
            }
        }
    }

    @objc nonisolated func verifyFile(
        _ pboard: NSPasteboard,
        userData _: String?,
        error _: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        let input = readFirstFileURL(from: pboard)
        Task { @MainActor in
            guard let input else {
                presentAlert(title: "Verify File", message: "No file selected.")
                return
            }
            NSApp.activate(ignoringOtherApps: true)
            // For a detached signature (e.g. report.pdf.sig) gpg resolves
            // the companion data file by stripping .sig/.asc.
            do {
                let (valid, signer, signerName, trust) = try await HelperXPCClient.shared.verifyFile(
                    inputPath: input.path,
                )
                let who = signerName ?? signer ?? "unknown signer"
                // Surface ownertrust only when it adds signal: "ultimate"
                // / "fully" reassure the reader; "marginal" / "never" /
                // "undefined" are warnings worth showing even on a valid
                // signature.
                let trustSuffix = trust.map { " [trust: \($0)]" } ?? ""
                presentAlert(
                    title: valid ? "Signature valid" : "Signature invalid",
                    message: "\(input.lastPathComponent) — \(who)\(trustSuffix)",
                )
            } catch {
                presentAlert(title: "Verify failed", message: error.localizedDescription)
            }
        }
    }

    @objc nonisolated func signFile(
        _ pboard: NSPasteboard,
        userData _: String?,
        error _: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        let input = readFirstFileURL(from: pboard)
        let signer = UserDefaults.standard.string(forKey: "defaultSignerFingerprint")
        Task { @MainActor in
            guard let input else {
                presentAlert(title: "Sign File", message: "No file selected.")
                return
            }
            guard let signer else {
                presentAlert(
                    title: "No signing key",
                    message: "Set a default signing key in Alp Settings → General.",
                )
                return
            }
            NSApp.activate(ignoringOtherApps: true)
            guard let output = promptSave(
                title: "Save signature",
                defaultName: "\(input.lastPathComponent).sig",
                relativeTo: input,
            ) else { return }
            do {
                try await HelperXPCClient.shared.signFile(
                    inputPath: input.path,
                    outputPath: output.path,
                    signer: signer,
                )
                presentAlert(
                    title: "Signed",
                    message: output.lastPathComponent,
                    reveal: output,
                )
            } catch {
                presentAlert(title: "Sign failed", message: error.localizedDescription)
            }
        }
    }

    @objc nonisolated func encryptFile(
        _ pboard: NSPasteboard,
        userData _: String?,
        error _: AutoreleasingUnsafeMutablePointer<NSString?>,
    ) {
        let input = readFirstFileURL(from: pboard)
        Task { @MainActor in
            guard let input else {
                presentAlert(title: "Encrypt File", message: "No file selected.")
                return
            }
            NSApp.activate(ignoringOtherApps: true)
            do {
                let keys = try await HelperXPCClient.shared.listAllKeys()
                // Field-12 capability letters: lowercase = primary itself,
                // uppercase = at least one subkey advertises the cap.
                // Either way the key is a valid encryption recipient.
                let candidates = keys.filter { key in
                    !key.fingerprint.isEmpty
                        && key.capabilities.contains(where: { $0 == "e" || $0 == "E" })
                }
                guard !candidates.isEmpty else {
                    presentAlert(
                        title: "No encryption keys",
                        message: "Import or generate a key with an encrypt capability in the Keys tab first.",
                    )
                    return
                }
                guard let choice = await RecipientPickerWindow.present(
                    keys: candidates,
                    fileName: input.lastPathComponent,
                ) else { return }
                guard let output = promptSave(
                    title: "Save encrypted file",
                    defaultName: "\(input.lastPathComponent).gpg",
                    relativeTo: input,
                ) else { return }
                try await HelperXPCClient.shared.encryptFile(
                    inputPath: input.path,
                    outputPath: output.path,
                    recipients: choice.recipientFingerprints,
                    signer: choice.signerFingerprint,
                )
                presentAlert(
                    title: "Encrypted",
                    message: output.lastPathComponent,
                    reveal: output,
                )
            } catch {
                presentAlert(title: "Encrypt failed", message: error.localizedDescription)
            }
        }
    }

    // MARK: – File Services helpers

    /// Drop one common OpenPGP suffix to suggest a default plaintext
    /// filename. Falls back to the original name with a `.dec` tail when
    /// nothing matches, so the save panel never collides with the source.
    private nonisolated func strippedEncryptedExtensionName(for url: URL) -> String {
        let name = url.lastPathComponent
        for ext in ["gpg", "pgp", "asc"] {
            let dotted = ".\(ext)"
            if name.lowercased().hasSuffix(dotted) {
                return String(name.dropLast(dotted.count))
            }
        }
        return "\(name).dec"
    }

    private nonisolated func readFirstFileURL(from pboard: NSPasteboard) -> URL? {
        let options: [NSPasteboard.ReadingOptionKey: Any] = [.urlReadingFileURLsOnly: true]
        return (pboard.readObjects(forClasses: [NSURL.self], options: options) as? [URL])?.first
    }

    @MainActor
    private func promptSave(title: String, defaultName: String, relativeTo input: URL) -> URL? {
        let panel = NSSavePanel()
        panel.title = title
        panel.nameFieldStringValue = defaultName
        panel.directoryURL = input.deletingLastPathComponent()
        panel.canCreateDirectories = true
        // .OK == 1; modal returns .cancel when the user backs out.
        return panel.runModal() == .OK ? panel.url : nil
    }

    @MainActor
    private func presentAlert(title: String, message: String, reveal: URL? = nil) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = .informational
        if let reveal {
            alert.addButton(withTitle: "Show in Finder")
            alert.addButton(withTitle: "OK")
            let response = alert.runModal()
            if response == .alertFirstButtonReturn {
                NSWorkspace.shared.activateFileViewerSelecting([reveal])
            }
        } else {
            alert.addButton(withTitle: "OK")
            _ = alert.runModal()
        }
    }

    // MARK: – Private

    /// Reads UTF-8 text from `input`, awaits `transform`, writes the result
    /// back to `input`, and routes any thrown error through the AppKit
    /// Services error pointer. Synchronous on the calling thread by design —
    /// the Services protocol does not await a return value.
    private nonisolated func runService(
        input pboard: NSPasteboard,
        errorOut: AutoreleasingUnsafeMutablePointer<NSString?>,
        label: String,
        transform: @Sendable @escaping (Data) async throws -> Data,
    ) {
        guard let text = pboard.string(forType: .string), !text.isEmpty else {
            errorOut.pointee = "Alp: no text selected" as NSString
            return
        }
        let inputData = Data(text.utf8)

        let result: Result<Data, Error> = blockingAwait {
            do { return try await .success(transform(inputData)) }
            catch { return .failure(error) }
        }

        switch result {
        case let .success(output):
            guard let outputString = String(data: output, encoding: .utf8) else {
                errorOut.pointee = "Alp: \(label) result was not UTF-8 text" as NSString
                return
            }
            pboard.clearContents()
            pboard.setString(outputString, forType: .string)
        case let .failure(error):
            log.error("Service \(label, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            errorOut.pointee = "Alp \(label) failed: \(error.localizedDescription)" as NSString
        }
    }
}

/// Bridges an async closure into the synchronous AppKit Services callback.
/// `DispatchSemaphore` is the sanctioned pattern for this exact case: the
/// caller's thread is not the main thread (AppKit dispatches Services on a
/// dedicated queue) so blocking it does not freeze the UI.
private func blockingAwait<T: Sendable>(_ work: @Sendable @escaping () async -> T) -> T {
    let sema = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var output: T?
    Task.detached {
        output = await work()
        sema.signal()
    }
    sema.wait()
    // swiftlint:disable:next force_unwrapping
    return output!
}
