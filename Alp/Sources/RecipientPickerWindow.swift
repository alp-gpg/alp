import AppKit
import SwiftUI

/// Modal recipient picker shown when a user invokes the
/// "Encrypt File with Alp…" Service. Surfaces every key in the local
/// keyring with an encrypt-capable primary key, lets the user select one
/// or more recipients, and optionally enables a detached signature using
/// the default signing key.
///
/// The picker runs in a stand-alone borderless-style window because the
/// Service flow may fire when no other Alp window is open. It returns
/// nil when the user cancels.
@MainActor
enum RecipientPickerWindow {
    struct Selection {
        let recipientFingerprints: [String]
        /// Non-nil when the user asked Alp to also sign the encrypted
        /// payload with the default signing key.
        let signerFingerprint: String?
    }

    static func present(keys: [GPGKeyInfo], fileName: String) async -> Selection? {
        await withCheckedContinuation { cont in
            let viewModel = RecipientPickerViewModel(
                keys: keys,
                fileName: fileName,
                defaultSigner: UserDefaults.standard.string(forKey: "defaultSignerFingerprint"),
            )
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 460, height: 460),
                styleMask: [.titled, .closable],
                backing: .buffered,
                defer: false,
            )
            window.title = "Encrypt with Alp"
            window.isReleasedWhenClosed = false
            window.center()

            let resumed = ResumeOnce()
            /// Single completion path. Tearing down contentViewController and the
            /// associated observer here breaks the window → hosting controller →
            /// hosted view → completion-closure → window retain cycle, so the
            /// window (isReleasedWhenClosed = false) doesn't survive every
            /// Encrypt-File service invocation (§3.6).
            func finish(_ selection: RecipientPickerWindow.Selection?) {
                guard resumed.claim() else { return }
                // `finish` is always invoked on the main thread — from the
                // SwiftUI selection callback and from the NSWindowDelegate close
                // handler — but `withCheckedContinuation`'s closure is
                // nonisolated, so the compiler can't see that. Assert it to
                // mutate the main-actor `NSWindow` without a hop.
                MainActor.assumeIsolated {
                    window.orderOut(nil)
                    window.contentViewController = nil
                    window.delegate = nil
                    objc_setAssociatedObject(window, &Self.observerKey, nil, .OBJC_ASSOCIATION_RETAIN)
                }
                cont.resume(returning: selection)
            }
            let view = RecipientPickerView(viewModel: viewModel) { selection in
                finish(selection)
            }
            window.contentViewController = NSHostingController(rootView: view)
            // A window close button (Cmd-W or the red dot) is a cancel. We
            // forward it through the same completion as the explicit Cancel
            // button so the caller doesn't dangle.
            let closeObserver = WindowCloseObserver { finish(nil) }
            window.delegate = closeObserver
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            // Hold a strong reference to the observer so it outlives the
            // current scope — NSWindow.delegate is unowned.
            objc_setAssociatedObject(window, &Self.observerKey, closeObserver, .OBJC_ASSOCIATION_RETAIN)
        }
    }

    private nonisolated(unsafe) static var observerKey: UInt8 = 0
}

@MainActor
@Observable
private final class RecipientPickerViewModel {
    let keys: [GPGKeyInfo]
    let fileName: String
    let defaultSigner: String?
    var selectedRecipients: Set<String> = []
    var signWithDefaultKey: Bool

    init(keys: [GPGKeyInfo], fileName: String, defaultSigner: String?) {
        self.keys = keys
        self.fileName = fileName
        self.defaultSigner = defaultSigner
        // Default to on when the user has configured a signing key — most
        // file-encryption flows want a signature attached.
        signWithDefaultKey = defaultSigner != nil
    }
}

private struct RecipientPickerView: View {
    @Bindable var viewModel: RecipientPickerViewModel
    let onComplete: @MainActor (RecipientPickerWindow.Selection?) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Encrypt \(viewModel.fileName)")
                .font(.headline)
            Text("Pick one or more recipients. Each gets a key packet so any of them can decrypt.")
                .font(.callout)
                .foregroundStyle(.secondary)

            List {
                ForEach(viewModel.keys) { key in
                    Toggle(isOn: Binding(
                        get: { viewModel.selectedRecipients.contains(key.fingerprint) },
                        set: { isOn in
                            if isOn { viewModel.selectedRecipients.insert(key.fingerprint) }
                            else { viewModel.selectedRecipients.remove(key.fingerprint) }
                        },
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(key.displayName).lineLimit(1)
                            Text(key.shortFingerprint)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
            .listStyle(.bordered)
            .frame(minHeight: 240)

            if viewModel.defaultSigner != nil {
                Toggle("Also sign with my default key", isOn: $viewModel.signWithDefaultKey)
            } else {
                Text("Set a default signing key in Settings → General to attach a signature.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            HStack {
                Spacer()
                Button("Cancel") { onComplete(nil) }
                    .keyboardShortcut(.cancelAction)
                Button("Encrypt") {
                    let signer = viewModel.signWithDefaultKey ? viewModel.defaultSigner : nil
                    onComplete(RecipientPickerWindow.Selection(
                        recipientFingerprints: Array(viewModel.selectedRecipients),
                        signerFingerprint: signer,
                    ))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(viewModel.selectedRecipients.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 460, height: 460)
    }
}

/// Bridges an NSWindow `windowWillClose` into a one-shot callback. Used so
/// the Service flow can resume its continuation when the user dismisses
/// the picker without clicking Cancel or Encrypt.
@MainActor
private final class WindowCloseObserver: NSObject, NSWindowDelegate {
    private let onClose: () -> Void

    init(_ onClose: @escaping () -> Void) {
        self.onClose = onClose
    }

    func windowWillClose(_: Notification) {
        onClose()
    }
}

/// Single-shot guard so we never call the continuation twice (cancel
/// button followed by window-close, etc.).
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
