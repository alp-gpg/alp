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
