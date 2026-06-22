import AppKit
import Foundation
import os.log

private let log = Logger(subsystem: "app.alp.Alp.pinentry", category: "Pinentry")

// Native Assuan-speaking pinentry for gpg-agent. gpg-agent invokes us as
// a child process and drives the Assuan protocol over stdin/stdout. We
// pop a Cocoa secure-text-field prompt for GETPIN and a yes/no alert for
// CONFIRM. Everything else (SETxxx, OPTION, GETINFO) is acknowledged
// without state change beyond updating our prompt strings.
//
// Protocol reference: <https://www.gnupg.org/documentation/manuals/assuan/Server-responses.html>
// and pinentry's `doc/pinentry.texi` in the gnupg-pinentry source tree.

// MARK: – Assuan codec

/// Assuan command lines are ASCII; values within them are %-encoded so
/// CR / LF / `%` survive the line-oriented protocol.
enum Assuan {
    static func decode(_ s: String) -> String {
        // Decode at the *byte* level then interpret the result as UTF-8 once.
        // A multi-byte sequence like `%C3%A9` is two %-escapes that together
        // form one scalar (é); decoding each escape straight to a Unicode
        // scalar would instead yield "Ã©".
        let utf8 = Array(s.utf8)
        var bytes: [UInt8] = []
        bytes.reserveCapacity(utf8.count)
        var i = 0
        while i < utf8.count {
            if utf8[i] == 0x25, i + 2 < utf8.count, // '%'
               let hi = hexDigit(utf8[i + 1]), let lo = hexDigit(utf8[i + 2])
            {
                bytes.append(hi << 4 | lo)
                i += 3
            } else {
                bytes.append(utf8[i])
                i += 1
            }
        }
        return String(bytes: bytes, encoding: .utf8)
            ?? String(bytes: bytes, encoding: .isoLatin1)
            ?? ""
    }

    private static func hexDigit(_ b: UInt8) -> UInt8? {
        switch b {
        case 0x30 ... 0x39: b - 0x30 // 0-9
        case 0x41 ... 0x46: b - 0x41 + 10 // A-F
        case 0x61 ... 0x66: b - 0x61 + 10 // a-f
        default: nil
        }
    }

    static func encode(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x25, 0x0A, 0x0D: // % LF CR
                out.append(String(format: "%%%02X", scalar.value))
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        return out
    }

    /// Encode `s` for Assuan directly into a mutable byte buffer so the
    /// caller can zero it after writing — avoiding a second String copy
    /// of the passphrase lingering on the heap.
    static func encodeToBytes(_ s: String) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(s.count + 16)
        for scalar in s.unicodeScalars {
            switch scalar.value {
            case 0x25, 0x0A, 0x0D: // % LF CR
                let hex = String(format: "%%%02X", scalar.value)
                out.append(contentsOf: hex.utf8)
            default:
                out.append(contentsOf: String(scalar).utf8)
            }
        }
        return out
    }
}

// MARK: – State

/// Mutable session state collected from SET* commands and consumed by
/// GETPIN / CONFIRM. Value type because we copy snapshots onto the main
/// thread for each prompt; the Assuan loop owns the original.
struct PinentryState {
    var title: String = "Alp"
    var description: String = "Enter passphrase"
    var prompt: String = "Passphrase:"
    var error: String?
    var okLabel: String = "OK"
    var cancelLabel: String = "Cancel"
    /// Set when gpg-agent sends SETREPEAT to request a repeat-field
    /// confirmation flow. nil means no repeat required.
    var repeatPrompt: String?
    /// Inline message gpg-agent supplies via SETREPEATERROR (e.g.
    /// "Passphrases don't match"). Shown only when we re-prompt.
    var repeatError: String?
}

// MARK: – I/O helpers

private let stdoutHandle = FileHandle.standardOutput
private let stdinHandle = FileHandle.standardInput

/// Writes raw bytes to gpg-agent over stdout. Returns false when the pipe is
/// gone — the agent closed the connection because the operation was cancelled,
/// timed out, or already had what it needed. The deprecated `FileHandle.write(_:)`
/// instead raises an ObjC `NSFileHandleOperationException` on EPIPE, which is
/// uncatchable from Swift and aborts the whole process (the crash we saw mid-send).
@discardableResult
private func writeRaw(_ data: Data) -> Bool {
    do {
        try stdoutHandle.write(contentsOf: data)
        return true
    } catch {
        return false
    }
}

private func send(_ line: String) {
    let bytes = (line + "\n").data(using: .utf8) ?? Data()
    // Nothing left to talk to once the agent pipe is closed — exit cleanly
    // rather than crash on the next write.
    if !writeRaw(bytes) { exit(EXIT_FAILURE) }
}

private func sendOK(_ comment: String? = nil) {
    if let comment, !comment.isEmpty {
        send("OK \(comment)")
    } else {
        send("OK")
    }
}

private func sendErr(_ code: Int, _ message: String) {
    send("ERR \(code) \(message)")
}

/// Persistent stdin buffer. The Assuan loop reads one line at a time,
/// but stdin can deliver multiple lines per `availableData` call —
/// without this, every line after the first in a single chunk would be
/// silently discarded.
private nonisolated(unsafe) var stdinBuffer = Data()

/// Reads one CRLF/LF-terminated line from stdin. Returns nil on EOF
/// once the buffer is fully drained.
private func readAssuanLine() -> String? {
    while true {
        if let nl = stdinBuffer.firstIndex(of: 0x0A) {
            let line = stdinBuffer.subdata(in: stdinBuffer.startIndex ..< nl)
            stdinBuffer.removeSubrange(stdinBuffer.startIndex ... nl)
            return String(data: line, encoding: .utf8)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\r"))
        }
        let chunk = stdinHandle.availableData
        if chunk.isEmpty {
            // EOF. Surface any trailing line without a newline, then nil.
            if stdinBuffer.isEmpty { return nil }
            let trailing = String(data: stdinBuffer, encoding: .utf8)
            stdinBuffer.removeAll()
            return trailing
        }
        stdinBuffer.append(chunk)
    }
}

// MARK: – Cocoa prompts (must run on main)

@MainActor
private enum Prompt {
    /// Returns the entered passphrase, or nil when the user cancelled.
    /// When `state.repeatPrompt` is non-nil, the dialog shows a second
    /// secure field and only returns once both fields hold the same
    /// value; mismatches re-prompt inline with `repeatError`.
    static func passphrase(state: PinentryState) -> String? {
        var error = state.error
        while true {
            let alert = NSAlert()
            alert.alertStyle = .informational
            alert.messageText = state.title
            alert.informativeText = errorPrefixed(state.description, error: error)
            alert.addButton(withTitle: state.okLabel)
            alert.addButton(withTitle: state.cancelLabel)

            let primary = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 22))
            primary.placeholderString = state.prompt
            let confirm: NSSecureTextField?
            if let repeatLabel = state.repeatPrompt {
                let field = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 280, height: 22))
                field.placeholderString = repeatLabel
                confirm = field
                // Stack the two fields vertically inside a container so
                // we can present both in the alert's accessoryView slot.
                let stack = NSStackView(views: [primary, field])
                stack.orientation = .vertical
                stack.alignment = .leading
                stack.spacing = 8
                stack.translatesAutoresizingMaskIntoConstraints = false
                stack.frame = NSRect(x: 0, y: 0, width: 280, height: 56)
                alert.accessoryView = stack
            } else {
                confirm = nil
                alert.accessoryView = primary
            }
            alert.window.initialFirstResponder = primary

            bringToFront()
            let response = alert.runModal()
            guard response == .alertFirstButtonReturn else { return nil }

            let value = primary.stringValue
            if let confirm {
                guard value == confirm.stringValue else {
                    // Surface gpg-agent's mismatch message if we got
                    // one, else a sensible English fallback.
                    error = state.repeatError ?? "Passphrases do not match. Try again."
                    continue
                }
            }
            return value
        }
    }

    /// Returns true on Yes, false on No / Cancel.
    static func confirm(state: PinentryState, oneButton: Bool) -> Bool {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = state.title
        alert.informativeText = errorPrefixed(state.description, error: state.error)
        alert.addButton(withTitle: state.okLabel)
        if !oneButton {
            alert.addButton(withTitle: state.cancelLabel)
        }
        bringToFront()
        return alert.runModal() == .alertFirstButtonReturn
    }

    static func message(state: PinentryState) {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = state.title
        alert.informativeText = state.description
        alert.addButton(withTitle: state.okLabel)
        bringToFront()
        _ = alert.runModal()
    }

    private static func errorPrefixed(_ description: String, error: String?) -> String {
        guard let error, !error.isEmpty else { return description }
        return "⚠️ \(error)\n\n\(description)"
    }

    private static func bringToFront() {
        NSApp.activate(ignoringOtherApps: true)
    }
}

// MARK: – Main loop

private func runAssuanLoop() {
    var state = PinentryState()

    sendOK("Pleased to meet you, please come in")

    while let raw = readAssuanLine() {
        let line = raw.trimmingCharacters(in: .whitespaces)
        if line.isEmpty || line.hasPrefix("#") { continue }

        let parts = line.split(separator: " ", maxSplits: 1).map(String.init)
        let command = parts[0].uppercased()
        let argument = parts.count > 1 ? Assuan.decode(parts[1]) : ""

        switch command {
        case "BYE":
            sendOK("closing connection")
            DispatchQueue.main.async { NSApp.terminate(nil) }
            return

        case "RESET", "STOP":
            state.error = nil
            state.repeatPrompt = nil
            state.repeatError = nil
            sendOK()

        case "OPTION":
            // ttytype, lc-ctype, default-* — none affect our Cocoa UI.
            sendOK()

        case "GETINFO":
            switch argument {
            case "version": send("D 1.0.0+alp")
            case "pid": send("D \(getpid())")
            case "flavor": send("D alp")
            default: break
            }
            sendOK()

        case let cmd where cmd.hasPrefix("SET"):
            applySetCommand(cmd, argument: argument, state: &state)
            sendOK()

        case "GETPIN":
            let snapshot = state
            var pin: String?
            DispatchQueue.main.sync { pin = Prompt.passphrase(state: snapshot) }
            if let pin {
                // Build the D line as bytes and zero after writing so the
                // encoded passphrase doesn't linger in a second String on
                // the heap. The source String from NSSecureTextField is
                // still immutable/interred, but this limits the spread.
                var bytes: [UInt8] = Array("D ".utf8)
                bytes.append(contentsOf: Assuan.encodeToBytes(pin))
                bytes.append(0x0A) // \n
                let wrote = writeRaw(Data(bytes))
                bytes.resetBytes(in: 0 ..< bytes.count)
                guard wrote else { exit(EXIT_FAILURE) }
                sendOK()
            } else {
                sendErr(83_886_179, "Operation cancelled")
            }
            // Drop per-prompt state so a subsequent GETPIN does not
            // inherit a SETREPEAT request from the previous call.
            state.error = nil
            state.repeatPrompt = nil
            state.repeatError = nil

        case "CONFIRM":
            let oneButton = argument.contains("--one-button")
            let snapshot = state
            var ok = false
            DispatchQueue.main.sync { ok = Prompt.confirm(state: snapshot, oneButton: oneButton) }
            if ok { sendOK() } else { sendErr(83_886_194, "Not confirmed") }
            state.error = nil

        case "MESSAGE":
            let snapshot = state
            DispatchQueue.main.sync { Prompt.message(state: snapshot) }
            sendOK()

        case "NOP":
            sendOK()

        default:
            // Unknown commands get a soft error so gpg-agent can fall
            // back without aborting the whole flow.
            sendErr(83_886_184, "Unknown command \(command)")
        }
    }
    // EOF: gpg-agent closed stdin without sending BYE.
    DispatchQueue.main.async { NSApp.terminate(nil) }
}

/// Pinentry's button labels carry an `_` underscore accelerator (e.g.
/// `_OK`, `_Cancel`) that's meaningless in Cocoa. Strip it for display.
private func stripUnderscoreAccelerator(_ s: String) -> String {
    s.replacingOccurrences(of: "_", with: "")
}

/// Apply a SET* Assuan command to the session state. Pulled out of the
/// main dispatch switch so the loop's cyclomatic complexity stays
/// within budget. Unknown SET* commands are silently acknowledged —
/// the matching OK is emitted by the caller.
private func applySetCommand(_ command: String, argument: String, state: inout PinentryState) {
    switch command {
    case "SETTITLE":
        state.title = argument.isEmpty ? "Alp" : argument
    case "SETDESC":
        state.description = argument
    case "SETPROMPT":
        state.prompt = argument
    case "SETERROR":
        state.error = argument
    case "SETOK":
        state.okLabel = stripUnderscoreAccelerator(argument)
    case "SETCANCEL":
        state.cancelLabel = stripUnderscoreAccelerator(argument)
    case "SETREPEAT":
        // gpg-agent uses an empty argument or a localized label like
        // "_Re-enter:". Default to "Confirm:" when blank so users see
        // a meaningful placeholder either way.
        state.repeatPrompt = argument.isEmpty ? "Confirm:" : argument
    case "SETREPEATERROR":
        state.repeatError = argument.isEmpty ? nil : argument
    default:
        // SETNOTOK, SETKEYINFO, SETQUALITYBAR, SETQUALITYBAR_TT,
        // SETGENPIN, SETGENPIN_TT, SETTIMEOUT — we don't render quality
        // bars or the generated-pin helper today; ignoring keeps
        // gpg-agent happy.
        break
    }
}

// MARK: – Entry point

/// gpg-agent launches us with no main menu, so the standard editing key
/// equivalents (⌘X/⌘C/⌘V/⌘A) are never routed to the passphrase field's
/// editor — pasting a passphrase from a password manager silently fails.
/// Install a minimal Edit menu so those shortcuts reach the first responder
/// during the modal prompt. Cut/Copy stay harmless: NSSecureTextField's
/// field editor refuses to copy or cut its contents.
@MainActor
private func installEditMenu() {
    let mainMenu = NSMenu()
    let editItem = NSMenuItem()
    mainMenu.addItem(editItem)

    let editMenu = NSMenu(title: "Edit")
    editItem.submenu = editMenu
    editMenu.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    editMenu.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    editMenu.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    editMenu.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

    NSApp.mainMenu = mainMenu
}

// A broken pipe to gpg-agent must surface as a recoverable write error, never
// a SIGPIPE that kills us mid-prompt.
signal(SIGPIPE, SIG_IGN)
NSApplication.shared.setActivationPolicy(.accessory)
installEditMenu()
DispatchQueue.global(qos: .userInitiated).async {
    runAssuanLoop()
}

NSApplication.shared.run()
