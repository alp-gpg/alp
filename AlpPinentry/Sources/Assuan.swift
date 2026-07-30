import Foundation

// Pure Assuan protocol logic, kept out of main.swift so it can be compiled into
// the test target — top-level code in main.swift cannot be. Nothing here touches
// AppKit, stdin/stdout, or process state; the I/O loop lives in main.swift.

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

/// Pinentry's button labels carry an `_` underscore accelerator (e.g.
/// `_OK`, `_Cancel`) that's meaningless in Cocoa. Strip it for display.
func stripUnderscoreAccelerator(_ s: String) -> String {
    s.replacingOccurrences(of: "_", with: "")
}

/// Apply a SET* Assuan command to the session state. Pulled out of the
/// main dispatch switch so the loop's cyclomatic complexity stays
/// within budget. Unknown SET* commands are silently acknowledged —
/// the matching OK is emitted by the caller.
func applySetCommand(_ command: String, argument: String, state: inout PinentryState) {
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
