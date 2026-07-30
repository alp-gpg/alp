import Foundation
import Testing

// Tests for AlpPinentry's Assuan wire codec. This is the only path a passphrase
// travels between the user and gpg-agent, and a codec bug corrupts it silently:
// the key just stops unlocking, with no error pointing here. Everything below
// uses synthetic strings — never a real passphrase.

@Suite("Assuan percent-decoding")
struct AssuanDecodeTests {
    @Test
    func `decodes a multi-byte escape as one scalar, not two`() {
        // The documented bug this codec exists to avoid: decoding each escape
        // straight to a Unicode scalar yields "Ã©" (mojibake) instead of "é".
        // Any passphrase with a non-ASCII character depends on this.
        #expect(Assuan.decode("caf%C3%A9") == "café")
        #expect(Assuan.decode("%E2%82%AC") == "€")
        #expect(Assuan.decode("%F0%9F%94%91") == "🔑")
    }

    @Test
    func `decodes the three escapes the protocol requires`() {
        #expect(Assuan.decode("%25") == "%")
        #expect(Assuan.decode("%0A") == "\n")
        #expect(Assuan.decode("%0D") == "\r")
    }

    @Test
    func `accepts lowercase hex digits`() {
        // gpg-agent emits uppercase, but the protocol permits either and a
        // half-implemented table would mangle only some inputs.
        #expect(Assuan.decode("%c3%a9") == "é")
        #expect(Assuan.decode("%0a") == "\n")
    }

    @Test
    func `passes through text with nothing to decode`() {
        #expect(Assuan.decode("Enter passphrase:") == "Enter passphrase:")
        #expect(Assuan.decode("") == "")
    }

    @Test
    func `leaves malformed escapes alone instead of dropping bytes`() {
        // A truncated or invalid escape must survive verbatim. Swallowing it
        // would silently shorten a passphrase containing a literal '%'.
        #expect(Assuan.decode("abc%") == "abc%")
        #expect(Assuan.decode("abc%C") == "abc%C")
        #expect(Assuan.decode("%ZZ") == "%ZZ")
        #expect(Assuan.decode("100%") == "100%")
    }

    @Test
    func `decodes an escape sitting at the very end of the line`() {
        // Boundary on the `i + 2 < count` index check: the last three bytes
        // being a complete escape is legal and must still decode.
        #expect(Assuan.decode("ab%25") == "ab%")
        #expect(Assuan.decode("%41") == "A")
    }
}

@Suite("Assuan percent-encoding")
struct AssuanEncodeTests {
    @Test
    func `escapes only percent, LF and CR`() {
        // Over-escaping is as bad as under-escaping: gpg-agent would receive a
        // passphrase that is not the one the user typed.
        #expect(Assuan.encode("%") == "%25")
        #expect(Assuan.encode("\n") == "%0A")
        #expect(Assuan.encode("\r") == "%0D")
        #expect(Assuan.encode("café") == "café")
        #expect(Assuan.encode("plain text") == "plain text")
    }

    @Test
    func `round-trips through decode unchanged`() {
        for sample in ["", "plain", "100%", "a%b%%c", "line\nbreak", "cr\rlf\n",
                       "café € 🔑", "%25", "%0A", "tab\tand spaces"]
        {
            #expect(Assuan.decode(Assuan.encode(sample)) == sample, "round trip failed")
        }
    }

    @Test
    func `encodeToBytes matches encode byte for byte`() {
        // encodeToBytes exists so the caller can zero the buffer after writing;
        // it is a second implementation of the same rule and must not drift.
        for sample in ["", "plain", "100%", "café € 🔑", "line\nbreak", "cr\rlf"] {
            #expect(Assuan.encodeToBytes(sample) == Array(Assuan.encode(sample).utf8))
        }
    }
}

@Suite("Assuan SET* command handling")
struct AssuanSetCommandTests {
    @Test
    func `strips the underscore accelerator from button labels`() {
        // Pinentry labels carry a `_` mnemonic that Cocoa does not understand.
        var state = PinentryState()
        applySetCommand("SETOK", argument: "_OK", state: &state)
        applySetCommand("SETCANCEL", argument: "_Cancel", state: &state)
        #expect(state.okLabel == "OK")
        #expect(state.cancelLabel == "Cancel")
    }

    @Test
    func `defaults the repeat prompt when gpg-agent sends no label`() {
        var state = PinentryState()
        applySetCommand("SETREPEAT", argument: "", state: &state)
        #expect(state.repeatPrompt == "Confirm:")

        var labelled = PinentryState()
        applySetCommand("SETREPEAT", argument: "Re-enter:", state: &labelled)
        #expect(labelled.repeatPrompt == "Re-enter:")
    }

    @Test
    func `treats an empty repeat error as no error`() {
        var state = PinentryState()
        applySetCommand("SETREPEATERROR", argument: "", state: &state)
        #expect(state.repeatError == nil)

        applySetCommand("SETREPEATERROR", argument: "Passphrases do not match", state: &state)
        #expect(state.repeatError == "Passphrases do not match")
    }

    @Test
    func `falls back to the app name for an empty title`() {
        var state = PinentryState()
        applySetCommand("SETTITLE", argument: "", state: &state)
        #expect(state.title == "Alp")

        applySetCommand("SETTITLE", argument: "Unlock", state: &state)
        #expect(state.title == "Unlock")
    }

    @Test
    func `ignores SET commands it does not render`() {
        // SETQUALITYBAR and friends must be accepted silently — the caller
        // still emits OK — without disturbing any prompt string.
        var state = PinentryState()
        let before = state
        for command in ["SETQUALITYBAR", "SETKEYINFO", "SETNOTOK", "SETGENPIN", "SETTIMEOUT"] {
            applySetCommand(command, argument: "whatever", state: &state)
        }
        #expect(state.title == before.title)
        #expect(state.description == before.description)
        #expect(state.prompt == before.prompt)
        #expect(state.okLabel == before.okLabel)
        #expect(state.cancelLabel == before.cancelLabel)
        #expect(state.repeatPrompt == nil)
        #expect(state.repeatError == nil)
    }

    @Test
    func `records the prompt strings gpg-agent supplies`() {
        var state = PinentryState()
        applySetCommand("SETDESC", argument: "Please unlock the key", state: &state)
        applySetCommand("SETPROMPT", argument: "Passphrase:", state: &state)
        applySetCommand("SETERROR", argument: "Bad passphrase", state: &state)
        #expect(state.description == "Please unlock the key")
        #expect(state.prompt == "Passphrase:")
        #expect(state.error == "Bad passphrase")
    }
}
