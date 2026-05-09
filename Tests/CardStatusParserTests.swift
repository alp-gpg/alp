import Foundation
import Testing

@Suite("GPG card-status colon parser")
struct CardStatusParserTests {
    @Test
    func `empty input yields a not-present card`() {
        let card = GPGHelper.parseCardStatusColons("")
        #expect(!card.isPresent)
        #expect(card.manufacturer == nil)
        #expect(card.serial == nil)
    }

    @Test
    func `parses YubiKey-shaped output end to end`() {
        let raw = """
        Reader:1050:0407:0001:Yubico YubiKey OTP+FIDO+CCID 00 00:0:
        version:0303
        vendor:0006:Yubico
        serial:0F123456
        name:Doe<<John
        lang:en
        sex:m
        url:
        login:
        forcepin:1:::
        keyattr:1:1:4096:::
        keyattr:2:1:4096:::
        keyattr:3:18:ed25519:::
        maxpinlen:127:127:127
        pinretry:3:0:3:3:3:3
        sigcount:5
        kdf:off
        uif:0:0:0
        cafpr::::
        fpr:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:::
        """
        let card = GPGHelper.parseCardStatusColons(raw)
        #expect(card.isPresent)
        #expect(card.manufacturer == "Yubico")
        #expect(card.serial == "0F123456")
        #expect(card.cardholderName == "Doe John")
        #expect(card.version == "3.3")
        // pinretry produces 6 numbers on a YubiKey (counters + max).
        // The view treats the leading triple as user / reset / admin.
        #expect(card.pinRetriesLeft.prefix(3) == [3, 0, 3])
        #expect(card.keyFingerprints == [
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        ])
        #expect(card.keyAlgorithms[0] == "RSA 4096")
        #expect(card.keyAlgorithms[1] == "RSA 4096")
        #expect(card.keyAlgorithms[2] == "Ed25519")
    }

    @Test
    func `version padding handles short hex strings`() {
        // gpg pads to 4 hex chars for OpenPGP cards; our parser tolerates
        // shorter strings just in case a card omits the padding.
        let raw = "version:31\n"
        let card = GPGHelper.parseCardStatusColons(raw)
        #expect(card.version == "31.0")
    }

    @Test
    func `missing fingerprints decode as empty strings`() {
        let raw = """
        vendor:0006:Yubico
        fpr::::
        """
        let card = GPGHelper.parseCardStatusColons(raw)
        #expect(card.keyFingerprints == ["", "", ""])
    }
}
