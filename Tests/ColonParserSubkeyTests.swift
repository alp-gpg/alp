import Foundation
import Testing

@Suite("Colon listing parser — subkeys")
struct ColonParserSubkeyTests {
    @Test("Primary with no subkeys has empty subkeys array")
    func noSubkeys() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        uid:u::::1700000000::DEADBEEF::Alice <a@x>::::::::::0:
        """
        let keys = await helper.testParseColonKeyListing(text)
        #expect(keys.count == 1)
        #expect(keys[0].subkeys.isEmpty)
    }

    @Test("Primary with one encrypt subkey captures fingerprint, caps, expiry, algo")
    func oneSubkey() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        uid:u::::1700000000::DEADBEEF::Alice <a@x>::::::::::0:
        sub:u:3072:1:BBBB2222CCCC3333:1700000000:1900000000:::::e::::::23:
        fpr:::::::::BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666:
        """
        let keys = await helper.testParseColonKeyListing(text)
        #expect(keys.count == 1)
        #expect(keys[0].subkeys.count == 1)
        let sub = keys[0].subkeys[0]
        #expect(sub.fingerprint == "BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666")
        #expect(sub.capabilities == "e")
        #expect(sub.isRevoked == false)
        #expect(sub.algorithm == "RSA 3072")
        #expect(sub.expiryDate != nil)
    }

    @Test("Revoked subkey is marked isRevoked")
    func revokedSubkey() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        sub:r:3072:1:BBBB2222CCCC3333:1700000000:1900000000:::::e::::::23:
        fpr:::::::::BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666:
        """
        let keys = await helper.testParseColonKeyListing(text)
        #expect(keys[0].subkeys.first?.isRevoked == true)
    }

    @Test("Expired subkey under valid primary — primary stays valid")
    func expiredSubkey() async {
        let helper = await GPGHelper()
        let pastTs = String(Int(Date(timeIntervalSinceNow: -86400).timeIntervalSince1970))
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        sub:u:3072:1:BBBB2222CCCC3333:1700000000:\(pastTs):::::e::::::23:
        fpr:::::::::BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666:
        """
        let keys = await helper.testParseColonKeyListing(text)
        #expect(keys[0].isExpired == false)
        #expect(keys[0].subkeys[0].isExpired == true)
    }

    @Test("Multiple subkeys captured in order")
    func multipleSubkeys() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        sub:u:3072:1:BBBB2222CCCC3333:1700000000:1900000000:::::e::::::23:
        fpr:::::::::1111111111111111111111111111111111111111:
        sub:u:255:22:CCCC3333DDDD4444:1700000000:1900000000:::::s:::::ed25519::
        fpr:::::::::2222222222222222222222222222222222222222:
        """
        let keys = await helper.testParseColonKeyListing(text)
        #expect(keys[0].subkeys.count == 2)
        #expect(keys[0].subkeys[0].fingerprint == "1111111111111111111111111111111111111111")
        #expect(keys[0].subkeys[1].fingerprint == "2222222222222222222222222222222222222222")
        #expect(keys[0].subkeys[1].capabilities == "s")
    }

    @Test("Ed25519 subkey uses curve name as algorithm")
    func ed25519Algorithm() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        sub:u:255:22:CCCC3333DDDD4444:1700000000:1900000000:::::s:::::ed25519::
        fpr:::::::::2222222222222222222222222222222222222222:
        """
        let keys = await helper.testParseColonKeyListing(text)
        let algo = keys[0].subkeys.first?.algorithm ?? ""
        #expect(algo.localizedCaseInsensitiveContains("ed25519"))
    }

    @Test("Stub secret key (sec#) still produces a primary")
    func stubSecret() async {
        let helper = await GPGHelper()
        let text = """
        sec:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        uid:u::::1700000000::DEADBEEF::Alice <a@x>::::::::::0:
        ssb:u:3072:1:BBBB2222CCCC3333:1700000000:1900000000:::::e::::::23:
        fpr:::::::::1111111111111111111111111111111111111111:
        """
        let keys = await helper.testParseColonKeyListing(text)
        #expect(keys.count == 1)
        #expect(keys[0].subkeys.count == 1)
    }
}
