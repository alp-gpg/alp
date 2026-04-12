import Foundation
import Testing

@Suite("GPGSubkey")
struct GPGSubkeyTests {
    @Test("isExpired is false when expiryDate is nil")
    func neverExpires() {
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "e",
            expiryDate: nil,
            algorithm: "RSA 3072",
            isRevoked: false,
        )
        #expect(sub.isExpired == false)
    }

    @Test("isExpired is true when expiryDate is in the past")
    func pastExpiry() {
        let past = Date(timeIntervalSinceNow: -3600)
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "e",
            expiryDate: past,
            algorithm: nil,
            isRevoked: false,
        )
        #expect(sub.isExpired == true)
    }

    @Test("isExpired is false when expiryDate is in the future")
    func futureExpiry() {
        let future = Date(timeIntervalSinceNow: 3600)
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "e",
            expiryDate: future,
            algorithm: nil,
            isRevoked: false,
        )
        #expect(sub.isExpired == false)
    }

    @Test("capabilityIcons maps sign/encrypt/auth")
    func iconMapping() {
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "sea",
            expiryDate: nil,
            algorithm: nil,
            isRevoked: false,
        )
        #expect(sub.capabilityIcons.contains("signature"))
        #expect(sub.capabilityIcons.contains("lock"))
        #expect(sub.capabilityIcons.contains("person.badge.key"))
    }

    @Test("capabilityIcons is empty for unknown capabilities")
    func unknownCaps() {
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "c",
            expiryDate: nil,
            algorithm: nil,
            isRevoked: false,
        )
        #expect(sub.capabilityIcons.isEmpty)
    }

    @Test("id equals fingerprint for Identifiable conformance")
    func identifiableId() {
        let fp = "B".repeating(40)
        let sub = GPGSubkey(
            fingerprint: fp,
            capabilities: "",
            expiryDate: nil,
            algorithm: nil,
            isRevoked: false,
        )
        #expect(sub.id == fp)
    }
}

private extension String {
    func repeating(_ count: Int) -> String { String(repeating: self, count: count) }
}
