import Foundation
import Testing

@Suite("GPGSubkey")
struct GPGSubkeyTests {
    @Test
    func `isExpired is false when expiryDate is nil`() {
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "e",
            expiryDate: nil,
            algorithm: "RSA 3072",
            isRevoked: false,
        )
        #expect(sub.isExpired == false)
    }

    @Test
    func `isExpired is true when expiryDate is in the past`() {
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

    @Test
    func `isExpired is false when expiryDate is in the future`() {
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

    @Test
    func `capabilityIcons maps sign/encrypt/auth`() {
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

    @Test
    func `capabilityIcons is empty for unknown capabilities`() {
        let sub = GPGSubkey(
            fingerprint: "A".repeating(40),
            capabilities: "c",
            expiryDate: nil,
            algorithm: nil,
            isRevoked: false,
        )
        #expect(sub.capabilityIcons.isEmpty)
    }

    @Test
    func `id equals fingerprint for Identifiable conformance`() {
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
    func repeating(_ count: Int) -> String {
        String(repeating: self, count: count)
    }
}
