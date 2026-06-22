import Foundation
import Testing

struct GPGHealthStatusTests {
    @Test
    func `allPassed is true when every check passes`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/opt/homebrew/bin/gpg"
        status.gpgVersion = "2.4.7"
        status.versionSufficient = true
        status.agentRunning = true
        status.pinentryConfigured = true
        status.pinentryPath = "/opt/homebrew/bin/pinentry-mac"
        status.hasSecretKeys = true
        status.secretKeyCount = 2
        status.tofuSupported = true
        #expect(status.allPassed)
        #expect(status.issues.isEmpty)
    }

    @Test
    func `allPassed is false when gpg not found`() {
        let status = GPGHealthStatus()
        #expect(!status.allPassed)
        #expect(status.issues.contains { $0.contains("GnuPG not found") })
    }

    @Test
    func `allPassed is false when version too old`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/usr/bin/gpg"
        status.gpgVersion = "2.0.1"
        status.versionSufficient = false
        #expect(!status.allPassed)
        #expect(status.issues.contains { $0.contains("too old") })
    }

    @Test
    func `issues reports agent not running`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/usr/bin/gpg"
        status.versionSufficient = true
        #expect(status.issues.contains { $0.contains("gpg-agent") })
    }

    @Test
    func `issues reports pinentry not configured`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/usr/bin/gpg"
        status.versionSufficient = true
        status.agentRunning = true
        #expect(status.issues.contains { $0.contains("pinentry") })
    }

    @Test
    func `issues reports no secret keys`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/usr/bin/gpg"
        status.versionSufficient = true
        status.agentRunning = true
        status.pinentryConfigured = true
        #expect(status.issues.contains { $0.contains("No secret keys") })
    }

    @Test
    func `issues reports tofu not supported`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/usr/bin/gpg"
        status.versionSufficient = true
        status.agentRunning = true
        status.pinentryConfigured = true
        status.hasSecretKeys = true
        #expect(status.issues.contains { $0.contains("tofu+pgp") })
    }

    @Test
    func `warnings flag pre-RFC-9580 gpg`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/opt/homebrew/bin/gpg"
        status.gpgVersion = "2.2.40"
        status.versionSufficient = true
        status.rfc9580Ready = false
        #expect(status.warnings.contains { $0.contains("RFC 9580") })
    }

    @Test
    func `warnings stay empty on a modern gpg`() {
        var status = GPGHealthStatus()
        status.gpgPath = "/opt/homebrew/bin/gpg"
        status.gpgVersion = "2.4.7"
        status.versionSufficient = true
        status.rfc9580Ready = true
        #expect(status.warnings.isEmpty)
    }

    @Test
    func `warnings stay silent when gpg is missing`() {
        // Don't double up — missing gpg already shows up as a hard
        // issue; the RFC 9580 advisory would be noise.
        let status = GPGHealthStatus()
        #expect(status.warnings.isEmpty)
    }

    @Test
    func `allPassed ignores rfc9580Ready`() {
        // RFC 9580 is advisory; Alp still operates on older gpg.
        var status = GPGHealthStatus()
        status.gpgPath = "/opt/homebrew/bin/gpg"
        status.gpgVersion = "2.2.40"
        status.versionSufficient = true
        status.agentRunning = true
        status.pinentryConfigured = true
        status.hasSecretKeys = true
        status.secretKeyCount = 1
        status.tofuSupported = true
        status.rfc9580Ready = false
        #expect(status.allPassed)
    }
}
