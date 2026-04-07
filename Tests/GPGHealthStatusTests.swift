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
        #expect(status.issues.contains { $0.contains("pinentry-mac") })
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
}
