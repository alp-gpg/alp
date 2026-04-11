# Keys List Hierarchy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship hierarchical Keys list with auto-hidden expired keys and privacy-aware keyserver refresh, per `docs/superpowers/specs/2026-04-11-keys-list-hierarchy-design.md`.

**Architecture:** Data model gains `GPGSubkey` and `GPGKeyInfo.subkeys`; the colon parser is rewritten as a flush-based state machine; `importKey` returns a `GPGImportResult` struct parsed from gpg's `IMPORT_OK` status line; a new `KeyserverRefreshService` fetches from the pinned `keys.openpgp.org` session, verifies the fingerprint via `previewKey`, then imports; an `ExpiredKeyRefresher` drives a 4-way batch with cancel; the SwiftUI Table switches to hierarchical rows and gains a filter toggle, a banner, and per-row actions.

**Tech Stack:** Swift 6.3, SwiftUI (macOS 26), Swift Testing, Tuist-generated Xcode project, `xcodebuild` for build/test, `swiftlint` for lint gates.

**Conventions used throughout this plan:**
- **Test runner:** `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO` (abbreviated in steps as `xcodebuild test`).
- **Filter runs to one suite:** add `-only-testing:AlpTests/<SuiteName>/<testName>` to target a single test.
- **Lint:** `swiftlint lint --quiet` after each task; commit only if exit is clean.
- **Commits:** every task ends with a focused commit using imperative Present-tense subject (match the `git log` style).

---

## File Structure

**Created:**
- `Shared/AsyncSemaphore.swift` — tiny concurrency primitive used by `ExpiredKeyRefresher`.
- `Alp/Sources/KeyserverRefreshService.swift` — stateless service that fetches + verifies + imports.
- `Alp/Sources/ExpiredKeyRefresher.swift` — MainActor state holder for the batch refresh UI.
- `Alp/Sources/KeyListRow.swift` — `enum KeyRow` wrapper plus the hierarchical row renderers.
- `Alp/Sources/ExpiredKeysBanner.swift` — banner view shown above the Keys table.
- `Tests/GPGSubkeyTests.swift` — unit tests for `GPGSubkey` helpers.
- `Tests/ColonParserSubkeyTests.swift` — parser tests covering the new subkey + algorithm + revocation cases.
- `Tests/GPGImportResultTests.swift` — unit tests for the `IMPORT_OK` parser.
- `Tests/KeyserverRefreshServiceTests.swift` — tests with an injected mock fetcher.
- `Tests/ExpiredKeyRefresherTests.swift` — cancellation + concurrency tests.
- `Tests/KeysViewModelFilterTests.swift` — filter / count tests.
- `Tests/AsyncSemaphoreTests.swift` — semaphore primitive test.

**Modified:**
- `Shared/GPGKeyInfo.swift` — add `GPGSubkey`, add `subkeys` field, remove custom `init(from:)`.
- `Shared/GPGHelperProtocol.swift` — change `importKey` reply shape.
- `AlpHelper/Sources/GPGHelper.swift` — parser rewrite, `GPGImportResult` type, `_importKey` returns it, nonisolated bridge updated, `parseColonKeyListing` pinned to new state machine.
- `Alp/Sources/HelperXPCClient.swift` — `importKey` async wrapper returns `GPGImportResult`.
- `AlpExtension/Sources/GPGXPCClient.swift` — same.
- `Alp/Sources/KeySettingsView.swift` — switch to hierarchical `Table(children:)`, add toggle + banner + context menu, rename "Refresh" → "Reload", read new `importKey` result.
- `Alp/Sources/SettingsViewModel.swift` — expose `expiredPublishedCount`, drive `ExpiredKeyRefresher`, filter for `showExpired`.
- `Alp/Sources/GeneralSettingsView.swift` — new "Keys" sub-section with `autoRefreshExpiredOnShow` toggle.
- `Tests/XPCRoundtripTests.swift` — update importKey roundtrip test to consume the new return value.
- `Tests/GPGHelperTests.swift` — no logic change; any references to old `importKey` return type updated.

---

## Task 1 — GPGSubkey Type + GPGKeyInfo Subkeys Field

**Files:**
- Modify: `Shared/GPGKeyInfo.swift`
- Test: `Tests/GPGSubkeyTests.swift` (new)

- [ ] **Step 1: Write the failing tests**

Create `Tests/GPGSubkeyTests.swift`:

```swift
import Foundation
import Testing

@Suite("GPGSubkey")
struct GPGSubkeyTests {
    @Test("isExpired is false when expiryDate is nil")
    func neverExpires() {
        let s = GPGSubkey(fingerprint: "A".repeating(40), capabilities: "e",
                          expiryDate: nil, algorithm: "RSA 3072", isRevoked: false)
        #expect(s.isExpired == false)
    }

    @Test("isExpired is true when expiryDate is in the past")
    func pastExpiry() {
        let past = Date(timeIntervalSinceNow: -3600)
        let s = GPGSubkey(fingerprint: "A".repeating(40), capabilities: "e",
                          expiryDate: past, algorithm: nil, isRevoked: false)
        #expect(s.isExpired == true)
    }

    @Test("isExpired is false when expiryDate is in the future")
    func futureExpiry() {
        let future = Date(timeIntervalSinceNow: 3600)
        let s = GPGSubkey(fingerprint: "A".repeating(40), capabilities: "e",
                          expiryDate: future, algorithm: nil, isRevoked: false)
        #expect(s.isExpired == false)
    }

    @Test("capabilityIcons maps sign/encrypt/auth")
    func iconMapping() {
        let s = GPGSubkey(fingerprint: "A".repeating(40), capabilities: "sea",
                          expiryDate: nil, algorithm: nil, isRevoked: false)
        #expect(s.capabilityIcons.contains("signature"))
        #expect(s.capabilityIcons.contains("lock"))
        #expect(s.capabilityIcons.contains("person.badge.key"))
    }

    @Test("capabilityIcons is empty for unknown capabilities")
    func unknownCaps() {
        let s = GPGSubkey(fingerprint: "A".repeating(40), capabilities: "c",
                          expiryDate: nil, algorithm: nil, isRevoked: false)
        #expect(s.capabilityIcons.isEmpty)
    }

    @Test("id equals fingerprint for Identifiable conformance")
    func identifiableId() {
        let fp = "B".repeating(40)
        let s = GPGSubkey(fingerprint: fp, capabilities: "",
                          expiryDate: nil, algorithm: nil, isRevoked: false)
        #expect(s.id == fp)
    }
}

private extension String {
    func repeating(_ count: Int) -> String { String(repeating: self, count: count) }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `xcodebuild test -only-testing:AlpTests/GPGSubkey -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: FAIL with "cannot find 'GPGSubkey' in scope".

- [ ] **Step 3: Add the GPGSubkey type and wire it into GPGKeyInfo**

Open `Shared/GPGKeyInfo.swift`. Replace the whole file with:

```swift
import Foundation

/// Subkey material attached to a primary key.
struct GPGSubkey: Codable, Sendable, Identifiable, Hashable {
    let fingerprint: String
    /// gpg capability flags, e.g. "e", "s", "sca".
    let capabilities: String
    /// Unix-timestamped expiry, nil for non-expiring subkeys.
    let expiryDate: Date?
    /// Human-readable algorithm + size, e.g. "RSA 3072", "Ed25519". Nil when
    /// the listing didn't include enough information to format it.
    let algorithm: String?
    /// True when the subkey is revoked (`sub r:...` in colon output).
    let isRevoked: Bool

    var id: String { fingerprint }

    var isExpired: Bool {
        guard let expiryDate else { return false }
        return expiryDate < Date.now
    }

    /// SF Symbol names to render for each capability flag.
    var capabilityIcons: [String] {
        var icons: [String] = []
        let caps = capabilities.lowercased()
        if caps.contains("s") { icons.append("signature") }
        if caps.contains("e") { icons.append("lock") }
        if caps.contains("a") { icons.append("person.badge.key") }
        return icons
    }
}

/// A GPG primary key summary, JSON-serialisable for transport over XPC.
struct GPGKeyInfo: Codable, Sendable, Identifiable, Hashable {
    let fingerprint: String
    let userIDs: [String]
    /// gpg capability flags for the primary key itself.
    let capabilities: String
    /// True when a matching secret key is available in the local keyring.
    var hasSecretKey: Bool
    /// Primary-key expiry, nil for non-expiring keys.
    var expiryDate: Date?
    /// Subkeys attached to this primary. Empty when the key has none.
    var subkeys: [GPGSubkey]

    var id: String { fingerprint }

    var isExpired: Bool {
        guard let expiryDate else { return false }
        return expiryDate < Date.now
    }

    var displayName: String { userIDs.first ?? fingerprint }

    /// Name-only portion of the primary UID, stripped of the email address.
    /// E.g. "Alice Example <alice@example.com>" → "Alice Example"
    var shortName: String {
        guard let uid = userIDs.first else { return String(fingerprint.prefix(8)) }
        if let range = uid.range(of: " <") {
            return String(uid[uid.startIndex..<range.lowerBound])
        }
        return uid
    }

    /// Last 16 hex characters formatted as "ABCD 1234 EFGH 5678".
    var shortFingerprint: String {
        let last16 = String(fingerprint.suffix(16)).uppercased()
        guard last16.count == 16 else { return fingerprint }
        return stride(from: 0, to: 16, by: 4).map { i in
            let start = last16.index(last16.startIndex, offsetBy: i)
            let end   = last16.index(start, offsetBy: 4)
            return String(last16[start..<end])
        }.joined(separator: " ")
    }

    init(
        fingerprint: String,
        userIDs: [String],
        capabilities: String,
        hasSecretKey: Bool = false,
        expiryDate: Date? = nil,
        subkeys: [GPGSubkey] = []
    ) {
        self.fingerprint = fingerprint
        self.userIDs = userIDs
        self.capabilities = capabilities
        self.hasSecretKey = hasSecretKey
        self.expiryDate = expiryDate
        self.subkeys = subkeys
    }
}
```

Note: the custom `init(from:)` is **gone**. Swift synthesizes `Codable` for both
types. Pre-release means no backward-compat shim.

- [ ] **Step 4: Run the new test suite to confirm it passes**

Run: `xcodebuild test -only-testing:AlpTests/GPGSubkey -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: PASS for all 6 tests.

- [ ] **Step 5: Run the full suite to catch any collateral breakage**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: All tests pass. If `GPGKeyInfoTests` fails due to the missing custom init, update its decoding tests to match the synthesized Codable shape — every encode must round-trip via the synthesized encoder.

- [ ] **Step 6: Lint and commit**

```bash
swiftlint lint --quiet
git add Shared/GPGKeyInfo.swift Tests/GPGSubkeyTests.swift Tests/GPGKeyInfoTests.swift
git commit -m "Add GPGSubkey type and subkeys field to GPGKeyInfo"
```

---

## Task 2 — Colon Parser Captures Subkeys

**Files:**
- Modify: `AlpHelper/Sources/GPGHelper.swift` (`parseColonKeyListing` + new helper)
- Test: `Tests/ColonParserSubkeyTests.swift` (new)

- [ ] **Step 1: Write the failing tests**

Create `Tests/ColonParserSubkeyTests.swift`:

```swift
import Foundation
import Testing

@Suite("Colon listing parser — subkeys")
struct ColonParserSubkeyTests {
    /// Helper: build a colon listing from one primary key + optional subkey lines.
    private func listing(
        primary: String,
        uids: [String] = [],
        subkeys: [String] = []
    ) -> String {
        var out = primary + "\n"
        for uid in uids { out += uid + "\n" }
        for sub in subkeys { out += sub + "\n" }
        return out
    }

    @Test("Primary with no subkeys has empty subkeys array")
    func noSubkeys() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        uid:u::::1700000000::DEADBEEF::Alice <a@x>::::::::::0:
        """
        let keys = helper.testParseColonKeyListing(text)
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
        sub:u:3072:1:BBBB2222CCCC3333:1700000000:1900000000::::e::::::23:
        fpr:::::::::BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666:
        """
        let keys = helper.testParseColonKeyListing(text)
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
        sub:r:3072:1:BBBB2222CCCC3333:1700000000:1900000000::::e::::::23:
        fpr:::::::::BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666:
        """
        let keys = helper.testParseColonKeyListing(text)
        #expect(keys[0].subkeys.first?.isRevoked == true)
    }

    @Test("Expired subkey under valid primary — primary stays valid")
    func expiredSubkey() async {
        let helper = await GPGHelper()
        let pastTs = String(Int(Date(timeIntervalSinceNow: -86400).timeIntervalSince1970))
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        sub:u:3072:1:BBBB2222CCCC3333:1700000000:\(pastTs)::::e::::::23:
        fpr:::::::::BBBB2222CCCC3333DDDD4444EEEE5555FFFF6666:
        """
        let keys = helper.testParseColonKeyListing(text)
        #expect(keys[0].isExpired == false)
        #expect(keys[0].subkeys[0].isExpired == true)
    }

    @Test("Multiple subkeys captured in order")
    func multipleSubkeys() async {
        let helper = await GPGHelper()
        let text = """
        pub:u:3072:1:AAAA1111BBBB2222:1700000000:0::u:::scESC::::::23::0:
        fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:
        sub:u:3072:1:BBBB2222CCCC3333:1700000000:1900000000::::e::::::23:
        fpr:::::::::1111111111111111111111111111111111111111:
        sub:u:255:22:CCCC3333DDDD4444:1700000000:1900000000::::s::::::23:ed25519:
        fpr:::::::::2222222222222222222222222222222222222222:
        """
        let keys = helper.testParseColonKeyListing(text)
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
        sub:u:255:22:CCCC3333DDDD4444:1700000000:1900000000::::s::::::23:ed25519:
        fpr:::::::::2222222222222222222222222222222222222222:
        """
        let keys = helper.testParseColonKeyListing(text)
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
        ssb:u:3072:1:BBBB2222CCCC3333:1700000000:1900000000::::e::::::23:
        fpr:::::::::1111111111111111111111111111111111111111:
        """
        let keys = helper.testParseColonKeyListing(text)
        #expect(keys.count == 1)
        #expect(keys[0].subkeys.count == 1)
    }
}
```

- [ ] **Step 2: Add the `testParseColonKeyListing` test seam**

`parseColonKeyListing` is currently private. Add a test-visible wrapper at the
bottom of `GPGHelper.swift` so tests can exercise it without going through
gpg:

```swift
#if DEBUG
extension GPGHelper {
    /// Test-only hook into the colon listing parser. Kept inside `#if DEBUG`
    /// so it does not ship in Release builds.
    func testParseColonKeyListing(_ text: String) -> [GPGKeyInfo] {
        parseColonKeyListing(text)
    }
}
#endif
```

- [ ] **Step 3: Run tests to verify they fail on the new assertions**

Run: `xcodebuild test -only-testing:AlpTests/ColonParserSubkeyTests -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: most tests FAIL because the current parser discards subkey records.

- [ ] **Step 4: Rewrite `parseColonKeyListing` as a flush state machine**

Open `AlpHelper/Sources/GPGHelper.swift`. Replace the existing
`parseColonKeyListing` function with:

```swift
    private func parseColonKeyListing(_ text: String) -> [GPGKeyInfo] {
        var keys: [GPGKeyInfo] = []

        var primaryFingerprint: String?
        var primaryUIDs: [String] = []
        var primaryCapabilities = ""
        var primaryExpiry: Date?
        var subkeys: [GPGSubkey] = []

        /// Staging area for the subkey we're currently filling in. We can't
        /// build the final `GPGSubkey` until its `fpr` line arrives because
        /// the subkey's full fingerprint appears on a subsequent record.
        struct PendingSubkey {
            var fingerprint: String = ""
            var capabilities: String = ""
            var expiry: Date? = nil
            var algorithm: String? = nil
            var isRevoked: Bool = false
        }
        var pendingSubkey: PendingSubkey?

        func flushSubkey() {
            guard let pending = pendingSubkey, !pending.fingerprint.isEmpty else {
                pendingSubkey = nil
                return
            }
            subkeys.append(GPGSubkey(
                fingerprint: pending.fingerprint,
                capabilities: pending.capabilities,
                expiryDate: pending.expiry,
                algorithm: pending.algorithm,
                isRevoked: pending.isRevoked
            ))
            pendingSubkey = nil
        }

        func flushPrimary() {
            flushSubkey()
            guard let fp = primaryFingerprint, !fp.isEmpty else { return }
            keys.append(GPGKeyInfo(
                fingerprint: fp,
                userIDs: primaryUIDs,
                capabilities: primaryCapabilities,
                expiryDate: primaryExpiry,
                subkeys: subkeys
            ))
            primaryFingerprint = nil
            primaryUIDs = []
            primaryCapabilities = ""
            primaryExpiry = nil
            subkeys = []
        }

        for raw in text.components(separatedBy: "\n") {
            let fields = raw.trimmingCharacters(in: .init(charactersIn: "\r"))
                            .components(separatedBy: ":")
            guard let recordType = fields.first, !recordType.isEmpty else { continue }

            if recordType.hasPrefix("pub") || recordType.hasPrefix("sec") {
                flushPrimary()
                primaryCapabilities = fields.count > 11 ? fields[11] : ""
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    primaryExpiry = Date(timeIntervalSince1970: ts)
                } else {
                    primaryExpiry = nil
                }
            } else if recordType.hasPrefix("sub") || recordType.hasPrefix("ssb") {
                flushSubkey()
                var pending = PendingSubkey()
                pending.isRevoked = fields.count > 1 && fields[1] == "r"
                pending.capabilities = fields.count > 11 ? fields[11] : ""
                if fields.count > 6, let ts = TimeInterval(fields[6]), ts > 0 {
                    pending.expiry = Date(timeIntervalSince1970: ts)
                }
                pending.algorithm = Self.formatAlgorithm(
                    id: fields.count > 3 ? fields[3] : "",
                    bits: fields.count > 2 ? fields[2] : "",
                    curve: fields.count > 16 ? fields[16] : ""
                )
                pendingSubkey = pending
            } else if recordType == "fpr" {
                if pendingSubkey != nil {
                    if fields.count > 9 { pendingSubkey?.fingerprint = fields[9] }
                } else if primaryFingerprint == nil, fields.count > 9 {
                    primaryFingerprint = fields[9]
                }
            } else if recordType == "uid" {
                if pendingSubkey == nil, fields.count > 9, !fields[9].isEmpty {
                    primaryUIDs.append(fields[9])
                }
            }
        }
        flushPrimary()
        return keys
    }

    /// Maps gpg's numeric algorithm id + bit size + curve name to a
    /// human-readable label, e.g. "RSA 3072" or "Ed25519".
    ///
    /// Algorithm ids come from RFC 4880 + gpg extensions:
    ///   1 = RSA, 16 = ElGamal, 17 = DSA, 18 = ECDH, 19 = ECDSA, 22 = EdDSA.
    static func formatAlgorithm(id: String, bits: String, curve: String) -> String? {
        guard let algoId = Int(id) else { return nil }
        let name: String
        switch algoId {
        case 1:  name = "RSA"
        case 16: name = "ElGamal"
        case 17: name = "DSA"
        case 18: name = "ECDH"
        case 19: name = "ECDSA"
        case 22: name = "EdDSA"
        default: return nil
        }
        // ECC keys prefer the curve name when it's present — "Ed25519" is
        // more useful than "EdDSA 255".
        if [18, 19, 22].contains(algoId), !curve.isEmpty {
            return curve.capitalized
        }
        if !bits.isEmpty { return "\(name) \(bits)" }
        return name
    }
```

- [ ] **Step 5: Run the parser tests**

Run: `xcodebuild test -only-testing:AlpTests/ColonParserSubkeyTests -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests PASS.

- [ ] **Step 6: Run the full suite to catch regressions**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests pass. Specifically `GPGHelperTests.listSecretKeys` and
`encryptDecrypt` and `signVerify` must still pass — they exercise the parser
via real gpg output.

- [ ] **Step 7: Lint and commit**

```bash
swiftlint lint --quiet
git add AlpHelper/Sources/GPGHelper.swift Tests/ColonParserSubkeyTests.swift
git commit -m "Capture subkeys in colon listing parser"
```

---

## Task 3 — GPGImportResult Type + Status Parser

**Files:**
- Modify: `AlpHelper/Sources/GPGHelper.swift` (add struct + parser)
- Test: `Tests/GPGImportResultTests.swift` (new)

- [ ] **Step 1: Write the failing tests**

Create `Tests/GPGImportResultTests.swift`:

```swift
import Foundation
import Testing

@Suite("GPGImportResult parsing")
struct GPGImportResultTests {
    @Test("IMPORT_OK 0 → all flags false, fingerprint captured")
    func notActuallyChanged() {
        let status = "[GNUPG:] IMPORT_OK 0 AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.fingerprint == "AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555")
        #expect(result.newKey == false)
        #expect(result.newUserIDs == false)
        #expect(result.updatedSignatures == false)
        #expect(result.newSubkeys == false)
    }

    @Test("IMPORT_OK 1 → newKey")
    func entirelyNewKey() {
        let status = "[GNUPG:] IMPORT_OK 1 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.newKey == true)
        #expect(result.newUserIDs == false)
    }

    @Test("IMPORT_OK 2 → newUserIDs")
    func newUserIDs() {
        let status = "[GNUPG:] IMPORT_OK 2 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.newUserIDs == true)
        #expect(result.newKey == false)
    }

    @Test("IMPORT_OK 4 → updatedSignatures")
    func newSignatures() {
        let status = "[GNUPG:] IMPORT_OK 4 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.updatedSignatures == true)
        #expect(result.newSubkeys == false)
    }

    @Test("IMPORT_OK 8 → newSubkeys")
    func newSubkeys() {
        let status = "[GNUPG:] IMPORT_OK 8 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.newSubkeys == true)
        #expect(result.updatedSignatures == false)
    }

    @Test("IMPORT_OK 12 → updatedSignatures + newSubkeys (combined flags)")
    func combinedFlags() {
        let status = "[GNUPG:] IMPORT_OK 12 AAAA"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.updatedSignatures == true)
        #expect(result.newSubkeys == true)
        #expect(result.newUserIDs == false)
        #expect(result.newKey == false)
    }

    @Test("Missing IMPORT_OK returns nil fingerprint and all flags false")
    func missingLine() {
        let status = "[GNUPG:] IMPORT_PROBLEM 0"
        let result = GPGHelper.parseImportResult(from: status)
        #expect(result.fingerprint == nil)
        #expect(result.newKey == false)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `xcodebuild test -only-testing:AlpTests/GPGImportResult -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: FAIL with "cannot find 'GPGImportResult' / 'parseImportResult'".

- [ ] **Step 3: Add the type and parser**

Open `AlpHelper/Sources/GPGHelper.swift`. Add these at the top level of the
file, just above the `actor GPGHelper` declaration:

```swift
/// Summary of a `gpg --import` run, parsed from the IMPORT_OK status line.
struct GPGImportResult: Codable, Sendable {
    let fingerprint: String?
    /// Bit 0 (value 1) — key was entirely new to the keyring.
    let newKey: Bool
    /// Bit 1 (value 2) — new user IDs were attached to an existing key.
    let newUserIDs: Bool
    /// Bit 2 (value 4) — new self-signatures (typically an extended expiry).
    let updatedSignatures: Bool
    /// Bit 3 (value 8) — new subkeys were added.
    let newSubkeys: Bool
}
```

Inside the `GPGHelper` actor, add the static parser (near the other static
helpers like `parseMicalg`):

```swift
    /// Parses gpg's `IMPORT_OK <reason> <fingerprint>` status line.
    /// Bit mapping comes from gpg's `doc/DETAILS`:
    ///   1 = new key, 2 = new UIDs, 4 = new sigs, 8 = new subkeys.
    static func parseImportResult(from statusText: String) -> GPGImportResult {
        for line in statusText.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: " ")
            guard let idx = parts.firstIndex(of: "IMPORT_OK"),
                  parts.count > idx + 2,
                  let reason = Int(parts[idx + 1])
            else { continue }
            let fingerprint = parts[idx + 2]
            return GPGImportResult(
                fingerprint: fingerprint,
                newKey: reason & 1 != 0,
                newUserIDs: reason & 2 != 0,
                updatedSignatures: reason & 4 != 0,
                newSubkeys: reason & 8 != 0
            )
        }
        return GPGImportResult(
            fingerprint: nil,
            newKey: false,
            newUserIDs: false,
            updatedSignatures: false,
            newSubkeys: false
        )
    }
```

- [ ] **Step 4: Run the tests**

Run: `xcodebuild test -only-testing:AlpTests/GPGImportResult -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all 7 tests PASS.

- [ ] **Step 5: Lint and commit**

```bash
swiftlint lint --quiet
git add AlpHelper/Sources/GPGHelper.swift Tests/GPGImportResultTests.swift
git commit -m "Add GPGImportResult parser for gpg IMPORT_OK status"
```

---

## Task 4 — importKey Returns GPGImportResult Over XPC

**Files:**
- Modify: `Shared/GPGHelperProtocol.swift`
- Modify: `AlpHelper/Sources/GPGHelper.swift` (`_importKey` + nonisolated bridge)
- Modify: `Alp/Sources/HelperXPCClient.swift`
- Modify: `AlpExtension/Sources/GPGXPCClient.swift`
- Modify: `Alp/Sources/KeySettingsView.swift` (consume new return)
- Modify: `Tests/XPCRoundtripTests.swift` (round-trip test for new shape)

- [ ] **Step 1: Update the protocol**

Open `Shared/GPGHelperProtocol.swift`. Replace the `importKey` declaration with:

```swift
    /// reply: (jsonEncodedGPGImportResult?, error?)
    func importKey(armoredKey: Data, reply: @escaping @Sendable (Data?, NSError?) -> Void)
```

Note the reply shape changed — it's now `(Data?, NSError?)` because the Data
holds a JSON-encoded `GPGImportResult`. Previous shape `(NSError?)` is removed.

- [ ] **Step 2: Update `_importKey` in GPGHelper**

Open `AlpHelper/Sources/GPGHelper.swift`. Replace `_importKey` with:

```swift
    func _importKey(_ armoredKey: Data) async throws -> GPGImportResult {
        let args = ["--batch", "--yes", "--status-fd", "2", "--import"]
        let (_, stderr, exitCode) = try await runGPGRaw(args, input: armoredKey)
        let stderrText = String(data: stderr, encoding: .utf8) ?? ""
        guard exitCode == 0 else {
            throw GPGError.processError(exitCode: exitCode, stderr: stderrText)
        }
        return Self.parseImportResult(from: stderrText)
    }
```

Also replace the nonisolated `importKey` bridge lower down with:

```swift
    nonisolated func importKey(
        armoredKey: Data,
        reply: @escaping @Sendable (Data?, NSError?) -> Void
    ) {
        guard armoredKey.count <= Self.maxPayloadSize else {
            reply(nil, GPGError.encodingError("payload too large").asNSError); return
        }
        Task {
            do {
                let result = try await self._importKey(armoredKey)
                let encoded = try JSONEncoder().encode(result)
                reply(encoded, nil)
            } catch let e as GPGError {
                reply(nil, e.asNSError)
            } catch {
                reply(nil, error as NSError)
            }
        }
    }
```

- [ ] **Step 3: Update `HelperXPCClient.importKey`**

Open `Alp/Sources/HelperXPCClient.swift`. Replace the `importKey` wrapper with:

```swift
    func importKey(_ armoredKey: Data) async throws -> GPGImportResult {
        try await call { proxy, resume in
            proxy.importKey(armoredKey: armoredKey) { data, error in
                if let error { resume(.failure(error)) }
                else if let data {
                    do {
                        let result = try JSONDecoder().decode(GPGImportResult.self, from: data)
                        resume(.success(result))
                    } catch {
                        resume(.failure(error))
                    }
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }
```

- [ ] **Step 4: Update `GPGXPCClient.importKey`**

Open `AlpExtension/Sources/GPGXPCClient.swift`. Replace the `importKey` wrapper
with:

```swift
    func importKey(_ armoredKey: Data) async throws -> GPGImportResult {
        try await call { proxy, resume in
            proxy.importKey(armoredKey: armoredKey) { data, error in
                if let error { resume(.failure(error)) }
                else if let data {
                    do {
                        let result = try JSONDecoder().decode(GPGImportResult.self, from: data)
                        resume(.success(result))
                    } catch {
                        resume(.failure(error))
                    }
                } else {
                    resume(.failure(GPGError.xpcUnavailable))
                }
            }
        }
    }
```

- [ ] **Step 5: Update the single file-import call site**

Open `Alp/Sources/KeySettingsView.swift`. Find `importKeyFromFile`. Replace the
`Task { ... }` body with:

```swift
        Task {
            do {
                let data = try Data(contentsOf: url)
                let result = try await HelperXPCClient.shared.importKey(data)
                vm.lastImportSummary = Self.summarize(result)
                await vm.refreshKeys()
            } catch {
                vm.helperError = error.localizedDescription
            }
        }
```

Add the summarizer as a static helper on the view:

```swift
    private static func summarize(_ result: GPGImportResult) -> String {
        if result.newKey { return "Imported new key" }
        if result.updatedSignatures || result.newSubkeys || result.newUserIDs {
            return "Updated existing key"
        }
        return "Key already up to date"
    }
```

You will wire `lastImportSummary` into `SettingsViewModel` in the next step,
so compilation will fail temporarily.

- [ ] **Step 6: Add `lastImportSummary` to SettingsViewModel**

Open `Alp/Sources/SettingsViewModel.swift`. Near the other `@Published`
properties add:

```swift
    /// Non-error user feedback for the most recent key import. Shown as a
    /// transient summary in the Keys section.
    var lastImportSummary: String?
```

- [ ] **Step 7: Update the XPC round-trip test**

Open `Tests/XPCRoundtripTests.swift`. Add a new test at the bottom of the
suite (before the closing brace):

```swift
    @Test("importKey bridge returns GPGImportResult")
    func importKeyBridgeReturnsResult() async throws {
        let fp = try await firstSecretKeyFingerprint()
        // Export an existing key so we have real armored data to re-import.
        let exported = try await helper._export(fp)
        let resultData: Data = try await withCheckedThrowingContinuation { cont in
            helper.importKey(armoredKey: exported) { data, error in
                if let error { cont.resume(throwing: error) }
                else if let data { cont.resume(returning: data) }
                else { cont.resume(throwing: GPGError.encodingError("nil")) }
            }
        }
        let result = try JSONDecoder().decode(GPGImportResult.self, from: resultData)
        // Re-importing an already-present key should not mark it as new.
        #expect(result.newKey == false)
        #expect(result.fingerprint != nil)
    }
```

This test depends on a helper method `_export` that does not exist yet. Add it
to `GPGHelper`:

```swift
    func _export(_ fingerprint: String) async throws -> Data {
        guard Self.isValidFingerprint(fingerprint) else {
            throw GPGError.encodingError("invalid fingerprint")
        }
        let args = ["--batch", "--yes", "--armor", "--export", fingerprint]
        return try await runGPG(args)
    }
```

- [ ] **Step 8: Build and fix any lingering compile errors**

Run: `xcodebuild build -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: BUILD SUCCEEDED. If `GPGHelperTests.signVerify` or similar now fails
compilation because they referenced `importKey` in a particular way, update
them to match the new signature.

- [ ] **Step 9: Run the full test suite**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests PASS, including the new `importKeyBridgeReturnsResult`.

- [ ] **Step 10: Lint and commit**

```bash
swiftlint lint --quiet
git add Shared/GPGHelperProtocol.swift AlpHelper/Sources/GPGHelper.swift \
        Alp/Sources/HelperXPCClient.swift AlpExtension/Sources/GPGXPCClient.swift \
        Alp/Sources/KeySettingsView.swift Alp/Sources/SettingsViewModel.swift \
        Tests/XPCRoundtripTests.swift
git commit -m "Return GPGImportResult from importKey XPC bridge"
```

---

## Task 5 — AsyncSemaphore Primitive

**Files:**
- Create: `Shared/AsyncSemaphore.swift`
- Test: `Tests/AsyncSemaphoreTests.swift`

- [ ] **Step 1: Write the failing test**

Create `Tests/AsyncSemaphoreTests.swift`:

```swift
import Foundation
import Testing

@Suite("AsyncSemaphore")
struct AsyncSemaphoreTests {
    @Test("Permits up to N concurrent holders, then gates")
    func concurrencyLimit() async {
        let sem = AsyncSemaphore(value: 2)
        let counter = ActorCounter()

        await withTaskGroup(of: Void.self) { group in
            for _ in 0 ..< 10 {
                group.addTask {
                    await sem.wait()
                    defer { Task { await sem.signal() } }
                    await counter.bump()
                    try? await Task.sleep(nanoseconds: 10_000_000)
                    await counter.dropAfter()
                }
            }
        }

        let peak = await counter.peak
        #expect(peak <= 2, "Peak concurrency \(peak) exceeded semaphore limit 2")
    }
}

private actor ActorCounter {
    private(set) var peak = 0
    private var current = 0
    func bump() {
        current += 1
        if current > peak { peak = current }
    }
    func dropAfter() { current -= 1 }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `xcodebuild test -only-testing:AlpTests/AsyncSemaphore -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: FAIL with "cannot find 'AsyncSemaphore' in scope".

- [ ] **Step 3: Implement the semaphore**

Create `Shared/AsyncSemaphore.swift`:

```swift
import Foundation

/// A minimal async-await counting semaphore. Used by `ExpiredKeyRefresher`
/// to cap parallel keyserver fetches.
///
/// The actor serializes access to `permits` and the waiter queue, and each
/// `wait()` suspends via a `CheckedContinuation` when no permit is free.
/// `signal()` resumes one waiter if any are queued, otherwise returns a
/// permit to the pool.
actor AsyncSemaphore {
    private var permits: Int
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init(value: Int) {
        precondition(value >= 0, "AsyncSemaphore value must be non-negative")
        self.permits = value
    }

    func wait() async {
        if permits > 0 {
            permits -= 1
            return
        }
        await withCheckedContinuation { cont in
            waiters.append(cont)
        }
    }

    func signal() {
        if let next = waiters.first {
            waiters.removeFirst()
            next.resume()
        } else {
            permits += 1
        }
    }
}
```

- [ ] **Step 4: Run the test**

Run: `xcodebuild test -only-testing:AlpTests/AsyncSemaphore -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
swiftlint lint --quiet
git add Shared/AsyncSemaphore.swift Tests/AsyncSemaphoreTests.swift
git commit -m "Add AsyncSemaphore primitive for concurrency-capped work"
```

---

## Task 6 — KeyserverRefreshService

**Files:**
- Create: `Alp/Sources/KeyserverRefreshService.swift`
- Test: `Tests/KeyserverRefreshServiceTests.swift`

- [ ] **Step 1: Define the fetcher protocol and outcome type inside the service file**

Create `Alp/Sources/KeyserverRefreshService.swift`:

```swift
import Foundation

/// Result of attempting to refresh a single key from keys.openpgp.org.
enum KeyserverRefreshOutcome: Equatable, Sendable {
    /// Upstream returned a newer self-signature or new subkey material;
    /// the local keyring has been updated.
    case updated
    /// Upstream has the key but it matches what we already have.
    case alreadyCurrent
    /// The key is not published on the keyserver.
    case notPublished
}

/// Errors specific to the keyserver refresh path. Generic network errors
/// bubble up as the underlying URLError / NSError from the URLSession call.
enum KeyserverRefreshError: Error, Equatable {
    /// The keyserver returned a key whose primary fingerprint does not match
    /// the one we requested. Treated as a *security* failure: the local
    /// keyring is never touched in this case.
    case fingerprintMismatch(requested: String, got: String?)
}

/// Network-facing seam for tests. Production uses `LiveKeyserverFetcher`
/// which wraps `KeyserverSession.shared`.
protocol KeyserverFetcher: Sendable {
    func fetch(fingerprint: String) async throws -> FetchedKey
}

enum FetchedKey: Sendable {
    case notPublished
    case found(Data)
}

/// Production fetcher against https://keys.openpgp.org over the pinned session.
struct LiveKeyserverFetcher: KeyserverFetcher {
    func fetch(fingerprint: String) async throws -> FetchedKey {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "keys.openpgp.org"
        components.percentEncodedPath = "/vks/v1/by-fingerprint/" + fingerprint
        guard let url = components.url, url.scheme == "https" else {
            throw KeyserverRefreshError.fingerprintMismatch(requested: fingerprint, got: nil)
        }
        let (data, response) = try await KeyserverSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse else { return .notPublished }
        switch http.statusCode {
        case 200: return .found(data)
        case 404: return .notPublished
        default:  throw URLError(.badServerResponse)
        }
    }
}

/// Thin wrapper over the helper's preview + import calls. A protocol so we
/// can inject a fake in unit tests without spinning up real gpg.
protocol KeyPreviewImporter: Sendable {
    func preview(_ data: Data) async throws -> [GPGKeyInfo]
    func `import`(_ data: Data) async throws -> GPGImportResult
}

struct LiveKeyPreviewImporter: KeyPreviewImporter {
    func preview(_ data: Data) async throws -> [GPGKeyInfo] {
        // Route through the main app's XPC client — this service runs in the
        // Alp process, not the Mail extension.
        try await HelperXPCClient.shared.previewKey(data)
    }
    func `import`(_ data: Data) async throws -> GPGImportResult {
        try await HelperXPCClient.shared.importKey(data)
    }
}

/// Orchestrates: fetch → preview verify → import.
///
/// The preview step is the security guarantee: certificate pinning prevents
/// in-transit tampering, and fingerprint-matching catches the remaining case
/// where anything upstream returns an unexpected key.
struct KeyserverRefreshService: Sendable {
    let fetcher: KeyserverFetcher
    let importer: KeyPreviewImporter

    init(
        fetcher: KeyserverFetcher = LiveKeyserverFetcher(),
        importer: KeyPreviewImporter = LiveKeyPreviewImporter()
    ) {
        self.fetcher = fetcher
        self.importer = importer
    }

    func refresh(fingerprint expected: String) async throws -> KeyserverRefreshOutcome {
        let fetched = try await fetcher.fetch(fingerprint: expected)
        switch fetched {
        case .notPublished:
            return .notPublished
        case .found(let data):
            let previewed = try await importer.preview(data)
            guard previewed.first?.fingerprint == expected else {
                throw KeyserverRefreshError.fingerprintMismatch(
                    requested: expected,
                    got: previewed.first?.fingerprint
                )
            }
            let result = try await importer.import(data)
            if result.updatedSignatures || result.newSubkeys || result.newUserIDs {
                return .updated
            }
            return .alreadyCurrent
        }
    }
}
```

`HelperXPCClient.previewKey` does not exist yet — we need to add it. Open
`Alp/Sources/HelperXPCClient.swift` and add:

```swift
    func previewKey(_ armoredKey: Data) async throws -> [GPGKeyInfo] {
        try await call { proxy, resume in
            proxy.previewKey(armoredKey: armoredKey) { dataList, error in
                if let error { resume(.failure(error)) }
                else { resume(.success(Self.decodeKeys(dataList))) }
            }
        }
    }
```

- [ ] **Step 2: Write the tests**

Create `Tests/KeyserverRefreshServiceTests.swift`:

```swift
import Foundation
import Testing

@Suite("KeyserverRefreshService")
struct KeyserverRefreshServiceTests {
    final class StubFetcher: KeyserverFetcher, @unchecked Sendable {
        var stub: Result<FetchedKey, Error> = .success(.notPublished)
        func fetch(fingerprint: String) async throws -> FetchedKey {
            try stub.get()
        }
    }

    final class StubImporter: KeyPreviewImporter, @unchecked Sendable {
        var previewResult: Result<[GPGKeyInfo], Error> = .success([])
        var importResult: Result<GPGImportResult, Error> = .success(
            GPGImportResult(fingerprint: nil, newKey: false, newUserIDs: false,
                            updatedSignatures: false, newSubkeys: false)
        )
        private(set) var importCalled = false
        func preview(_ data: Data) async throws -> [GPGKeyInfo] {
            try previewResult.get()
        }
        func `import`(_ data: Data) async throws -> GPGImportResult {
            importCalled = true
            return try importResult.get()
        }
    }

    private func expectedFingerprint() -> String { String(repeating: "A", count: 40) }

    @Test("notPublished short-circuits before preview")
    func notPublishedShortCircuits() async throws {
        let fetcher = StubFetcher()
        fetcher.stub = .success(.notPublished)
        let importer = StubImporter()
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: expectedFingerprint())
        #expect(outcome == .notPublished)
        #expect(importer.importCalled == false)
    }

    @Test("fingerprint mismatch throws and does NOT import")
    func fingerprintMismatchRejectsImport() async {
        let requested = expectedFingerprint()
        let other = String(repeating: "B", count: 40)
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: other, userIDs: [], capabilities: "")
        ])
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        await #expect(throws: KeyserverRefreshError.self) {
            _ = try await service.refresh(fingerprint: requested)
        }
        #expect(importer.importCalled == false)
    }

    @Test("updatedSignatures maps to .updated")
    func updatedSignaturesPath() async throws {
        let fp = expectedFingerprint()
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: "")
        ])
        importer.importResult = .success(
            GPGImportResult(fingerprint: fp, newKey: false, newUserIDs: false,
                            updatedSignatures: true, newSubkeys: false)
        )
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: fp)
        #expect(outcome == .updated)
        #expect(importer.importCalled == true)
    }

    @Test("no changes maps to .alreadyCurrent")
    func alreadyCurrentPath() async throws {
        let fp = expectedFingerprint()
        let fetcher = StubFetcher()
        fetcher.stub = .success(.found(Data("armored".utf8)))
        let importer = StubImporter()
        importer.previewResult = .success([
            GPGKeyInfo(fingerprint: fp, userIDs: [], capabilities: "")
        ])
        // All flags false
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        let outcome = try await service.refresh(fingerprint: fp)
        #expect(outcome == .alreadyCurrent)
    }

    @Test("network error propagates")
    func networkErrorPropagates() async {
        let fetcher = StubFetcher()
        fetcher.stub = .failure(URLError(.notConnectedToInternet))
        let importer = StubImporter()
        let service = KeyserverRefreshService(fetcher: fetcher, importer: importer)
        await #expect(throws: URLError.self) {
            _ = try await service.refresh(fingerprint: expectedFingerprint())
        }
    }
}
```

- [ ] **Step 3: Build and run the new tests**

Run: `xcodebuild test -only-testing:AlpTests/KeyserverRefreshService -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all 5 tests PASS.

- [ ] **Step 4: Lint and commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/KeyserverRefreshService.swift Alp/Sources/HelperXPCClient.swift \
        Tests/KeyserverRefreshServiceTests.swift
git commit -m "Add KeyserverRefreshService with preview-before-import verification"
```

---

## Task 7 — ExpiredKeyRefresher (Batch + Cancel)

**Files:**
- Create: `Alp/Sources/ExpiredKeyRefresher.swift`
- Test: `Tests/ExpiredKeyRefresherTests.swift`

- [ ] **Step 1: Write the tests**

Create `Tests/ExpiredKeyRefresherTests.swift`:

```swift
import Foundation
import Testing

@Suite("ExpiredKeyRefresher")
@MainActor
struct ExpiredKeyRefresherTests {
    final class SlowStubImporter: KeyPreviewImporter, @unchecked Sendable {
        var delayNanos: UInt64 = 50_000_000
        let peak = AtomicCounter()
        func preview(_ data: Data) async throws -> [GPGKeyInfo] {
            // Return a matching fingerprint so the service proceeds to import.
            [GPGKeyInfo(
                fingerprint: String(data: data, encoding: .utf8) ?? "",
                userIDs: [], capabilities: ""
            )]
        }
        func `import`(_ data: Data) async throws -> GPGImportResult {
            await peak.enter()
            defer { Task { await peak.leave() } }
            try await Task.sleep(nanoseconds: delayNanos)
            return GPGImportResult(
                fingerprint: String(data: data, encoding: .utf8),
                newKey: false, newUserIDs: false,
                updatedSignatures: true, newSubkeys: false
            )
        }
    }

    final class StubFetcher: KeyserverFetcher, @unchecked Sendable {
        func fetch(fingerprint: String) async throws -> FetchedKey {
            .found(Data(fingerprint.utf8))
        }
    }

    private func makeKeys(count: Int) -> [GPGKeyInfo] {
        (0 ..< count).map { i in
            let fp = String(format: "%040d", i)  // 40-char zero-padded int
            return GPGKeyInfo(
                fingerprint: fp, userIDs: [], capabilities: "",
                expiryDate: Date(timeIntervalSince1970: 1)  // expired
            )
        }
    }

    @Test("Parallelism is capped at 4")
    func parallelismCap() async {
        let importer = SlowStubImporter()
        let service = KeyserverRefreshService(
            fetcher: StubFetcher(), importer: importer
        )
        let refresher = ExpiredKeyRefresher(service: service, maxConcurrent: 4)
        let keys = makeKeys(count: 12)
        await refresher.runUntilDone(keys: keys)
        let peak = await importer.peak.peakValue
        #expect(peak <= 4, "Peak concurrency \(peak) exceeded cap 4")
    }

    @Test("Cancellation stops further imports")
    func cancellation() async {
        let importer = SlowStubImporter()
        importer.delayNanos = 200_000_000  // slow enough to observe cancel
        let service = KeyserverRefreshService(
            fetcher: StubFetcher(), importer: importer
        )
        let refresher = ExpiredKeyRefresher(service: service, maxConcurrent: 2)
        let keys = makeKeys(count: 20)
        refresher.start(keys: keys)
        try? await Task.sleep(nanoseconds: 100_000_000)
        refresher.cancel()
        try? await Task.sleep(nanoseconds: 300_000_000)
        let completed = refresher.rowState.values.filter { state in
            if case .idle = state { return false }
            if case .fetching = state { return false }
            return true
        }.count
        #expect(completed < 20, "Expected cancellation to prevent finishing all 20 keys")
    }

    @Test("Row states transition idle → fetching → updated")
    func stateTransitions() async {
        let importer = SlowStubImporter()
        let service = KeyserverRefreshService(
            fetcher: StubFetcher(), importer: importer
        )
        let refresher = ExpiredKeyRefresher(service: service, maxConcurrent: 4)
        let keys = makeKeys(count: 3)
        await refresher.runUntilDone(keys: keys)
        for key in keys {
            #expect(refresher.rowState[key.fingerprint] == .updated)
        }
    }
}

actor AtomicCounter {
    private var current = 0
    private(set) var peakValue = 0
    func enter() {
        current += 1
        if current > peakValue { peakValue = current }
    }
    func leave() { current -= 1 }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `xcodebuild test -only-testing:AlpTests/ExpiredKeyRefresher -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: FAIL with "cannot find 'ExpiredKeyRefresher' in scope".

- [ ] **Step 3: Implement the refresher**

Create `Alp/Sources/ExpiredKeyRefresher.swift`:

```swift
import Foundation
import Observation

/// MainActor state holder for the "check keyserver for expired keys" flow.
/// Holds per-row transition state and a single in-flight task so the banner
/// can offer a `Cancel` button.
@MainActor
@Observable
final class ExpiredKeyRefresher {
    enum RowState: Equatable {
        case idle
        case fetching
        case updated
        case alreadyCurrent
        case notPublished
        case failed(String)
    }

    private(set) var rowState: [String: RowState] = [:]
    private(set) var isRunning = false

    private let service: KeyserverRefreshService
    private let maxConcurrent: Int
    private var currentTask: Task<Void, Never>?

    init(service: KeyserverRefreshService = KeyserverRefreshService(),
         maxConcurrent: Int = 4) {
        self.service = service
        self.maxConcurrent = maxConcurrent
    }

    func start(keys: [GPGKeyInfo]) {
        guard !isRunning else { return }
        isRunning = true
        for key in keys { rowState[key.fingerprint] = .idle }
        currentTask = Task { [weak self] in
            guard let self else { return }
            await self.run(keys: keys)
            await MainActor.run { self.isRunning = false }
        }
    }

    func cancel() {
        currentTask?.cancel()
    }

    /// Convenience for tests — awaits the batch before returning.
    func runUntilDone(keys: [GPGKeyInfo]) async {
        start(keys: keys)
        await currentTask?.value
    }

    private func run(keys: [GPGKeyInfo]) async {
        let semaphore = AsyncSemaphore(value: maxConcurrent)
        await withTaskGroup(of: Void.self) { group in
            for key in keys {
                let service = self.service
                let fp = key.fingerprint
                group.addTask { [weak self] in
                    await semaphore.wait()
                    defer { Task { await semaphore.signal() } }
                    guard !Task.isCancelled else { return }
                    await MainActor.run { self?.rowState[fp] = .fetching }
                    do {
                        let outcome = try await service.refresh(fingerprint: fp)
                        guard !Task.isCancelled else { return }
                        await MainActor.run { [outcome] in
                            switch outcome {
                            case .updated:        self?.rowState[fp] = .updated
                            case .alreadyCurrent: self?.rowState[fp] = .alreadyCurrent
                            case .notPublished:   self?.rowState[fp] = .notPublished
                            }
                        }
                    } catch {
                        let message = (error as? LocalizedError)?.errorDescription
                            ?? String(describing: error)
                        await MainActor.run { self?.rowState[fp] = .failed(message) }
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 4: Run tests**

Run: `xcodebuild test -only-testing:AlpTests/ExpiredKeyRefresher -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/ExpiredKeyRefresher.swift Tests/ExpiredKeyRefresherTests.swift
git commit -m "Add ExpiredKeyRefresher for batch keyserver refresh with cancel"
```

---

## Task 8 — SettingsViewModel: Filter + Counters + Refresher Ownership

**Files:**
- Modify: `Alp/Sources/SettingsViewModel.swift`
- Test: `Tests/KeysViewModelFilterTests.swift` (new)

- [ ] **Step 1: Write the tests**

Create `Tests/KeysViewModelFilterTests.swift`:

```swift
import Foundation
import Testing

@Suite("Keys view model filter")
@MainActor
struct KeysViewModelFilterTests {
    private func makeKey(
        fp: String,
        expired: Bool = false,
        published: Bool = false,
        store: SettingsViewModel
    ) -> GPGKeyInfo {
        let expiry: Date? = expired ? Date(timeIntervalSince1970: 1) : nil
        if published {
            store.keyserverStatus[fp] = .found
        }
        return GPGKeyInfo(
            fingerprint: fp, userIDs: ["User <x@y>"],
            capabilities: "scESC",
            hasSecretKey: false, expiryDate: expiry, subkeys: []
        )
    }

    @Test("filteredKeys(showExpired: false) hides expired primaries")
    func hidesExpired() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: false, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, store: vm)
        ]
        let visible = vm.filteredKeys(showExpired: false)
        #expect(visible.count == 1)
        #expect(visible.first?.fingerprint == String(repeating: "A", count: 40))
    }

    @Test("filteredKeys(showExpired: true) returns everything")
    func showsAll() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: false, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, store: vm)
        ]
        #expect(vm.filteredKeys(showExpired: true).count == 2)
    }

    @Test("expiredPublishedCount counts only published expired primaries")
    func publishedExpiredCount() {
        let vm = SettingsViewModel()
        vm.allKeys = [
            makeKey(fp: String(repeating: "A", count: 40), expired: true, published: true, store: vm),
            makeKey(fp: String(repeating: "B", count: 40), expired: true, published: false, store: vm),
            makeKey(fp: String(repeating: "C", count: 40), expired: false, published: true, store: vm)
        ]
        #expect(vm.expiredPublishedCount == 1)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `xcodebuild test -only-testing:AlpTests/KeysViewModelFilter -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: FAIL — methods don't exist yet.

- [ ] **Step 3: Add the filter methods**

Open `Alp/Sources/SettingsViewModel.swift`. Add inside the `SettingsViewModel`
class:

```swift
    /// Returns the primary keys that should be shown given the "Show expired"
    /// toggle state. A primary is hidden only when its *own* expiry has
    /// passed; subkeys expiring independently do not hide their parent.
    func filteredKeys(showExpired: Bool) -> [GPGKeyInfo] {
        guard !showExpired else { return allKeys }
        return allKeys.filter { !$0.isExpired }
    }

    /// Count of expired primary keys that are published on keys.openpgp.org —
    /// i.e. the ones Alp can plausibly refresh. Used to drive the banner in
    /// `KeySettingsView`.
    var expiredPublishedCount: Int {
        allKeys.filter { key in
            key.isExpired && keyserverStatus[key.fingerprint] == .found
        }.count
    }
```

Also add the refresher as a lazy property:

```swift
    /// Shared across the Keys settings view's banner + per-row actions.
    lazy var expiredRefresher = ExpiredKeyRefresher()
```

- [ ] **Step 4: Run the tests**

Run: `xcodebuild test -only-testing:AlpTests/KeysViewModelFilter -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/SettingsViewModel.swift Tests/KeysViewModelFilterTests.swift
git commit -m "Expose filteredKeys and expiredPublishedCount on SettingsViewModel"
```

---

## Task 9 — Hierarchical Keys Table

**Files:**
- Create: `Alp/Sources/KeyListRow.swift`
- Modify: `Alp/Sources/KeySettingsView.swift`

- [ ] **Step 1: Create the KeyRow wrapper**

Create `Alp/Sources/KeyListRow.swift`:

```swift
import SwiftUI

/// Unified row type for the hierarchical Keys table. Each top-level row is
/// a `.primary`, each nested disclosure row is a `.subkey`.
enum KeyRow: Identifiable, Hashable {
    case primary(GPGKeyInfo)
    case subkey(GPGSubkey, parentFingerprint: String)

    var id: String {
        switch self {
        case .primary(let k):            return "p-\(k.fingerprint)"
        case .subkey(let s, let parent): return "s-\(parent)-\(s.fingerprint)"
        }
    }

    var displayName: String {
        switch self {
        case .primary(let k):   return k.displayName
        case .subkey:           return ""
        }
    }

    var shortFingerprint: String {
        switch self {
        case .primary(let k):    return k.shortFingerprint
        case .subkey(let s, _):  return Self.shortFingerprint(s.fingerprint)
        }
    }

    var expiryDate: Date? {
        switch self {
        case .primary(let k):    return k.expiryDate
        case .subkey(let s, _):  return s.expiryDate
        }
    }

    var isExpired: Bool {
        switch self {
        case .primary(let k):    return k.isExpired
        case .subkey(let s, _):  return s.isExpired
        }
    }

    var isRevoked: Bool {
        switch self {
        case .primary:           return false
        case .subkey(let s, _):  return s.isRevoked
        }
    }

    var capabilityIcons: [String] {
        switch self {
        case .primary(let k):    return Self.primaryIcons(from: k.capabilities)
        case .subkey(let s, _):  return s.capabilityIcons
        }
    }

    /// When this row expands, what does the disclosure triangle reveal?
    /// `nil` means leaf row (no triangle). Empty array means "row can expand
    /// but has nothing to show" — we return `nil` in that case.
    var children: [KeyRow]? {
        switch self {
        case .primary(let k) where !k.subkeys.isEmpty:
            return k.subkeys.map { .subkey($0, parentFingerprint: k.fingerprint) }
        default:
            return nil
        }
    }

    /// The primary row's capability icons also use the
    /// `signature / lock / person.badge.key` mapping; reuse the subkey helper
    /// for consistency.
    private static func primaryIcons(from capabilities: String) -> [String] {
        var icons: [String] = []
        let caps = capabilities.lowercased()
        if caps.contains("s") { icons.append("signature") }
        if caps.contains("e") { icons.append("lock") }
        if caps.contains("a") { icons.append("person.badge.key") }
        if caps.contains("c") { icons.append("checkmark.seal") }
        return icons
    }

    /// Short-form formatter for raw subkey fingerprints — mirrors
    /// `GPGKeyInfo.shortFingerprint`.
    private static func shortFingerprint(_ fingerprint: String) -> String {
        let last16 = String(fingerprint.suffix(16)).uppercased()
        guard last16.count == 16 else { return fingerprint }
        return stride(from: 0, to: 16, by: 4).map { i in
            let start = last16.index(last16.startIndex, offsetBy: i)
            let end   = last16.index(start, offsetBy: 4)
            return String(last16[start..<end])
        }.joined(separator: " ")
    }
}
```

- [ ] **Step 2: Switch the Table to hierarchical rows**

Open `Alp/Sources/KeySettingsView.swift`. Replace the whole `Table(...)` call
site (the block currently rendering the flat table) with this hierarchical
version:

```swift
                Table(of: KeyRow.self, sortOrder: $sortOrder) {
                    TableColumn("Type") { row in
                        KeyRowTypeLabel(row: row)
                    }
                    .width(70)

                    TableColumn("User ID") { row in
                        Text(row.displayName)
                            .lineLimit(1)
                            .strikethrough(row.isRevoked || row.isExpired)
                    }

                    TableColumn("Capabilities") { row in
                        HStack(spacing: 4) {
                            ForEach(row.capabilityIcons, id: \.self) { sym in
                                Image(systemName: sym)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(80)

                    TableColumn("Fingerprint") { row in
                        Text(row.shortFingerprint)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    .width(160)

                    TableColumn("Expires") { row in
                        ExpiryLabel(date: row.expiryDate)
                    }
                    .width(100)

                    TableColumn("keys.openpgp.org") { row in
                        if case .primary(let key) = row {
                            KeyserverStatusLabel(status: vm.keyserverStatus[key.fingerprint])
                        } else {
                            EmptyView()
                        }
                    }
                    .width(140)
                } rows: {
                    ForEach(primaryRows) { primaryRow in
                        if let children = primaryRow.children {
                            DisclosureTableRow(primaryRow) {
                                ForEach(children) { child in
                                    TableRow(child)
                                }
                            }
                        } else {
                            TableRow(primaryRow)
                        }
                    }
                }
```

Add the helper computed property and row-type label below the `body` property:

```swift
    /// Primary-key rows to feed into the Table, after applying the
    /// "show expired" toggle and the user's sort order.
    private var primaryRows: [KeyRow] {
        let filtered = vm.filteredKeys(showExpired: showExpired)
        let sorted = filtered.sorted { a, b in
            for comparator in sortOrder {
                // Compare on the primary-key fields. Subkey rows inherit
                // their parent's sort position.
                let aRow = KeyRow.primary(a)
                let bRow = KeyRow.primary(b)
                switch comparator.compare(aRow, bRow) {
                case .orderedAscending:  return true
                case .orderedDescending: return false
                case .orderedSame:       continue
                }
            }
            if a.hasSecretKey != b.hasSecretKey { return a.hasSecretKey }
            return a.displayName.localizedCompare(b.displayName) == .orderedAscending
        }
        return sorted.map { .primary($0) }
    }
```

Add the show-expired state at the top of the view:

```swift
    @AppStorage("showExpiredKeys") private var showExpired = false
```

Change `sortOrder`'s type to `[KeyPathComparator<KeyRow>]`:

```swift
    @State private var sortOrder: [KeyPathComparator<KeyRow>] = []
```

Add the new row type label below the existing `KeyTypeLabel`:

```swift
private struct KeyRowTypeLabel: View {
    let row: KeyRow
    var body: some View {
        switch row {
        case .primary(let k):
            KeyTypeLabel(hasSecretKey: k.hasSecretKey, isExpired: k.isExpired)
        case .subkey(let s, _):
            HStack(spacing: 4) {
                Image(systemName: "key")
                    .foregroundStyle(.secondary)
                Text(s.isRevoked ? "REVOKED" : "sub")
                    .font(.caption2)
                    .foregroundStyle(s.isRevoked ? .red : .secondary)
                    .strikethrough(s.isRevoked)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel(s.isRevoked ? "Revoked subkey" : "Subkey")
        }
    }
}
```

- [ ] **Step 3: Build**

Run: `xcodebuild build -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: BUILD SUCCEEDED. If `Table rows:` builder syntax fails on this
macOS SDK version, fall back to `Table(primaryRows, children: \.children)` —
both forms render a hierarchical table; the `rows:` builder is just more
explicit about the disclosure relationship.

- [ ] **Step 4: Run the full test suite**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/KeyListRow.swift Alp/Sources/KeySettingsView.swift
git commit -m "Render Keys table with hierarchical subkey rows"
```

---

## Task 10 — Expired Keys Banner + Show/Hide Toggle

**Files:**
- Create: `Alp/Sources/ExpiredKeysBanner.swift`
- Modify: `Alp/Sources/KeySettingsView.swift`

- [ ] **Step 1: Create the banner view**

Create `Alp/Sources/ExpiredKeysBanner.swift`:

```swift
import SwiftUI

/// Above-the-table banner shown when expired keys are visible and at least
/// one of them is published on the keyserver. Swaps to a progress variant
/// while the batch refresh is running.
struct ExpiredKeysBanner: View {
    let expiredPublishedCount: Int
    let isRunning: Bool
    let onCheckNow: () -> Void
    let onCancel: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: isRunning ? "hourglass" : "exclamationmark.triangle.fill")
                .foregroundStyle(isRunning ? .blue : .orange)
                .font(.title3)

            if isRunning {
                Text("Checking \(expiredPublishedCount) expired keys on keys.openpgp.org…")
                    .font(.callout)
                Spacer()
                Button("Cancel", action: onCancel)
                    .keyboardShortcut(.cancelAction)
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    Text("\(expiredPublishedCount) expired keys")
                        .font(.callout.bold())
                    Text("Alp can check keys.openpgp.org for updates.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Check now", action: onCheckNow)
                    .help("Sends each expired key's fingerprint to keys.openpgp.org over a certificate-pinned TLS connection.")
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(.yellow.opacity(0.15))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(.orange.opacity(0.35), lineWidth: 1)
        )
        .padding(.horizontal)
        .padding(.top, 8)
    }
}
```

- [ ] **Step 2: Add the toolbar toggle and wire the banner into KeySettingsView**

Open `Alp/Sources/KeySettingsView.swift`. In the `toolbar` modifier, add:

```swift
            ToolbarItem {
                Toggle(isOn: $showExpired) {
                    Label(showExpired ? "Hide expired" : "Show all",
                          systemImage: showExpired ? "eye.slash" : "eye")
                }
                .toggleStyle(.button)
                .help(showExpired ? "Hide expired keys" : "Show expired keys")
            }
```

Wrap the existing table body in a `VStack` so the banner can sit above it.
Replace the entire `else { Table(...) }` block (added in Task 9) with:

```swift
            } else {
                VStack(spacing: 0) {
                    if showExpired && vm.expiredPublishedCount > 0 {
                        ExpiredKeysBanner(
                            expiredPublishedCount: vm.expiredPublishedCount,
                            isRunning: vm.expiredRefresher.isRunning,
                            onCheckNow: { startBatchRefresh() },
                            onCancel: { vm.expiredRefresher.cancel() }
                        )
                    }
                    Table(of: KeyRow.self, sortOrder: $sortOrder) {
                        TableColumn("Type") { row in
                            KeyRowTypeLabel(row: row)
                        }
                        .width(70)

                        TableColumn("User ID") { row in
                            Text(row.displayName)
                                .lineLimit(1)
                                .strikethrough(row.isRevoked || row.isExpired)
                        }

                        TableColumn("Capabilities") { row in
                            HStack(spacing: 4) {
                                ForEach(row.capabilityIcons, id: \.self) { sym in
                                    Image(systemName: sym)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .width(80)

                        TableColumn("Fingerprint") { row in
                            Text(row.shortFingerprint)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        .width(160)

                        TableColumn("Expires") { row in
                            ExpiryLabel(date: row.expiryDate)
                        }
                        .width(100)

                        TableColumn("keys.openpgp.org") { row in
                            if case .primary(let key) = row {
                                KeyserverStatusLabel(status: vm.keyserverStatus[key.fingerprint])
                            } else {
                                EmptyView()
                            }
                        }
                        .width(140)
                    } rows: {
                        ForEach(primaryRows) { primaryRow in
                            if let children = primaryRow.children {
                                DisclosureTableRow(primaryRow) {
                                    ForEach(children) { child in
                                        TableRow(child)
                                    }
                                }
                            } else {
                                TableRow(primaryRow)
                            }
                        }
                    }
                }
                .onChange(of: showExpired) { _, newValue in
                    if newValue && autoRefresh && vm.expiredPublishedCount > 0 {
                        startBatchRefresh()
                    }
                }
            }
```

Add `startBatchRefresh` as a private method on the view:

```swift
    private func startBatchRefresh() {
        let candidates = vm.allKeys.filter { key in
            key.isExpired && vm.keyserverStatus[key.fingerprint] == .found
        }
        vm.expiredRefresher.start(keys: candidates)
    }
```

Add the auto-refresh preference storage property near the other `@AppStorage`
properties at the top of the view (the `.onChange` modifier is already wired
into the `VStack` above):

```swift
    @AppStorage("autoRefreshExpiredOnShow") private var autoRefresh = false
```

- [ ] **Step 3: Build and run**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests PASS; the build is the implicit check that the new view
compiles.

- [ ] **Step 4: Commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/ExpiredKeysBanner.swift Alp/Sources/KeySettingsView.swift
git commit -m "Add expired keys banner with show-all toggle"
```

---

## Task 11 — Per-Row Context Menu + Row State Indicator

**Files:**
- Modify: `Alp/Sources/KeySettingsView.swift`

- [ ] **Step 1: Add context menu + per-row refresh**

In `KeySettingsView`, modify the `Table` to add a `.contextMenu(forSelectionType:)`
modifier. Since hierarchical Tables can be tricky with selection, simpler
approach: wrap each row's content in a `.contextMenu { }` inside the row
renderer.

Replace the "Type" column's renderer (from Task 9) with a wrapper that also
installs the context menu:

```swift
                    TableColumn("Type") { row in
                        KeyRowTypeLabel(row: row)
                            .overlay(alignment: .trailing) {
                                rowStateBadge(for: row)
                            }
                            .contextMenu {
                                contextMenu(for: row)
                            }
                    }
                    .width(90)
```

Add the helpers at the bottom of the view:

```swift
    @ViewBuilder
    private func contextMenu(for row: KeyRow) -> some View {
        switch row {
        case .primary(let key):
            Button("Copy fingerprint") {
                copyToPasteboard(key.fingerprint)
            }
            Button("Refresh from keyserver") {
                Task { await refreshSingle(fingerprint: key.fingerprint) }
            }
            .disabled(vm.keyserverStatus[key.fingerprint] != .found)
            Button("Reveal on keys.openpgp.org…") {
                openKeyserverPage(for: key.fingerprint)
            }
        case .subkey(let sub, _):
            Button("Copy fingerprint") {
                copyToPasteboard(sub.fingerprint)
            }
        }
    }

    @ViewBuilder
    private func rowStateBadge(for row: KeyRow) -> some View {
        guard case .primary(let key) = row else { return AnyView(EmptyView()) }
        let state = vm.expiredRefresher.rowState[key.fingerprint]
        return AnyView(
            Group {
                switch state {
                case .fetching:
                    ProgressView().controlSize(.mini)
                case .failed(let message):
                    Image(systemName: "xmark.circle.fill")
                        .foregroundStyle(.red)
                        .help(message)
                default:
                    EmptyView()
                }
            }
        )
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }

    private func openKeyserverPage(for fingerprint: String) {
        var components = URLComponents()
        components.scheme = "https"
        components.host = "keys.openpgp.org"
        components.percentEncodedPath = "/pks/lookup"
        components.queryItems = [
            .init(name: "op", value: "get"),
            .init(name: "search", value: "0x" + fingerprint)
        ]
        guard let url = components.url else { return }
        NSWorkspace.shared.open(url)
    }

    private func refreshSingle(fingerprint: String) async {
        let service = KeyserverRefreshService()
        do {
            _ = try await service.refresh(fingerprint: fingerprint)
            await vm.refreshKeys()
        } catch {
            vm.helperError = error.localizedDescription
        }
    }
```

- [ ] **Step 2: Build and run full test suite**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/KeySettingsView.swift
git commit -m "Add per-row context menu and refresh state badge"
```

---

## Task 12 — Rename Toolbar "Refresh" → "Reload" + Auto-Refresh Preference

**Files:**
- Modify: `Alp/Sources/KeySettingsView.swift`
- Modify: `Alp/Sources/GeneralSettingsView.swift`

- [ ] **Step 1: Rename the toolbar button**

In `Alp/Sources/KeySettingsView.swift`, find the existing toolbar item that
says `"Refresh"` and change both the label and the help text:

```swift
            ToolbarItem {
                Button("Reload", systemImage: "arrow.clockwise") {
                    Task { await vm.refreshKeys() }
                }
                .help("Re-read keys from the local keyring")
            }
```

- [ ] **Step 2: Add the Keys sub-section to General settings**

Open `Alp/Sources/GeneralSettingsView.swift`. Add a new `keysSection` view
alongside `setupChecklist`:

```swift
    private var keysSection: some View {
        GroupBox("Keys") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle(isOn: $autoRefreshExpiredOnShow) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Automatically check keyserver when showing expired keys")
                        Text("When enabled, Alp will fetch updates from keys.openpgp.org whenever you reveal expired keys. Uses a pinned TLS connection.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .padding(8)
        }
    }

    @AppStorage("autoRefreshExpiredOnShow") private var autoRefreshExpiredOnShow = false
```

Wire `keysSection` into the body of `GeneralSettingsView`, placed below the
`setupChecklist`:

```swift
        VStack(alignment: .leading, spacing: 16) {
            setupChecklist
            keysSection
            Spacer()
        }
```

- [ ] **Step 3: Build and run**

Run: `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO`
Expected: all tests PASS.

- [ ] **Step 4: Commit**

```bash
swiftlint lint --quiet
git add Alp/Sources/KeySettingsView.swift Alp/Sources/GeneralSettingsView.swift
git commit -m "Rename Refresh to Reload and add auto-refresh preference"
```

---

## Task 13 — Manual Smoke Test and TODO Update

- [ ] **Step 1: Open the built app and smoke test the Keys list**

```bash
xcodebuild build -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO
open ~/Library/Developer/Xcode/DerivedData/Alp-*/Build/Products/Debug/Alp.app
```

Verify by eye:

1. Keys table shows the user's keys with disclosure triangles on primaries that
   have subkeys.
2. Expanding a primary shows subkey rows with capability icons, fingerprint,
   and expiry.
3. Revoked subkeys render with a strikethrough and a red "REVOKED" badge.
4. The "Show all / Hide expired" toolbar toggle actually hides expired primaries.
5. When toggled on with at least one expired+published key, the banner appears.
6. Clicking "Check now" fires the batch; while running, the banner shows the
   progress variant with a Cancel button.
7. Right-clicking a primary row shows the three context menu items; the
   "Refresh from keyserver" item is disabled when the key is not published.
8. "Reload" in the toolbar re-reads the local keyring without touching the
   network (verify via Console.app / network monitor if desired).

- [ ] **Step 2: Update TODO.md**

Open `TODO.md` and move the in-progress line to Done:

```markdown
## In Progress

_nothing in progress_

## Done

- ~~Keys list hierarchy + expired key handling~~ — spec at
  `docs/superpowers/specs/2026-04-11-keys-list-hierarchy-design.md`
- ~~Security audit fixes~~ …
```

- [ ] **Step 3: Commit**

```bash
git add TODO.md
git commit -m "Mark Keys list hierarchy feature as done in TODO"
```

---

## Done Criteria

- All 13 tasks committed.
- `xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO` is green.
- `swiftlint lint --quiet` is silent.
- Manual smoke test of the running app exercises: subkey disclosure, revoked
  strikethrough, show/hide toggle, banner appearance + "Check now" action +
  cancel, per-row context menu with "Refresh from keyserver" / "Copy
  fingerprint" / "Reveal on keys.openpgp.org…", and the renamed "Reload"
  toolbar button.
- `TODO.md` reflects that the feature is complete.
