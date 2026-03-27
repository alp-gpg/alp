# Alp — Apple Mail Extension for GPGTools

## Context

Build a modern macOS **26** Mail extension (MailKit framework) that integrates with an existing GPGTools installation to provide GPG encrypt, decrypt, sign, and verify capabilities inside Apple Mail. Legacy Mail plugins were removed in macOS Sonoma; MailKit is the only supported approach. Because the extension sandbox prevents calling external binaries directly, we bridge to the existing `gpg` binary and `gpg-agent` via an embedded XPC helper — using the user's existing keyring, gpg-agent, and pinentry-mac rather than an independent key store. Uses all latest macOS 26 / Xcode 26 / Swift 6.3 platform features.

## Architecture

```
Mail.app → [MailKit XPC] → AlpExtension (sandboxed)
                                  ↓ NSXPCConnection (Mach service, XPCPeerRequirement)
                           AlpHelper (unsandboxed, SMAppService daemon)
                                  ↓ async Process
                           gpg binary ↔ gpg-agent ↔ pinentry-mac
```

Three Xcode targets, one app bundle:

| Target | Type | Sandbox | Purpose |
|--------|------|---------|---------|
| `Alp` | macOS App | Yes | Wrapper app + settings UI (Liquid Glass) + helper installer |
| `AlpExtension` | Mail Extension | Yes | MailKit protocols, compose toolbar UI |
| `AlpHelper` | Launchd Daemon | **No** | Calls gpg binary; async/await XPC service |

- **App Group:** `group.com.TEAMID.alp` (shared UserDefaults + containers)
- **Bundle IDs:** `com.TEAMID.alp`, `com.TEAMID.alp.extension`, `com.TEAMID.alp.helper`
- **Deployment target:** macOS 26.0
- **Swift:** 6.3, strict concurrency (`-strict-concurrency=complete`)
- **Xcode:** 26

---

## Project Structure

```
/Users/rha/git/alp/
├── .git/
├── .gitignore
├── PLAN.md                        ← this file
├── Alp.xcodeproj/
├── Alp/                        # Target: main app
│   ├── AlpApp.swift            # @main SwiftUI App
│   ├── ContentView.swift          # NavigationSplitView settings root
│   ├── SettingsViewModel.swift    # @Observable view model
│   ├── HelperInstaller.swift      # SMAppService.daemon registration
│   ├── Info.plist
│   └── Alp.entitlements
├── AlpExtension/               # Target: Mail extension
│   ├── AlpExtensionPrincipal.swift   # NSObject, MEExtension
│   ├── SecurityHandler.swift            # MEMessageSecurityHandler
│   ├── ComposeHandler.swift             # MEComposeSessionHandler
│   ├── ComposeViewController.swift      # MEExtensionViewController + NSHostingController
│   ├── ComposeView.swift                # SwiftUI Liquid Glass toolbar panel
│   ├── ComposeViewModel.swift           # @Observable + @MainActor
│   ├── GPGXPCClient.swift               # NSXPCConnection + async wrappers
│   ├── PGPMessageParser.swift           # PGP/MIME & inline PGP detection
│   ├── Info.plist
│   └── AlpExtension.entitlements
├── AlpHelper/                  # Target: unsandboxed XPC daemon
│   ├── main.swift                 # NSXPCListener setup
│   ├── GPGHelper.swift            # actor implementing GPGHelperProtocol
│   ├── com.TEAMID.alp.helper.plist   # launchd plist
│   └── Info.plist
├── Shared/                        # Source files added to multiple targets
│   ├── GPGHelperProtocol.swift    # @objc XPC protocol
│   ├── GPGKeyInfo.swift           # Codable model
│   └── GPGError.swift             # Sendable Error enum
└── Tests/
    ├── GPGHelperTests.swift       # Swift Testing @Suite
    ├── PGPMessageParserTests.swift
    └── XPCRoundtripTests.swift
```

---

## Latest Platform Features Used

| Feature | Where Used |
|---------|-----------|
| `@Observable` macro | All view models — replaces `ObservableObject` |
| Swift 6.3 strict concurrency | Entire codebase; `actor`-isolated helper |
| `async/await` + `CheckedContinuation` | Wrap MailKit completion handlers; XPC calls |
| `XPCPeerRequirement` (macOS 26) | Validate helper code signature before connecting |
| `SMAppService.daemon` | Helper registration — no legacy SMJobBless |
| `glassEffect(.regular, in: .capsule)` | Liquid Glass compose toolbar panel |
| SF Symbols 6 `.symbolEffect(.bounce)` / `.variableColor` | Lock/sign toggle animations |
| Swift Testing `@Test`, `@Suite`, `#expect` | All unit tests |
| `NavigationSplitView` | Settings sidebar + detail |
| `@Bindable` | Bindings into `@Observable` view models |

---

## Shared Protocol — `GPGHelperProtocol.swift`

Added to both `AlpExtension` and `AlpHelper` targets.

```swift
import Foundation

@objc protocol GPGHelperProtocol: NSObjectProtocol {
    func encrypt(data: Data,
                 recipientFingerprints: [String],
                 signingFingerprint: String?,
                 reply: @escaping @Sendable (Data?, NSError?) -> Void)

    func decrypt(data: Data,
                 reply: @escaping @Sendable (Data?, String?, NSError?) -> Void)
    // reply: (plaintext, signerFingerprint?, error?)

    func sign(data: Data,
              signingFingerprint: String,
              reply: @escaping @Sendable (Data?, NSError?) -> Void)

    func verify(data: Data,
                signatureData: Data?,
                reply: @escaping @Sendable (Bool, String?, NSError?) -> Void)
    // reply: (valid, signerFingerprint?, error?)

    func listSecretKeys(reply: @escaping @Sendable ([Data]?, NSError?) -> Void)
    // [Data] = JSON-encoded [GPGKeyInfo]

    func publicKeyExists(email: String,
                         reply: @escaping @Sendable (Bool, String?, NSError?) -> Void)
    // reply: (found, fingerprint?, error?)
}
```

---

## AlpHelper — `GPGHelper.swift`

Unsandboxed `actor` that drives the gpg binary. Auto-detects gpg path
(`/opt/homebrew/bin/gpg` → `/usr/local/bin/gpg` → PATH). All `Process`
launches inherit the user's environment so gpg-agent socket and GNUPGHOME
are resolved correctly. Passphrase prompts are handled transparently by the
existing pinentry-mac.

```
encrypt:  gpg --batch --yes --armor --trust-model always
              --encrypt [--sign --local-user <fp>]
              --recipient <fp>… --output -
decrypt:  gpg --batch --yes --decrypt --status-fd 2 --output -
sign:     gpg --batch --yes --armor --detach-sign --local-user <fp> --output -
verify:   gpg --batch --verify --status-fd 1 <sigfile> -
list:     gpg --list-secret-keys --with-colons --with-fingerprint
check:    gpg --list-keys --with-colons <email>
```

```swift
actor GPGHelper: NSObject, GPGHelperProtocol {
    private let gpgPath: String

    private func runGPG(_ args: [String], input: Data? = nil) async throws -> Data {
        // Process() + Pipe, async via AsyncStream / withCheckedThrowingContinuation
        // stdout captured; stderr checked for GPG error codes
    }

    // Each protocol method calls runGPG, then calls reply(result, nil) or reply(nil, error)
    nonisolated func encrypt(data: Data, recipientFingerprints: [String],
                             signingFingerprint: String?,
                             reply: @escaping @Sendable (Data?, NSError?) -> Void) {
        Task { await self._encrypt(data, recipientFingerprints, signingFingerprint, reply) }
    }
    // … etc
}
```

---

## AlpHelper — `main.swift`

```swift
import Foundation

final class HelperDelegate: NSObject, NSXPCListenerDelegate {
    func listener(_ listener: NSXPCListener,
                  shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // macOS 26: set XPCPeerRequirement to only accept connections from
        // code signed by the same team ID
        connection.exportedInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        connection.exportedObject = GPGHelper()
        connection.resume()
        return true
    }
}

let listener = NSXPCListener(machServiceName: "com.TEAMID.alp.helper")
listener.delegate = HelperDelegate()
listener.resume()
dispatchMain()
```

---

## AlpExtension — `GPGXPCClient.swift`

All protocol methods exposed as `async throws` via `CheckedContinuation`.

```swift
@MainActor
final class GPGXPCClient: @unchecked Sendable {
    static let shared = GPGXPCClient()
    private let connection: NSXPCConnection

    init() {
        connection = NSXPCConnection(machServiceName: "com.TEAMID.alp.helper")
        connection.remoteObjectInterface = NSXPCInterface(with: GPGHelperProtocol.self)
        // TODO: set XPCPeerRequirement for team ID validation
        connection.resume()
    }

    func decrypt(_ data: Data) async throws -> (plaintext: Data, signer: String?) {
        try await withCheckedThrowingContinuation { cont in
            (connection.remoteObjectProxy as! GPGHelperProtocol)
                .decrypt(data: data) { plain, signer, err in
                    if let err { cont.resume(throwing: err) }
                    else { cont.resume(returning: (plain!, signer)) }
                }
        }
    }
    // encrypt, sign, verify, listSecretKeys, publicKeyExists — same pattern
}
```

---

## AlpExtension — `SecurityHandler.swift`

`MEMessageSecurityHandler` — bridges MailKit's completion-handler API to async/await.

```swift
final class SecurityHandler: NSObject, MEMessageSecurityHandler {

    // Called as recipients change in compose window
    func getEncodingStatus(for message: MEMessage,
                           completionHandler: @escaping (MEOutgoingMessageEncodingStatus) -> Void) {
        Task {
            var missing: [String] = []
            for addr in (message.toAddresses + message.ccAddresses) {
                let (found, _) = try await GPGXPCClient.shared.publicKeyExists(addr.address)
                if !found { missing.append(addr.address) }
            }
            completionHandler(MEOutgoingMessageEncodingStatus(
                canSign: true,
                canEncrypt: missing.isEmpty,
                securityError: missing.isEmpty ? nil : GPGError.missingKeys(missing),
                addressesFailingEncryption: missing))
        }
    }

    // Called at send time — returns RFC822 encoded message
    func encode(_ message: MEMessage,
                completionHandler: @escaping (MEEncodedOutgoingMessage?, Error?) -> Void) {
        Task {
            do { completionHandler(try await encodeMessage(message), nil) }
            catch { completionHandler(nil, error) }
        }
    }

    // Called for received PGP messages
    func decodeMessage(_ message: MEMessage,
                       completionHandler: @escaping (MEMessageDecodeResult) -> Void) {
        Task { completionHandler(await decodeIncoming(message)) }
    }

    func securityInformationForMessage(
        _ message: MEMessage,
        completionHandler: @escaping (MEMessageSecurityInformation) -> Void) {
        // Return cached security info (was signed/encrypted, who signed it)
    }
}
```

Both PGP/MIME (RFC 3156 `multipart/encrypted`) and inline PGP
(`-----BEGIN PGP MESSAGE-----`) formats are handled by `PGPMessageParser`
before handing off to the XPC client.

---

## AlpExtension — `ComposeView.swift`

Liquid Glass toolbar panel shown in Mail's compose window.

```swift
struct ComposeView: View {
    @Bindable var vm: ComposeViewModel

    var body: some View {
        HStack(spacing: 12) {
            Toggle(isOn: $vm.shouldSign) {
                Label("Sign", systemImage: "signature")
                    .symbolEffect(.bounce, value: vm.shouldSign)
            }
            .toggleStyle(.button).tint(.blue)

            Toggle(isOn: $vm.shouldEncrypt) {
                Label("Encrypt", systemImage: "lock.fill")
                    .symbolEffect(.variableColor, value: vm.shouldEncrypt)
            }
            .toggleStyle(.button).tint(.green)
            .disabled(!vm.canEncrypt)

            if !vm.missingKeyEmails.isEmpty {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .help("No public key for: \(vm.missingKeyEmails.joined(separator: ", "))")
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
        .glassEffect(.regular, in: .capsule)   // macOS 26 Liquid Glass
        .task { await vm.refresh() }
    }
}
```

---

## Entitlements

**`AlpExtension.entitlements`**
```xml
<key>com.apple.security.app-sandbox</key><true/>
<key>com.apple.security.application-groups</key>
<array><string>group.com.TEAMID.alp</string></array>
<key>com.apple.security.temporary-exception.mach-lookup.global-name</key>
<array><string>com.TEAMID.alp.helper</string></array>
```

**`Alp.entitlements`** — same sandbox + app-groups + `com.apple.smJobBless` true

**`AlpHelper`** — no sandbox entitlement (needs filesystem + exec access for gpg)

---

## Helper Registration — `HelperInstaller.swift`

```swift
import ServiceManagement

func installHelper() throws {
    let service = SMAppService.daemon(plistName: "com.TEAMID.alp.helper.plist")
    try service.register()
}

func uninstallHelper() throws {
    let service = SMAppService.daemon(plistName: "com.TEAMID.alp.helper.plist")
    try service.unregister()
}
```

launchd plist embedded at `Contents/Library/LaunchDaemons/com.TEAMID.alp.helper.plist`:
```xml
<key>Label</key><string>com.TEAMID.alp.helper</string>
<key>MachServices</key><dict>
    <key>com.TEAMID.alp.helper</key><true/>
</dict>
<key>BundleProgram</key>
<string>Contents/Library/LoginItems/AlpHelper.app/Contents/MacOS/AlpHelper</string>
```

---

## Main App Settings (Alp)

```swift
NavigationSplitView {
    List(selection: $selection) {
        Label("General",  systemImage: "gear")
        Label("Keys",     systemImage: "key.fill")
        Label("Helper",   systemImage: "wrench.and.screwdriver")
    }
} detail: {
    switch selection {
    case .general: GeneralSettingsView()   // sign/encrypt defaults
    case .keys:    KeySettingsView()       // lists secret keys via XPC
    case .helper:  HelperStatusView()      // install/uninstall + status
    default:       EmptyView()
    }
}
```

---

## Tests — Swift Testing

```swift
import Testing
@testable import AlpHelper

@Suite("GPG Helper")
struct GPGHelperTests {
    let fingerprint = "2BC83F55A4007468864C680E1B7CC8D4D4E914AA"

    @Test("Round-trip encrypt/decrypt")
    func encryptDecrypt() async throws {
        let helper = await GPGHelper()
        let plaintext = Data("Hello, Alp!".utf8)
        let cipher = try await helper._encrypt(plaintext, [fingerprint], fingerprint)
        let (decrypted, signer) = try await helper._decrypt(cipher)
        #expect(decrypted == plaintext)
        #expect(signer == fingerprint)
    }

    @Test("Sign and verify")
    func signVerify() async throws { … }

    @Test("Missing key disables encrypt")
    func missingKey() async throws { … }
}
```

---

## Implementation Order

1. `git init` + `.gitignore` + `PLAN.md` ← **done**
2. Create `Alp.xcodeproj` with 3 targets + app group capability
3. `Shared/`: `GPGHelperProtocol.swift`, `GPGKeyInfo.swift`, `GPGError.swift`
4. `AlpHelper/`: `GPGHelper.swift` (gpg Process calls) + `main.swift` (XPC listener)
5. `AlpExtension/`: `GPGXPCClient.swift` + `PGPMessageParser.swift`
6. `AlpExtension/`: `SecurityHandler.swift` (encode / decode / status)
7. `AlpExtension/`: `ComposeViewModel.swift` + `ComposeView.swift` + `ComposeViewController.swift`
8. `AlpExtension/`: `AlpExtensionPrincipal.swift`
9. `Alp/`: settings UI + `HelperInstaller.swift`
10. Launchd plist + all entitlements + Info.plists
11. `Tests/` with Swift Testing suite
12. `README.md` — build instructions, enabling the extension in Mail

---

## Verification

1. **Unit tests:** `Cmd+U` in Xcode — encrypt/decrypt/sign/verify against the real key `2BC83F55A4007468864C680E1B7CC8D4D4E914AA`
2. **Helper smoke test:** run `AlpHelper` directly in a terminal, connect manually via `NSXPCConnection`
3. **End-to-end in Mail:**
   - Build & run Alp → click "Install Helper" → grant permission
   - Mail → Settings → Extensions → enable Alp
   - New compose window → Liquid Glass toolbar with lock + sign icons appears
   - Add yourself as recipient → lock icon enables
   - Send → verify `Content-Type: multipart/encrypted` in Sent
   - Open received message → decrypted body + signature badge shown
4. **Edge cases:** missing recipient key (lock disabled + orange warning), gpg not installed (error in HelperStatusView), revoked/expired keys
5. **Console.app** → filter `com.TEAMID.alp.helper` for XPC and gpg diagnostics
