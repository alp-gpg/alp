<p align="center">
  <img src="Alp/Resources/Logo/alp-logo.svg" alt="Alp" width="200" />
</p>

<h1 align="center">Alp</h1>

<p align="center">
  A macOS 26 Mail extension that adds GPG sign, encrypt, decrypt, and verify to Apple Mail — using your existing <code>brew install gnupg</code> keychain.
</p>

---

## Prerequisites

```bash
brew install gnupg          # primary gpg binary target
brew install pinentry-mac   # GUI passphrase dialog (required)
brew install tuist          # Xcode project generation
brew install swiftlint swiftformat   # optional: code quality
```

### GPG Configuration

Alp's helper agent runs in the background with no terminal. Your `gpg-agent.conf` **must** specify the GUI pinentry:

```bash
# ~/.gnupg/gpg-agent.conf — required lines:
pinentry-program /opt/homebrew/bin/pinentry-mac
```

Your `gpg.conf` must **not** contain `pinentry-mode loopback` (this forces terminal-based passphrase entry, which fails from a background daemon).

After changing config, restart the agent:

```bash
gpgconf --kill all
```

> **GPGTools users:** `gpg` from `/usr/local/MacGPG2/bin/gpg` is auto-detected as a fallback. Homebrew gnupg takes priority.

## Setup

```bash
# 1. Generate the Xcode project (not committed to git)
tuist generate

# 2. Open in Xcode 26
open Alp.xcworkspace
```

## Build & Run

1. Set your **Apple Developer Team ID** in `Project.swift` — replace `3G6WR6H4M5` with your Team ID in:
   - `Project.swift` (`DEVELOPMENT_TEAM` entries)
   - `AlpHelper/Sources/main.swift` (XPC `setCodeSigningRequirement`)
   - `AlpExtension/Sources/GPGXPCClient.swift` (client-side `setCodeSigningRequirement`)
   - `Alp/Sources/HelperXPCClient.swift` (client-side `setCodeSigningRequirement`)

2. Set your **bundle ID prefix** — replace `com.CXM87Z432P.alp` if needed in:
   - `Project.swift` (all `bundleId` entries)
   - `AlpHelper/SupportingFiles/com.CXM87Z432P.alp.helper.plist`
   - All `*.entitlements` files
   - `AlpHelper/Sources/main.swift` (Mach service name)
   - `AlpExtension/Sources/GPGXPCClient.swift` (Mach service name)
   - `Alp/Sources/HelperXPCClient.swift` (Mach service name)

3. **Build & Run** the `Alp` scheme in Xcode.

4. In the running app, click **"Install Helper"** to register the background agent.

5. Open **Mail → Settings → Extensions** and enable **Alp**.

## Architecture

```
Mail.app → [MailKit XPC] → AlpExtension (sandboxed)
                                ↓ NSXPCConnection (Mach service)
                         AlpHelper (unsandboxed, SMAppService agent)
                                ↓ Process()
                         gpg binary ↔ gpg-agent ↔ pinentry-mac
```

| Target | Type | Sandbox | Purpose |
|--------|------|---------|---------|
| `Alp` | macOS App | No | Settings UI + helper installer |
| `AlpExtension` | Mail Extension | Yes | MailKit protocols, compose toolbar |
| `AlpHelper` | Launch Agent | **No** | Calls the gpg binary |

## Using in Mail

**Received messages:** Alp transparently decrypts PGP/MIME and inline-PGP messages and verifies signatures, showing the signer's key fingerprint.

**Compose:** A toolbar panel appears with **Sign** and **Encrypt** toggles.
- **Sign** is on by default.
- **Encrypt** enables automatically when all recipients have public keys in your keyring.
- A warning icon appears for recipients with no public key.

## Security

- All gpg operations run in the **unsandboxed** helper (`AlpHelper`) outside of Mail's sandbox.
- The helper only accepts XPC connections from processes signed with the same Team ID (enforced via `setCodeSigningRequirement`).
- Client connections (extension → helper) also verify the helper's Team ID signature.
- No keys, passphrases, or plaintext are stored by Alp. All key material lives in gpg-agent.
- The gpg subprocess receives a sanitised environment (allowlisted variables only) to prevent `GNUPGHOME` redirection or `DYLD_INSERT_LIBRARIES` injection.
- XPC payload size is bounded (50 MB) to prevent memory exhaustion.
- Trust model is `tofu+pgp` (Trust-On-First-Use) — warns on key changes rather than blindly trusting all keys.
- All log output uses os_log default privacy (redacted in production). No plaintext, fingerprints, or email addresses are logged.

## Development

```bash
tuist generate          # regenerate Xcode project after Project.swift changes
tuist build             # command-line build (CI)
swiftlint               # lint
swiftformat .           # format
```

The `.xcodeproj` and `.xcworkspace` are **not committed** — regenerate with `tuist generate`.

## Tests

Run the `AlpTests` scheme in Xcode (`⌘U`). Tests require:
- `gpg` installed and reachable
- At least one secret key in your keyring

Tests dynamically discover the first secret key in your keyring — no hardcoded fingerprint needed.

## Known Pitfalls

These are hard-won lessons from debugging. Do not regress:

- **MailKit `@MainActor`**: Every MailKit protocol method and `init()` must be `nonisolated`. MailKit calls from its XPC queue, not the main thread. `@preconcurrency` suppresses compile errors but Swift 6.3 still crashes at runtime.
- **`SMAppService.agent` not `.daemon`**: Daemons run as root and can't access the user's `~/.gnupg` keyring. The main app must **not** be sandboxed (sandboxed apps can't register unsandboxed agents).
- **AlpHelper code signing**: Requires `CREATE_INFOPLIST_SECTION_IN_BINARY`, `OTHER_CODE_SIGN_FLAGS --identifier`, hardened runtime, and Team ID. Without the embedded Info.plist, SMAppService rejects registration.
- **gpg `--batch` and decrypt**: The `--batch` flag prevents pinentry passphrase prompts. Never use it for decrypt.
- **Pipe deadlock**: stdout and stderr from gpg must be read concurrently. Sequential reads deadlock when either pipe's 64 KB OS buffer fills.
- **gpg `--verify` exit code**: Non-zero exit is valid (bad/untrusted signature). Use the raw runner and parse status output regardless of exit code.

## License

MIT
