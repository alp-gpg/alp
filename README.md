# Alp

A macOS 26 Mail extension that adds GPG sign, encrypt, decrypt, and verify to Apple Mail — using your existing `brew install gnupg` keychain.

## Prerequisites

```bash
brew install gnupg          # primary gpg binary target
brew install tuist          # Xcode project generation
brew install swiftlint swiftformat   # optional: code quality
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

1. Set your **Apple Developer Team ID** — search the project for `TEAMID` and replace with your actual Team ID in:
   - `Project.swift` (bundle IDs)
   - All `*.entitlements` files
   - `AlpHelper/Sources/main.swift` (XPCPeerRequirement comment)
   - `AlpHelper/SupportingFiles/com.TEAMID.alp.helper.plist`

2. **Build & Run** the `Alp` scheme in Xcode.

3. In the running app, click **"Install Helper"** and approve the system prompt.

4. Open **Mail → Settings → Extensions** and enable **Alp**.

## Architecture

```
Mail.app → [MailKit XPC] → AlpExtension (sandboxed)
                                  ↓ NSXPCConnection (Mach service)
                           AlpHelper (unsandboxed, SMAppService daemon)
                                  ↓ Process()
                           gpg binary ↔ gpg-agent ↔ pinentry-mac
```

| Target | Type | Sandbox | Purpose |
|--------|------|---------|---------|
| `Alp` | macOS App | Yes | Settings UI + helper installer |
| `AlpExtension` | Mail Extension | Yes | MailKit protocols, compose toolbar |
| `AlpHelper` | Launchd Daemon | **No** | Calls the gpg binary |

## Using in Mail

**Compose:** A Liquid Glass toolbar panel appears with **Sign** and **Encrypt** toggles.
- **Sign** is on by default.
- **Encrypt** enables automatically when all recipients have public keys in your keyring.
- An orange warning icon appears for recipients with no public key.

**Received messages:** Alp transparently decrypts PGP/MIME and inline-PGP messages and verifies signatures, showing the signer's key fingerprint.

## Development workflow

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

The fingerprint `2BC83F55A4007468864C680E1B7CC8D4D4E914AA` is used as the default test key — change it in `Tests/GPGHelperTests.swift` if needed.

## Security notes

- All gpg operations run in the **unsandboxed** helper (`AlpHelper`) outside of Mail's sandbox.
- The helper only accepts XPC connections from processes with the same Team ID (enforced via `XPCPeerRequirement` — uncomment the requirement string in `main.swift` once you have a signing identity).
- No keys, passphrases, or plaintext are stored by Alp. All key material lives in gpg-agent.
