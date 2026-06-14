# Verifying Alp

This document explains how to convince yourself that the Alp binary on
your Mac is doing what its source code says it does — no analytics, no
phone-home, no keylogging, no key exfiltration. Everything here is
something you can run from your own terminal in a few minutes.

If any check below fails, **do not run the binary**. Open an issue at
<https://github.com/alp-gpg/alp/issues>.

## 1. Confirm the binary signature

```bash
codesign --verify --deep --strict --verbose=2 /Applications/Alp.app
codesign -dvv /Applications/Alp.app 2>&1 | grep -E 'Authority|TeamIdentifier'
```

Expected:

```
Authority=Developer ID Application: Robert Haist (3G6WR6H4M5)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=3G6WR6H4M5
```

Reject any other Team ID. Alp is published only under `3G6WR6H4M5`.

```bash
spctl --assess --type execute --verbose /Applications/Alp.app
```

Expected: `accepted, source=Notarized Developer ID`.

## 2. Confirm the helper signature

The XPC helper runs unsandboxed and is the only component that touches
your gpg binary. Its signature must match the same Team ID as the app.

```bash
codesign -dvv /Applications/Alp.app/Contents/MacOS/AlpHelper 2>&1 | grep TeamIdentifier
```

Alp itself enforces this at runtime: every XPC connection is gated by
`setCodeSigningRequirement` (see `Shared/BuildConfig.swift`). A binary
signed by a different team cannot impersonate the helper.

## 3. Confirm Alp does not phone home on first launch

Alp's update check is **opt-in**. A fresh install makes zero
outbound network calls until you flip the switch under
**General → Updates**. The updater is notification-only — it never
installs anything; at most it tells you a newer notarized DMG exists
and links the download page.

The trade-off: leaving update checks off means you also miss Alp's own
bug fixes and cert-pin rotations until you manually re-download from
GitHub Releases or run `brew upgrade --cask alp`. We recommend enabling
update checks or letting brew carry the load.

Verify with Little Snitch, LuLu, or by tcpdump on an isolated machine:

```bash
sudo tcpdump -i any -nn 'tcp and not port 22'
# Then launch /Applications/Alp.app, open compose, do not enable updates.
# Expected: zero outbound connections.
```

Keyserver lookups (`keys.openpgp.org`, WKD, HKPS pool) are only made
when you explicitly click *Find Key* or refresh a key. Typing a
recipient address triggers a **local** keyring lookup, not a network
call.

## 4. Audit the source code

Alp is intentionally small. The whole codebase is ~10,000 lines of
Swift that map cleanly to the surface area documented in `README.md`.

| Where to look | What it does |
|---------------|--------------|
| `AlpHelper/Sources/GPGHelper.swift` | Drives the `gpg` binary via `Process`. All gpg invocations are constructed here — read this file to know exactly which gpg flags Alp can call. |
| `AlpHelper/Sources/GPGHelper+FileOps.swift` | File-level encrypt/decrypt/sign/verify. Streams gpg via `--output <path>`. |
| `Shared/GPGHelperProtocol.swift` | The XPC API exposed to the sandboxed app and Mail extension. Nothing outside this protocol can be called over XPC. |
| `Alp/Sources/ServicesProvider.swift` | The macOS Services menu entry points (`Decrypt with Alp`, `Decrypt File with Alp`, etc.). |
| `AlpExtension/Sources/SecurityHandler.swift` | MailKit's hook for incoming/outgoing messages. |
| `Alp/Sources/HelperXPCClient.swift` / `AlpExtension/Sources/GPGXPCClient.swift` | The two XPC clients (app + Mail extension) that talk to the helper. |
| `Alp/Sources/KeyserverSession.swift` | The only outbound HTTPS code path. Uses SPKI pinning for `keys.openpgp.org`. |

Read those files (a few thousand lines total) and you have read every
moving part of Alp.

## 5. Audit the gpg invocations

The helper passes an allowlisted environment to gpg (see
`GPGHelper.sanitizedEnvironment` in `GPGHelper.swift`). It strips
`GNUPGHOME`, `DYLD_INSERT_LIBRARIES`, and everything else not on the
allowlist, so a hostile caller can't redirect the keyring or inject a
dylib.

Every fingerprint passed to gpg is validated as 40-char hex via
`GPGHelper.isValidFingerprint`. Argument smuggling like
`--homedir /tmp/evil` is rejected before the `Process` is started.

Every file path passed to a file-op call is validated as absolute and
non-empty by `GPGHelper.validateFileOpPaths`. Input must exist and
output cannot equal input.

## 6. Build it yourself

The most reliable verification is to build Alp from source and compare
behavior. See [BUILDING.md](../BUILDING.md) for the dev setup and
[REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md) for an honest accounting
of what is and is not reproducible across machines. The `Project.swift`
Tuist manifest is the single source of truth for build settings; the
`.xcodeproj` is generated at build time and never committed.

```bash
git clone https://github.com/alp-gpg/alp
cd alp
./scripts/setup.sh
tuist generate
xcodebuild test -workspace Alp.xcworkspace -scheme Alp -destination 'platform=macOS'
```

If the resulting binary behaves the same as the released DMG, you have
end-to-end proof that the released binary matches the source.

## 7. SHA256 checksums

Every release ships a `SHA256SUMS` file alongside the DMG. Verify the
download independently:

```bash
shasum -a 256 -c Alp-<VERSION>.SHA256SUMS
```

Expected: `Alp-<VERSION>.dmg: OK`. Any other output means the bytes
on disk do not match what we released — stop and re-download from the
official GitHub Releases page.

## 8. Update-manifest signing

The update notification is driven by a signed `release.json`. It carries an
Ed25519 signature whose public half is embedded in
`Alp/SupportingFiles/Info.plist` (`AlpUpdatePublicKey`); Alp verifies the
signature over the raw manifest bytes with CryptoKit before showing any
prompt. The matching private key never leaves the release operator's macOS
Keychain. An attacker who hijacks the feed or the GitHub Releases URL can at
worst show a false notification pointing at a binary that must still pass
Gatekeeper and the Team-ID check above — there is no self-installing path to
abuse.

You can confirm the embedded public key by reading the Info.plist:

```bash
/usr/libexec/PlistBuddy -c 'Print :AlpUpdatePublicKey' /Applications/Alp.app/Contents/Info.plist
```

## 9. What Alp does not protect

These are limits, not bugs. We surface them in the app too:

- **Drafts are not encrypted.** Mail saves drafts to IMAP/iCloud before
  Alp can encrypt anything. Turn off "Store drafts on server" in Mail
  Settings → Accounts → Mailbox Behaviors for accounts you use with
  PGP.
- **Subject lines are not encrypted.** RFC 3156 leaves the
  `Subject:` header in the clear.
- **Memo fields written via Services** end up on the pasteboard in
  plaintext. Copy carefully.

If you can find a way around any of these — or a place where Alp does
something the source doesn't explain — file an issue. We mean it.
