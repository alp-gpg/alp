# Verifying Alp

How to check that the installed Alp matches its source and makes no
unexpected network connections. Every check runs from Terminal.

If any check below fails, **do not run the binary**. Open an issue at
<https://github.com/alp-gpg/alp/issues>.

## 1. Confirm the binary signature

```bash
codesign --verify --deep --strict --verbose=2 /Applications/Alp.app
codesign -dvv /Applications/Alp.app 2>&1 | grep -E 'Authority|TeamIdentifier'
```

Expected:

```text
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

The helper (`AlpHelper`, a launch agent registered via SMAppService) runs unsandboxed and is the only component that touches
your gpg binary. Its signature must match the same Team ID as the app.

```bash
codesign -dvv /Applications/Alp.app/Contents/MacOS/AlpHelper 2>&1 | grep TeamIdentifier
```

Alp itself enforces this at runtime: every XPC connection is gated by
`setCodeSigningRequirement` (calls in `Shared/HelperConnection.swift`
and `AlpHelper/Sources/main.swift`; the requirement strings live in
`Shared/BuildConfig.swift`). A binary
signed by a different team cannot impersonate the helper.

### Which components are sandboxed

Check for yourself:

```bash
codesign -d --entitlements - /Applications/Alp.app
codesign -d --entitlements - /Applications/Alp.app/Contents/PlugIns/AlpExtension.appex
```

`AlpExtension` — the only component that ever sees untrusted input, i.e.
mail from strangers — **is** sandboxed. The app and the helper are not.

That is a deliberate trade, not an oversight. Since macOS 14.2 a sandboxed
app may only register an `SMAppService` agent whose target executable is
also sandboxed. `AlpHelper` has to exec `gpg`, so it cannot be sandboxed —
and while the app was sandboxed, installing the helper failed for everyone
with `deny(1) job-creation` ("Operation not permitted"). Alp is Developer ID
signed and notarized, never App Store, so the app sandbox is optional; the
part that matters — untrusted content stays confined — is unchanged.

Hardened runtime stays on for every binary, and the XPC code-signing
requirement above is what actually keeps other processes away from the
helper.

## 3. Confirm Alp does not phone home on first launch

Alp's update check is **opt-in**. A fresh install makes zero
outbound network calls until you flip the switch under
**General → Updates**. The updater is notification-only — it never
installs anything; at most it tells you a newer notarized DMG exists
and links the download page. With update checks off, you get fixes and
certificate-pin rotations only by downloading new releases from GitHub
Releases manually.

Verify with Little Snitch, LuLu, or by tcpdump on an isolated machine:

```bash
sudo tcpdump -i any -nn 'tcp and not port 22'
# Then launch /Applications/Alp.app, open compose, do not enable updates.
# Expected: zero outbound connections.
```

Keyserver lookups are only made on explicit user action — clicking
_Find Key_, refreshing a key, publishing a key, or (opt-in, off by
default) enabling the publish-status check in General → Keyserver
Security. _Find Key_ tries these sources in order until one returns a
key: `keys.openpgp.org`, the recipient domain's Web Key Directory,
`api.protonmail.ch`, and `keyserver.ubuntu.com`. Typing a recipient
address triggers a **local** keyring lookup, not a network call.

SPKI certificate pinning applies to `keys.openpgp.org` traffic
(`Shared/KeyserverSession.swift`). WKD, Proton, and Ubuntu-pool
lookups and the opt-in update check use plain TLS — their hosts are
either user-derived (WKD) or secondary sources that rotate
certificates on their own schedule.

## 4. Audit the source code

Alp is about 11,000 lines of Swift (excluding tests).

| Where to look                                                                   | What it does                                                                                                                                   |
| ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `AlpHelper/Sources/GPGHelper.swift`                                             | Drives the `gpg` binary via `Process`. All gpg invocations are constructed here — read this file to know exactly which gpg flags Alp can call. |
| `AlpHelper/Sources/GPGHelper+FileOps.swift`                                     | File-level encrypt/decrypt/sign/verify. Streams gpg via `--output <path>`.                                                                     |
| `Shared/GPGHelperProtocol.swift`                                                | The XPC API exposed to the app and the sandboxed Mail extension. Nothing outside this protocol can be called over XPC.                         |
| `Alp/Sources/ServicesProvider.swift`                                            | The macOS Services menu entry points (`Decrypt with Alp`, `Decrypt File with Alp`, etc.).                                                      |
| `AlpExtension/Sources/SecurityHandler.swift`                                    | MailKit's hook for incoming/outgoing messages.                                                                                                 |
| `Alp/Sources/HelperXPCClient.swift` / `AlpExtension/Sources/GPGXPCClient.swift` | The two XPC clients (app + Mail extension) that talk to the helper.                                                                            |
| `Shared/KeyserverSession.swift`                                                 | Shared HTTPS session with SPKI pinning for `keys.openpgp.org`.                                                                                 |
| `Shared/WKDClient.swift`                                                        | Web Key Directory lookups (HTTPS to the recipient's mail domain).                                                                              |
| `Shared/KeyserverUploader.swift`                                                | Key publishing to `keys.openpgp.org` (VKS upload + verify request).                                                                            |
| `Alp/Sources/KeyserverRefreshService.swift`                                     | Per-key refresh from `keys.openpgp.org`.                                                                                                       |
| `Alp/Sources/SettingsViewModel.swift`                                           | Opt-in publish-status check (HEAD request to `keys.openpgp.org`).                                                                              |
| `Alp/Sources/UpdateChecker.swift`                                               | Opt-in update check against `alp-gpg.github.io` (Ed25519-verified).                                                                            |
| `AlpExtension/Sources/ComposeView.swift`                                        | Compose-time _Find Key_ (keys.openpgp.org → WKD → Proton → Ubuntu pool).                                                                       |

Those are **all** of Alp's outbound network call sites.

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

### The pinentry shim

If you enabled "Use Alp Pinentry" (General → Pinentry), Alp writes a
shell script at `~/Library/Application Support/Alp/pinentry` and points
`~/.gnupg/gpg-agent.conf`'s `pinentry-program` directive at it. gpg-agent
execs this shim on every passphrase prompt; the shim resolves the
current Alp.app bundle (via Spotlight if the app was moved) and execs
the embedded `AlpPinentry` binary.

This file is **user-writable** (0755, owned by your user) — any process
running as you could in principle replace it. This is a deliberate
trade-off so app updates and moves don't break the pinentry reference.
The shim itself only execs a code-signed binary inside the app bundle;
it never handles passphrases directly (that's `AlpPinentry`'s job, via
`NSSecureTextField`). To verify the shim hasn't been tampered with:

```bash
cat ~/Library/Application\ Support/Alp/pinentry
```

It should be a short `/bin/sh` script that execs
`$APP_BUNDLE/Contents/Helpers/AlpPinentry`. If it contains anything
else, delete it and re-run "Use Alp Pinentry" from Alp's settings.

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
bash scripts/test.sh
```

Matching behavior is evidence, not proof; see
[REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md) for what can be compared.

## 7. SHA256 checksums

Every release ships `Alp-<VERSION>.SHA256SUMS` and a detached GPG signature,
`Alp-<VERSION>.SHA256SUMS.asc`, alongside the DMG. First check the signature
with the maintainer's key, then the checksum:

```bash
gpg --keyserver hkps://keys.openpgp.org \
    --recv-keys 2BC83F55A4007468864C680E1B7CC8D4D4E914AA
gpg --verify Alp-<VERSION>.SHA256SUMS.asc Alp-<VERSION>.SHA256SUMS
shasum -a 256 -c Alp-<VERSION>.SHA256SUMS
```

Expected from `gpg --verify`: `Good signature`, with primary key fingerprint
`2BC8 3F55 A400 7468 864C  680E 1B7C C8D4 D4E9 14AA`.

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
- **Decrypt with Alp (Services) returns plaintext.** The decrypted text
  passes through the Services pasteboard and replaces the selection in the
  source app, which may save or sync it unencrypted.

If you find a way around any of these, or a place where Alp does
something the source doesn't explain, file an issue.
