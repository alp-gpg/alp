# Alp — Code Review: robustness, macOS compliance, security UX, dependencies

**Reviewed at commit `951aeb5`** (branch `claude/code-review-macos-security-3x9ojy`), 2026-06-11.

Alp is a genuinely well-built, security-conscious app. The XPC trust boundary
is correct, gpg argument handling is carefully defended, destructive actions are
well-confirmed, and the privacy posture (no phone-home, consent-default-off
updates, honest drafts/subject warnings) is exemplary. The findings below are
about the gaps that remain — and a few are serious.

This report covers four areas: correctness/security of the crypto core, the
MailKit extension and app UX, macOS platform compliance, and dependency/SDK
currency including the Sparkle auto-updater.

---

## Contents

- [Changes already landed on this branch](#changes-already-landed-on-this-branch)
- [Severity legend](#severity-legend)
- [1. Correctness bugs that undermine the security promise](#1-correctness-bugs-that-undermine-the-security-promise)
- [2. Security hardening (crypto core / helper / pinentry)](#2-security-hardening-crypto-core--helper--pinentry)
- [3. Robustness](#3-robustness)
- [4. macOS compliance & idiom](#4-macos-compliance--idiom)
- [5. Security UX](#5-security-ux)
- [6. Dependencies, SDK currency & release pipeline](#6-dependencies-sdk-currency--release-pipeline)
- [7. Sparkle: recommendation to remove](#7-sparkle-recommendation-to-remove)
- [8. Strengths worth preserving](#8-strengths-worth-preserving)
- [Suggested order of work](#suggested-order-of-work)

---

## Changes already landed on this branch

Two additive, low-risk helper hardening fixes (with tests) were implemented and
pushed, because they are well-contained and clearly correct by inspection:

1. **Decompression-bomb DoS bound** — `_decrypt` now passes `--max-output` to
   gpg so a compressed OpenPGP packet that expands to many GB aborts instead of
   OOM-killing the helper. (Commit `afc1edd`.)
2. **Shell-injection guard on the pinentry shim** — `_installAlpPinentry` now
   validates `bundlePath` before interpolating it into the persisted `/bin/sh`
   shim gpg-agent executes on every passphrase prompt. (Commit `afc1edd`.)

> **Everything else in this report is documented, not implemented.** This review
> was performed in an environment without a Swift toolchain, and the repository's
> CI builds against a real macOS 26 SDK. The remaining fixes — especially the
> MIME-correctness changes, compose-state persistence, and Sparkle removal — need
> compilation and (for the release items) release-infrastructure changes to land
> safely. Pushing them blind would risk a red CI and, worse for a crypto app,
> subtle untested behavior. They are specified precisely so they can be
> implemented and tested directly.

## Severity legend

- **Critical** — can cause silent loss of confidentiality/authenticity, or data loss.
- **High** — wrong security result or a path that breaks a core promise.
- **Medium** — incorrect behavior, robustness gap, or compliance issue.
- **Low** — polish, idiom, maintainability.

---

## 1. Correctness bugs that undermine the security promise

### 1.1 [High] PGP/MIME signature verification hashes the wrong bytes
`Shared/PGPMessageParser.swift:102-112` (consumed by `AlpExtension/Sources/SecurityHandler.swift:198-208`)

`partBody` strips the part's MIME headers and trims whitespace, but RFC 3156
signs the **entire first MIME part** — its headers, body, and exact CRLFs — up
to (not including) the CRLF before the closing boundary.

```swift
func partBody(_ part: String) -> Data? {
    let stripped: String = if let r = part.range(of: "\r\n\r\n") ?? part.range(of: "\n\n") {
        String(part[r.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
    } else {
        part.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    return stripped.data(using: .utf8)
}
```

Standards-compliant signed mail (Thunderbird, GnuPG/Enigmail, Proton export)
will show **"Invalid signature"** on genuinely valid messages. Even Alp's own
sign→verify round-trip fails: `pgpMIMESigned` signs `canonicalBody` *including*
its RFC 822 headers (`SecurityHandler.swift:284-288`), but on read-back
`partBody` strips those headers before verifying. Training users to see and
ignore false invalid-signature banners is itself a security harm.

**Fix:** extract the first part as **raw bytes** between the boundary
delimiters (after the CRLF that follows `--boundary`, up to but excluding the
CRLF before the next `--boundary`), with no header stripping and no trimming;
pass that to `verify(_:signature:)`. The existing tests
(`Tests/PGPMessageParserTests.swift`) assert only *detection*, never
byte-exactness — add a round-trip test that signs and then verifies the same
bytes.

### 1.2 [Critical] Compose state can fail open to plaintext
`Shared/ComposeSessionStore.swift:71-81`, `AlpExtension/Sources/SecurityHandler.swift:115-117`, `AlpExtension/Sources/ComposeViewModel.swift:120-133`

Per-window sign/encrypt state lives only in the extension process's memory
(`ComposeSessionStore.shared`). At send time `encode()` looks it up by context
ID and **silently falls back to global defaults on a miss**:

```swift
let state = contextToSession[contextID].flatMap { sessions[$0] }
return (
    state?.shouldSign    ?? shouldSignFallback,     // "signByDefault"    (off by default)
    state?.shouldEncrypt ?? shouldEncryptFallback,  // "encryptByDefault" (off by default)
    ...
)
```

If the extension process is torn down between the user toggling Encrypt ON and
pressing Send (jetsam, crash, Mail relaunch restoring a compose window), the
registered state is gone and the message is sent **unencrypted and unsigned
with no error and no warning** — the exact failure mode this kind of tool must
never have. The codebase already shows awareness that the extension restarts
(the `extensionLastSeen` heartbeat in `AlpExtensionPrincipal.swift:12`).

**Fix:** have `ComposeViewModel.syncStateToStore()` write-through persist
`contextID → State` into the app-group `UserDefaults` (it already holds the
suite), and have `state(forContextID:)` read that before falling back to global
defaults; expire entries in `unregister`. Alternatively, fail closed: if a
persisted record says the user enabled encryption for this context but the
in-memory state is missing, return an encoding error rather than plaintext.

### 1.3 [High] Outgoing encrypted mail is not encrypted to the sender
`AlpExtension/Sources/SecurityHandler.swift:244-269`, confirmed against `AlpHelper/Sources/GPGHelper.swift:145-156`

`buildOutgoing` collects fingerprints only for `recipientEmails` (To/Cc/Bcc);
`_encrypt` adds only `--recipient fp` per entry and no self key. Unless the
user's personal `gpg.conf` contains `encrypt-to`, every message they send
encrypted is **undecryptable by themselves** — opening their own Sent items
yields a decryption error. This is the single most common complaint pattern for
naive PGP-mail integrations.

**Fix:** append the user's own encryption key to the recipient list in
`buildOutgoing` (ideally as a hidden recipient), behind a settings toggle
"Encrypt to my own key" defaulting ON.

### 1.4 [High] Recipient key availability is only computed when the compose panel (re)appears
`AlpExtension/Sources/ComposeView.swift:98`, `AlpExtension/Sources/ComposeViewModel.swift:35-64`, `AlpExtension/Sources/ComposeHandler.swift`

`vm.refresh()` runs only in `.task { await vm.refresh() }` (when the toolbar
panel becomes visible) and after a key import. The handler implements no
`annotateAddressesForSession`, so:

- A new message starts with zero recipients → `canEncrypt` is `false` → Encrypt
  disabled. The user must close and reopen the Alp panel after adding recipients.
- Editing recipients with the panel open never updates `canEncrypt` /
  `missingKeyEmails`; the warning triangle and tooltips show stale data.

**Fix:** implement
`MEComposeSessionHandler.annotateAddressesForSession(_:completionHandler:)` —
Mail calls it as addresses change — and route it into `vm.refresh()`. The
annotation API also lets you mark key-less addresses red inline, a large UX win.

---

## 2. Security hardening (crypto core / helper / pinentry)

> Items 2.1 and 2.2 are **fixed on this branch** (commit `afc1edd`). They are
> listed here for completeness of the security picture.

### 2.1 [High — FIXED] Unbounded gpg stdout enabled a decompression-bomb DoS
`AlpHelper/Sources/GPGHelper.swift:108-117` (`runGPGRaw`)

`readDataToEndOfFile()` read all gpg stdout into memory with no cap. Input was
capped at `maxPayloadSize` (50 MB) but **output was not**, and `_decrypt` is
driven by the sandboxed Mail extension with attacker-controlled ciphertext from
incoming email. A highly compressed literal packet ("zip bomb") expands to many
GB during `gpg --decrypt`, OOM-killing the helper with no user interaction.

**Fix applied:** `_decrypt` passes `--max-output <4 × maxPayloadSize>` so gpg
aborts instead of exhausting memory.

### 2.2 [Medium — FIXED] Shell injection into the persisted pinentry shim
`AlpHelper/Sources/GPGHelper.swift:795-823` (`_installAlpPinentry`)

`bundlePath` was interpolated straight into a `/bin/sh` script persisted at
`~/Library/Application Support/Alp/pinentry` (0755) and executed by gpg-agent as
the user on every passphrase prompt. A `bundlePath` containing `"`, `` ` ``, or
`$(...)` would inject code. The legitimate caller passes `Bundle.main.bundlePath`,
but the helper trusted it blindly while validating every other XPC argument.

**Fix applied:** new `isValidBundlePathForShim` rejects shell metacharacters
(`" $ \ ``), control chars, relative paths, and anything not ending in `.app`;
`_installAlpPinentry` guards on it. Covered by `GPGHelperShimPathValidationTests`.

### 2.3 [Medium] No timeout on gpg subprocesses
`AlpHelper/Sources/GPGHelper.swift:108-117`

`runGPGRaw` does `readDataToEndOfFile()` then `waitUntilExit()` with no timeout
or `terminate()` path. If gpg/gpg-agent/pinentry wedges, the call never returns;
the XPC client gives up after 60s/300s but the helper's `Process` keeps running
indefinitely, orphaning gpg processes and pinning a cooperative-pool thread
(the blocking reads run synchronously inside the `GPGHelper` actor's async
methods).

**Fix:** add a watchdog that calls `terminate()` (then SIGKILL) after a bound
matched to the client timeout; run the blocking pipe reads off the actor's
executor. Use the longer interactive bound for pinentry-driven calls.

### 2.4 [Medium] Fragile keyserver certificate pinning
`Shared/KeyserverSession.swift:37-45`

Pins the single Let's Encrypt **E7** intermediate, but Let's Encrypt rotates
issuance across **E5–E9** (and is rolling out a new "Generation Y" hierarchy),
so pin misses will be routine. Only the ECDSA root (ISRG Root X2) is pinned —
an RSA-chain cert would miss entirely. In strict mode this intermittently
breaks key lookups; in the default mode it silently degrades to standard TLS far
more often than intended.

**Fix:** pin the **long-lived ISRG roots — both X1 and X2** — instead of the
volatile intermediate; roots are stable for years and cover both chains.
Regenerate the hash values via the existing `KeyserverPinningTests` canary,
which prints the current chain hashes on mismatch. (Hash values were left
unchanged in this pass rather than guessed — a wrong pin is worse than the
status quo.) Note: the stored values are `SecKeyCopyExternalRepresentation`
digests, not true SPKI DER, so the `pinnedSPKIHashes` name is misleading and the
values can't be cross-checked against public pin databases.

### 2.5 [Low] Passphrase held in a non-zeroizable `String` in the pinentry
`AlpPinentry/Sources/main.swift:170, 264`

The entered passphrase lives in `NSSecureTextField.stringValue` and a Swift
`String`, is `Assuan.encode`d into another `String`, and is never wiped. Swift
`String` storage can't be reliably zeroed. `NSSecureTextField` does enable
secure event input while first-responder (good), but the cleartext lingers in
the heap after the prompt closes. This is the only component that ever sees
passphrases in cleartext (the helper itself never touches them).

**Fix:** build the `D` line in a mutable `Data`/`[UInt8]` and `resetBytes` it
after writing to stdout; pull from the field's secure storage where possible.

### 2.6 [Low] Assuan percent-decoder treats each `%XX` as a Unicode scalar, not a byte
`AlpPinentry/Sources/main.swift:27-33`

`UInt8(hex)` is appended via `Unicode.Scalar(v)`, so a UTF-8 sequence like
`%C3%A9` decodes to `Ã©` instead of `é`. Affects SETDESC/SETPROMPT *display*
strings only (cosmetic). The encode side is correct for passphrases.

**Fix:** accumulate decoded bytes into `Data` and decode as UTF-8 once.

### 2.7 [Low] File-op paths are not symlink-resolved
`AlpHelper/Sources/GPGHelper+FileOps.swift:169-174`

`outputPath == inputPath` is a string compare only, and `isValidAbsolutePath`
does not canonicalize (acknowledged in code). Not a privilege boundary crossing
(helper runs unsandboxed as the user; only signed clients connect), but a
symlinked output path could clobber an unexpected file. Optional `realpath`
re-check for defense in depth.

---

## 3. Robustness

### 3.1 [Medium] Unsynchronized mutable dictionary in the compose handler
`AlpExtension/Sources/ComposeHandler.swift:5`

```swift
private nonisolated(unsafe) var controllers: [UUID: ComposeViewController] = [:]
```

`viewController(for:)` and `mailComposeSessionDidEnd` both mutate it; MailKit
calls arrive on its private XPC queue while view-controller creation must be
main-thread, so two isolation domains touch this dictionary with
`nonisolated(unsafe)` suppressing the checker. A real data race with multiple
compose windows. Confine to `@MainActor` or guard with a lock.

### 3.2 [Medium] Helper failure renders as "No Keys Found" with a Generate button
`Alp/Sources/SettingsViewModel.swift:243-246`, `Alp/Sources/KeySettingsView.swift:78-87`

```swift
} catch {
    allKeys = []
    secretKeys = []
}
```

A transient helper/XPC error empties the key list and the UI shows "No Keys
Found — Generate a new pair…". For a user with years of keys this reads as data
loss and invites generating a duplicate. Track a `keysLoadError` and show an
error state with Retry.

### 3.3 [Medium] `decodedMessage` over-claims and over-decrypts
`AlpExtension/Sources/SecurityHandler.swift:35-59`, `Shared/PGPMessageParser.swift:49-53`

- Non-PGP messages return `MEDecodedMessage(.notSecured)` instead of `nil`,
  routing all mail through the extension's re-serialization path unnecessarily.
- `parse` scans the **entire body** for `-----BEGIN PGP MESSAGE-----`, so a plain
  email *quoting* an armored block (a tutorial, a forward) is treated as
  inline-encrypted: gpg runs, **pinentry may pop up** for a message the user just
  clicked, and on failure an error banner appears on readable mail.

**Fix:** restrict inline detection to messages whose text/plain part actually
begins with an armor block; return `nil` from `decodedMessage` when `parse`
returns nil.

### 3.4 [Medium] Network-dependent unit test
`Tests/KeyserverPinningTests.swift`

Performs a live TLS handshake to `keys.openpgp.org` inside the unit suite —
flaky in CI and a remote dependency in every `xcodebuild test`. Move to an
integration lane or gate behind an env flag; keep the canary's
actionable-output behavior.

### 3.5 [Low] XPC invalidation handler overwrite under concurrency
`Alp/Sources/HelperXPCClient.swift:537`, `AlpExtension/Sources/GPGXPCClient.swift:179`

Both clients set `connection.invalidationHandler` per call; with concurrent
calls only the most recent handler fires on invalidation, so earlier calls wait
out their 60s/300s timer. The timer prevents a hang but failure is needlessly
slow. Propagate per-call errors via the proxy error handler, or fail all
in-flight calls.

### 3.6 [Low] `RecipientPickerWindow` leaks the window
`Alp/Sources/RecipientPickerWindow.swift:40-58`

`onComplete` (captured by the hosted view) retains `window` →
`contentViewController` → view → closure; with `isReleasedWhenClosed = false`
the window survives each Encrypt-File service invocation.

---

## 4. macOS compliance & idiom

### 4.1 [Medium] No `Settings` scene; multiple settings windows
`Alp/Sources/AlpApp.swift:28-32`, `Alp/Sources/ContentView.swift:9`

Uses `WindowGroup`; ⌘, does nothing, and File ▸ New Window spawns independent
windows each with its own `SettingsViewModel` and periodic health-check loop —
two windows can disagree about helper status. Use a single `Window` instance, or
a real `Settings` scene plus `openSettings`.

### 4.2 [Medium] "Verify with Alp" service destroys the user's selection
`Alp/SupportingFiles/Info.plist:76-79`, `Alp/Sources/ServicesProvider.swift:55-70`

The verify service declares `NSReturnTypes: NSStringPboardType`, so AppKit
replaces the user's selected (signed) text with the status string — destroying
the text it just verified, contradicting the code's own comment. Drop
`NSReturnTypes` for the verify service and present an alert/notification like the
file services do.

### 4.3 [Medium] Services may block the main thread for up to 300 s
`Alp/Sources/ServicesProvider.swift:319-365`

`runService` blocks the calling thread on a semaphore (`blockingAwait`) for up
to the interactive timeout (decrypt → pinentry, 300 s). The whole design rests
on the assumption that "AppKit dispatches Services on a dedicated queue"; if that
is wrong, Alp beachballs for the entire passphrase interaction. Verify the
threading assumption; note the `@objc` methods are `@MainActor` (class
isolation) while `runService` is `nonisolated`, so one of the two isolation
assumptions must be wrong under strict checking.

### 4.4 [Low] Extension can't localize
`AlpExtension/Resources/` (no string catalog)

The app target has a well-tended `Localizable.xcstrings`, but the extension
target has no catalog, so the compose UI and `GPGError`'s `String(localized:)`
strings can't localize in that bundle. Several `NSAlert` literals in
`KeySettingsView` and `ServicesProvider` are plain literals that bypass
localization entirely.

### 4.5 [Low] Deprecated `Alert` API
`Alp/Sources/KeySettingsView.swift:325-339`

The delete-key confirm uses the deprecated `Alert` value type while the rest of
the file uses the modern `.alert` modifiers. Works, but will rot.

---

## 5. Security UX

### 5.1 [High] "Generate Revocation Certificate…" actually revokes the key immediately
`Alp/Sources/KeySettingsView.swift:417, 246-258`, `Shared/GPGHelperProtocol.swift:333-345`

The context-menu label promises the standard "generate a revocation cert as an
offline backup" workflow, but the RPC imports the certificate and revokes the key
on the spot. It also offers the cert via a save panel *after* revocation — cancel
the panel and the cert is lost while the key stays revoked. A user following the
conventional best practice (generate a revocation cert right after key creation,
store it offline) will destroy their key.

**Fix:** expose the helper's generate-only path (`GPGHelper+Backup.swift:84`);
rename the destructive action "Revoke Key…" with an explicit confirm button; and
write the cert to disk *before* importing it.

### 5.2 [Medium] Autocrypt auto-imports silently with no provenance
`AlpExtension/Sources/SecurityHandler.swift:47-49, 150-163`

Every decoded message triggers `tryAutocryptImport`. The `addr`/`From` match is
good hygiene, but `From` is attacker-controlled: a forged `From` plus the
attacker's key gets imported silently when no key is held for that address, then
shows as encryptable in compose — indistinguishable from a deliberately imported
key. This is the accepted Autocrypt TOFU tradeoff, but Alp surfaces **no
provenance or trust indication anywhere**.

**Fix:** tag Autocrypt-origin keys (the helper can record origin) and surface it
in the Keys table and compose tooltip; skip import for junk-flagged mail.

### 5.3 [Medium] `getEncodingStatus` misdiagnoses a stopped helper
`AlpExtension/Sources/SecurityHandler.swift:63-100`

The `composeContext` is discarded, so the status doesn't consult
`ComposeSessionStore`: (a) a "Missing public keys" error is reported even when
the user never enabled encryption; (b) any XPC failure is folded into "missing
keys" (`catch { missingEmails.append(email) }`), producing the cryptically wrong
"Missing public keys for: \<every recipient\>" instead of the actionable
`xpcUnavailable` text it already has. Look up `state(forContextID:)`, suppress
the error when `shouldEncrypt == false`, and surface `xpcUnavailable` distinctly.

### 5.4 [Medium] Inline-PGP transfer-encoding mishandling
`AlpExtension/Sources/SecurityHandler.swift:242-289`, `Shared/OutgoingMIMEParser.swift:67-108`

`OutgoingMIMEParser.split` returns body bytes verbatim — still quoted-printable
or base64 if Mail encoded them — and `rewriteContentTypeHeaders` relabels them
`text/plain; 7bit` **without decoding**. A clearsigned `café` becomes `caf=C3=A9`
on the recipient's screen, and inline-encrypted bodies decrypt to QP soup. Decode
the Content-Transfer-Encoding before clearsigning/encrypting, or return `nil`
(fall back to PGP/MIME) when CTE isn't 7bit/8bit.

### 5.5 [Medium] Inconsistent header handling between inline and PGP/MIME builders
`AlpExtension/Sources/SecurityHandler.swift:298-305 vs 313-365`

`inlinePGPMessage` returns a complete RFC 822 message (Subject/From/Date
preserved), while `pgpMIMEEncrypted`/`pgpMIMESigned` start at `Content-Type:
multipart/...` with no top-level headers and no `MIME-Version`. At most one
matches what Mail expects from `MEEncodedOutgoingMessage(rawData:)`. Also verify
`message.rawData` excludes `Bcc:` at encrypt time, or Bcc identities leak inside
the encrypted payload to all recipients. Add an integration test capturing the
actual sent bytes for both paths.

### 5.6 [Low] Raw gpg stderr surfaces to users
`Shared/GPGError.swift:20-21`

`GPGError.processError` renders `gpg exited with code N: <stderr>`. Actionable
for experts, cryptic for the target audience. Map the common cases to plain
guidance.

### 5.7 [Low] Other UX polish
- **Keyring-wide keyserver presence checks with no opt-out** —
  `Alp/Sources/SettingsViewModel.swift:239-241, 287-307` HEAD-requests
  `keys.openpgp.org` for *every* key on every load/refresh, disclosing the whole
  contact-key graph. For a "no phone-home without consent" app this deserves a
  toggle.
- **Helper-down compose tooltips mislead** —
  `AlpExtension/Sources/ComposeViewModel.swift:53-61`: with the helper dead,
  `canEncrypt` can be `true` and encryption fails only at send. Detect
  `xpcUnavailable` and show a dedicated "Alp helper not running" affordance.
- **Update toggle is next-launch only** — `Alp/Sources/GeneralSettingsView.swift:301`
  writes `SUEnableAutomaticChecks` to defaults but the running `SPUUpdater`
  won't observe it; no "takes effect after relaunch" hint.
- **`ExpiredKeyRefresher` success states unsurfaced** —
  `Alp/Sources/KeySettingsView.swift:440-453` renders only `.fetching`/`.failed`;
  `.updated`/`.alreadyCurrent`/`.notPublished` never reach the user.
- **No way to cancel a wedged generate/pinentry** — `GenerateKeySheet` disables
  Cancel while `isGenerating` and the call can take up to 300 s.

---

## 6. Dependencies, SDK currency & release pipeline

| Dependency | Where pinned | Pinned | Latest | Status |
|---|---|---|---|---|
| Sparkle | `Project.swift:32`, `.package.resolved` | 2.9.2 | 2.9.3 | 1 patch behind (cosmetic). 2.9.2 already has the recent security fixes. **Only SPM dependency.** |
| Tuist | **unpinned** — `scripts/setup.sh`, both workflows do bare `brew install tuist` | floating | 4.x | Generates the whole Xcode project; floating contradicts the reproducible-build doc |
| Xcode / macOS SDK | `Tuist.swift`, workflows (26.4 → 26.3 → 26.2 fallback) | 26.4 | 26.4.x | Current-ish |
| actions/checkout | workflows | v6 | v6 | Current |
| softprops/action-gh-release | `release.yml:85` | v2 | v3 | One major behind; third-party action holding secrets |

### Findings
- **[Medium] `upToNextMajor` on the security-sensitive updater** —
  `Project.swift:32`. `.package.resolved` mitigates, but neither CI nor the
  release build passes `-onlyUsePackageVersionsFromResolvedFile`, so a fresh
  runner could resolve a newer Sparkle than was audited. Use `.exact` or enforce
  the resolved file in CI.
- **[Medium] Tuist unpinned in the release path** — `release.yml`. Pin via
  `.tuist-version`/mise or a versioned cask.
- **[Medium] GitHub Actions pinned by mutable tag, not SHA** — the release
  workflow holds Developer ID + Apple ID secrets and `contents: write`. Pin
  third-party actions by full commit SHA.
- **[Low] No Dependabot/Renovate** watching Sparkle or the actions.
- **[Good] `scripts/setup.sh` has no `curl | bash`** — refuses to install
  Homebrew itself; clean.
- **[Low] Doc rot** — `docs/REPRODUCIBLE-BUILD.md` references a
  `Tuist/Package.swift` that doesn't exist; `setup.sh` runs `tuist install`
  which is a no-op/error without it.

### Two release-pipeline bugs that mean no release has ever shipped end-to-end
- **[High] Updates can never be offered: `CURRENT_PROJECT_VERSION` is hardcoded
  `"1"`** — `Project.swift:17`, never injected by `build-release.sh` or
  `release.yml`. Sparkle compares the appcast's `<sparkle:version>` against the
  installed CFBundleVersion; every release ships build `1`, so v1.0.1 is never
  newer than v1.0.0. `CFBundleShortVersionString` is likewise hardcoded `1.0`
  (`Info.plist:12`), so `Alp-1.2.3.dmg` would contain an app claiming 1.0.
  **Fix this regardless of the Sparkle decision** — no updater of any kind can
  fire without it.
- **[High] `notarytool submit` is given a bare `.app`** —
  `scripts/build-release.sh:52`. notarytool only accepts `.zip`/`.dmg`/`.pkg`, so
  the pipeline breaks at notarization. Fix:
  `ditto -c -k --keepParent "$APP_PATH" Alp.zip`, submit the zip, staple the app;
  ideally also notarize the final DMG.
- **[Medium] Appcast signing is manual and out-of-band** —
  `build-release.sh:89-101` only prints the `sign_update` line; CI never installs
  the Sparkle CLI or holds the EdDSA key, so on CI the signature step is always
  skipped. The operator must run `sign_update` locally and hand-edit
  `docs/appcast.xml`.
- **[Medium] EdDSA private key lifecycle** — lives solely in the operator's login
  Keychain; no documented backup, rotation, or compromise procedure. Single
  laptop = single point of failure for the update channel.
- **[Low] `SHA256SUMS` is unsigned** — uploaded to the same release as the DMG, so
  it defends against corruption, not substitution. For a GPG project, ship a
  detached GPG signature on it.
- **[Low] Unnecessary sandbox exception** — `Alp.entitlements` grants mach-lookup
  for `org.sparkle-project.Downloader`, but that XPC service is for apps *without*
  `network.client` — which Alp has. Dead weight; only `InstallerLauncher` is
  needed.

---

## 7. Sparkle: recommendation to remove

The footprint is minimal and vanilla: one `SPUStandardUpdaterController`
(`AlpApp.swift:15-26`), one "Check for Updates…" menu item, one opt-in toggle, an
empty appcast template, and full-DMG enclosures only — **no deltas, channels,
phased rollout, or custom UI**. With `SUAutomaticallyUpdate=false`, its only
value today is "check, show dialog, download, verify EdDSA, swap the bundle when
the user clicks Install" — and the user already clicks through every update.

Sparkle is also ~75% of the third-party code in a product whose entire pitch
(`docs/VERIFYING.md`) is "small enough to audit every moving part," and it forces
two `temporary-exception.mach-lookup` entitlements that security-minded users
notice.

### Recommendation: replace with a notification-only updater (~250–400 LOC)

The app is **sandboxed** in Release (`Alp.entitlements`), so a self-replacing
updater would need either to drop the sandbox or teach the unsandboxed
**AlpHelper** to replace the whole app — turning "the one component that touches
your gpg" into one that can replace the entire app, plus re-implementing
Sparkle's genuinely hard quarantine/App-Translocation/atomic-swap logic (which
would hit Alp's `Contents/Library/LaunchAgents` plist and in-bundle pinentry shim
paths especially hard). A notification-only design has a strictly smaller blast
radius than any self-installing design, Sparkle included.

**Implementation sketch:**
1. `Alp/Sources/UpdateChecker.swift` (~150 LOC, `@Observable`): `URLSession`
   (ephemeral) fetch of `release.json` + `release.json.sig` from
   `alp-gpg.github.io`; verify with CryptoKit
   `Curve25519.Signing.PublicKey(rawRepresentation:)` over the **raw JSON bytes**
   (never re-serialize); decode `{version, build, minOS, url, sha256, notes}`;
   compare `build` against CFBundleVersion with **downgrade/replay rejection**;
   reject if `minOS` > current OS.
2. UI (~80 LOC): reuse the existing toggle (rename the storage key off
   `SUEnableAutomaticChecks`) and the "Check for Updates…" menu; on a hit show a
   sheet with version, notes, a selectable SHA256, and "Open Download Page"
   (`NSWorkspace.open`) + "Skip This Version". **Zero privileged code** —
   Gatekeeper/notarization provides install authenticity.
3. Scheduling (~30 LOC): on launch + every 24 h when opted in; jittered; plain
   GET, no identifying data.
4. Release tooling: replace `sign_update` with a ~40-line Ed25519 signer
   producing `release.json.sig`; emit `release.json` with version/build/sha256
   filled automatically (removing the manual XML edit); GPG-sign `SHA256SUMS`.
   Delete `docs/appcast.xml`.
5. Cleanup: remove the `packages:` block and Sparkle dep from `Project.swift`,
   both mach-lookup exceptions from `Alp.entitlements`, all `SU*` keys from
   `Info.plist`, and `.package.resolved`. **SPM dependency count drops to zero.**
6. Tests: signature verification (valid/invalid/wrong-key/truncated), version
   comparison incl. downgrade rejection, JSON-decode fuzz — all pure functions.

**Trust model after removal:** (1) the Ed25519 key for *notification
authenticity*, (2) Apple notarization/Developer ID for *install authenticity*,
enforced by the OS at install time. A compromised GitHub Pages or even a
compromised Ed25519 key can at worst show a false notification pointing at a
binary that must still pass Gatekeeper and the user's documented Team-ID check.

**Prerequisite either way:** fix the hardcoded `CURRENT_PROJECT_VERSION` (§6), or
no updater fires.

**Fallback if update friction is unacceptable — "keep Sparkle, hardened":** bump
to `.exact("2.9.3")`, add `-onlyUsePackageVersionsFromResolvedFile` to CI/release
builds, delete the dead Downloader mach-lookup exception, automate appcast
generation in `build-release.sh`, and pin Sparkle by revision hash.

---

## 8. Strengths worth preserving

- **XPC trust boundary is correct.** Both ends call `setCodeSigningRequirement`
  pinning Team ID *and* specific bundle identifiers (`Shared/BuildConfig.swift:23-30`);
  the kernel-enforced check is strictly better than racy `processIdentifier`/
  audit-token checks. A fresh `GPGHelper` is vended per connection.
- **Argument/option injection is well defended.** Fingerprints validated to 40
  hex chars before reaching `--recipient`/`--local-user`/`--export-secret-keys`;
  `--` separators precede user paths; edit-key inputs reject control chars.
- **Environment sanitization** drops `GNUPGHOME`/`DYLD_*` and hardcodes `PATH`.
- **Passphrases never traverse the helper** — all secret-key ops rely on
  gpg-agent + pinentry; the backup exports the key still passphrase-protected,
  then symmetrically re-wraps it (`--symmetric --cipher-algo AES256`, iterated
  S2K).
- **Fail-closed send path.** `encode()` throws on missing keys and always
  populates the encoding result's error fields — Mail won't silently send for
  state it knows about. (The gap is §1.2's *state loss*, not the error plumbing.)
- **XPC robustness pattern** — timeout timer + single-resume `ResumeGuard` +
  invalidation/error handlers + code-signing requirement; `decodedMessage`'s 75 s
  outer bound is correctly sized above the 60 s inner timeout.
- **Destructive-action UX is exemplary** — distinct "Delete Secret Key Only" vs
  "Delete Key", clear subkey revoke-vs-delete copy, pre-flight alerts that
  pre-empt double-pinentry confusion.
- **Privacy honesty** — drafts-on-server and unencrypted-subject warnings in both
  the compose popover and settings, with exact System Settings paths;
  consent-default-off updates.
- **MIME details done right where attempted** — `micalg` passed through from
  `SIG_CREATED`; ciphertext appended as raw bytes (never round-tripped through
  `String`); quoted-boundary regex handled; sign-then-encrypt single pass.
- **Setup-flow resilience** — checklist auto-navigates to the first failing step,
  distinguishes Login-Items approval, offers a real GnuPG install path, uses the
  app-group heartbeat to detect the extension.
- **launchd/SMAppService usage is correct** — demand-launched Mach service, plist
  embedded at `Contents/Library/LaunchAgents`, `--identifier` pinned at sign time
  so the code-signing `identifier` clause holds; debug bootstrap `#if DEBUG`-gated.
- **Broad unit-test surface** — 225 Swift Testing cases across 28 files, including
  tamper-resistance and pinning canaries. (Gaps: the signed-MIME byte-exactness
  of §1.1 and the CTE handling of §5.4 are exactly the spots not covered.)

---

## Suggested order of work

1. **Release-pipeline bugs (§6):** the hardcoded `CURRENT_PROJECT_VERSION` and the
   `notarytool` bare-`.app` — nothing ships, and no updater fires, without these.
2. **Correctness bugs (§1):** state persistence / fail-closed (§1.2), exact
   signed-part bytes (§1.1), encrypt-to-self (§1.3), live recipient checks (§1.4).
3. **Sparkle removal (§7)** (or the hardened-keep fallback).
4. **Robustness (§2.3, §3):** subprocess timeout, the data race, helper-down
   key-list state, cert-pin roots.
5. **macOS / UX polish (§4, §5):** Settings scene, verify-service selection,
   revocation-flow rename, extension localization.

---

*Two of the security findings (§2.1, §2.2) are already fixed and pushed on this
branch. The rest are specified to be implemented and tested against a real
macOS 26 build.*
