# GPGTools-Parity Roadmap

**Status:** Draft
**Owner:** rhaist
**Date:** 2026-05-09
**Goal:** Identify and close the gaps between Alp and GPG Suite (GPGTools) so
Alp can credibly replace the whole Suite, not just GPGMail.

## Context

Alp today is a strong **MailKit extension** for macOS 26 Tahoe. GPG Suite
ships four products in one package: GPGMail, GPG Keychain, MacGPG, and GPG
Services. Mail-side parity is largely done; the rest is missing.

Existing helper API (`GPGHelperProtocol`):
`encrypt`, `decrypt`, `sign`, `verify`, `previewKey`, `importKey`,
`listAllKeys`, `listSecretKeys`, `publicKeyExists`, `checkHealth`.

No support for delete, export, generate, edit, revoke, sign-key, ownertrust.
Keyserver lookup limited to keys.openpgp.org. No Sparkle, no Services menu,
no file encrypt/decrypt, no inline-PGP outgoing path. Depends on the user
having `gpg` already installed.

## Scope of P0

The work below is what must land before "Alp = GPG Suite alternative" is
credible. Items are sized to be shippable in 1-2 commits each.

### Helper RPC additions (foundational)

All key-lifecycle UI depends on the helper exposing these. Group them so the
protocol stays stable.

1. **deletePublicKey(fingerprint)** — `gpg --batch --yes --delete-keys FP`.
2. **deleteSecretKey(fingerprint)** — `gpg --batch --yes --delete-secret-keys FP`.
   Requires confirmation in the UI; gpg also prompts unless `--batch --yes`.
3. **exportPublicKey(fingerprint) -> Data** — `gpg --armor --export FP`.
4. **exportSecretKey(fingerprint) -> Data** — `gpg --armor --export-secret-keys FP`.
   Will trigger pinentry; the helper passes the prompt through.
5. **generatePrimaryKey(name, email, comment?, expiry)** — `--batch --gen-key`
   with an Ed25519 sign primary + Cv25519 encrypt subkey, optional comment,
   2y expiry by default. Returns the new fingerprint.
6. **changePassphrase(fingerprint)** — `--edit-key FP passwd save` via expect-style
   command stream; pinentry handles the actual prompts.
7. **setExpiry(fingerprint, days)** — `--edit-key FP expire <days> save`.
8. **revokePrimaryKey(fingerprint, reason)** — `--gen-revoke` then `--import` of
   the resulting revocation cert.

All inputs go through `isValidFingerprint`, and the email/name parameters
must be validated against an allow-list (no shell metacharacters; gpg's
`--batch` mode accepts them via stdin so injection risk is low but we should
still strip control characters).

### Discovery improvements

9. **WKD lookup** (RFC draft, de-facto standard).
   * Advanced method: `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<zbase32(SHA1(localpart))>`
   * Direct method (fallback): `https://<domain>/.well-known/openpgpkey/hu/<zbase32(SHA1(localpart))>`
   * Use as a fallback after keys.openpgp.org returns notFound, and as a
     primary source when the user has flagged the domain as "WKD-preferred".
   * Same pinned-session pattern is **not** appropriate (open web of domains).
     Use a fresh `URLSession.ephemeral` with strict ATS.

### Onboarding gaps

10. **First-run gpg install guidance** — the Setup checklist already detects
    a missing `gpg`. Add an action button that opens the Homebrew install
    command in Terminal (preferred) or the gnupg.org download page. Document
    the bundling decision (next step) in this spec.

11. **Pinentry-mac path** — **Decision (2026-05-09): rely on Homebrew's
    `pinentry-mac`.** The first-run installer sheet already runs
    `brew install gnupg pinentry-mac` so the common path lands users on a
    working passphrase prompt. The health check surfaces missing pinentry
    explicitly, and `GPGHealthStatus` accepts any GUI pinentry binary
    (pinentry-mac, pinentry-gnome3, pinentry-qt) so users with custom setups
    are not penalised.

    Bundling pinentry-mac was rejected: it would force us to maintain
    notarisation for an additional binary and the upstream license terms
    (GPLv3) make distributing it inside our own DMG awkward. Building an
    Assuan-speaking passphrase prompt was rejected: high effort for a
    one-off polish that almost no other gpg client gets right.

    Follow-up if this proves wrong in user testing: revisit the bundled-
    pinentry option behind a feature gate before considering an Assuan
    rewrite.

### Compose / send-side gaps

12. **Inline-PGP outgoing toggle** — RFC 4880 ASCII-armored body inside a
    plain `text/plain` MIME part, no `multipart/encrypted` wrapper. Some
    legacy recipients only handle this. Off by default; per-message override
    in compose; remembered per-recipient (future P1).

13. **Per-account default signing key** — store a `[fromEmail: fingerprint]`
    map in app-group defaults. `ComposeViewModel.refresh` picks the signer
    matching `session.mailMessage.fromAddress` before falling back to the
    global default. Settings adds a per-identity picker once detected.

### Distribution gaps

14. **Sparkle auto-update** — required because we tell users to bump quickly
    on cert pin rotations and on security fixes. Use Sparkle 2 with EdDSA
    signing; appcast hosted on GitHub Pages or releases. Sign DMGs in
    `scripts/build-release.sh`.

15. **Services menu / file encrypt-decrypt** — new macOS app extension target
    (or a tiny helper app) registering Services items: *Encrypt Selection*,
    *Decrypt Selection*, *Sign Selection*, *Verify Signature*. Reuses the
    helper via the existing XPC client (extension-side bundle id added to
    `BuildConfig.clientRequirement`). File drag-drop deferred to P1.

## Order of work

```
1. Spec + TODO update                    (you are here)
2. RPCs: delete/export                   (smallest; pure additions)
3. RPC: generatePrimaryKey               (depends on pinentry decision)
4. RPCs: edit-key passphrase/expiry/revoke
5. Settings UI: row actions + generate sheet
6. WKD lookup
7. First-run gpg install guidance
8. Inline-PGP outgoing toggle
9. Per-account default signing key
10. Services menu target
11. Sparkle wiring
```

Each helper RPC ships with a unit test using a sandboxed `GNUPGHOME` so
tests do not touch the user's keyring. Existing tests (`GPGHelperValidationTests`,
`KeyserverPinningTests`, etc.) are the model.

## Out of scope (deferred to P1)

- Sign-others'-keys / set ownertrust UI
- Photo IDs
- HKPS pool / proton.me lookup
- Keyserver upload (publish-own-key)
- Smartcard / YubiKey panel
- Localization
- Address-book "encryptable" badge
- Drag-drop file ops (Services menu first)

## Out of scope (P2)

- Subject-line encryption (Memoryhole / RFC 3156bis — non-standard)
- Web-of-Trust depth tooling
- Tor routing

## Risks

- **Pinentry choice blocks key generation UX.** Resolve in step 3 or accept
  that key gen launches a Terminal pinentry on a stock setup.
- **WKD over arbitrary HTTPS hosts** opens a wider attack surface than the
  pinned keys.openpgp.org path. Mitigate with strict ATS + small response
  size cap. No certificate pinning across the open WKD universe.
- **Bundling MacGPG** is a much bigger lift than this spec covers — keep it
  off the critical path; revisit only after onboarding tells us it's the
  blocker for adoption.
