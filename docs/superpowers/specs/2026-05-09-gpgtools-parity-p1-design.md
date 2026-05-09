# GPGTools-Parity P1 Roadmap

**Status:** Draft
**Owner:** rhaist
**Date:** 2026-05-09
**Predecessor:** [`2026-05-09-gpgtools-parity-design.md`](2026-05-09-gpgtools-parity-design.md)
**Goal:** Cover the second tier of gaps between Alp and GPG Suite — the
features users notice once the core P0 surface is good enough to live with.

## Context

P0 closed the must-have parity gaps: full key lifecycle in Settings, WKD
discovery, inline-PGP outgoing, per-account signing, Services menu,
strict-pinning toggle, opt-in Sparkle, gpg installer guidance. P1 is what
turns Alp from "works" into "feels finished" against GPG Suite.

## Scope

### 1. Keyserver upload (publish own key)

A user generates a key with Alp's wizard, then has no way to share it
publicly without dropping into `gpg --send-keys`. Add a "Publish to
keys.openpgp.org…" action on rows for keys the user owns.

* **Helper RPC**: `uploadPublicKey(fingerprint: String) -> URL?`. Body of
  the call exports the armored public key and POSTs it to
  `https://keys.openpgp.org/vks/v1/upload`. The VKS reply includes a
  `token` and `key_fpr`; we follow up with a request to the
  `request-verify` endpoint for each UID email so verification mails go
  out automatically. The reply URL is the verification link presented to
  the user — they click in their inbox to complete publication.
* **UI**: per-row context menu entry on primary keys with a secret half.
  After upload, show a sheet listing the UID emails with "Verification
  pending" and a refresh button that re-runs the keyserver status check.
* **Pinning**: the upload uses `KeyserverSession.shared` so the existing
  SPKI pinning + strict-mode toggle apply.

### 2. Sign-key + ownertrust

GPG power users build a Web of Trust by certifying others' keys. Two
operations cover ~all of the day-to-day surface:

* `signKey(fingerprint:withSigner:level:)` driving
  `gpg --quick-sign-key <fp>` (default cert level) or
  `gpg --quick-lsign-key <fp>` (local non-exportable). The user chooses
  exportable vs local in the UI.
* `setOwnerTrust(fingerprint:level:)` driving `--import-ownertrust` with a
  `<fingerprint>:<level>:` line, since `--edit-key trust` is interactive.
  Level is one of: unknown (1), never (2), marginal (3), full (4),
  ultimate (5). RFC 4880 §5.2.3.13.

UI: per-row "Certify" button with a signer picker (which of *your* secret
keys signs theirs) and an exportable/local toggle. A trust pill in the row
shows the current ownertrust level and opens a small picker to change it.

### 3. Multi-keyserver fallback chain

`KeyserverClient.fetch` already tries `keys.openpgp.org` then WKD. Add two
more sources for users on services that don't sync to
keys.openpgp.org:

1. `keys.openpgp.org` (existing, primary)
2. WKD advanced + direct (existing)
3. **proton.me directory** — `https://api.protonmail.ch/pks/lookup?op=get&search=<email>`
   covers ProtonMail users who only publish through Proton's own KT
   transparency log.
4. **HKPS pool** — `hkps://keyserver.ubuntu.com/pks/lookup?op=get&search=<email>`
   as a fallback for older OpenPGP infrastructure that still uses SKS-shaped
   directories.

Each source uses a fresh `URLSession.ephemeral` (we cannot pin certs across
the open keyserver universe; strict ATS is the relevant guarantee). The
`KeyserverClient.Error.notFound` path tries each in order; first hit wins.
The missing-keys popover labels the matched source so the user knows what
trusted them.

### 4. Smartcard / YubiKey panel

Smartcards work today because gpg-agent handles them — Alp does nothing
special, but the user has no way to see *that* a card is plugged in.
Surface read-only metadata.

* **Helper RPC**: `cardStatus()` runs `gpg --card-status --with-colons`
  and parses the colon listing into a `GPGCardStatus` struct
  (`manufacturer`, `serial`, `cardholder`, `signKeyFingerprint`,
  `encryptKeyFingerprint`, `authKeyFingerprint`, `signaturePINTriesLeft`,
  …). Returns `nil` when no card is present.
* **UI**: a new "Smartcard" section in General settings, hidden when no
  card is detected. Shows manufacturer + serial + the three on-card
  fingerprints with key links if those are also in the local keyring.
  Read-only — adding card management UI (PIN change, key transfer) is
  deferred.

### 5. Photo IDs in Keys table

UAT packets are an underused but pleasant feature: a 64×64 portrait
embedded in the public key. Surface the thumbnail next to the UID column.

* `gpg --list-options show-photos --list-keys` writes each photo to a temp
  file. Easier path: `gpg --list-packets --no-armor` exposes UAT packets
  inline; parse the JPEG bytes and decode in-memory.
* The `parseColonKeyListing` flow already gathers per-key data; add an
  optional `photoData: Data?` field on `GPGKeyInfo` populated when the
  user attribute is present.
* `KeyListRow` shows a 24×24 image thumbnail aligned with the User ID
  column when `photoData` is non-nil.

Add/remove flows are deferred — generating a UAT requires bundled tooling
that's noisy.

### 6. Localization pass

Strings are mostly already wrapped through SwiftUI's `Text(...)` /
`Label(...)`, which routes through `Localizable.xcstrings` automatically.
A few hardcoded `String` literals in error messages, helper output, and
shell strings remain. The pass:

* Audit each `*.swift` for raw string literals shown to the user; convert
  to `String(localized:)` with stable keys.
* Seed `de.lproj` and `fr.lproj` entries in `Localizable.xcstrings` and
  rough-translate via Apple's machine translation (Xcode 26 has it built
  in). Real translations follow when contributors arrive.
* Keep the catalog sorted alphabetically so diffs stay readable.

## Order of work

```
14. P1 spec (this file)
15. uploadPublicKey RPC + UI
16. signKey + setOwnerTrust RPCs + UI
17. Multi-keyserver fallback chain
18. Smartcard panel
19. Photo IDs
20. Localization
```

Items 15–17 are independent of 18–20 and can ship in any order.

## Out of scope (defer to P2)

* Address-book "encryptable" badge in Contacts (needs Contacts entitlement
  + per-recipient cache invalidation)
* Bundled MacGPG2 / pinentry-mac (revisit only if Homebrew installer UX
  proves inadequate)
* Memoryhole / RFC 3156bis subject-line encryption (not a published
  standard)
* Tor routing for keyserver lookups (separate spec; needs Tor binary
  bundling + circuit lifecycle UX)
* SOCKS5 / per-account proxy for keyserver fetches

## Risks

* **VKS upload rate-limiting**: keys.openpgp.org limits uploads per IP. A
  user with many keys to publish could hit that. Mitigate by serialising
  upload calls and surfacing the rate-limit error verbatim.
* **Proton API drift**: the `api.protonmail.ch/pks/lookup` endpoint is
  documented but not under a stability guarantee. Treat 4xx as "not
  found" and move on.
* **Photo ID parser**: gpg's `--list-packets` output is not stable across
  versions. Guard the parser with a try/catch and fall back to no-photo
  when extraction fails.
* **Localization velocity**: machine-translated UI in a security tool can
  produce dangerous mistranslations. Default to English and ship locales
  only after a native speaker reviews the strings.
