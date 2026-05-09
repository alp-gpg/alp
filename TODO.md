# Alp TODO

## Must Fix (manual release steps)

- [ ] Add GitHub secrets for release pipeline (`DEVELOPER_ID_CERTIFICATE_P12`,
      `DEVELOPER_ID_CERTIFICATE_PASSWORD`, `KEYCHAIN_PASSWORD`, `APPLE_ID`,
      `APPLE_ID_PASSWORD`, `APPLE_TEAM_ID`)
- [ ] Create `alp-gpg/homebrew-tap` repo with cask formula derived from
      `scripts/alp.rb.template`
- [x] Run Sparkle `generate_keys` once and embed the public key in
      `Alp/SupportingFiles/Info.plist` (`SUPublicEDKey`). Private key lives
      in the login Keychain — back it up via Keychain Access export.
- [ ] Enable GitHub Pages on `alp-gpg/alp` from the `docs/` folder so the
      Sparkle appcast is served at <https://alp-gpg.github.io/alp/appcast.xml>.

## In Progress

- [ ] **Keys list hierarchy + expired key handling**
      Spec: `docs/superpowers/specs/2026-04-11-keys-list-hierarchy-design.md`

- [x] **GPGTools-parity P0**
      Spec: `docs/superpowers/specs/2026-05-09-gpgtools-parity-design.md`

- [ ] **GPGTools-parity P1**
      Spec: `docs/superpowers/specs/2026-05-09-gpgtools-parity-p1-design.md`
  - [x] Keyserver upload + per-UID verification flow (Publish to keys.openpgp.org…)
  - [x] `signKey` + `setOwnerTrust` RPCs + per-row Certify / Trust UI
  - [x] Multi-keyserver fallback chain (proton.me, HKPS pool after WKD)
  - [x] Smartcard / YubiKey read-only status panel
  - [x] Localization pass — wrap LocalizedError descriptions in
        `String(localized:)` so the xcstrings catalog covers them
  - **Dropped**: Photo IDs — UAT packets imply visual identity
        verification, which is the wrong mental model for a security
        tool. Fingerprint comparison is the actual primitive.

## Future / Deferred

Ideas captured while designing other work. Not scheduled — promote into a phase
when they become relevant. Each entry links to the spec it came from.

### From Keys UI hierarchy (2026-04-11)

- [ ] Key detail view (creation time, key flags, trust level, full fingerprint,
      per-subkey stats)
- [ ] "Cleanup" action — prune revoked/expired subkeys from the local keyring
- [ ] Per-subkey refresh from keyserver
- [ ] Tor / anonymity routing for keyserver fetches

*(WKD lookup and revocation certificate management promoted into the
GPGTools-parity P0 above.)*

### Unscheduled

- [ ] Helper crash notification with "reinstall" button
      (carried over from the original Phase 4 roadmap)

## Done

- ~~Security audit fixes~~ — 30 items across P0–P4, 62 tests green
- ~~Release pipeline~~ — `release.yml`, `build-release.sh`, `ExportOptions.plist`,
  `scripts/alp.rb.template`, SHA256SUMS generation
- ~~Setup checklist in GeneralSettingsView~~ — helper → GPG → Mail extension → signing key
- ~~Auto-navigate to problem area on launch~~ — `ContentView` jumps to Helper
  section when `helperStatus != .enabled`
- ~~Periodic health check~~ — `startPeriodicHealthCheck` while visible
- ~~Extension heartbeat via app group defaults~~
- ~~Compose session state tracking by `contextID`~~
- ~~"No GPG" indicator and encrypt tooltip in ComposeView~~
- ~~`canSign` / `canEncrypt` gating in ComposeViewModel~~
- ~~XPC reconnection + crash detection with 60s call timeout~~
- ~~Keyserver error differentiation (`.found`, `.notFound`, `.unreachable`)~~
- ~~Certificate pinning~~ — SPKI pinning, graceful fallback, UI warning, canary test
- ~~Human-readable GPG error mapping (`GPGError` cases, tests)~~
- ~~Key import from file in KeySettingsView~~
- ~~Expired key table badge + picker warning~~ *(finishing in the in-progress
  Keys UI hierarchy spec above)*
- ~~Test coverage~~ — 62 tests across 11 suites (parser, validation, tamper
  resistance, XPC roundtrip, keyserver pinning, compose session isolation,
  MIME edge cases)
- ~~Accessibility~~ — VoiceOver labels on all interactive elements
