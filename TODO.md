# Alp TODO

Items here are scoped to "GPG for Apple Mail." If an item does not
serve a Mail-PGP user, it does not belong here.

## Release blockers (operator action — not code)

- [ ] Add GitHub secrets for the release pipeline:
      `DEVELOPER_ID_CERTIFICATE_P12`, `DEVELOPER_ID_CERTIFICATE_PASSWORD`,
      `KEYCHAIN_PASSWORD`, `APPLE_ID`, `APPLE_ID_PASSWORD`, `APPLE_TEAM_ID`.
- [ ] Create `alp-gpg/homebrew-tap` repo. Cask formula already lives at
      `scripts/alp.rb.template` (gnupg dep only — Alp ships its own
      pinentry now).
- [ ] Enable GitHub Pages on `alp-gpg/alp` from `/docs` so the Sparkle
      appcast resolves at <https://alp-gpg.github.io/alp/appcast.xml>.
- [ ] Manual click-through of every Services-menu file flow + every
      compose-toolbar action in a real Mail.app before tagging
      `v1.0.0`. Tests don't cover UI threading or save-panel UX.

## Active backlog (mission-aligned, will likely land)

(empty — the backup wizard and RFC 9580 readiness advisory have
shipped. New items go here as they emerge.)

## Open-ended

- [ ] **Real translations.** The xcstrings catalog already captures
      every user-facing string. Gated on native speakers per locale —
      no schedule.

## Out of scope (won't do unless mission shifts)

These were considered and rejected because they do not serve a
Mail-PGP user enough to justify the maintenance cost:

- Smartcard write ops beyond the user-PIN change that already ships
  (key-to-card transfer, factory-reset). Provisioning-time, not
  day-to-day. YubiKey GUIs already exist.
- Per-subkey refresh from keyserver. Whole-primary refresh covers
  the case in practice.
- Tor / SOCKS proxy for keyserver fetches. Wrong audience for Apple
  Mail.
- Address-book "encryptable" badge in Contacts. Large Contacts-API
  surface for marginal payoff over the existing compose-time check.
- Git commit-signing wizard, SSH-via-gpg-agent, gpg-agent cache
  management. All off-mission — they would turn Alp into a generic
  GPG productivity tool. Use `gpgconf` from Terminal.
