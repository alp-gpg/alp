# Alp TODO

## Operator (manual, blocking first public release)

- [ ] Add GitHub secrets for the release pipeline:
      `DEVELOPER_ID_CERTIFICATE_P12`, `DEVELOPER_ID_CERTIFICATE_PASSWORD`,
      `KEYCHAIN_PASSWORD`, `APPLE_ID`, `APPLE_ID_PASSWORD`, `APPLE_TEAM_ID`.
- [ ] Create `alp-gpg/homebrew-tap` repo with a cask formula derived
      from `scripts/alp.rb.template`.
- [ ] Enable GitHub Pages on `alp-gpg/alp` from `/docs` once the repo is
      public, so the Sparkle appcast is served at
      <https://alp-gpg.github.io/alp/appcast.xml>.

## Future ideas (mission-aligned only)

Alp is GPG for Apple Mail. Ideas here must serve a Mail-PGP user. We
do not bolt on git tooling, SSH-auth helpers, or general macOS-GPG
productivity features just because they share a binary.

- [ ] **Key backup + restore wizard.** Guided export of secret key
      + revocation certificate to an encrypted bundle, with a "test
      restore on a different Mac" walk-through. Protects users from
      losing the only copy of the key that decrypts their mail.
- [ ] **Per-subkey refresh from keyserver.** Today's refresh is
      whole-primary; granular refresh would catch subkey rotation
      faster.
- [ ] **Address-book "encryptable" badge in Contacts.** Surface
      whether an address can receive PGP mail without composing first.
- [ ] **Tor / SOCKS proxy for keyserver fetches.** For users on hostile
      networks.
- [ ] **RFC 9580 readiness check.** Health check warns when local gpg
      is older than the version shipping RFC 9580 support (gpg ≥ 2.4.5
      / Sequoia). Helps users on distro-locked gpg avoid silent compat
      issues.
- [ ] **Real translations.** The xcstrings catalog already captures
      every user-facing string; needs native speakers per locale.
