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

## Future ideas (not scheduled)

### Adjacent expansion — "macOS GPG productivity tool"

PGP-email is a flat-to-shrinking market; GPG-the-tool isn't going
anywhere because of Linux package signing, git commit signing,
YubiKey, ProtonMail, RFC 9580 refresh, and Sequoia rebuild. These
extend Alp's value to the GPG users who don't email-PGP much, which
is most of them.

- [ ] **Smartcard / YubiKey write ops (remaining).** Transfer key
      to card and factory-reset card. User-PIN and admin-PIN change
      already ship.
- [ ] **Key backup + restore wizard.** Guided export of secret key
      + revocation certificate to an encrypted bundle, with a "test
      restore on a different Mac" walk-through. Protects users from
      the most common GPG-disaster: losing the only copy of the key.
- [ ] **SSH-key via gpg-agent.** Configure gpg-agent's SSH socket
      and link an authentication-capable subkey for `ssh-add -L`-style
      use. Power user feature; cheap to wire once card-write lands.
- [ ] **RFC 9580 / crypto-refresh readiness.** Health check warns
      when local gpg is older than the version that ships RFC 9580
      support (gpg ≥ 2.4.5 / Sequoia builds). Helps users on Linux
      distro-locked gpg avoid silent compat issues.

### Mail-side polish

- [ ] Per-subkey refresh from keyserver (today's refresh is whole-primary).
- [ ] Tor / SOCKS proxy for keyserver fetches.
- [ ] Address-book "encryptable" badge in Contacts.
- [ ] Real translations once a native speaker is available per locale —
      the xcstrings catalog already captures every user-facing string.
