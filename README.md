<p align="center">
  <img src="Alp/Resources/Logo/alp-logo.svg" alt="Alp" width="200" />
</p>

<h1 align="center">Alp</h1>

<p align="center">
  A macOS 26 Mail extension that adds GPG sign, encrypt, decrypt, and verify to Apple Mail — using your existing <code>gnupg</code> keychain.
</p>

---

## What It Does

Alp integrates OpenPGP into Apple Mail without replacing it. Once installed, it works transparently:

- **Incoming mail:** Automatically decrypts PGP/MIME and inline-PGP messages. Verifies signatures and shows the signer's fingerprint.
- **Composing:** A toolbar appears with **Sign**, **Encrypt**, and **Inline** toggles. Encrypt enables automatically when all recipients have public keys in your keyring. Missing keys can be looked up and imported from `keys.openpgp.org` (with a Web Key Directory fallback for self-hosted domains) directly from the compose window. The signing key is auto-picked to match the From address; you can override per-message.
- **Key management:** The Keys tab lists every key in your keyring with hierarchy + subkeys. Per-row actions cover Generate (Ed25519 + Cv25519), Export (public/secret), Change Passphrase, Set Expiry, Generate Revocation Certificate, and Delete. Expired keys can be batch-refreshed against `keys.openpgp.org` over a pinned TLS connection.
- **Services menu:** Right-click any selected text in macOS → Services to Decrypt, Verify, or Sign with Alp without opening Mail.

## Requirements

- macOS 26 (Tahoe) or later
- GnuPG 2.x and a GUI pinentry. Alp's Setup checklist offers a one-click
  Homebrew install or a link to <https://gnupg.org/download/> if you skip
  Homebrew. Manual install:
  ```bash
  brew install gnupg pinentry-mac
  ```

## Installation

> Pre-built binaries are not yet available. See [BUILDING.md](BUILDING.md) for instructions on building from source.

Run the **Alp** app. The **General → Setup** checklist walks you through:

1. **Install Helper** — registers the background XPC agent via `SMAppService`.
2. **GPG Environment** — health-checks `gpg`, `gpg-agent`, and pinentry. Offers an installer if `gpg` is missing.
3. **Enable Mail Extension** — opens System Settings to the right pane.
4. **Choose Signing Key** — picks a default; future compose windows pre-select keys matching the From address automatically.

### GPG Configuration

Alp's helper runs in the background with no terminal. Your `gpg-agent.conf` **must** use the GUI pinentry:

```
# ~/.gnupg/gpg-agent.conf
pinentry-program /opt/homebrew/bin/pinentry-mac
```

Your `gpg.conf` must **not** contain `pinentry-mode loopback` (this forces terminal-based entry, which fails from a background daemon).

After changing config, restart the agent:

```bash
gpgconf --kill all
```

> **GPGTools users:** The binary at `/usr/local/MacGPG2/bin/gpg` is auto-detected as a fallback. Homebrew gnupg takes priority.

## How It Works

```
Mail.app → [MailKit XPC] → AlpExtension (sandboxed)
                                ↓ NSXPCConnection (Mach service)
                         AlpHelper (unsandboxed, SMAppService agent)
                                ↓ Process()
                         gpg binary ↔ gpg-agent ↔ pinentry-mac
```

The Mail extension runs inside Apple Mail's sandbox and cannot call external binaries directly. Alp bridges this gap with a lightweight XPC helper agent that talks to your existing `gpg` installation. No keys, passphrases, or plaintext are ever stored by Alp — all key material lives in `gpg-agent`.

## Security

- **XPC peer pinning:** the helper accepts only the main app and the Mail extension by bundle identifier + Team ID; clients verify the helper's bundle ID in turn. Signing requirements live in `Shared/BuildConfig.swift`.
- **Sanitised gpg environment:** the helper's gpg subprocess inherits an allowlisted environment (HOME, USER, LANG, …) only — `GNUPGHOME` redirection, `DYLD_INSERT_LIBRARIES` injection, and similar tricks are blocked.
- **Argument injection:** all fingerprints are validated as 40-hex-char strings before being passed to gpg. Names, emails, and revocation descriptions reject `<>()` and control characters.
- **XPC payload bounded:** 50 MB per call.
- **Keyserver TLS pinning:** lookups against `keys.openpgp.org` go through an SPKI-pinned `URLSession`. A `Strict pinning` toggle in General settings cancels handshakes on mismatch (off by default to survive cert rotations); pin mismatches surface a non-blocking warning.
- **Update integrity:** Sparkle DMGs are EdDSA-signed; the embedded public key in `Info.plist` is what authorises an install. An attacker who hijacks the appcast or the GitHub Releases asset still cannot ship a malicious binary.
- **Trust model:** `tofu+pgp` (Trust-On-First-Use) — warns on key changes.
- **Logging:** `os_log` default privacy is `.private`; plaintext, fingerprints, and email addresses are never logged in release builds.

### Privacy stance

- **No telemetry, no analytics.** Alp does not phone home for anything.
- **Auto-update is opt-in.** A fresh install performs zero network calls to `alp-gpg.github.io`. Enable auto-checks under **General → Updates** when you trust us to fetch update metadata.
- **Keyserver lookups are local-keyring-driven.** The compose window asks the helper whether *you* already have a recipient's key — that's a local lookup, not a keyserver query. Keyserver traffic only happens when you click *Find Key* in the missing-keys popover, when *you* refresh expired keys you own, or when the Keys tab badges your own published keys.

### Privacy limits to know

- **Drafts are not encrypted.** Mail saves drafts to IMAP/iCloud as you type; encryption only happens at send. Disable "Store drafts on server" for any account where you use PGP — Mail → Settings → Accounts → Mailbox Behaviors.
- **Subject lines are not encrypted.** PGP/MIME (RFC 3156) leaves the Subject header in cleartext. Keep sensitive details out of the subject.

Both surface as warnings inside General settings and the compose window.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to submit changes.

## License

MIT
