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
- **Composing:** A toolbar appears with **Sign** and **Encrypt** toggles. Sign is on by default. Encrypt enables automatically when all recipients have public keys in your keyring. Missing keys can be looked up and imported from `keys.openpgp.org` directly from the compose window.
- **Key management:** The settings window lists all keys in your keyring, shows expiry dates, and checks publication status on `keys.openpgp.org`.

## Requirements

- macOS 26 (Tahoe) or later
- [GnuPG](https://gnupg.org/) 2.x — `brew install gnupg`
- [pinentry-mac](https://github.com/GPGTools/pinentry-mac) — `brew install pinentry-mac`

## Installation

> Pre-built binaries are not yet available. See [BUILDING.md](BUILDING.md) for instructions on building from source.

1. Build and run the **Alp** app.
2. Click **"Install Helper"** in the Helper tab to register the background agent.
3. Open **Mail → Settings → Extensions** and enable **Alp**.

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

- XPC connections are authenticated via code signing — both sides verify the same Team ID.
- The gpg subprocess receives a sanitised environment (allowlisted variables only) to prevent `GNUPGHOME` redirection or `DYLD_INSERT_LIBRARIES` injection.
- XPC payload size is bounded (50 MB) to prevent memory exhaustion.
- Trust model is `tofu+pgp` (Trust-On-First-Use) — warns on key changes.
- All log output uses `os_log` default privacy (redacted in production). No plaintext, fingerprints, or email addresses are logged.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to submit changes.

## License

MIT
