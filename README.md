<p align="center">
  <img src="Alp/Resources/Logo/alp-logo.svg" alt="Alp" width="200" />
</p>

<h1 align="center">Alp</h1>

<p align="center">GPG for Apple Mail on macOS 26.</p>

---

Alp adds Sign, Encrypt, Decrypt, and Verify to Apple Mail using your existing `gnupg` keys. It does not replace Mail and does not store your keys — `gpg-agent` keeps doing that.

## What it does

Open Mail with Alp installed and PGP just works. Encrypted messages decrypt on read; signed messages show the signer's fingerprint. The compose window grows three buttons — Sign, Encrypt, and Inline (for legacy clients that can't read PGP/MIME).

When you add a recipient who isn't in your keyring, Alp can find them. It checks `keys.openpgp.org` first, then falls back to Web Key Directory for self-hosted domains. The popover next to the Encrypt button shows the result and lets you import in one click. The signing key auto-selects to match whichever From address you're using.

The Keys tab is a full key manager. Generate an Ed25519 + Cv25519 pair, change a passphrase, set or extend an expiry, export public or secret material, generate a revocation certificate, or delete a key — the same surface a dedicated app like GPG Keychain would give you, without leaving Settings.

There's also a Services menu integration. Select PGP-encrypted text in any app, right-click → Services → Decrypt with Alp. Same for Verify and Sign.

For files, right-click any item in Finder (or another app's open panel) and pick **Decrypt File with Alp**, **Verify File with Alp**, **Sign File with Alp**, or **Encrypt File with Alp…**. Decrypt and Sign open a save panel pre-populated with a sensible default name; Verify pops a one-line result with the signer's identity; Encrypt opens a recipient picker that lists every key in your local keyring with an encrypt capability.

## Requirements

macOS 26 (Tahoe) and a working GnuPG install. The Setup checklist offers a one-click Homebrew path; if you'd rather not use Homebrew, install GnuPG from <https://gnupg.org/download/>. The pinentry passphrase prompt ships inside Alp itself — General → Pinentry has a "Use Alp Pinentry" button that wires it into `gpg-agent.conf` for you, so `pinentry-mac` is no longer required.

## Installation

Pre-built binaries aren't published yet — see [BUILDING.md](BUILDING.md) to build from source.

When you launch the app, the **General → Setup** checklist walks you through:

1. **Install Helper** — registers a small background agent via `SMAppService`.
2. **GPG Environment** — health-checks `gpg`, `gpg-agent`, and pinentry, and offers an installer if anything is missing.
3. **Enable Mail Extension** — opens System Settings to the right pane.
4. **Choose Signing Key** — picks a default; future compose windows pre-select a key matching the From address automatically.

### A note on pinentry

The simplest path is **General → Pinentry → "Use Alp Pinentry"**. Alp writes its bundled prompt into `~/.gnupg/gpg-agent.conf` and restarts gpg-agent — no external binaries, no manual config edits.

If you'd rather use a different pinentry (pinentry-mac from Homebrew or GPG Suite, pinentry-qt, etc.), point gpg-agent at it directly:

```
# ~/.gnupg/gpg-agent.conf
pinentry-program /opt/homebrew/bin/pinentry-mac
```

Either way, `~/.gnupg/gpg.conf` must not contain `pinentry-mode loopback` — that forces a terminal-only prompt the helper can't answer. After changing config, run `gpgconf --kill gpg-agent`.

GPG Suite users: Alp finds `/usr/local/MacGPG2/bin/gpg` automatically, with Homebrew taking priority.

## How it works

```
Mail.app → [MailKit XPC] → AlpExtension (sandboxed)
                              ↓ NSXPCConnection
                         AlpHelper (unsandboxed, SMAppService)
                              ↓ Process()
                         gpg ↔ gpg-agent ↔ pinentry
```

The Mail extension is sandboxed and can't call external binaries. Alp bridges that gap with a small XPC helper that talks to your existing `gpg`. No keys, passphrases, or plaintext are stored anywhere by Alp.

## Security

A few things worth knowing about how Alp protects you:

- The helper only accepts XPC connections from the Alp app and Alp Mail extension, by exact bundle identifier and Team ID. A different binary signed by the same Apple Developer account can't impersonate either side.
- The gpg subprocess runs with an allowlisted environment, so a malicious caller can't redirect `GNUPGHOME` or inject a dylib via `DYLD_INSERT_LIBRARIES`.
- Every fingerprint passed to gpg is validated as 40-character hex. Argument smuggling via `--homedir /tmp/evil` doesn't work.
- Keyserver lookups to `keys.openpgp.org` use SPKI pinning. A "Strict pinning" toggle in General settings cancels the handshake on mismatch — off by default so cert rotations don't lock you out, on for high-risk setups.
- Auto-update DMGs (when enabled) are EdDSA-signed. Anyone who hijacks the appcast or the release URL can't ship a malicious binary without our private key.
- Logging respects `os_log` `.private` — plaintext, fingerprints, and email addresses never appear in release logs.

[docs/VERIFYING.md](docs/VERIFYING.md) walks through how to confirm any of the above on your own machine — signature checks, source-audit map, gpg invocation review, and a build-from-source recipe.

### Privacy

Alp does not phone home. No analytics, no crash reporting, no usage pings.

Auto-update is opt-in. A fresh install makes zero network calls until you flip the switch in **General → Updates**. Brew users get updates through `brew upgrade --cask alp` and don't need it.

Keyserver traffic happens only when you ask for it: clicking *Find Key* on a missing recipient, refreshing expired keys, or letting the Keys tab check whether your own published keys are up. Typing recipients does not leak — that's a local keyring lookup.

### What encryption does not protect

PGP on a MailKit extension has two limits worth pointing out:

- **Drafts are not encrypted.** Mail saves drafts to IMAP/iCloud while you type, before Alp gets to encrypt anything. For accounts you use with PGP, turn off "Store drafts on server" in Mail → Settings → Accounts → Mailbox Behaviors.
- **Subject lines are not encrypted.** RFC 3156 leaves headers in the clear. Keep sensitive content in the body.

Both also surface as warnings inside General settings and the compose window so you don't have to remember.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE).
