# Security Policy

Alp handles GPG key material and passphrases. We take security reports
seriously and ask you to follow coordinated disclosure.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security reports.**

Please use GitHub's private vulnerability reporting:

1. Go to <https://github.com/alp-gpg/alp/security/advisories/new>
2. Click "Report a vulnerability"

Alternatively, email **rhaist@mailbox.org** with:

- A description of the issue and its impact
- Steps to reproduce (proof of concept, if applicable)
- Affected version(s)

If you want encrypted communication, encrypt your report to the
maintainer's OpenPGP key:

```
2BC8 3F55 A400 7468 864C  680E 1B7C C8D4 D4E9 14AA
```

Fetch it from `keys.openpgp.org`:

```
gpg --keyserver hkps://keys.openpgp.org \
    --recv-keys 2BC83F55A4007468864C680E1B7CC8D4D4E914AA
```

The same key signs every `SHA256SUMS.asc` on the GitHub release pages,
so you can confirm the fingerprint against any published release.

## Response Timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 5 business days
- **Fix or mitigation:** target 30 days for high-severity, 90 days for
  low-severity. Complex issues may take longer; we'll keep you informed.

## Scope

- Alp (the macOS app, Mail extension, XPC helper, and pinentry)
- The release pipeline (`scripts/build-release.sh`, GitHub Actions
  workflows)
- The update distribution channel (`release.json` signing, GitHub Pages)

Out of scope: vulnerabilities in GnuPG itself (report to the GnuPG
project), vulnerabilities in macOS or Apple frameworks (report to
Apple).

## Safe Harbor

We will not take legal action against researchers who:

- Make a good-faith effort to avoid privacy violations, data
  destruction, and service interruption
- Give us reasonable time to remediate before public disclosure
- Do not demand payment in exchange for withholding disclosure

## Disclosure

Once a fix is released, we publish a GitHub Security Advisory with
credit to the reporter (unless they prefer to remain anonymous).
