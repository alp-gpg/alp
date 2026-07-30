#!/usr/bin/env bash
#
# Runs AlpTests against a throwaway keyring instead of the developer's own.
#
# Why a scratch $HOME and not $GNUPGHOME: GPGHelper.sanitizedEnvironment()
# forwards HOME but deliberately strips GNUPGHOME, so a caller cannot redirect
# the keyring — that is the point of the allowlist and must not be relaxed for
# tests. gpg still derives its homedir from $HOME, so overriding HOME for the
# test process alone gives a hermetic keyring with no production change.
#
# Build and run are split because a scratch $HOME has no login keychain: code
# signing has to happen under the real one, the test run does not.
#
# Extra arguments are forwarded to both xcodebuild invocations, e.g.
#   scripts/test.sh CODE_SIGNING_ALLOWED=NO
#
set -euo pipefail
cd "$(dirname "$0")/.."

DERIVED_DATA=${DERIVED_DATA:-build/DerivedData}

command -v gpg >/dev/null || { echo "gpg not found — brew install gnupg" >&2; exit 1; }

# Unconditional: an existing workspace generated before the last Project.swift
# change would silently omit new test files and still report green.
tuist generate --no-open

xcodebuild build-for-testing \
    -workspace Alp.xcworkspace -scheme Alp \
    -destination 'platform=macOS' -derivedDataPath "$DERIVED_DATA" \
    -enableCodeCoverage YES "$@"

# AlpXPCTests is in its own scheme and is never *run* here — it needs the
# installed helper and the real HOME. Build it anyway so it cannot rot
# uncompiled; see CONTRIBUTING.md for how to run it.
xcodebuild build-for-testing \
    -workspace Alp.xcworkspace -scheme AlpXPCTests \
    -destination 'platform=macOS' -derivedDataPath "$DERIVED_DATA" "$@"

# Deliberately under /tmp rather than $TMPDIR: gpg puts its agent sockets in the
# homedir, and a unix socket path is capped at 104 bytes. macOS $TMPDIR is
# already ~50 chars of /var/folders/…, which leaves too little headroom and
# fails as "can't connect to the keyboxd: File name too long".
TEST_HOME=$(mktemp -d /tmp/alp-test.XXXXXX)
cleanup() {
    gpgconf --homedir "$TEST_HOME/.gnupg" --kill all >/dev/null 2>&1 || true
    rm -rf "$TEST_HOME"
}
trap cleanup EXIT

# Fixture key. Passphrase-less on purpose: a protected key would route every
# signing test through gpg-agent into AlpPinentry and block on a human.
GNUPGHOME="$TEST_HOME/.gnupg" && export GNUPGHOME
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"

# Non-interactive pinentry, reachable only from this scratch homedir. Some
# operations prompt even on a passphrase-less key — adding a subkey makes
# gpg-agent ask what should protect the new key, and a symmetric backup wrap
# asks for an archive passphrase — and there is no human to answer. The
# passphrase must be non-empty: gpg-agent rejects an empty answer for
# symmetric encryption and re-prompts forever, hanging until the helper's
# timeout. Anything the stub protects, the stub can also unlock, so every
# prompt in the suite resolves to the same fixed answer.
cat > "$GNUPGHOME/pinentry-stub.sh" <<'STUB'
#!/bin/sh
echo "OK Pleased to meet you"
while read -r line; do
    case "$line" in
        GETPIN*) printf 'D alp-test-fixture\nOK\n' ;;
        BYE*) echo "OK closing connection"; exit 0 ;;
        *) echo "OK" ;;
    esac
done
STUB
chmod 700 "$GNUPGHOME/pinentry-stub.sh"
echo "pinentry-program $GNUPGHOME/pinentry-stub.sh" > "$GNUPGHOME/gpg-agent.conf"

gpg --batch --quiet --passphrase '' \
    --quick-gen-key 'Alp Test <test@alp.invalid>' default default never
unset GNUPGHOME

# TEST_RUNNER_ prefix is how xcodebuild forwards a variable into the test
# process; without it the value never arrives. Signals to GPGKeyLifecycleTests
# that the keyring is disposable, so its revoke/delete tests may run — they stay
# skipped under a bare ⌘U against a real keyring.
HOME="$TEST_HOME" TEST_RUNNER_ALP_HERMETIC_KEYRING=1 xcodebuild test-without-building \
    -workspace Alp.xcworkspace -scheme Alp \
    -destination 'platform=macOS' -derivedDataPath "$DERIVED_DATA" \
    -enableCodeCoverage YES "$@"

# Per-target coverage summary — printed locally, and appended to the GitHub
# Actions job summary when running in CI. Deliberately no external coverage
# service: that would need a CI token and a third-party uploader, and this
# repo's CI is secret-free on purpose.
XCRESULT=$(ls -td "$DERIVED_DATA"/Logs/Test/*.xcresult | head -1)
xcrun xccov view --report --only-targets "$XCRESULT"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Coverage"
        echo '```'
        xcrun xccov view --report --only-targets "$XCRESULT"
        echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
fi
