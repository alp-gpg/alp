#!/usr/bin/env bash
# Build, sign, notarize, and package Alp into a DMG.
# Usage: ./scripts/build-release.sh [version]
#   version: e.g. "1.0.0" — defaults to git tag (v prefix stripped)
#
# Required environment:
#   DEVELOPER_ID_APPLICATION  — signing identity, e.g. "Developer ID Application: Name (TEAMID)"
#   APPLE_ID                  — Apple ID for notarization
#   APPLE_ID_PASSWORD         — app-specific password
#   APPLE_TEAM_ID             — Team ID for notarization
set -euo pipefail

VERSION="${1:-$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//')}"
if [[ -z "$VERSION" ]]; then
    echo "Error: No version provided and no git tag found." >&2
    exit 1
fi

echo "==> Building Alp $VERSION"

ARCHIVE_PATH="build/Alp.xcarchive"
EXPORT_PATH="build/export"
DMG_PATH="build/Alp-${VERSION}.dmg"

rm -rf build
mkdir -p build

# Generate Xcode project
tuist generate --no-open

# Archive
#
# Inject the real version into both CFBundleVersion (CURRENT_PROJECT_VERSION)
# and CFBundleShortVersionString (MARKETING_VERSION). The committed defaults are
# "1"/"1.0"; without this injection every release would ship build "1" and the
# update checker would never see a newer build to offer.
xcodebuild archive \
    -workspace Alp.xcworkspace \
    -scheme Alp \
    -configuration Release \
    -archivePath "$ARCHIVE_PATH" \
    -destination 'generic/platform=macOS' \
    CURRENT_PROJECT_VERSION="$VERSION" \
    MARKETING_VERSION="$VERSION" \
    CODE_SIGN_IDENTITY="${DEVELOPER_ID_APPLICATION}" \
    CODE_SIGN_STYLE=Manual \
    DEVELOPMENT_TEAM="${APPLE_TEAM_ID}"

# Export
xcodebuild -exportArchive \
    -archivePath "$ARCHIVE_PATH" \
    -exportPath "$EXPORT_PATH" \
    -exportOptionsPlist scripts/ExportOptions.plist

APP_PATH="$EXPORT_PATH/Alp.app"

# Notarize
#
# notarytool only accepts .zip/.dmg/.pkg — never a bare .app. Zip the app
# (keeping the parent so the bundle structure is preserved), submit the zip,
# then staple the original .app. The DMG is notarized+stapled separately below.
echo "==> Notarizing app..."
APP_ZIP="build/Alp-app.zip"
ditto -c -k --keepParent "$APP_PATH" "$APP_ZIP"
xcrun notarytool submit "$APP_ZIP" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_ID_PASSWORD" \
    --wait

# Staple
xcrun stapler staple "$APP_PATH"

# Create DMG
echo "==> Creating DMG..."
create-dmg \
    --volname "Alp" \
    --volicon "$APP_PATH/Contents/Resources/AppIcon.icns" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "Alp.app" 150 200 \
    --app-drop-link 450 200 \
    --no-internet-enable \
    "$DMG_PATH" \
    "$APP_PATH"

# Sign DMG
codesign --force --sign "${DEVELOPER_ID_APPLICATION}" "$DMG_PATH"

# Notarize and staple the DMG itself so Gatekeeper clears it offline (the
# common case: a user downloads the DMG directly rather than via Sparkle).
echo "==> Notarizing DMG..."
xcrun notarytool submit "$DMG_PATH" \
    --apple-id "$APPLE_ID" \
    --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_ID_PASSWORD" \
    --wait
xcrun stapler staple "$DMG_PATH"

# SHA256 manifest. Lets users verify download integrity independently — useful
# when fetching via curl/wget or comparing against the GitHub release page.
SHASUM_PATH="build/Alp-${VERSION}.SHA256SUMS"
( cd build && shasum -a 256 "Alp-${VERSION}.dmg" ) > "$SHASUM_PATH"
echo "==> SHA256 manifest at $SHASUM_PATH"
cat "$SHASUM_PATH"
DMG_SHA="$(awk '{print $1}' "$SHASUM_PATH")"

# Detached GPG signature on the checksums. Unlike a bare SHA256SUMS (which only
# defends against corruption, not substitution), a detached GPG signature lets
# users confirm the checksums came from us — fitting for a GPG app. Best-effort:
# set GPG_SIGNING_KEY (a key id/fingerprint in the runner keyring) to enable.
if [[ -n "${GPG_SIGNING_KEY:-}" ]]; then
    gpg --local-user "$GPG_SIGNING_KEY" --armor --detach-sign \
        --output "${SHASUM_PATH}.asc" "$SHASUM_PATH"
    echo "==> Signed checksums at ${SHASUM_PATH}.asc"
else
    echo "Note: GPG_SIGNING_KEY not set — SHA256SUMS left unsigned." >&2
fi

# release.json — the manifest the in-app notification-only updater fetches and
# verifies (Ed25519 over the raw JSON bytes). Emitted with python3 so the JSON
# is well-formed and stable; do NOT reformat it after signing.
RELEASE_JSON="build/release.json"
DOWNLOAD_URL="${RELEASE_DOWNLOAD_URL:-https://github.com/alp-gpg/alp/releases/download/v${VERSION}/Alp-${VERSION}.dmg}"
RELEASE_NOTES="${RELEASE_NOTES:-Bug fixes and improvements.}"
MIN_OS="${MIN_OS:-26.0}"
python3 - "$VERSION" "$MIN_OS" "$DOWNLOAD_URL" "$DMG_SHA" "$RELEASE_NOTES" > "$RELEASE_JSON" <<'PY'
import json, sys
version, min_os, url, sha, notes = sys.argv[1:6]
json.dump({"version": version, "minOS": min_os, "url": url, "sha256": sha, "notes": notes}, sys.stdout)
PY
echo "==> Wrote $RELEASE_JSON"
cat "$RELEASE_JSON"; echo

# Sign release.json with Ed25519 using CryptoKit (no Sparkle dependency).
# The private key is a base64-encoded 32-byte raw Ed25519 seed, provided
# via the ALP_UPDATE_PRIVATE_KEY env var. The matching public key is
# embedded in the app as AlpUpdatePublicKey in Info.plist; UpdateChecker
# verifies this base64 signature over the raw release.json bytes.
if [[ -n "${ALP_UPDATE_PRIVATE_KEY:-}" ]]; then
    swift scripts/sign-release.swift "$RELEASE_JSON" > "build/release.json.sig"
    echo "==> release.json.sig:"; cat "build/release.json.sig"
    echo "==> Commit build/release.json + build/release.json.sig to /docs and push (GitHub Pages serves the feed)."
else
    echo "Warning: ALP_UPDATE_PRIVATE_KEY not set — release.json.sig not produced." >&2
    echo "         Generate a keypair (see BUILDING.md) and store the private key as a GitHub secret." >&2
fi

echo "==> Done: $DMG_PATH"
