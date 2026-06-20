#!/usr/bin/env bash
# Capture screenshots of whatever app window is currently frontmost.
#
# Workflow:
#   1. Run this script in a terminal.
#   2. Click the Alp window (or Mail compose, or any other window) you want.
#   3. Switch back to the terminal, press ENTER. Optionally type a short
#      label first (e.g. "compose-toolbar") so the file is named for you.
#   4. Repeat for the next screen. Ctrl+C when done.
#
# Output:  build/ui-screenshots/<timestamp>/<NN>[-label].png
#
# First run will prompt for Accessibility / Screen Recording permissions.
# Approve both in System Settings → Privacy & Security and rerun.
set -euo pipefail

DIR="build/ui-screenshots/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$DIR"

cat <<EOF
Saving to: $DIR/
Focus the window you want captured, then come back here and press ENTER.
Optionally type a label first ("compose-toolbar", "set-expiry-sheet", …).
Ctrl+C to stop.

EOF

i=1
while true; do
    if ! read -r -p "  capture $(printf '%02d' "$i")> " LABEL; then
        echo
        break
    fi

    WIN_ID="$(osascript -e \
        'tell application "System Events" to get id of first window of (first application process whose frontmost is true)' \
        2>/dev/null || true)"

    SAFE_LABEL="$(printf '%s' "$LABEL" | tr -cd '[:alnum:]-_' | cut -c1-40)"
    NAME="$(printf '%02d' "$i")"
    [[ -n "$SAFE_LABEL" ]] && NAME="${NAME}-${SAFE_LABEL}"
    FILE="$DIR/${NAME}.png"

    if [[ -n "$WIN_ID" ]]; then
        # -l captures one specific on-screen window by ID.
        screencapture -l"$WIN_ID" -o "$FILE"
    else
        # Fallback: full-screen grab if accessibility lookup failed.
        screencapture -x -o "$FILE"
    fi

    if [[ -s "$FILE" ]]; then
        echo "    saved $FILE"
        i=$((i + 1))
    else
        echo "    capture failed (empty file). Check permissions in" \
             "System Settings → Privacy & Security → Screen Recording."
        rm -f "$FILE"
    fi
done

echo "Done. ${DIR}/"
