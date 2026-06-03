#!/usr/bin/env bash
#
# HackberryPiOS autostart manager.
#
# Launches the UI automatically when you log in on the device's primary
# console (tty1) — exactly what you want on a dedicated handheld — while
# leaving SSH sessions and other TTYs untouched.
#
# It is intentionally easy to turn off:
#   ./scripts/autostart.sh enable     # install the autostart hook
#   ./scripts/autostart.sh disable    # remove it again
#   ./scripts/autostart.sh status     # show current state
#
# Even while enabled you can suppress a single boot by setting the env var
#   HPI_NO_AUTOSTART=1
# (e.g. add it before login, or press Ctrl+C to drop to the shell).
#
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCHER="$REPO/.venv/bin/hackberrypios"
RC="${HPI_RC_FILE:-$HOME/.bashrc}"

BEGIN="# >>> HackberryPiOS autostart >>>"
END="# <<< HackberryPiOS autostart <<<"

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

is_enabled() { grep -qF "$BEGIN" "$RC" 2>/dev/null; }

remove_block() {
    [[ -f "$RC" ]] || return 0
    # Delete everything between the markers (inclusive).
    sed -i.hpi-bak "/$(printf '%s' "$BEGIN" | sed 's/[][\.*^$/]/\\&/g')/,/$(printf '%s' "$END" | sed 's/[][\.*^$/]/\\&/g')/d" "$RC"
    rm -f "$RC.hpi-bak"
}

enable() {
    if [[ ! -x "$LAUNCHER" ]]; then
        warn "Launcher not found at $LAUNCHER — run ./install.sh first."
        warn "Continuing anyway; the hook will work once the venv exists."
    fi
    remove_block            # avoid duplicate blocks
    cat >> "$RC" <<EOF
$BEGIN
# Auto-launch HackberryPiOS on the primary console only.
# Disable with: $REPO/scripts/autostart.sh disable
if [ -z "\$HPI_NO_AUTOSTART" ] && [ "\$(tty)" = "/dev/tty1" ] && [ -x "$LAUNCHER" ]; then
    "$LAUNCHER"
fi
$END
EOF
    say "Autostart enabled (launches on tty1 login)."
    say "Disable any time: $REPO/scripts/autostart.sh disable"
}

disable() {
    if is_enabled; then
        remove_block
        say "Autostart disabled."
    else
        say "Autostart was not enabled — nothing to do."
    fi
}

status() {
    if is_enabled; then
        say "Autostart is ENABLED in $RC (launches on tty1)."
    else
        say "Autostart is DISABLED."
    fi
}

case "${1:-status}" in
    enable)  enable ;;
    disable) disable ;;
    status)  status ;;
    *) echo "Usage: $0 {enable|disable|status}"; exit 1 ;;
esac
