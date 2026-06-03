#!/usr/bin/env bash
#
# HackberryPiOS installer for Raspberry Pi OS (Bookworm or newer).
# Installs the external scanning tools, sets up a Python virtual environment,
# and (optionally) grants the unprivileged capabilities arp-scan/nmap need.
#
# Usage:  ./install.sh            # full install
#         ./install.sh --no-apt   # skip apt (Python venv only)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"
SKIP_APT=0
[[ "${1:-}" == "--no-apt" ]] && SKIP_APT=1

# External tools that power the scans. All are in the Raspberry Pi OS repos.
APT_PACKAGES=(
  nmap arp-scan smbclient samba-common-bin avahi-utils
  iw network-manager iproute2 dnsutils iperf3 curl
)

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

if [[ "$SKIP_APT" -eq 0 ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    say "Installing system tools (sudo apt-get)…"
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv python3-pip "${APT_PACKAGES[@]}"
  else
    warn "apt-get not found — skipping system packages (not a Debian system?)."
  fi
fi

say "Creating Python virtual environment in $VENV…"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip setuptools wheel >/dev/null
say "Installing HackberryPiOS…"
"$VENV/bin/pip" install -e "$HERE"

# Allow arp-scan & nmap raw-socket scans without sudo (optional, recommended).
if command -v setcap >/dev/null 2>&1; then
  for bin in arp-scan nmap; do
    path="$(command -v "$bin" 2>/dev/null || true)"
    if [[ -n "$path" ]]; then
      say "Granting cap_net_raw to $bin…"
      sudo setcap cap_net_raw,cap_net_admin+eip "$path" 2>/dev/null \
        || warn "Could not setcap $bin (will fall back to sudo / ping sweep)."
    fi
  done
fi

cat <<EOF

$(say "Done.")

Launch the UI:        $VENV/bin/hackberrypios
Headless full sweep:  $VENV/bin/hackberrypios --cli
Export a report:      $VENV/bin/hackberrypios --cli --json report.json

Tip: add an alias to ~/.bashrc:
    alias hpi='$VENV/bin/hackberrypios'

Launch automatically on the device console at login (easy to undo):
    $HERE/scripts/autostart.sh enable      # turn on
    $HERE/scripts/autostart.sh disable     # turn off
EOF
