"""MAC-address vendor (OUI) lookup.

Bundling the full IEEE OUI registry (~3 MB) would bloat the repo, so instead we
read nmap's ``nmap-mac-prefixes`` file at runtime when it is present — that
gives full vendor coverage for free on any box with nmap installed. When it is
missing we fall back to the small built-in hint table in :mod:`utils`.
"""

from __future__ import annotations

import os
from functools import lru_cache

from .utils import humanise_mac_vendor

_PREFIX_PATHS = [
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
]


@lru_cache(maxsize=1)
def _load_db() -> dict[str, str]:
    """Parse ``nmap-mac-prefixes`` into ``{AABBCC: 'Vendor'}`` (cached)."""
    for path in _PREFIX_PATHS:
        if not os.path.exists(path):
            continue
        db: dict[str, str] = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2 and len(parts[0]) == 6:
                        db[parts[0].upper()] = parts[1].strip()
        except OSError:
            return {}
        return db
    return {}


def lookup(mac: str | None) -> str:
    """Return the vendor for *mac*, or an empty string if unknown."""
    if not mac:
        return ""
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    db = _load_db()
    if prefix in db:
        return db[prefix]
    return humanise_mac_vendor(mac)


def have_full_db() -> bool:
    return bool(_load_db())
