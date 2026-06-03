"""Per-site profiles.

When you look after several networks, a profile stores the context for each one
— AD domain, expected subnet, NTP server, an optional SMB username, and free
notes — so arriving on site is "load profile → scan" instead of retyping
everything.

Profiles live as JSON under ``~/.config/hackberrypios/profiles/``. Passwords are
deliberately **not** stored (enter them per scan); a username may be saved for
convenience.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field

CONFIG_DIR = os.path.expanduser(
    os.path.join(os.environ.get("XDG_CONFIG_HOME", "~/.config"), "hackberrypios"))
PROFILE_DIR = os.path.join(CONFIG_DIR, "profiles")


@dataclass
class Profile:
    name: str
    domain: str = ""
    subnet: str = ""           # CIDR, e.g. 10.20.30.0/24
    ntp_server: str = ""       # host/IP to check clock skew against
    username: str = ""         # optional SMB username (no password stored)
    notes: str = ""

    def slug(self) -> str:
        return re.sub(r"[^A-Za-z0-9_-]+", "_", self.name).strip("_") or "profile"


def _ensure_dir() -> None:
    os.makedirs(PROFILE_DIR, exist_ok=True)


def path_for(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", name).strip("_") or "profile"
    return os.path.join(PROFILE_DIR, f"{slug}.json")


def save(profile: Profile) -> str:
    _ensure_dir()
    p = path_for(profile.name)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(asdict(profile), fh, indent=2)
    return p


def load(name: str) -> Profile | None:
    p = path_for(name)
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        return Profile(**{k: data.get(k, "") for k in
                          ("name", "domain", "subnet", "ntp_server",
                           "username", "notes")})
    except (OSError, ValueError, TypeError):
        return None


def list_profiles() -> list[str]:
    if not os.path.isdir(PROFILE_DIR):
        return []
    names = []
    for fn in sorted(os.listdir(PROFILE_DIR)):
        if fn.endswith(".json") and not fn.endswith(".baseline.json"):
            prof = load(fn[:-5])
            names.append(prof.name if prof else fn[:-5])
    return names


def delete(name: str) -> bool:
    p = path_for(name)
    removed = False
    for target in (p, p.replace(".json", ".baseline.json")):
        if os.path.exists(target):
            os.remove(target)
            removed = True
    return removed
