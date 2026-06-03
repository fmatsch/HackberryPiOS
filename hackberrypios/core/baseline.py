"""Network baselines and change detection.

Save the set of hosts seen on a site, then on the next visit compare against it
to surface **new**, **missing**, and **changed** devices. New unknown hosts are
effectively rogue-device detection; an IP whose MAC changed can indicate
spoofing or a swapped device.

Baselines are keyed to a profile and stored next to it as
``<profile>.baseline.json``.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime

from . import profiles


@dataclass
class BaselineHost:
    ip: str
    mac: str = ""
    name: str = ""


@dataclass
class BaselineDiff:
    new_hosts: list[BaselineHost] = field(default_factory=list)
    missing_hosts: list[BaselineHost] = field(default_factory=list)
    changed_hosts: list[str] = field(default_factory=list)   # human-readable
    baseline_date: str = ""
    had_baseline: bool = True

    @property
    def clean(self) -> bool:
        return not (self.new_hosts or self.missing_hosts or self.changed_hosts)

    @property
    def summary(self) -> str:
        if not self.had_baseline:
            return "no baseline saved yet"
        if self.clean:
            return "no changes since baseline"
        return (f"{len(self.new_hosts)} new, {len(self.missing_hosts)} missing, "
                f"{len(self.changed_hosts)} changed")


def _baseline_path(profile_name: str) -> str:
    return profiles.path_for(profile_name).replace(".json", ".baseline.json")


def save(profile_name: str, hosts) -> str:
    """Persist *hosts* (discovery.Host list) as the baseline for a profile."""
    profiles._ensure_dir()
    data = {
        "saved": datetime.now().isoformat(timespec="seconds"),
        "hosts": [{"ip": h.ip, "mac": h.mac or "", "name": h.name or ""}
                  for h in hosts],
    }
    path = _baseline_path(profile_name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return path


def load(profile_name: str) -> dict | None:
    path = _baseline_path(profile_name)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _key(mac: str, ip: str) -> str:
    """Identify a host by MAC when available, else by IP."""
    return mac.lower() if mac else f"ip:{ip}"


def compare(profile_name: str, hosts) -> BaselineDiff:
    """Compare current *hosts* against the saved baseline for the profile."""
    stored = load(profile_name)
    if stored is None:
        return BaselineDiff(had_baseline=False)

    old = {_key(h.get("mac", ""), h.get("ip", "")): h for h in stored["hosts"]}
    new = {_key(h.mac or "", h.ip): h for h in hosts}

    diff = BaselineDiff(baseline_date=stored.get("saved", ""))

    for key, h in new.items():
        if key not in old:
            diff.new_hosts.append(BaselineHost(h.ip, h.mac or "", h.name or ""))
        else:
            o = old[key]
            if o.get("ip") and o["ip"] != h.ip:
                diff.changed_hosts.append(
                    f"{h.mac or h.ip}: IP {o['ip']} → {h.ip}")
            old_name = o.get("name") or ""
            new_name = h.name or ""
            if old_name and new_name and old_name != new_name:
                diff.changed_hosts.append(
                    f"{h.ip}: name {old_name} → {new_name}")

    for key, o in old.items():
        if key not in new:
            diff.missing_hosts.append(
                BaselineHost(o.get("ip", ""), o.get("mac", ""), o.get("name", "")))

    return diff
