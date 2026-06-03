"""Local device info for the header — battery and CPU temperature.

The HackberryPi is a battery-powered handheld, so showing charge state at a
glance is genuinely useful. Everything degrades to ``present=False`` on systems
without the relevant sysfs entries (e.g. a desktop or macOS).
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass


@dataclass
class Battery:
    present: bool = False
    percent: int | None = None
    status: str = ""        # Charging / Discharging / Full / Not charging

    @property
    def icon(self) -> str:
        if not self.present or self.percent is None:
            return ""
        if self.status.lower() == "charging":
            return "⚡"
        if self.percent >= 80:
            return "█"
        if self.percent >= 40:
            return "▓"
        if self.percent >= 15:
            return "▒"
        return "░"


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return None


def battery() -> Battery:
    """Read the first battery-type power supply under sysfs."""
    for supply in sorted(glob.glob("/sys/class/power_supply/*")):
        type_ = _read(os.path.join(supply, "type")) or ""
        if type_.lower() != "battery":
            continue
        cap = _read(os.path.join(supply, "capacity"))
        if cap is None:
            continue
        try:
            pct = int(cap)
        except ValueError:
            continue
        return Battery(present=True, percent=pct,
                       status=_read(os.path.join(supply, "status")) or "")
    return Battery(present=False)


def cpu_temp_c() -> float | None:
    """Best-effort CPU temperature in °C (Raspberry Pi thermal zone)."""
    raw = _read("/sys/class/thermal/thermal_zone0/temp")
    if raw and raw.lstrip("-").isdigit():
        return int(raw) / 1000.0
    return None
