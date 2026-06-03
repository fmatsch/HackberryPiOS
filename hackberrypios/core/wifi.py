"""Wi-Fi survey and link quality.

Uses NetworkManager (`nmcli`) when present — it gives security info without
root — and falls back to `iw dev <if> scan`. Also reports the current link
(signal, bitrate, frequency) which feeds the recommendation engine.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .utils import have, run
from . import netinfo


@dataclass
class AccessPoint:
    ssid: str
    bssid: str = ""
    channel: str = ""
    band: str = ""           # 2.4 GHz / 5 GHz / 6 GHz
    signal: int | None = None      # percentage 0-100
    security: str = ""
    in_use: bool = False

    @property
    def is_open(self) -> bool:
        sec = self.security.lower()
        return sec in ("", "--", "none", "open")

    @property
    def is_weak_crypto(self) -> bool:
        sec = self.security.lower()
        return "wep" in sec or ("wpa1" in sec and "wpa2" not in sec)


@dataclass
class WifiLink:
    connected: bool = False
    ssid: str = ""
    signal: int | None = None
    bitrate: str = ""
    frequency: str = ""
    security: str = ""


@dataclass
class WifiSurvey:
    interface: str | None = None
    link: WifiLink = field(default_factory=WifiLink)
    access_points: list[AccessPoint] = field(default_factory=list)
    error: str | None = None

    @property
    def open_networks(self) -> list[AccessPoint]:
        return [ap for ap in self.access_points if ap.is_open]

    @property
    def weak_networks(self) -> list[AccessPoint]:
        return [ap for ap in self.access_points if ap.is_weak_crypto]


def _wireless_iface() -> str | None:
    ctx = netinfo.gather()
    for iface in ctx.interfaces:
        if iface.is_wireless:
            return iface.name
    return None


def _band_for_channel(chan: str) -> str:
    try:
        c = int(chan)
    except ValueError:
        return ""
    if 1 <= c <= 14:
        return "2.4 GHz"
    if 32 <= c <= 177:
        return "5 GHz"
    return ""


def _nmcli_survey(iface: str | None) -> WifiSurvey:
    survey = WifiSurvey(interface=iface)
    run(["nmcli", "device", "wifi", "rescan"], timeout=10)
    res = run(["nmcli", "-t", "-f",
               "IN-USE,SSID,BSSID,CHAN,SIGNAL,SECURITY",
               "device", "wifi", "list"], timeout=15)
    if not res.ok:
        survey.error = res.stderr.strip() or "nmcli wifi list failed"
        return survey

    for line in res.stdout.splitlines():
        # nmcli escapes ':' inside BSSID as '\:'
        fields = re.split(r"(?<!\\):", line)
        fields = [f.replace("\\:", ":") for f in fields]
        if len(fields) < 6:
            continue
        in_use, ssid, bssid, chan, signal, security = fields[:6]
        try:
            sig = int(signal)
        except ValueError:
            sig = None
        ap = AccessPoint(
            ssid=ssid or "<hidden>",
            bssid=bssid,
            channel=chan,
            band=_band_for_channel(chan),
            signal=sig,
            security=security.strip() or "Open",
            in_use=in_use.strip() == "*",
        )
        survey.access_points.append(ap)
        if ap.in_use:
            survey.link = WifiLink(connected=True, ssid=ap.ssid, signal=sig,
                                   security=ap.security)

    survey.access_points.sort(key=lambda a: (a.signal or 0), reverse=True)
    _augment_link(survey, iface)
    return survey


def _augment_link(survey: WifiSurvey, iface: str | None) -> None:
    """Add bitrate/frequency to the current link via `iw`."""
    if not iface or not have("iw"):
        return
    res = run(["iw", "dev", iface, "link"], timeout=5)
    if "Not connected" in res.stdout or not res.ok:
        return
    survey.link.connected = True
    br = re.search(r"tx bitrate:\s*([\d.]+\s*\w+)", res.stdout)
    fr = re.search(r"freq:\s*(\d+)", res.stdout)
    ss = re.search(r"signal:\s*(-?\d+)\s*dBm", res.stdout)
    if br:
        survey.link.bitrate = br.group(1)
    if fr:
        survey.link.frequency = f"{int(fr.group(1)) / 1000:.3f} GHz"
    if ss and survey.link.signal is None:
        # convert dBm roughly to a 0-100 quality figure
        dbm = int(ss.group(1))
        survey.link.signal = max(0, min(100, 2 * (dbm + 100)))


def _iw_survey(iface: str) -> WifiSurvey:
    survey = WifiSurvey(interface=iface)
    res = run(["iw", "dev", iface, "scan"], timeout=20, sudo=True)
    if not res.ok:
        survey.error = "iw scan failed (needs root)"
        return survey

    ap: AccessPoint | None = None
    for line in res.stdout.splitlines():
        bss = re.match(r"BSS ([0-9a-f:]{17})", line.strip())
        if bss:
            if ap:
                survey.access_points.append(ap)
            ap = AccessPoint(ssid="<hidden>", bssid=bss.group(1))
            continue
        if ap is None:
            continue
        if "SSID:" in line:
            ap.ssid = line.split("SSID:", 1)[1].strip() or "<hidden>"
        elif "signal:" in line:
            m = re.search(r"signal:\s*(-?[\d.]+)", line)
            if m:
                ap.signal = max(0, min(100, int(2 * (float(m.group(1)) + 100))))
        elif "DS Parameter set: channel" in line:
            m = re.search(r"channel (\d+)", line)
            if m:
                ap.channel = m.group(1)
                ap.band = _band_for_channel(m.group(1))
        elif "RSN:" in line:
            ap.security = "WPA2"
        elif "WPA:" in line and not ap.security:
            ap.security = "WPA"
    if ap:
        survey.access_points.append(ap)
    for a in survey.access_points:
        if not a.security:
            a.security = "Open"
    survey.access_points.sort(key=lambda a: (a.signal or 0), reverse=True)
    _augment_link(survey, iface)
    return survey


def survey() -> WifiSurvey:
    """Run a Wi-Fi survey using the best available backend."""
    iface = _wireless_iface()
    if have("nmcli"):
        return _nmcli_survey(iface)
    if iface and have("iw"):
        return _iw_survey(iface)
    return WifiSurvey(interface=iface,
                      error="no Wi-Fi tooling (nmcli/iw) or no wireless interface")


# Non-overlapping 2.4 GHz channels.
_NON_OVERLAP_24 = [1, 6, 11]


@dataclass
class ChannelAdvice:
    counts_24: dict[int, int] = field(default_factory=dict)   # channel -> AP count
    counts_5: dict[int, int] = field(default_factory=dict)
    best_24: int | None = None
    best_5: int | None = None
    current_channel: str = ""
    notes: list[str] = field(default_factory=list)


def analyse_channels(survey: WifiSurvey) -> ChannelAdvice:
    """Recommend the least congested channel from a completed survey.

    For 2.4 GHz we only consider the non-overlapping channels 1/6/11 and weight
    by how many APs sit on or adjacent to each. For 5 GHz we pick the least used
    seen channel.
    """
    advice = ChannelAdvice()
    for ap in survey.access_points:
        try:
            ch = int(ap.channel)
        except (ValueError, TypeError):
            continue
        if 1 <= ch <= 14:
            advice.counts_24[ch] = advice.counts_24.get(ch, 0) + 1
        elif ch >= 32:
            advice.counts_5[ch] = advice.counts_5.get(ch, 0) + 1
        if ap.in_use:
            advice.current_channel = ap.channel

    if advice.counts_24 or any(1 <= int(a.channel or 0) <= 14
                               for a in survey.access_points
                               if (a.channel or "").isdigit()):
        # Weighted load for each non-overlapping channel (adjacent channels
        # within ±2 interfere on 2.4 GHz).
        load = {}
        for cand in _NON_OVERLAP_24:
            load[cand] = sum(cnt for ch, cnt in advice.counts_24.items()
                             if abs(ch - cand) <= 2)
        advice.best_24 = min(load, key=load.get)
        advice.notes.append(
            f"2.4 GHz: least congested non-overlapping channel is "
            f"{advice.best_24} ({load[advice.best_24]} nearby AP(s)).")

    if advice.counts_5:
        # Prefer a clean channel not currently used by anyone.
        used = set(advice.counts_5)
        advice.best_5 = min(advice.counts_5, key=advice.counts_5.get)
        advice.notes.append(
            f"5 GHz: channel {advice.best_5} is the least used of those in range "
            f"({advice.counts_5[advice.best_5]} AP(s)). Consider any unused DFS "
            f"channel for more headroom.")

    if not advice.notes:
        advice.notes.append("Not enough APs in range to make a channel "
                            "recommendation.")
    return advice
