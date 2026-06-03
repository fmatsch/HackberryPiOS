"""Recommendation engine.

Turns the raw scan results into a short, prioritised, human-readable list of
"what you should look at / do next" — the bit that makes HackberryPiOS a
*one-stop* assistant rather than just a pile of scanners.

Each recommendation has a priority and a category so the dashboard can show a
compact, colour-coded action list tailored to the screen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Priority(IntEnum):
    DONE = 0        # positive confirmation
    INFO = 1
    SUGGESTED = 2
    IMPORTANT = 3
    URGENT = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass
class Recommendation:
    text: str
    priority: Priority
    category: str = "general"

    def __lt__(self, other: "Recommendation") -> bool:
        return self.priority > other.priority


@dataclass
class Assessment:
    recommendations: list[Recommendation] = field(default_factory=list)
    score: int = 100        # 0-100 network health score (higher = better)

    def add(self, text: str, priority: Priority, category: str = "general") -> None:
        self.recommendations.append(Recommendation(text, priority, category))

    @property
    def top(self) -> list[Recommendation]:
        return sorted(self.recommendations)


def build(*, netctx=None, hosts=None, dc_statuses=None, share_results=None,
          printers=None, wifi=None, security_findings=None,
          latency=None, baseline_diff=None) -> Assessment:
    """Assemble an :class:`Assessment` from whatever results are available.

    Every argument is optional; the engine only comments on data it was given,
    so it works incrementally as the user runs more scans.
    """
    a = Assessment()
    penalty = 0

    # --- Connectivity / local context -------------------------------------
    if netctx is not None:
        if not netctx.primary or not netctx.primary.ipv4:
            a.add("No active network connection detected — connect to a "
                  "network before scanning.", Priority.URGENT, "connectivity")
            penalty += 40
        else:
            a.add(f"Connected on {netctx.primary.name} "
                  f"({netctx.primary.cidr}).", Priority.DONE, "connectivity")
        if netctx.primary and not netctx.gateway:
            a.add("No default gateway — local-only connectivity.",
                  Priority.IMPORTANT, "connectivity")
            penalty += 10
        if not netctx.dns_servers:
            a.add("No DNS servers configured — name resolution will fail.",
                  Priority.IMPORTANT, "connectivity")
            penalty += 8

    # --- Domain controllers ------------------------------------------------
    if dc_statuses:
        healthy = [d for d in dc_statuses if d.health == "healthy"]
        down = [d for d in dc_statuses if not d.reachable]
        degraded = [d for d in dc_statuses if d.health == "degraded"]
        if healthy:
            a.add(f"{len(healthy)} domain controller(s) reachable and healthy.",
                  Priority.DONE, "directory")
        if degraded:
            names = ", ".join(d.host for d in degraded)
            a.add(f"DC(s) degraded (missing critical services): {names}.",
                  Priority.IMPORTANT, "directory")
            penalty += 12
        if down:
            names = ", ".join(d.host for d in down)
            a.add(f"DC(s) unreachable: {names}. Check routing/firewall/DC health.",
                  Priority.URGENT, "directory")
            penalty += 20

    # --- Inventory ---------------------------------------------------------
    if hosts is not None:
        named = sum(1 for h in hosts if h.name)
        a.add(f"{len(hosts)} hosts discovered ({named} with names).",
              Priority.INFO, "inventory")
        unknown = len(hosts) - named
        if unknown > 0 and len(hosts) > 0:
            a.add(f"{unknown} host(s) without resolvable names — verify they "
                  "are expected devices, not rogue/unmanaged.",
                  Priority.SUGGESTED, "inventory")

    # --- Shares ------------------------------------------------------------
    if share_results is not None:
        anon = [r for r in share_results if r.guest_allowed]
        if anon:
            a.add(f"{len(anon)} host(s) expose anonymous SMB shares — restrict "
                  "to authenticated access.", Priority.URGENT, "data")
            penalty += 15 * min(len(anon), 3)
        elif share_results:
            a.add(f"{len(share_results)} host(s) share files; none anonymous.",
                  Priority.DONE, "data")

    # --- Printers ----------------------------------------------------------
    if printers is not None and printers:
        jetdirect = [p for p in printers if "JetDirect" in p.protocols]
        a.add(f"{len(printers)} printer(s) found.", Priority.INFO, "printing")
        if jetdirect:
            a.add(f"{len(jetdirect)} printer(s) expose raw port 9100 — ensure "
                  "they're on a trusted VLAN and firmware is current.",
                  Priority.SUGGESTED, "printing")

    # --- Wi-Fi -------------------------------------------------------------
    if wifi is not None and not wifi.error:
        if wifi.open_networks:
            a.add(f"{len(wifi.open_networks)} open (unencrypted) Wi-Fi "
                  "network(s) in range.", Priority.IMPORTANT, "wireless")
            penalty += 8
        if wifi.weak_networks:
            a.add(f"{len(wifi.weak_networks)} Wi-Fi network(s) using WEP/WPA1 — "
                  "upgrade to WPA2/WPA3.", Priority.URGENT, "wireless")
            penalty += 12
        if wifi.link.connected and wifi.link.signal is not None:
            if wifi.link.signal < 40:
                a.add(f"Weak Wi-Fi signal ({wifi.link.signal}%) on "
                      f"{wifi.link.ssid} — move closer or add an AP.",
                      Priority.SUGGESTED, "wireless")
            else:
                a.add(f"Wi-Fi link healthy ({wifi.link.signal}% on "
                      f"{wifi.link.ssid}).", Priority.DONE, "wireless")

    # --- Latency / performance --------------------------------------------
    if latency is not None and not latency.error:
        if latency.quality in ("poor", "fair"):
            a.add(f"Gateway latency {latency.rtt_avg:.0f} ms / "
                  f"{latency.loss_pct:.0f}% loss — investigate congestion or "
                  "cabling.", Priority.IMPORTANT, "performance")
            penalty += 6
        elif latency.quality == "excellent":
            a.add(f"LAN latency excellent ({latency.rtt_avg:.1f} ms).",
                  Priority.DONE, "performance")

    # --- Security findings -------------------------------------------------
    if security_findings:
        from .security import Severity
        crit = [f for f in security_findings if f.severity >= Severity.HIGH]
        med = [f for f in security_findings
               if f.severity == Severity.MEDIUM]
        if crit:
            a.add(f"{len(crit)} high/critical security finding(s) — review the "
                  "Security tab immediately.", Priority.URGENT, "security")
            penalty += 10 * min(len(crit), 4)
        if med:
            a.add(f"{len(med)} medium security finding(s) to remediate.",
                  Priority.IMPORTANT, "security")
            penalty += 4 * min(len(med), 4)
        if not crit and not med:
            a.add("No high/medium security findings in what was scanned.",
                  Priority.DONE, "security")

    # --- Baseline / change detection --------------------------------------
    if baseline_diff is not None and baseline_diff.had_baseline:
        if baseline_diff.new_hosts:
            a.add(f"{len(baseline_diff.new_hosts)} NEW host(s) since baseline — "
                  "verify they are authorised, not rogue devices.",
                  Priority.URGENT, "inventory")
            penalty += 8 * min(len(baseline_diff.new_hosts), 3)
        if baseline_diff.changed_hosts:
            a.add(f"{len(baseline_diff.changed_hosts)} host(s) changed "
                  "IP/MAC/name since baseline — possible spoofing or swaps.",
                  Priority.IMPORTANT, "inventory")
        if baseline_diff.missing_hosts:
            a.add(f"{len(baseline_diff.missing_hosts)} host(s) from baseline are "
                  "missing — confirm expected downtime.", Priority.SUGGESTED,
                  "inventory")
        if baseline_diff.clean:
            a.add("Inventory matches the saved baseline — no changes.",
                  Priority.DONE, "inventory")

    if not a.recommendations:
        a.add("Run a discovery scan to populate the dashboard.",
              Priority.SUGGESTED, "general")

    a.score = max(0, 100 - penalty)
    return a
