"""Host discovery on the local subnet.

Strategy (best available first):
  1. ``arp-scan`` (fast, gives MAC + vendor)  -- needs root/cap_net_raw
  2. ``nmap -sn`` ping sweep                  -- works unprivileged
  3. ``ip neigh`` (passive ARP cache)         -- always available fallback

Names are resolved opportunistically via reverse DNS, NetBIOS (``nmblookup``)
and mDNS, since mixed Linux/Windows-AD networks expose names differently.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
from dataclasses import dataclass, field

from . import oui
from .utils import find_ipv4, have, run


@dataclass
class Host:
    ip: str
    mac: str | None = None
    name: str | None = None
    vendor: str | None = None
    os: str = ""               # populated by os_fingerprint()
    source: str = ""           # how it was discovered
    tags: list[str] = field(default_factory=list)

    def merge(self, other: "Host") -> None:
        self.mac = self.mac or other.mac
        self.name = self.name or other.name
        self.vendor = self.vendor or other.vendor
        self.os = self.os or other.os
        for t in other.tags:
            if t not in self.tags:
                self.tags.append(t)


def _reverse_dns(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _netbios_name(ip: str) -> str | None:
    res = run(["nmblookup", "-A", ip], timeout=6)
    if not res.ok:
        return None
    for line in res.stdout.splitlines():
        # "    WORKSTATION     <00> -         B <ACTIVE>"
        m = re.match(r"\s+(\S+)\s+<00>\s+-?\s+\w*\s*<ACTIVE>", line)
        if m and not line.strip().startswith("MAC"):
            name = m.group(1)
            if name != "__MSBROWSE__":
                return name
    return None


def _arp_scan(cidr: str) -> list[Host]:
    res = run(["arp-scan", "--localnet", "--quiet", "--plain"],
              timeout=40, sudo=True)
    if not res.ok:
        # Try explicit interface-less localnet without --plain (older versions)
        res = run(["arp-scan", cidr], timeout=40, sudo=True)
        if not res.ok:
            return []
    hosts: list[Host] = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and find_ipv4(parts[0]):
            mac = parts[1]
            vendor = " ".join(parts[2:]) if len(parts) > 2 else None
            hosts.append(Host(ip=parts[0], mac=mac.lower(),
                              vendor=vendor or oui.lookup(mac) or None,
                              source="arp-scan"))
    return hosts


def _nmap_ping(cidr: str) -> list[Host]:
    res = run(["nmap", "-sn", "-n", "--max-retries", "1", cidr], timeout=90)
    if not res.ok:
        return []
    hosts: list[Host] = []
    current_ip = None
    for line in res.stdout.splitlines():
        m = re.search(r"Nmap scan report for ([\d.]+)", line)
        if m:
            current_ip = m.group(1)
            hosts.append(Host(ip=current_ip, source="nmap"))
            continue
        mac_m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})\s*(?:\(([^)]*)\))?", line)
        if mac_m and hosts:
            hosts[-1].mac = mac_m.group(1).lower()
            vendor = mac_m.group(2)
            hosts[-1].vendor = (vendor if vendor and vendor != "Unknown"
                                else oui.lookup(mac_m.group(1)) or None)
    return hosts


def _ip_neigh() -> list[Host]:
    res = run(["ip", "neigh"], timeout=5)
    hosts: list[Host] = []
    for line in res.stdout.splitlines():
        m = re.match(r"([\d.]+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})", line)
        if m and "FAILED" not in line:
            hosts.append(Host(ip=m.group(1), mac=m.group(2).lower(),
                              vendor=oui.lookup(m.group(2)) or None,
                              source="arp-cache"))
    return hosts


def discover(cidr: str, *, resolve_names: bool = True,
             progress=None) -> list[Host]:
    """Discover hosts on *cidr*.

    ``progress`` is an optional callable ``(stage: str)`` for UI feedback.
    """
    def emit(stage: str) -> None:
        if progress:
            progress(stage)

    by_ip: dict[str, Host] = {}

    def add_all(hosts: list[Host]) -> None:
        for h in hosts:
            if h.ip in by_ip:
                by_ip[h.ip].merge(h)
            else:
                by_ip[h.ip] = h

    if have("arp-scan"):
        emit("arp-scan sweep")
        add_all(_arp_scan(cidr))

    if have("nmap"):
        emit("nmap ping sweep")
        add_all(_nmap_ping(cidr))

    if not by_ip:
        emit("reading ARP cache")
        add_all(_ip_neigh())

    hosts = sorted(by_ip.values(), key=lambda h: tuple(int(x) for x in h.ip.split(".")))

    if resolve_names and hosts:
        emit(f"resolving {len(hosts)} names")
        _resolve_names(hosts)

    return hosts


def _resolve_names(hosts: list[Host]) -> None:
    """Resolve names for all hosts in parallel (rDNS first, then NetBIOS)."""
    nb_available = have("nmblookup")

    def resolve(host: Host) -> None:
        host.name = _reverse_dns(host.ip)
        if not host.name and nb_available:
            host.name = _netbios_name(host.ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        pool.map(resolve, hosts)


def os_fingerprint(hosts: list[Host], *, progress=None) -> list[Host]:
    """Populate ``Host.os`` via nmap OS detection (``-O``; needs root).

    Mutates and returns the same list. Hosts are probed one at a time so the UI
    can report progress; this is inherently slow, so it's an explicit action
    rather than part of the default discovery sweep.
    """
    if not have("nmap"):
        return hosts
    for host in hosts:
        if progress:
            progress(host.ip)
        res = run(["nmap", "-O", "--osscan-guess", "-Pn", host.ip],
                  timeout=60, sudo=True)
        if not res.stdout:
            continue
        m = re.search(r"Running:\s*(.+)", res.stdout)
        if not m:
            m = re.search(r"OS details:\s*(.+)", res.stdout)
        if not m:
            m = re.search(r"Aggressive OS guesses:\s*([^,\n]+)", res.stdout)
        if m:
            host.os = m.group(1).strip()
    return hosts
