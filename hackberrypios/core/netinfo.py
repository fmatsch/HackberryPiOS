"""Local network context: interfaces, IP/CIDR, gateway, DNS, default route.

This is the first thing the dashboard needs — everything else (host discovery,
DC checks, recommendations) keys off the currently-connected subnet.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

from .utils import run


@dataclass
class Interface:
    name: str
    ipv4: str | None = None
    cidr: str | None = None          # e.g. 192.168.1.0/24
    mac: str | None = None
    is_up: bool = False
    is_wireless: bool = False


@dataclass
class NetContext:
    interfaces: list[Interface] = field(default_factory=list)
    primary: Interface | None = None
    gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    hostname: str = ""
    error: str | None = None

    @property
    def subnet(self) -> str | None:
        return self.primary.cidr if self.primary else None


def _wireless_interfaces() -> set[str]:
    res = run(["iw", "dev"], timeout=5)
    if not res.ok:
        return set()
    return set(re.findall(r"Interface\s+(\S+)", res.stdout))


def _parse_ip_addr() -> list[Interface]:
    """Parse `ip -o addr` + `ip -o link` for interface details."""
    interfaces: dict[str, Interface] = {}
    wireless = _wireless_interfaces()

    link = run(["ip", "-o", "link"], timeout=5)
    for line in link.stdout.splitlines():
        m = re.match(r"\d+:\s+(\S+):\s+<([^>]*)>", line)
        if not m:
            continue
        name = m.group(1).split("@")[0]
        if name == "lo":
            continue
        flags = m.group(2)
        mac_m = re.search(r"link/\w+\s+([0-9a-f:]{17})", line)
        interfaces[name] = Interface(
            name=name,
            mac=mac_m.group(1) if mac_m else None,
            is_up="UP" in flags.split(","),
            is_wireless=name in wireless,
        )

    addr = run(["ip", "-o", "-4", "addr"], timeout=5)
    for line in addr.stdout.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+([\d.]+)/(\d+)", line)
        if not m:
            continue
        name, ip, prefix = m.group(1), m.group(2), m.group(3)
        if name not in interfaces:
            interfaces[name] = Interface(name=name)
        iface = interfaces[name]
        iface.ipv4 = ip
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        iface.cidr = str(net)

    return list(interfaces.values())


def _default_gateway() -> str | None:
    res = run(["ip", "route", "show", "default"], timeout=5)
    m = re.search(r"default via ([\d.]+)", res.stdout)
    return m.group(1) if m else None


def _dns_servers() -> list[str]:
    servers: list[str] = []
    # NetworkManager / systemd-resolved aware first
    res = run(["resolvectl", "status"], timeout=5)
    if res.ok:
        servers = re.findall(r"DNS Servers?:\s*([\d.]+)", res.stdout)
    if not servers:
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                servers = re.findall(r"nameserver\s+([\d.]+)", fh.read())
        except OSError:
            pass
    # de-duplicate, keep order
    seen: list[str] = []
    for s in servers:
        if s not in seen:
            seen.append(s)
    return seen


def gather() -> NetContext:
    """Collect the full local network context."""
    ctx = NetContext(hostname=socket.gethostname())
    try:
        ctx.interfaces = _parse_ip_addr()
    except Exception as exc:  # pragma: no cover - defensive
        ctx.error = f"interface parse failed: {exc}"
        return ctx

    ctx.gateway = _default_gateway()
    ctx.dns_servers = _dns_servers()

    # Pick the interface that owns the default route, else first UP iface w/ IP.
    candidates = [i for i in ctx.interfaces if i.ipv4 and i.is_up]
    if ctx.gateway:
        gw = ipaddress.ip_address(ctx.gateway)
        for iface in candidates:
            if iface.cidr and gw in ipaddress.ip_network(iface.cidr):
                ctx.primary = iface
                break
    if ctx.primary is None and candidates:
        ctx.primary = candidates[0]

    return ctx
