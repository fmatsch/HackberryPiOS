"""Rogue DHCP server detection.

Sends a broadcast DHCP DISCOVER and collects every server that answers. More
than one responding server (or one that isn't your sanctioned server) is a
classic, disruptive misconfiguration — or an attack.

Uses nmap's ``broadcast-dhcp-discover`` NSE script (needs root, so it runs via
sudo). Reports each offering server with the lease/gateway/DNS it hands out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .utils import have, run


@dataclass
class DhcpOffer:
    server: str
    offered_ip: str = ""
    router: str = ""
    dns: str = ""
    domain: str = ""
    lease: str = ""


@dataclass
class DhcpResult:
    offers: list[DhcpOffer] = field(default_factory=list)
    error: str | None = None

    @property
    def server_ips(self) -> list[str]:
        seen: list[str] = []
        for o in self.offers:
            if o.server and o.server not in seen:
                seen.append(o.server)
        return seen

    @property
    def rogue_suspected(self) -> bool:
        return len(self.server_ips) > 1


def discover(*, interface: str | None = None, timeout: int = 25) -> DhcpResult:
    """Broadcast a DHCP DISCOVER and return all offers seen."""
    result = DhcpResult()
    if not have("nmap"):
        result.error = "nmap required for DHCP discovery"
        return result

    args = ["nmap", "--script", "broadcast-dhcp-discover"]
    if interface:
        args += ["-e", interface]
    res = run(args, timeout=timeout, sudo=True)
    if not res.stdout:
        result.error = res.stderr.strip() or "no nmap output (needs root?)"
        return result

    # The script prints one "Response N of M" block per offering server.
    blocks = re.split(r"Response \d+ of \d+", res.stdout)
    for block in blocks:
        srv = re.search(r"Server Identifier:\s*([\d.]+)", block)
        if not srv:
            continue
        offer = DhcpOffer(server=srv.group(1))
        ip = re.search(r"IP Offered:\s*([\d.]+)", block)
        rtr = re.search(r"Router:\s*([\d.]+)", block)
        dns = re.search(r"Domain Name Server:\s*([\d.\s]+)", block)
        dom = re.search(r"Domain Name:\s*(\S+)", block)
        lease = re.search(r"IP Address Lease Time:\s*(.+)", block)
        if ip:
            offer.offered_ip = ip.group(1)
        if rtr:
            offer.router = rtr.group(1)
        if dns:
            offer.dns = dns.group(1).strip()
        if dom:
            offer.domain = dom.group(1)
        if lease:
            offer.lease = lease.group(1).strip()
        result.offers.append(offer)

    if not result.offers and "DHCP" not in res.stdout:
        result.error = "no DHCP servers responded (or insufficient privilege)"
    return result
