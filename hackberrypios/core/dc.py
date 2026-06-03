"""Active Directory / Domain Controller reachability checks.

A DC is identified by the cluster of services it exposes. Rather than relying
on one probe we check the canonical AD port set and (when possible) the DNS
SRV records that AD publishes, which is the most reliable way to *locate*
domain controllers without knowing their IPs in advance.
"""

from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass, field

from .utils import have, run

# Ports that together strongly indicate a Windows Domain Controller.
DC_PORTS: dict[int, str] = {
    53: "DNS", 88: "Kerberos", 135: "RPC", 389: "LDAP",
    445: "SMB", 464: "kpasswd", 636: "LDAPS",
    3268: "Global Catalog", 3269: "GC-SSL",
}
# The subset that is essentially mandatory for a healthy DC.
CRITICAL = (88, 389, 445)


@dataclass
class DCStatus:
    host: str
    name: str | None = None
    reachable: bool = False
    is_dc: bool = False
    open_ports: dict[int, bool] = field(default_factory=dict)
    latency_ms: float | None = None
    ldap_base: str | None = None
    error: str | None = None

    @property
    def open_service_names(self) -> list[str]:
        return [DC_PORTS[p] for p, ok in self.open_ports.items() if ok]

    @property
    def health(self) -> str:
        if not self.reachable:
            return "down"
        if self.is_dc and all(self.open_ports.get(p) for p in CRITICAL):
            return "healthy"
        if self.is_dc:
            return "degraded"
        return "reachable"


def _tcp_check(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ping_latency(host: str) -> float | None:
    res = run(["ping", "-c", "1", "-W", "1", host], timeout=4)
    m = re.search(r"time=([\d.]+)\s*ms", res.stdout)
    return float(m.group(1)) if m else None


def _ldap_base(host: str) -> str | None:
    """Read the defaultNamingContext from RootDSE via an anonymous LDAP query."""
    if not have("ldapsearch"):
        return None
    res = run(["ldapsearch", "-x", "-H", f"ldap://{host}", "-s", "base",
               "-b", "", "defaultNamingContext"], timeout=8)
    m = re.search(r"defaultNamingContext:\s*(.+)", res.stdout)
    return m.group(1).strip() if m else None


def check_host(host: str) -> DCStatus:
    """Probe a single host to determine if it is a reachable DC."""
    status = DCStatus(host=host)
    status.latency_ms = _ping_latency(host)

    for port in DC_PORTS:
        status.open_ports[port] = _tcp_check(host, port)

    status.reachable = (status.latency_ms is not None or
                        any(status.open_ports.values()))
    # DC heuristic: Kerberos + LDAP + SMB all reachable.
    status.is_dc = all(status.open_ports.get(p) for p in CRITICAL)

    if status.is_dc:
        status.ldap_base = _ldap_base(host)

    try:
        status.name = socket.gethostbyaddr(host)[0]
    except OSError:
        status.name = None

    return status


def discover_dcs(domain: str) -> list[str]:
    """Find DC hostnames for *domain* via AD's LDAP SRV records."""
    record = f"_ldap._tcp.dc._msdcs.{domain}"
    hosts: list[str] = []

    if have("dig"):
        res = run(["dig", "+short", "SRV", record], timeout=8)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) == 4:
                hosts.append(parts[3].rstrip("."))
    elif have("host"):
        res = run(["host", "-t", "SRV", record], timeout=8)
        for line in res.stdout.splitlines():
            m = re.search(r"SRV record.*?\s(\S+)\.$", line)
            if m:
                hosts.append(m.group(1))
    return hosts


def check_domain(domain: str) -> list[DCStatus]:
    """Locate and check every DC for *domain*."""
    dc_hosts = discover_dcs(domain)
    if not dc_hosts:
        st = DCStatus(host=domain)
        st.error = f"no _ldap._tcp.dc._msdcs.{domain} SRV records found"
        return [st]
    return [check_host(h) for h in dc_hosts]
