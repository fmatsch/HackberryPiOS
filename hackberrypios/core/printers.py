"""Printer discovery across the common protocols found in mixed networks.

  * mDNS / Bonjour (`_ipp._tcp`, `_printer._tcp`)  via avahi-browse
  * Raw JetDirect (TCP 9100), IPP (631), LPD (515) port probes
  * SMB shared printers (Type=Printer) reuse the shares module
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

from .utils import have, run

PRINTER_PORTS = {515: "LPD", 631: "IPP", 9100: "JetDirect"}


@dataclass
class Printer:
    host: str
    name: str = ""
    protocols: list[str] = field(default_factory=list)
    model: str = ""
    source: str = ""


def _avahi_printers() -> list[Printer]:
    if not have("avahi-browse"):
        return []
    res = run(["avahi-browse", "-rtp", "_ipp._tcp", "_printer._tcp",
               "_pdl-datastream._tcp"], timeout=15)
    if not res.ok:
        # avahi-browse can't take multiple types in one call on some versions
        out = ""
        for svc in ("_ipp._tcp", "_printer._tcp", "_pdl-datastream._tcp"):
            r = run(["avahi-browse", "-rtp", svc], timeout=10)
            out += r.stdout
        res_text = out
    else:
        res_text = res.stdout

    printers: dict[str, Printer] = {}
    for line in res_text.splitlines():
        if not line.startswith("="):
            continue
        # =;eth0;IPv4;HP_LaserJet;_ipp._tcp;local;host.local;192.168.1.50;631;"..."
        f = line.split(";")
        if len(f) < 8:
            continue
        name = f[3].replace("\\032", " ")
        ip = f[7]
        svc = f[4]
        proto = {"_ipp._tcp": "IPP", "_printer._tcp": "LPD",
                 "_pdl-datastream._tcp": "JetDirect"}.get(svc, svc)
        model = ""
        tm = re.search(r'ty=([^"]+)', line)
        if tm:
            model = tm.group(1)
        p = printers.setdefault(ip, Printer(host=ip, name=name, source="mDNS"))
        if proto not in p.protocols:
            p.protocols.append(proto)
        p.model = p.model or model
        p.name = p.name or name
    return list(printers.values())


def _port_open(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_host(host: str) -> Printer | None:
    """Return a Printer if *host* exposes any printing protocol."""
    protocols = [name for port, name in PRINTER_PORTS.items()
                 if _port_open(host, port)]
    if not protocols:
        return None
    try:
        name = socket.gethostbyaddr(host)[0]
    except OSError:
        name = ""
    return Printer(host=host, name=name, protocols=protocols, source="port-scan")


def scan_subnet(hosts: list[str], *, progress=None) -> list[Printer]:
    """Discover printers: mDNS announcements first, then port-probe each host."""
    import concurrent.futures

    found: dict[str, Printer] = {}
    for p in _avahi_printers():
        found[p.host] = p

    def work(ip: str) -> Printer | None:
        if progress:
            progress(ip)
        return probe_host(ip)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        for p in pool.map(work, hosts):
            if not p:
                continue
            if p.host in found:
                for proto in p.protocols:
                    if proto not in found[p.host].protocols:
                        found[p.host].protocols.append(proto)
            else:
                found[p.host] = p
    return list(found.values())
