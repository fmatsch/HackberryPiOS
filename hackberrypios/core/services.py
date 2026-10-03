"""Network-wide service discovery.

Combines host discovery with per-host port scanning to build an inventory of
the services running across the subnet, grouped by service so you can answer
"what is running on this network, and where?".

Strategy (best available first):
  1. a single ``nmap`` invocation over every target (service/version detection,
     efficient parallelism handled by nmap itself)
  2. the pure-Python threaded TCP-connect scanner from :mod:`.ports`, one host
     at a time, so the tool still works on a minimal install without nmap.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
from dataclasses import dataclass, field

from . import ports
from .utils import have, run


@dataclass
class ServiceEndpoint:
    """A single open service on a single host."""
    ip: str
    port: int
    service: str
    proto: str = "tcp"
    version: str = ""
    name: str | None = None        # resolved hostname, if known

    @property
    def label(self) -> str:
        return self.service or ports.COMMON_PORTS.get(self.port, f"port-{self.port}")


@dataclass
class ServiceGroup:
    """All endpoints that expose the same service, across the network."""
    service: str
    endpoints: list[ServiceEndpoint] = field(default_factory=list)

    @property
    def host_count(self) -> int:
        return len({e.ip for e in self.endpoints})


@dataclass
class NetworkServices:
    endpoints: list[ServiceEndpoint] = field(default_factory=list)
    hosts_scanned: int = 0
    duration: float = 0.0
    method: str = ""
    error: str | None = None

    @property
    def host_count(self) -> int:
        return len({e.ip for e in self.endpoints})

    def groups(self) -> list[ServiceGroup]:
        """Endpoints grouped by service, busiest service first."""
        by_service: dict[str, ServiceGroup] = {}
        for e in self.endpoints:
            key = e.label
            by_service.setdefault(key, ServiceGroup(service=key)).endpoints.append(e)
        return sorted(by_service.values(),
                      key=lambda g: (-g.host_count, g.service))


def _ip_sort_key(ip: str):
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts), "")
    return (1, (), ip)


# Matches "Nmap scan report for <name> (<ip>)" or "... for <ip>".
_REPORT_RE = re.compile(
    r"Nmap scan report for (?:(?P<name>\S+) \((?P<ip1>[\d.]+)\)|(?P<ip2>[\d.]+))")
_PORT_RE = re.compile(
    r"(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|open\|filtered)\s+"
    r"(?P<service>\S+)?\s*(?P<version>.*)")


def _parse_nmap_multi(stdout: str, names: dict[str, str | None]
                      ) -> list[ServiceEndpoint]:
    """Parse multi-target nmap output into service endpoints."""
    endpoints: list[ServiceEndpoint] = []
    current_ip: str | None = None
    current_name: str | None = None
    for line in stdout.splitlines():
        rep = _REPORT_RE.search(line)
        if rep:
            current_ip = rep.group("ip1") or rep.group("ip2")
            current_name = rep.group("name")
            continue
        if not current_ip:
            continue
        pm = _PORT_RE.match(line.strip())
        if pm and "open" in pm.group("state"):
            endpoints.append(ServiceEndpoint(
                ip=current_ip,
                port=int(pm.group("port")),
                proto=pm.group("proto"),
                service=(pm.group("service") or "").strip(),
                version=(pm.group("version") or "").strip(),
                name=names.get(current_ip) or current_name,
            ))
    return endpoints


def _nmap_scan(targets: list[str], names: dict[str, str | None], *,
               fast: bool, with_version: bool, timeout: int) -> NetworkServices:
    args = ["nmap", "-Pn", "-T4", "-n"]
    if fast:
        args += ["--top-ports", "200"]
    else:
        args += ["-p-"]
    if with_version:
        args += ["-sV", "--version-light"]
    args += targets

    res = run(args, timeout=timeout)
    result = NetworkServices(hosts_scanned=len(targets), method="nmap")
    if not res.ok and not res.stdout:
        result.error = res.stderr.strip() or "nmap failed"
        return result
    result.endpoints = _parse_nmap_multi(res.stdout, names)
    return result


def _socket_scan(targets: list[str], names: dict[str, str | None], *,
                 fast: bool, max_workers: int, progress) -> NetworkServices:
    result = NetworkServices(hosts_scanned=len(targets), method="tcp-connect")
    scan_ports = ports.TOP_PORTS if fast else sorted(
        set(range(1, 1025)) | set(ports.TOP_PORTS))

    def scan_one(ip: str):
        if progress:
            progress(ip)
        return ip, ports._socket_scan(ip, scan_ports, timeout=0)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for ip, res in pool.map(scan_one, targets):
            for op in res.open_ports:
                result.endpoints.append(ServiceEndpoint(
                    ip=ip, port=op.port, proto=op.proto,
                    service=op.service or ports.COMMON_PORTS.get(op.port, ""),
                    version=op.version, name=names.get(ip)))
    return result


def scan_network(hosts, *, fast: bool = True, with_version: bool = True,
                 max_workers: int = 8, timeout: int | None = None,
                 progress=None) -> NetworkServices:
    """Scan every host in *hosts* and return a network service inventory.

    *hosts* is a list of :class:`.discovery.Host` (or anything with ``.ip`` and
    ``.name``). ``progress`` is an optional ``(stage: str)`` callback for the UI.
    """
    targets = [h.ip for h in hosts]
    names = {h.ip: getattr(h, "name", None) for h in hosts}
    start = time.monotonic()

    if not targets:
        result = NetworkServices(error="No hosts to scan — discover hosts first.")
        return result

    if have("nmap"):
        # Scale the timeout with the number of hosts; a full (-p-) sweep is far
        # slower, so give it a much larger budget.
        if timeout is None:
            per_host = 25 if fast else 120
            timeout = min(90 + per_host * len(targets), 7200)
        if progress:
            progress(f"nmap scanning {len(targets)} host(s)")
        result = _nmap_scan(targets, names, fast=fast,
                            with_version=with_version, timeout=timeout)
    else:
        result = _socket_scan(targets, names, fast=fast,
                              max_workers=max_workers, progress=progress)

    result.endpoints.sort(key=lambda e: (_ip_sort_key(e.ip), e.port))
    result.duration = time.monotonic() - start
    return result
