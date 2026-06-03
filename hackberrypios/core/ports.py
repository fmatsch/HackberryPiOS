"""Port scanning for a single host or range.

Prefers ``nmap`` (service/version detection). Falls back to a lightweight
threaded TCP-connect scanner in pure Python when nmap is unavailable, so the
tool stays useful on a minimal install.
"""

from __future__ import annotations

import concurrent.futures
import re
import socket
from dataclasses import dataclass, field

from .utils import have, run

# Common ports worth knowing about in a mixed Linux / Windows-AD network.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap",
    443: "https", 445: "smb", 464: "kpasswd", 514: "syslog",
    548: "afp", 587: "submission", 631: "ipp/print", 636: "ldaps",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3268: "ldap-gc", 3269: "ldaps-gc", 3306: "mysql",
    3389: "rdp", 5060: "sip", 5353: "mdns", 5432: "postgres",
    5900: "vnc", 5985: "winrm", 5986: "winrm-s", 8080: "http-alt",
    8443: "https-alt", 9100: "jetdirect/print",
}

# A focused fast set used by the default scan profile.
TOP_PORTS = sorted(COMMON_PORTS)


@dataclass
class OpenPort:
    port: int
    proto: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"


@dataclass
class PortScanResult:
    target: str
    open_ports: list[OpenPort] = field(default_factory=list)
    duration: float = 0.0
    method: str = ""
    error: str | None = None


def _nmap_scan(target: str, *, fast: bool, with_version: bool,
               timeout: int) -> PortScanResult:
    args = ["nmap", "-Pn", "-T4"]
    if fast:
        args += ["--top-ports", "200"]
    else:
        args += ["-p-"]
    if with_version:
        args += ["-sV", "--version-light"]
    args.append(target)

    res = run(args, timeout=timeout)
    result = PortScanResult(target=target, method="nmap")
    if not res.ok and not res.stdout:
        result.error = res.stderr.strip() or "nmap failed"
        return result

    for line in res.stdout.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+(open|filtered|open\|filtered)\s+(\S+)?\s*(.*)",
                     line.strip())
        if m and "open" in m.group(3):
            result.open_ports.append(OpenPort(
                port=int(m.group(1)),
                proto=m.group(2),
                state=m.group(3),
                service=(m.group(4) or "").strip(),
                version=(m.group(5) or "").strip(),
            ))
    return result


def _socket_scan(target: str, ports: list[int], *, timeout: int) -> PortScanResult:
    result = PortScanResult(target=target, method="tcp-connect")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as exc:
        result.error = f"cannot resolve {target}: {exc}"
        return result

    def probe(port: int) -> OpenPort | None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.8)
            if sock.connect_ex((ip, port)) == 0:
                return OpenPort(port=port, service=COMMON_PORTS.get(port, ""))
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
        for op in pool.map(probe, ports):
            if op:
                result.open_ports.append(op)
    result.open_ports.sort(key=lambda p: p.port)
    return result


def scan(target: str, *, fast: bool = True, with_version: bool = True,
         timeout: int = 180) -> PortScanResult:
    """Scan *target*. Uses nmap if present, else a pure-Python TCP scan."""
    import time
    start = time.monotonic()
    if have("nmap"):
        result = _nmap_scan(target, fast=fast, with_version=with_version,
                            timeout=timeout)
    else:
        ports = TOP_PORTS if fast else list(range(1, 1025)) + TOP_PORTS
        result = _socket_scan(target, sorted(set(ports)), timeout=timeout)
    result.duration = time.monotonic() - start
    return result
