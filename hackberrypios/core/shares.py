"""SMB / Windows share discovery and enumeration.

Two modes:
  * ``enumerate_host(ip)``  — list shares on one host via ``smbclient -L``
  * ``scan_subnet(hosts)``  — probe many hosts (445/139 reachable) for shares

Guest / anonymous access is attempted first (this is exactly what you want to
flag in a security review: shares that are world-readable). Authenticated
enumeration is supported by passing credentials.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field

from .utils import have, run


@dataclass
class Share:
    name: str
    type: str = ""
    comment: str = ""
    anonymous: bool = False        # reachable without credentials


@dataclass
class ShareResult:
    host: str
    shares: list[Share] = field(default_factory=list)
    reachable: bool = False
    authenticated: bool = False
    guest_allowed: bool = False
    error: str | None = None


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _parse_smbclient_list(text: str) -> list[Share]:
    shares: list[Share] = []
    in_section = False
    for line in text.splitlines():
        if re.search(r"^\s*Sharename\s+Type\s+Comment", line):
            in_section = True
            continue
        if in_section:
            if not line.strip() or line.strip().startswith("-"):
                continue
            if re.search(r"Server\s+Comment|Workgroup\s+Master", line):
                break
            m = re.match(r"\s*(\S.*?)\s{2,}(Disk|IPC|Printer)\s*(.*)$", line)
            if m:
                shares.append(Share(name=m.group(1).strip(),
                                    type=m.group(2),
                                    comment=m.group(3).strip()))
    return shares


def enumerate_host(host: str, *, username: str | None = None,
                   password: str | None = None, timeout: int = 20) -> ShareResult:
    """Enumerate shares on a single host."""
    result = ShareResult(host=host)

    if not (_port_open(host, 445) or _port_open(host, 139)):
        result.error = "SMB ports 445/139 closed"
        return result
    result.reachable = True

    if not have("smbclient"):
        result.error = "smbclient not installed"
        return result

    if username:
        auth = ["-U", f"{username}%{password or ''}"]
    else:
        # Anonymous / guest first — this is the security-relevant case.
        auth = ["-N"]

    res = run(["smbclient", "-L", host, "-g", *auth], timeout=timeout)
    # "-g" gives machine-readable "Disk|name|comment" lines on modern samba.
    if res.ok and "|" in res.stdout:
        for line in res.stdout.splitlines():
            parts = line.split("|")
            if len(parts) >= 2 and parts[0] in ("Disk", "Printer", "IPC"):
                result.shares.append(Share(
                    name=parts[1], type=parts[0],
                    comment=parts[2] if len(parts) > 2 else "",
                    anonymous=(username is None),
                ))
    else:
        # Fall back to the human-readable table.
        res2 = run(["smbclient", "-L", host, *auth], timeout=timeout)
        if res2.ok or "Sharename" in res2.stdout:
            for sh in _parse_smbclient_list(res2.stdout):
                sh.anonymous = username is None
                result.shares.append(sh)
        elif not result.shares:
            err = (res.stderr + res2.stderr).strip()
            result.error = err.splitlines()[-1] if err else "enumeration failed"
            return result

    result.authenticated = username is not None
    result.guest_allowed = (username is None and
                            any(s.type == "Disk" for s in result.shares))
    return result


def scan_subnet(hosts: list[str], *, username: str | None = None,
                password: str | None = None, progress=None) -> list[ShareResult]:
    """Probe a list of host IPs for accessible SMB shares."""
    import concurrent.futures

    results: list[ShareResult] = []

    def work(ip: str) -> ShareResult | None:
        if progress:
            progress(ip)
        r = enumerate_host(ip, username=username, password=password, timeout=12)
        return r if (r.reachable and r.shares) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        for r in pool.map(work, hosts):
            if r:
                results.append(r)
    return results
