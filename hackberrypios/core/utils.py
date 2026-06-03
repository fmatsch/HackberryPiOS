"""Shared helpers: command execution, tool detection, small parsers.

The whole toolkit is built around *graceful degradation*. On a fresh
Raspberry Pi OS not every external tool will be installed, so every feature
checks for its dependencies first and reports a clear, actionable message
instead of crashing.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache


@dataclass
class CommandResult:
    """Result of running an external command."""

    ok: bool
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing_tool: str | None = None

    @property
    def text(self) -> str:
        return self.stdout if self.stdout else self.stderr


# --------------------------------------------------------------------------- #
# External tools used by HackberryPiOS. `apt` is the package providing each.
# --------------------------------------------------------------------------- #
TOOLS: dict[str, str] = {
    "nmap": "nmap",
    "arp-scan": "arp-scan",
    "smbclient": "smbclient",
    "nmblookup": "samba-common-bin",
    "avahi-browse": "avahi-utils",
    "iw": "iw",
    "nmcli": "network-manager",
    "ip": "iproute2",
    "ping": "iputils-ping",
    "dig": "dnsutils",
    "host": "dnsutils",
    "iperf3": "iperf3",
    "curl": "curl",
    "openssl": "openssl",
    "rpcclient": "smbclient",
    "ntpdate": "ntpdate",
    "ldapsearch": "ldap-utils",
    "wkhtmltopdf": "wkhtmltopdf",
}


@lru_cache(maxsize=None)
def have(tool: str) -> bool:
    """Return True if *tool* is available on PATH (cached)."""
    return shutil.which(tool) is not None


def missing_tools() -> dict[str, str]:
    """Return ``{tool: apt_package}`` for every tool that is not installed."""
    return {t: pkg for t, pkg in TOOLS.items() if not have(t)}


def run(
    args: list[str],
    *,
    timeout: int = 30,
    needs: str | None = None,
    sudo: bool = False,
    input_text: str | None = None,
) -> CommandResult:
    """Run *args* and capture output.

    Parameters
    ----------
    needs:
        Name of the binary the command relies on. If it is not installed the
        command is not executed and ``missing_tool`` is set on the result.
    sudo:
        Prefix with ``sudo -n`` (non-interactive). Falls back silently to the
        unprivileged call if sudo is unavailable.
    input_text:
        Optional text piped to the command's standard input.
    """
    tool = needs or (args[0] if args else "")
    if tool and not have(tool):
        return CommandResult(
            ok=False, returncode=127, stdout="", stderr=f"{tool} not installed",
            missing_tool=tool,
        )

    cmd = list(args)
    if sudo and have("sudo"):
        cmd = ["sudo", "-n", *cmd]

    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            ok=False, returncode=124,
            stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
            stderr="timed out", timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(ok=False, returncode=127, stdout="", stderr="not found",
                             missing_tool=tool)

    return CommandResult(
        ok=proc.returncode == 0,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )


# --------------------------------------------------------------------------- #
# Small parsing / formatting helpers
# --------------------------------------------------------------------------- #
_MAC_RE = re.compile(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def find_macs(text: str) -> list[str]:
    return [m.group(0) for m in _MAC_RE.finditer(text)]


def find_ipv4(text: str) -> list[str]:
    return _IPV4_RE.findall(text)


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def valid_target(value: str) -> bool:
    """Accept a single IP, a CIDR range, or a resolvable-looking hostname."""
    value = value.strip()
    if not value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass
    if valid_ip(value):
        return True
    # crude hostname check
    return bool(re.match(r"^[A-Za-z0-9._-]+$", value))


def humanise_mac_vendor(mac: str) -> str:
    """Best-effort OUI-to-hint mapping for a handful of common vendors.

    A full IEEE OUI database would be large; we only flag a few prefixes that
    are useful when triaging a network (printers, virtualisation, IoT, APs).
    """
    oui = mac.upper().replace("-", ":")[:8]
    hints = {
        "00:00:0C": "Cisco",
        "00:1B:21": "Intel",
        "B8:27:EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:50:56": "VMware",
        "00:0C:29": "VMware",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Hyper-V",
        "00:21:5A": "HP/Printer",
        "00:1B:A9": "Brother/Printer",
        "00:26:73": "Ricoh/Printer",
        "00:00:48": "Epson/Printer",
        "AC:DE:48": "Apple",
        "F0:18:98": "Apple",
    }
    return hints.get(oui, "")
