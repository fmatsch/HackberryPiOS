"""Lightweight, non-intrusive security checks.

These are *defensive* posture checks for networks you administer — they look
for well-known misconfigurations (SMBv1, missing SMB signing, cleartext
admin protocols, anonymous shares, weak Wi-Fi crypto, exposed databases) and
return prioritised findings. Nothing here exploits or brute-forces anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from .utils import have, run


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass
class Finding:
    title: str
    severity: Severity
    target: str = ""
    detail: str = ""
    recommendation: str = ""

    def __lt__(self, other: "Finding") -> bool:
        return self.severity > other.severity  # sort high → low


# Cleartext / legacy services that should not be exposed on a managed network.
RISKY_SERVICES: dict[int, tuple[str, Severity, str]] = {
    23: ("Telnet", Severity.HIGH, "Disable Telnet; use SSH instead."),
    21: ("FTP", Severity.MEDIUM, "Replace FTP with SFTP/FTPS."),
    512: ("rexec", Severity.HIGH, "Disable r-services."),
    513: ("rlogin", Severity.HIGH, "Disable r-services."),
    514: ("rsh/syslog", Severity.MEDIUM, "Confirm this is syslog, not rsh."),
    1433: ("MS-SQL", Severity.MEDIUM, "MS-SQL should not be exposed broadly; firewall it."),
    3306: ("MySQL", Severity.MEDIUM, "Restrict MySQL to trusted hosts."),
    5432: ("PostgreSQL", Severity.MEDIUM, "Restrict PostgreSQL access."),
    5900: ("VNC", Severity.HIGH, "VNC is often unencrypted; tunnel over SSH/VPN."),
    6379: ("Redis", Severity.HIGH, "Redis is often unauthenticated; bind to localhost."),
    9200: ("Elasticsearch", Severity.HIGH, "Lock down Elasticsearch."),
    27017: ("MongoDB", Severity.HIGH, "MongoDB must require auth + firewalling."),
    11211: ("memcached", Severity.MEDIUM, "memcached is amplification-prone; firewall it."),
    3389: ("RDP", Severity.LOW, "Ensure NLA is on and RDP is VPN-gated."),
}


@dataclass
class HostSecurity:
    host: str
    findings: list[Finding] = field(default_factory=list)


def check_smb(host: str) -> list[Finding]:
    """Check SMB dialect (SMBv1) and message signing via nmap NSE if available."""
    findings: list[Finding] = []
    if not have("nmap"):
        return findings
    res = run(["nmap", "-Pn", "-p", "445", "--script",
               "smb-protocols,smb-security-mode,smb2-security-mode", host],
              timeout=60)
    out = res.stdout

    if "SMBv1" in out or "NT LM 0.12" in out:
        findings.append(Finding(
            title="SMBv1 enabled", severity=Severity.HIGH, target=host,
            detail="Host advertises the obsolete SMBv1 dialect.",
            recommendation="Disable SMBv1 (WannaCry/EternalBlue vector).",
        ))
    if "message_signing: disabled" in out or "Message signing disabled" in out:
        findings.append(Finding(
            title="SMB signing disabled", severity=Severity.MEDIUM, target=host,
            detail="SMB signing is not required.",
            recommendation="Require SMB signing to prevent relay/MITM attacks.",
        ))
    return findings


def evaluate_ports(host: str, open_ports) -> list[Finding]:
    """Flag risky services among already-scanned open ports.

    *open_ports* is the list from :class:`ports.PortScanResult.open_ports`.
    """
    findings: list[Finding] = []
    for op in open_ports:
        info = RISKY_SERVICES.get(op.port)
        if info:
            name, sev, rec = info
            findings.append(Finding(
                title=f"{name} exposed (port {op.port})",
                severity=sev, target=host,
                detail=f"{op.service or name} reachable on {host}:{op.port}.",
                recommendation=rec,
            ))
    # SMB present → suggest the deeper SMB check.
    if any(op.port == 445 for op in open_ports):
        findings.append(Finding(
            title="SMB exposed (port 445)", severity=Severity.INFO, target=host,
            detail="Run the SMB security check for signing / SMBv1 status.",
            recommendation="Verify SMB signing required and SMBv1 disabled.",
        ))
    return findings


def evaluate_shares(share_results) -> list[Finding]:
    """Flag anonymously-accessible shares (from shares.scan_subnet)."""
    findings: list[Finding] = []
    for r in share_results:
        if r.guest_allowed:
            disk = [s.name for s in r.shares if s.type == "Disk"]
            findings.append(Finding(
                title="Anonymous SMB share access",
                severity=Severity.HIGH, target=r.host,
                detail=f"Guest/anonymous access to: {', '.join(disk)}",
                recommendation="Disable guest access; require authentication.",
            ))
    return findings


def evaluate_wifi(survey) -> list[Finding]:
    """Flag open and weak-crypto wireless networks."""
    findings: list[Finding] = []
    for ap in survey.open_networks:
        findings.append(Finding(
            title=f"Open Wi-Fi: {ap.ssid}", severity=Severity.MEDIUM,
            target=ap.bssid or ap.ssid,
            detail="Network has no encryption.",
            recommendation="Use WPA2/WPA3-Enterprise or at minimum WPA2-PSK.",
        ))
    for ap in survey.weak_networks:
        findings.append(Finding(
            title=f"Weak Wi-Fi crypto: {ap.ssid}", severity=Severity.HIGH,
            target=ap.bssid or ap.ssid,
            detail=f"Uses {ap.security} (WEP/WPA1 are broken).",
            recommendation="Migrate to WPA2/WPA3.",
        ))
    return findings
