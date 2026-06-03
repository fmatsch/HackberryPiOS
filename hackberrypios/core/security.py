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


def sweep_smb(hosts: list[str], *, progress=None) -> list[Finding]:
    """Run the SMBv1 / signing check across many hosts in parallel."""
    import concurrent.futures

    findings: list[Finding] = []

    def work(host: str) -> list[Finding]:
        if progress:
            progress(host)
        return check_smb(host)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for res in pool.map(work, hosts):
            findings.extend(res)
    return findings


# Heuristic version-based hints. These are NOT a vulnerability scan — they flag
# well-known risky software versions worth a closer look, keyed by a substring
# match against nmap's service/version banner.
VERSION_HINTS: list[tuple[str, Severity, str]] = [
    ("vsftpd 2.3.4", Severity.CRITICAL, "vsftpd 2.3.4 shipped with a backdoor (CVE-2011-2523)."),
    ("OpenSSH 7.", Severity.LOW, "Older OpenSSH 7.x — review for known CVEs and update."),
    ("OpenSSH 6.", Severity.MEDIUM, "OpenSSH 6.x is end-of-life; upgrade."),
    ("OpenSSH 5.", Severity.MEDIUM, "OpenSSH 5.x is end-of-life; upgrade."),
    ("Apache/2.2", Severity.MEDIUM, "Apache 2.2 is end-of-life; upgrade to 2.4+."),
    ("Apache/2.0", Severity.HIGH, "Apache 2.0 is long end-of-life; upgrade."),
    ("nginx/1.0", Severity.MEDIUM, "Very old nginx; upgrade."),
    ("ProFTPD 1.3.3", Severity.HIGH, "ProFTPD 1.3.3c had a backdoor (CVE-2010-3867)."),
    ("Microsoft IIS/6.0", Severity.HIGH, "IIS 6.0 (Server 2003) is unsupported; CVE-2017-7269."),
    ("Microsoft IIS/7.", Severity.LOW, "IIS 7.x is dated; confirm patch level."),
    ("Exim 4.8", Severity.HIGH, "Old Exim 4.8x has critical RCEs (e.g. CVE-2019-10149)."),
    ("Samba 3.", Severity.HIGH, "Samba 3.x is end-of-life (SambaCry/CVE-2017-7494 era)."),
    ("Samba 4.0", Severity.MEDIUM, "Early Samba 4.0; review and update."),
    ("PHP/5.", Severity.MEDIUM, "PHP 5.x is end-of-life; upgrade."),
    ("MySQL 5.0", Severity.MEDIUM, "MySQL 5.0 is end-of-life."),
    ("OpenSSL/1.0", Severity.MEDIUM, "OpenSSL 1.0.x is end-of-life (Heartbleed era)."),
]


def evaluate_versions(host: str, open_ports) -> list[Finding]:
    """Flag risky software versions in scanned service banners (heuristic)."""
    findings: list[Finding] = []
    for op in open_ports:
        banner = f"{op.service} {op.version}".strip()
        if not banner:
            continue
        for needle, sev, note in VERSION_HINTS:
            if needle.lower() in banner.lower():
                findings.append(Finding(
                    title=f"Outdated software: {needle} (port {op.port})",
                    severity=sev, target=host,
                    detail=f"Detected '{banner}' on {host}:{op.port}.",
                    recommendation=note,
                ))
    return findings
