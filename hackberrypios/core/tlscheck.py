"""TLS / certificate inspection for HTTPS, LDAPS and other TLS services.

Reports the certificate's validity window (and days remaining), issuer/subject,
the negotiated protocol and cipher, and flags common problems: expired or
soon-to-expire certs, self-signed certs, and obsolete protocols (SSLv3/TLS1.0/
1.1). Certificate-expiry surprises are one of the most common real-world
outages, so this is a quick win.

Primary backend is ``openssl s_client`` (ubiquitous on Linux); a pure-Python
``ssl`` fallback covers boxes without the openssl CLI.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .utils import have, run

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}


@dataclass
class TlsResult:
    host: str
    port: int = 443
    ok: bool = False
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    days_left: int | None = None
    protocol: str = ""
    cipher: str = ""
    self_signed: bool = False
    issues: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        if any("expired" in i.lower() for i in self.issues):
            return "expired"
        if self.issues:
            return "warning"
        return "ok"


def _parse_openssl_date(value: str) -> datetime | None:
    # e.g. "Jun  3 12:00:00 2027 GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _via_openssl(host: str, port: int, timeout: int) -> TlsResult:
    result = TlsResult(host=host, port=port)
    # One handshake; feed empty stdin so s_client returns instead of hanging.
    res = run(["openssl", "s_client", "-connect", f"{host}:{port}",
               "-servername", host], timeout=timeout, input_text="")
    text = res.stdout + res.stderr

    proto = re.search(r"Protocol\s*:\s*(\S+)", text)
    ciph = re.search(r"Cipher\s*:\s*(\S+)", text)
    if proto:
        result.protocol = proto.group(1)
    if ciph and ciph.group(1) not in ("0000", "(NONE)"):
        result.cipher = ciph.group(1)

    pem = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                    text, re.DOTALL)
    if not pem:
        result.error = "no certificate returned"
        return result

    # Pipe the PEM into x509 for clean, locale-stable fields.
    x = run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate"],
            timeout=timeout, input_text=pem.group(0))
    fields = x.stdout
    subj = re.search(r"subject=\s*(.+)", fields)
    iss = re.search(r"issuer=\s*(.+)", fields)
    end = re.search(r"notAfter=(.+)", fields)
    if subj:
        result.subject = subj.group(1).strip()
    if iss:
        result.issuer = iss.group(1).strip()
    if end:
        result.not_after = end.group(1).strip()

    _finalise(result)
    return result


def _via_python(host: str, port: int, timeout: int) -> TlsResult:
    result = TlsResult(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.protocol = ssock.version() or ""
                cipher = ssock.cipher()
                if cipher:
                    result.cipher = cipher[0]
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        result.error = f"TLS connect failed: {exc}"
        return result

    if cert:
        result.not_after = cert.get("notAfter", "")
        result.subject = _name(cert.get("subject"))
        result.issuer = _name(cert.get("issuer"))
    elif der:
        # Unverified handshake: dates aren't exposed without parsing DER.
        result.issues.append("certificate could not be validated by the system "
                             "trust store (self-signed or unknown CA)")
        result.self_signed = True
    _finalise(result)
    return result


def _name(rdn) -> str:
    if not rdn:
        return ""
    parts = []
    for entry in rdn:
        for k, v in entry:
            if k in ("commonName", "organizationName"):
                parts.append(v)
    return ", ".join(parts)


def _finalise(result: TlsResult) -> None:
    if result.not_after:
        dt = _parse_openssl_date(result.not_after)
        if dt is None:
            try:
                dt = datetime.strptime(result.not_after, "%b %d %H:%M:%S %Y %Z")\
                    .replace(tzinfo=timezone.utc)
            except ValueError:
                dt = None
        if dt:
            days = (dt - datetime.now(timezone.utc)).days
            result.days_left = days
            if days < 0:
                result.issues.append(f"certificate expired {abs(days)} days ago")
            elif days < 30:
                result.issues.append(f"certificate expires in {days} days")
    if result.protocol in WEAK_PROTOCOLS:
        result.issues.append(f"obsolete protocol {result.protocol}")
    if result.subject and result.subject == result.issuer:
        result.self_signed = True
        result.issues.append("self-signed certificate")
    result.ok = result.error is None


def inspect(host: str, port: int = 443, *, timeout: int = 10) -> TlsResult:
    """Inspect the TLS certificate offered by *host:port*."""
    if have("openssl"):
        r = _via_openssl(host, port, timeout)
        if not r.error:
            return r
    return _via_python(host, port, timeout)
