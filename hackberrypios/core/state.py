"""Shared application state + high-level scan orchestration.

The UI keeps a single :class:`AppState` instance. Each scan writes its result
back into the state, and :meth:`AppState.assess` re-runs the recommendation
engine over everything gathered so far. This is also the entry point used by
the CLI (`python -m hackberrypios --cli ...`).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from enum import Enum

from . import (dc, discovery, netinfo, ports, printers, recommendations,
               security, shares, speedtest, wifi)


@dataclass
class AppState:
    netctx: netinfo.NetContext | None = None
    hosts: list[discovery.Host] = field(default_factory=list)
    dc_statuses: list[dc.DCStatus] = field(default_factory=list)
    share_results: list[shares.ShareResult] = field(default_factory=list)
    printers: list[printers.Printer] = field(default_factory=list)
    wifi: wifi.WifiSurvey | None = None
    port_scans: dict[str, ports.PortScanResult] = field(default_factory=dict)
    security_findings: list[security.Finding] = field(default_factory=list)
    gateway_latency: speedtest.LatencyResult | None = None
    domain: str = ""
    last_assessment: recommendations.Assessment | None = None

    # ------------------------------------------------------------------ #
    # Orchestrated scans
    # ------------------------------------------------------------------ #
    def refresh_netinfo(self) -> netinfo.NetContext:
        self.netctx = netinfo.gather()
        return self.netctx

    def host_ips(self) -> list[str]:
        return [h.ip for h in self.hosts]

    def run_discovery(self, cidr: str | None = None, *, progress=None
                      ) -> list[discovery.Host]:
        if cidr is None:
            if self.netctx is None:
                self.refresh_netinfo()
            cidr = self.netctx.subnet if self.netctx else None
        if not cidr:
            return []
        self.hosts = discovery.discover(cidr, progress=progress)
        return self.hosts

    def run_dc_check(self, *, domain: str | None = None, host: str | None = None
                     ) -> list[dc.DCStatus]:
        if host:
            self.dc_statuses = [dc.check_host(host)]
        else:
            dom = domain or self.domain or self._guess_domain()
            self.domain = dom
            self.dc_statuses = dc.check_domain(dom) if dom else []
        return self.dc_statuses

    def run_shares(self, *, username=None, password=None, progress=None
                   ) -> list[shares.ShareResult]:
        targets = self.host_ips() or self._fallback_hosts()
        self.share_results = shares.scan_subnet(
            targets, username=username, password=password, progress=progress)
        self.security_findings += security.evaluate_shares(self.share_results)
        self._dedup_findings()
        return self.share_results

    def run_printers(self, *, progress=None) -> list[printers.Printer]:
        targets = self.host_ips() or self._fallback_hosts()
        self.printers = printers.scan_subnet(targets, progress=progress)
        return self.printers

    def run_wifi(self) -> wifi.WifiSurvey:
        self.wifi = wifi.survey()
        self.security_findings += security.evaluate_wifi(self.wifi)
        self._dedup_findings()
        return self.wifi

    def run_port_scan(self, target: str, *, fast=True, with_version=True
                      ) -> ports.PortScanResult:
        result = ports.scan(target, fast=fast, with_version=with_version)
        self.port_scans[target] = result
        self.security_findings += security.evaluate_ports(
            target, result.open_ports)
        self._dedup_findings()
        return result

    def run_smb_security(self, target: str) -> list[security.Finding]:
        findings = security.check_smb(target)
        self.security_findings += findings
        self._dedup_findings()
        return findings

    def run_gateway_latency(self) -> speedtest.LatencyResult | None:
        if self.netctx is None:
            self.refresh_netinfo()
        gw = self.netctx.gateway if self.netctx else None
        if not gw:
            return None
        self.gateway_latency = speedtest.latency(gw)
        return self.gateway_latency

    def assess(self) -> recommendations.Assessment:
        self.last_assessment = recommendations.build(
            netctx=self.netctx,
            hosts=self.hosts or None,
            dc_statuses=self.dc_statuses or None,
            share_results=self.share_results or None,
            printers=self.printers or None,
            wifi=self.wifi,
            security_findings=self.security_findings or None,
            latency=self.gateway_latency,
        )
        return self.last_assessment

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _guess_domain(self) -> str:
        """Derive an AD domain guess from the local FQDN / search domain."""
        import socket
        fqdn = socket.getfqdn()
        if "." in fqdn and not fqdn.endswith(".local"):
            return fqdn.split(".", 1)[1]
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                import re
                m = re.search(r"^\s*search\s+(\S+)", fh.read(), re.MULTILINE)
                if m:
                    return m.group(1)
        except OSError:
            pass
        return ""

    def _fallback_hosts(self) -> list[str]:
        """If discovery hasn't run, enumerate the subnet hosts to probe."""
        if self.netctx is None:
            self.refresh_netinfo()
        if not self.netctx or not self.netctx.subnet:
            return []
        net = ipaddress.ip_network(self.netctx.subnet, strict=False)
        if net.num_addresses > 4096:
            return []  # too big to brute-force blindly
        return [str(ip) for ip in net.hosts()]

    def _dedup_findings(self) -> None:
        seen = set()
        unique = []
        for f in self.security_findings:
            key = (f.title, f.target)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.security_findings = unique

    # ------------------------------------------------------------------ #
    # Export
    # ------------------------------------------------------------------ #
    def to_report(self) -> dict:
        """Serialise the full state to a JSON-friendly report dict."""
        def enc(obj):
            if is_dataclass(obj) and not isinstance(obj, type):
                return {k: enc(v) for k, v in asdict(obj).items()}
            if isinstance(obj, Enum):
                return obj.name
            if isinstance(obj, dict):
                return {k: enc(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple)):
                return [enc(v) for v in obj]
            return obj

        self.assess()
        return {
            "generated": datetime.now().isoformat(timespec="seconds"),
            "tool": "HackberryPiOS",
            "network": enc(self.netctx),
            "hosts": enc(self.hosts),
            "domain_controllers": enc(self.dc_statuses),
            "shares": enc(self.share_results),
            "printers": enc(self.printers),
            "wifi": enc(self.wifi),
            "port_scans": enc(self.port_scans),
            "security_findings": enc(self.security_findings),
            "gateway_latency": enc(self.gateway_latency),
            "assessment": {
                "score": self.last_assessment.score if self.last_assessment else None,
                "recommendations": [
                    {"text": r.text, "priority": r.priority.name,
                     "category": r.category}
                    for r in (self.last_assessment.top if self.last_assessment else [])
                ],
            },
        }

    def export_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_report(), fh, indent=2)
