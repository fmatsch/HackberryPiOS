"""HackberryPiOS Textual UI.

A keyboard-driven, tabbed dashboard sized for the HackberryPi CM5 display.
Each tab maps to one capability; scans run in background threads so the UI
stays responsive. The Dashboard tab aggregates everything into a health
score plus a prioritised action list.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label,
                             Static, TabbedContent, TabPane)

from . import __version__
from .core import recommendations as reco
from .core.security import Severity
from .core.state import AppState

PRIORITY_STYLE = {
    "URGENT": "bold red",
    "IMPORTANT": "dark_orange",
    "SUGGESTED": "yellow",
    "INFO": "cyan",
    "DONE": "green",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "dark_orange",
    Severity.LOW: "yellow",
    Severity.INFO: "cyan",
}


def health_colour(score: int) -> str:
    if score >= 80:
        return "green"
    if score >= 55:
        return "yellow"
    return "red"


class HackberryApp(App):
    TITLE = "HackberryPiOS"
    SUB_TITLE = "Network audit"
    CSS_PATH = "app.tcss"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("r", "run_current", "Run"),
        ("a", "scan_all", "Scan all"),
        ("e", "export", "Export"),
        ("d", "show_dashboard", "Dashboard"),
        ("ctrl+r", "refresh_net", "Refresh net"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.state = AppState()

    # ----------------------------------------------------------------- #
    # Layout
    # ----------------------------------------------------------------- #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-dash", id="tabs"):
            with TabPane("Home", id="tab-dash"):
                yield from self._compose_dashboard()
            with TabPane("Hosts", id="tab-hosts"):
                yield from self._compose_hosts()
            with TabPane("Ports", id="tab-ports"):
                yield from self._compose_ports()
            with TabPane("Shares", id="tab-shares"):
                yield from self._compose_shares()
            with TabPane("Print", id="tab-printers"):
                yield from self._compose_printers()
            with TabPane("DC/AD", id="tab-dc"):
                yield from self._compose_dc()
            with TabPane("Wi-Fi", id="tab-wifi"):
                yield from self._compose_wifi()
            with TabPane("Speed", id="tab-speed"):
                yield from self._compose_speed()
            with TabPane("Sec", id="tab-security"):
                yield from self._compose_security()
        yield Footer()

    def _compose_dashboard(self) -> ComposeResult:
        with VerticalScroll(classes="pane"):
            yield Static(id="net-summary", classes="card")
            yield Static(id="score-box")
            yield Label("Recommendations", classes="card-title")
            yield Static(id="reco-list")

    def _compose_hosts(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="CIDR (auto-detected if empty)",
                            id="hosts-target")
                yield Button("Scan", id="hosts-run", variant="primary")
            yield Static("Press Scan to discover hosts on the subnet.",
                         id="hosts-status", classes="status")
            table = DataTable(id="hosts-table", cursor_type="row")
            table.add_columns("IP", "Name", "MAC", "Vendor", "Via")
            yield table

    def _compose_ports(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="Target IP / host", id="ports-target")
                yield Button("Fast", id="ports-fast", variant="primary")
                yield Button("Full", id="ports-full")
            yield Static("Enter a target (or pick one on the Hosts tab).",
                         id="ports-status", classes="status")
            table = DataTable(id="ports-table", cursor_type="row")
            table.add_columns("Port", "Proto", "Service", "Version")
            yield table

    def _compose_shares(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="user (blank = anonymous)",
                            id="shares-user")
                yield Input(placeholder="password", password=True,
                            id="shares-pass")
                yield Button("Scan", id="shares-run", variant="primary")
            yield Static("Scans discovered hosts for SMB shares.",
                         id="shares-status", classes="status")
            table = DataTable(id="shares-table", cursor_type="row")
            table.add_columns("Host", "Share", "Type", "Anon", "Comment")
            yield table

    def _compose_printers(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Button("Find printers", id="printers-run",
                             variant="primary")
            yield Static("Discovers printers via mDNS + port probes.",
                         id="printers-status", classes="status")
            table = DataTable(id="printers-table", cursor_type="row")
            table.add_columns("Host", "Name", "Protocols", "Model")
            yield table

    def _compose_dc(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="domain.example.com or DC IP",
                            id="dc-target")
                yield Button("Check", id="dc-run", variant="primary")
            yield Static("Locates & health-checks domain controllers.",
                         id="dc-status", classes="status")
            table = DataTable(id="dc-table", cursor_type="row")
            table.add_columns("Host", "Health", "Latency", "Services")
            yield table

    def _compose_wifi(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Button("Survey Wi-Fi", id="wifi-run", variant="primary")
            yield Static("Scans nearby access points + current link.",
                         id="wifi-status", classes="status")
            table = DataTable(id="wifi-table", cursor_type="row")
            table.add_columns("SSID", "Sig%", "Chan", "Band", "Security")
            yield table

    def _compose_speed(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="iperf3 server (optional)",
                            id="speed-target")
                yield Button("LAN ping", id="speed-ping", variant="primary")
                yield Button("iperf3", id="speed-iperf")
                yield Button("WAN", id="speed-wan")
            yield Static("Measure latency / throughput.",
                         id="speed-status", classes="status")
            yield Static(id="speed-result", classes="card")

    def _compose_security(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="host for deep SMB check (optional)",
                            id="sec-target")
                yield Button("SMB check", id="sec-smb", variant="primary")
            yield Static("Aggregated findings from all scans.",
                         id="sec-status", classes="status")
            table = DataTable(id="sec-table", cursor_type="row")
            table.add_columns("Sev", "Finding", "Target")
            yield table

    # ----------------------------------------------------------------- #
    # Lifecycle
    # ----------------------------------------------------------------- #
    def on_mount(self) -> None:
        self.run_refresh_net()

    # ----------------------------------------------------------------- #
    # Actions (key bindings)
    # ----------------------------------------------------------------- #
    def action_show_dashboard(self) -> None:
        self.query_one("#tabs", TabbedContent).active = "tab-dash"

    def action_refresh_net(self) -> None:
        self.run_refresh_net()

    def action_run_current(self) -> None:
        active = self.query_one("#tabs", TabbedContent).active
        mapping = {
            "tab-hosts": lambda: self.run_hosts(""),
            "tab-printers": self.run_printers,
            "tab-wifi": self.run_wifi,
            "tab-shares": lambda: self.run_shares(),
        }
        action = mapping.get(active)
        if action:
            action()
        else:
            self.notify("Use the buttons on this tab (needs a target).")

    def action_scan_all(self) -> None:
        self.run_scan_all()

    def action_export(self) -> None:
        self.run_export()

    # ----------------------------------------------------------------- #
    # Button routing
    # ----------------------------------------------------------------- #
    @on(Button.Pressed)
    def _route(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        routes = {
            "hosts-run": lambda: self.run_hosts(
                self.query_one("#hosts-target", Input).value),
            "ports-fast": lambda: self.run_ports(fast=True),
            "ports-full": lambda: self.run_ports(fast=False),
            "shares-run": self.run_shares,
            "printers-run": self.run_printers,
            "dc-run": self.run_dc,
            "wifi-run": self.run_wifi,
            "speed-ping": self.run_speed_ping,
            "speed-iperf": self.run_speed_iperf,
            "speed-wan": self.run_speed_wan,
            "sec-smb": self.run_smb_check,
        }
        handler = routes.get(bid)
        if handler:
            handler()

    @on(DataTable.RowSelected, "#hosts-table")
    def _host_selected(self, event: DataTable.RowSelected) -> None:
        """Selecting a host pre-fills the Ports/Security target inputs."""
        table = self.query_one("#hosts-table", DataTable)
        row = table.get_row(event.row_key)
        if row:
            ip = str(row[0])
            self.query_one("#ports-target", Input).value = ip
            self.query_one("#sec-target", Input).value = ip
            self.notify(f"Selected {ip} (pre-filled Ports & Sec tabs)")

    # ----------------------------------------------------------------- #
    # Helpers
    # ----------------------------------------------------------------- #
    def _set_status(self, sid: str, text: str) -> None:
        self.query_one(f"#{sid}", Static).update(text)

    def _refresh_dashboard(self) -> None:
        ctx = self.state.netctx
        if ctx:
            p = ctx.primary
            net = (f"[b]{ctx.hostname}[/b]   "
                   f"{p.name if p else '—'}  "
                   f"{p.ipv4 if p else 'no IP'}\n"
                   f"Subnet: {ctx.subnet or '—'}   "
                   f"GW: {ctx.gateway or '—'}\n"
                   f"DNS: {', '.join(ctx.dns_servers) or '—'}   "
                   f"Domain: {self.state.domain or '—'}")
        else:
            net = "No network context yet."
        self.query_one("#net-summary", Static).update(net)

        assessment = self.state.assess()
        col = health_colour(assessment.score)
        self.query_one("#score-box", Static).update(
            f"[b {col}]Network health: {assessment.score}/100[/]   "
            f"hosts:{len(self.state.hosts)}  "
            f"findings:{len(self.state.security_findings)}")

        lines = []
        for r in assessment.top[:12]:
            style = PRIORITY_STYLE.get(r.priority.name, "white")
            marker = "✓" if r.priority.name == "DONE" else "•"
            lines.append(f"[{style}]{marker} {r.text}[/]")
        self.query_one("#reco-list", Static).update("\n".join(lines))

    def _refresh_security_table(self) -> None:
        table = self.query_one("#sec-table", DataTable)
        table.clear()
        for f in sorted(self.state.security_findings):
            style = SEVERITY_STYLE.get(f.severity, "white")
            table.add_row(f"[{style}]{f.severity.label}[/]", f.title, f.target)

    # ----------------------------------------------------------------- #
    # Workers — each runs blocking core code off the UI thread
    # ----------------------------------------------------------------- #
    @work(thread=True, exclusive=False)
    def run_refresh_net(self) -> None:
        self.state.refresh_netinfo()
        # auto-guess domain for the DC tab
        if not self.state.domain:
            self.state.domain = self.state._guess_domain()
        self.call_from_thread(self._after_net)

    def _after_net(self) -> None:
        self._refresh_dashboard()
        if self.state.domain:
            self.query_one("#dc-target", Input).value = self.state.domain

    @work(thread=True)
    def run_hosts(self, cidr: str) -> None:
        cidr = cidr.strip() or None
        self.call_from_thread(self._set_status, "hosts-status",
                              "Discovering hosts… (this can take a minute)")

        def progress(stage: str) -> None:
            self.call_from_thread(self._set_status, "hosts-status",
                                  f"Discovering: {stage}…")

        hosts = self.state.run_discovery(cidr, progress=progress)
        self.call_from_thread(self._after_hosts, hosts)

    def _after_hosts(self, hosts) -> None:
        table = self.query_one("#hosts-table", DataTable)
        table.clear()
        for h in hosts:
            table.add_row(h.ip, h.name or "—", h.mac or "—",
                          h.vendor or "—", h.source)
        self._set_status("hosts-status",
                         f"Found {len(hosts)} host(s). "
                         "Select a row to target it on other tabs.")
        self._refresh_dashboard()

    @work(thread=True)
    def run_ports(self, *, fast: bool) -> None:
        target = self.query_one("#ports-target", Input).value.strip()
        if not target:
            self.call_from_thread(self.notify, "Enter a target first.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "ports-status",
                              f"Scanning {target} ({'fast' if fast else 'full'})…")
        result = self.state.run_port_scan(target, fast=fast)
        self.call_from_thread(self._after_ports, result)

    def _after_ports(self, result) -> None:
        table = self.query_one("#ports-table", DataTable)
        table.clear()
        for op in result.open_ports:
            table.add_row(str(op.port), op.proto, op.service or "—",
                          op.version or "—")
        msg = (f"[red]{result.error}[/]" if result.error else
               f"{len(result.open_ports)} open port(s) on {result.target} "
               f"via {result.method} in {result.duration:.1f}s")
        self._set_status("ports-status", msg)
        self._refresh_security_table()
        self._refresh_dashboard()

    @work(thread=True)
    def run_shares(self) -> None:
        user = self.query_one("#shares-user", Input).value.strip() or None
        pw = self.query_one("#shares-pass", Input).value or None
        self.call_from_thread(self._set_status, "shares-status",
                              "Scanning hosts for SMB shares…")

        def progress(ip: str) -> None:
            self.call_from_thread(self._set_status, "shares-status",
                                  f"Checking {ip}…")

        results = self.state.run_shares(username=user, password=pw,
                                        progress=progress)
        self.call_from_thread(self._after_shares, results)

    def _after_shares(self, results) -> None:
        table = self.query_one("#shares-table", DataTable)
        table.clear()
        count = 0
        for r in results:
            for s in r.shares:
                anon = "[red]yes[/]" if s.anonymous else "no"
                table.add_row(r.host, s.name, s.type, anon, s.comment or "—")
                count += 1
        self._set_status("shares-status",
                         f"{count} share(s) on {len(results)} host(s).")
        self._refresh_security_table()
        self._refresh_dashboard()

    @work(thread=True)
    def run_printers(self) -> None:
        self.call_from_thread(self._set_status, "printers-status",
                              "Discovering printers…")
        printers = self.state.run_printers()
        self.call_from_thread(self._after_printers, printers)

    def _after_printers(self, printers) -> None:
        table = self.query_one("#printers-table", DataTable)
        table.clear()
        for p in printers:
            table.add_row(p.host, p.name or "—",
                          ", ".join(p.protocols), p.model or "—")
        self._set_status("printers-status", f"Found {len(printers)} printer(s).")
        self._refresh_dashboard()

    @work(thread=True)
    def run_dc(self) -> None:
        target = self.query_one("#dc-target", Input).value.strip()
        if not target:
            self.call_from_thread(self.notify, "Enter a domain or DC IP.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "dc-status",
                              f"Checking {target}…")
        from .core.utils import valid_ip
        if valid_ip(target):
            statuses = self.state.run_dc_check(host=target)
        else:
            statuses = self.state.run_dc_check(domain=target)
        self.call_from_thread(self._after_dc, statuses)

    def _after_dc(self, statuses) -> None:
        table = self.query_one("#dc-table", DataTable)
        table.clear()
        health_col = {"healthy": "green", "degraded": "yellow",
                      "reachable": "cyan", "down": "red"}
        for d in statuses:
            if d.error:
                table.add_row(d.host, "[red]error[/]", "—", d.error)
                continue
            col = health_col.get(d.health, "white")
            lat = f"{d.latency_ms:.0f}ms" if d.latency_ms is not None else "—"
            table.add_row(d.name or d.host, f"[{col}]{d.health}[/]", lat,
                          ", ".join(d.open_service_names) or "—")
        self._set_status("dc-status", f"Checked {len(statuses)} target(s).")
        self._refresh_dashboard()

    @work(thread=True)
    def run_wifi(self) -> None:
        self.call_from_thread(self._set_status, "wifi-status",
                              "Surveying Wi-Fi…")
        survey = self.state.run_wifi()
        self.call_from_thread(self._after_wifi, survey)

    def _after_wifi(self, survey) -> None:
        table = self.query_one("#wifi-table", DataTable)
        table.clear()
        if survey.error:
            self._set_status("wifi-status", f"[red]{survey.error}[/]")
            return
        for ap in survey.access_points:
            sec = ap.security
            if ap.is_open:
                sec = "[red]Open[/]"
            elif ap.is_weak_crypto:
                sec = f"[red]{ap.security}[/]"
            name = ("[b]" + ap.ssid + "[/b]") if ap.in_use else ap.ssid
            table.add_row(name, str(ap.signal or "—"), ap.channel or "—",
                          ap.band or "—", sec)
        link = survey.link
        link_txt = (f"linked to {link.ssid} ({link.signal}%, {link.bitrate})"
                    if link.connected else "not associated")
        self._set_status("wifi-status",
                         f"{len(survey.access_points)} AP(s); {link_txt}")
        self._refresh_security_table()
        self._refresh_dashboard()

    @work(thread=True)
    def run_speed_ping(self) -> None:
        self.call_from_thread(self._set_status, "speed-status",
                              "Pinging gateway…")
        res = self.state.run_gateway_latency()
        self.call_from_thread(self._after_speed_ping, res)

    def _after_speed_ping(self, res) -> None:
        if res is None:
            self._set_status("speed-status", "[red]No gateway to ping.[/]")
            return
        if res.error:
            text = f"[red]{res.error}[/]"
        else:
            text = (f"[b]Gateway {res.host}[/b]\n"
                    f"avg {res.rtt_avg:.1f} ms  (min {res.rtt_min:.1f} / "
                    f"max {res.rtt_max:.1f})\n"
                    f"jitter {res.jitter:.1f} ms   loss {res.loss_pct:.0f}%\n"
                    f"quality: {res.quality}")
        self.query_one("#speed-result", Static).update(text)
        self._set_status("speed-status", "Latency test complete.")
        self._refresh_dashboard()

    @work(thread=True)
    def run_speed_iperf(self) -> None:
        server = self.query_one("#speed-target", Input).value.strip()
        if not server:
            self.call_from_thread(self.notify, "Enter an iperf3 server.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "speed-status",
                              f"Running iperf3 to {server}…")
        from .core import speedtest
        res = speedtest.iperf(server)
        self.call_from_thread(self._after_throughput, res)

    @work(thread=True)
    def run_speed_wan(self) -> None:
        self.call_from_thread(self._set_status, "speed-status",
                              "Testing WAN download…")
        from .core import speedtest
        res = speedtest.internet_download()
        self.call_from_thread(self._after_throughput, res)

    def _after_throughput(self, res) -> None:
        if res.error:
            text = f"[red]{res.error}[/]"
        else:
            text = (f"[b]{res.method} → {res.target}[/b]\n"
                    f"[b green]{res.mbps:.1f} Mbit/s[/]  "
                    f"({res.seconds:.1f}s)")
        self.query_one("#speed-result", Static).update(text)
        self._set_status("speed-status", "Throughput test complete.")

    @work(thread=True)
    def run_smb_check(self) -> None:
        target = self.query_one("#sec-target", Input).value.strip()
        if not target:
            self.call_from_thread(self.notify, "Enter a host to check.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "sec-status",
                              f"Deep SMB check on {target}…")
        self.state.run_smb_security(target)
        self.call_from_thread(self._after_smb_check)

    def _after_smb_check(self) -> None:
        self._refresh_security_table()
        self._set_status("sec-status",
                         f"{len(self.state.security_findings)} finding(s) total.")
        self._refresh_dashboard()

    @work(thread=True)
    def run_scan_all(self) -> None:
        """Run the full sweep in sensible order, updating each tab as it goes."""
        self.call_from_thread(self.notify, "Full scan started…")
        self.state.refresh_netinfo()
        self.call_from_thread(self._refresh_dashboard)

        hosts = self.state.run_discovery()
        self.call_from_thread(self._after_hosts, hosts)

        if self.state.domain:
            statuses = self.state.run_dc_check(domain=self.state.domain)
            self.call_from_thread(self._after_dc, statuses)

        self.state.run_wifi()
        self.call_from_thread(self._after_wifi, self.state.wifi)

        printers = self.state.run_printers()
        self.call_from_thread(self._after_printers, printers)

        shares = self.state.run_shares()
        self.call_from_thread(self._after_shares, shares)

        self.state.run_gateway_latency()
        self.call_from_thread(self._after_speed_ping, self.state.gateway_latency)

        self.call_from_thread(self.notify, "Full scan complete.")
        self.call_from_thread(self.action_show_dashboard)

    @work(thread=True)
    def run_export(self) -> None:
        path = Path.home() / f"hackberrypios-report-{datetime.now():%Y%m%d-%H%M%S}.json"
        try:
            self.state.export_json(str(path))
            self.call_from_thread(self.notify, f"Report saved: {path}")
        except Exception as exc:  # pragma: no cover
            self.call_from_thread(self.notify, f"Export failed: {exc}",
                                  severity="error")


def main() -> None:
    HackberryApp().run()


if __name__ == "__main__":
    main()
