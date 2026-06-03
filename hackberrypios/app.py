"""HackberryPiOS Textual UI.

A keyboard-driven, tabbed dashboard sized for the HackberryPi CM5 display.
Each tab maps to one capability; scans run in background threads so the UI
stays responsive. The Home tab aggregates everything into a health score plus
a prioritised action list, and the Site tab manages per-network profiles,
baselines and report export.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual import on, work
from textual.containers import Container, Horizontal, VerticalScroll
from textual.app import App, ComposeResult
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label,
                             Select, Static, TabbedContent, TabPane)

from . import __version__
from .core import profiles as profiles_mod
from .core import sysinfo, wifi as wifi_mod
from .core.security import Severity
from .core.state import AppState
from .core.utils import valid_ip

PRIORITY_STYLE = {
    "URGENT": "bold red", "IMPORTANT": "dark_orange", "SUGGESTED": "yellow",
    "INFO": "cyan", "DONE": "green",
}
SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red", Severity.HIGH: "red",
    Severity.MEDIUM: "dark_orange", Severity.LOW: "yellow", Severity.INFO: "cyan",
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
        ("d", "show_dashboard", "Home"),
        ("ctrl+r", "refresh_net", "Refresh net"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.state = AppState()
        self._hosts_all: list = []        # full host list for filtering
        self._wifi_timer = None           # live-survey interval handle

    # ----------------------------------------------------------------- #
    # Layout
    # ----------------------------------------------------------------- #
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="tab-dash", id="tabs"):
            with TabPane("Home", id="tab-dash"):
                yield from self._compose_dashboard()
            with TabPane("Site", id="tab-site"):
                yield from self._compose_site()
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

    def _compose_site(self) -> ComposeResult:
        with VerticalScroll(classes="pane"):
            yield Label("Site profile", classes="card-title")
            yield Select([], prompt="Load saved profile…", id="site-select")
            yield Input(placeholder="Profile name", id="site-name")
            yield Input(placeholder="AD domain (corp.example.com)", id="site-domain")
            yield Input(placeholder="Subnet CIDR (10.0.0.0/24)", id="site-subnet")
            yield Input(placeholder="NTP/time server (optional)", id="site-ntp")
            yield Input(placeholder="SMB username (optional, no password stored)",
                        id="site-user")
            yield Input(placeholder="Notes", id="site-notes")
            with Horizontal(classes="toolbar"):
                yield Button("Save", id="site-save", variant="primary")
                yield Button("Apply", id="site-apply")
                yield Button("Delete", id="site-delete", variant="error")
            yield Static(id="site-status", classes="status")

            yield Label("Baseline (change detection)", classes="card-title")
            with Horizontal(classes="toolbar"):
                yield Button("Save baseline", id="base-save", variant="primary")
                yield Button("Compare", id="base-compare")
            yield Static("Save the current hosts as a baseline, then compare on "
                         "your next visit to spot new/missing devices.",
                         id="base-status", classes="status")
            base_table = DataTable(id="base-table", cursor_type="row")
            base_table.add_columns("Change", "IP / detail", "Name", "MAC")
            yield base_table

            yield Label("Report", classes="card-title")
            with Horizontal(classes="toolbar"):
                yield Button("Export HTML", id="rep-html", variant="primary")
                yield Button("Export PDF", id="rep-pdf")
            yield Static("Exports a full styled report to your home folder.",
                         id="rep-status", classes="status")

    def _compose_hosts(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="CIDR (auto if empty)", id="hosts-target")
                yield Button("Scan", id="hosts-run", variant="primary")
                yield Button("OS scan", id="hosts-os")
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="filter (IP / name / vendor)…",
                            id="hosts-filter")
            yield Static("Press Scan to discover hosts on the subnet.",
                         id="hosts-status", classes="status")
            table = DataTable(id="hosts-table", cursor_type="row")
            table.add_columns("IP", "Name", "MAC", "Vendor", "OS", "Via")
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
                yield Input(placeholder="user (blank = anonymous)", id="shares-user")
                yield Input(placeholder="password", password=True, id="shares-pass")
                yield Button("Scan", id="shares-run", variant="primary")
            yield Static("Scans discovered hosts for SMB shares.",
                         id="shares-status", classes="status")
            table = DataTable(id="shares-table", cursor_type="row")
            table.add_columns("Host", "Share", "Type", "Anon", "Comment")
            yield table

    def _compose_printers(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Button("Find printers", id="printers-run", variant="primary")
            yield Static("Discovers printers via mDNS + port probes.",
                         id="printers-status", classes="status")
            table = DataTable(id="printers-table", cursor_type="row")
            table.add_columns("Host", "Name", "Protocols", "Model")
            yield table

    def _compose_dc(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="domain.example.com or DC IP", id="dc-target")
                yield Button("Check", id="dc-run", variant="primary")
            yield Static("Locates & health-checks domain controllers.",
                         id="dc-status", classes="status")
            table = DataTable(id="dc-table", cursor_type="row")
            table.add_columns("Host", "Health", "Latency", "Services")
            yield table

    def _compose_wifi(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Button("Survey", id="wifi-run", variant="primary")
                yield Button("Channels", id="wifi-channels")
                yield Button("Live", id="wifi-live")
            yield Static("Scans nearby access points + current link.",
                         id="wifi-status", classes="status")
            yield Static(id="wifi-advice", classes="card")
            table = DataTable(id="wifi-table", cursor_type="row")
            table.add_columns("SSID", "Sig%", "Chan", "Band", "Security")
            yield table

    def _compose_speed(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="iperf3 server (optional)", id="speed-target")
                yield Button("LAN ping", id="speed-ping", variant="primary")
                yield Button("iperf3", id="speed-iperf")
                yield Button("WAN", id="speed-wan")
            yield Static("Measure latency / throughput.",
                         id="speed-status", classes="status")
            yield Static(id="speed-result", classes="card")

    def _compose_security(self) -> ComposeResult:
        with Container(classes="pane"):
            with Horizontal(classes="toolbar"):
                yield Input(placeholder="host[:port] for TLS / SMB", id="sec-target")
                yield Button("TLS", id="sec-tls", variant="primary")
                yield Button("SMB", id="sec-smb")
            with Horizontal(classes="toolbar"):
                yield Button("NTP skew", id="sec-ntp", variant="primary")
                yield Button("Rogue DHCP", id="sec-dhcp")
                yield Button("SMBv1 sweep", id="sec-sweep")
            yield Input(placeholder="filter findings…", id="sec-filter")
            yield Static("Aggregated findings from all scans.",
                         id="sec-status", classes="status")
            table = DataTable(id="sec-table", cursor_type="row")
            table.add_columns("Sev", "Finding", "Target", "Recommendation")
            yield table

    # ----------------------------------------------------------------- #
    # Lifecycle
    # ----------------------------------------------------------------- #
    def on_mount(self) -> None:
        self.run_refresh_net()
        self._reload_profiles()
        self._update_header()
        self.set_interval(30, self._update_header)

    def _update_header(self) -> None:
        batt = sysinfo.battery()
        bits = []
        if self.state.profile:
            bits.append(self.state.profile.name)
        if batt.present and batt.percent is not None:
            bits.append(f"{batt.icon} {batt.percent}%")
        temp = sysinfo.cpu_temp_c()
        if temp is not None:
            bits.append(f"{temp:.0f}°C")
        self.sub_title = " · ".join(bits) if bits else "Network audit"

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
            "tab-shares": self.run_shares,
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
            "hosts-os": self.run_os_fingerprint,
            "ports-fast": lambda: self.run_ports(fast=True),
            "ports-full": lambda: self.run_ports(fast=False),
            "shares-run": self.run_shares,
            "printers-run": self.run_printers,
            "dc-run": self.run_dc,
            "wifi-run": self.run_wifi,
            "wifi-channels": self.run_channels,
            "wifi-live": self.toggle_wifi_live,
            "speed-ping": self.run_speed_ping,
            "speed-iperf": self.run_speed_iperf,
            "speed-wan": self.run_speed_wan,
            "sec-smb": self.run_smb_check,
            "sec-tls": self.run_tls_check,
            "sec-ntp": self.run_ntp_check,
            "sec-dhcp": self.run_dhcp_check,
            "sec-sweep": self.run_smb_sweep,
            "site-save": self.save_profile,
            "site-apply": self.apply_profile,
            "site-delete": self.delete_profile,
            "base-save": self.save_baseline,
            "base-compare": self.compare_baseline,
            "rep-html": lambda: self.run_report(pdf=False),
            "rep-pdf": lambda: self.run_report(pdf=True),
        }
        handler = routes.get(bid)
        if handler:
            handler()

    @on(DataTable.RowSelected, "#hosts-table")
    def _host_selected(self, event: DataTable.RowSelected) -> None:
        table = self.query_one("#hosts-table", DataTable)
        row = table.get_row(event.row_key)
        if row:
            ip = str(row[0])
            self.query_one("#ports-target", Input).value = ip
            self.query_one("#sec-target", Input).value = ip
            self.notify(f"Selected {ip} (pre-filled Ports & Sec tabs)")

    @on(Input.Changed, "#hosts-filter")
    def _filter_hosts(self, event: Input.Changed) -> None:
        self._render_hosts(event.value)

    @on(Input.Changed, "#sec-filter")
    def _filter_findings(self, event: Input.Changed) -> None:
        self._render_findings(event.value)

    @on(Select.Changed, "#site-select")
    def _profile_selected(self, event: Select.Changed) -> None:
        if event.value in (None, Select.BLANK):
            return
        self._load_profile_into_form(str(event.value))

    # ----------------------------------------------------------------- #
    # Helpers
    # ----------------------------------------------------------------- #
    def _set_status(self, sid: str, text: str) -> None:
        self.query_one(f"#{sid}", Static).update(text)

    def _refresh_dashboard(self) -> None:
        ctx = self.state.netctx
        if ctx:
            p = ctx.primary
            prof = f"   Profile: {self.state.profile.name}" if self.state.profile else ""
            net = (f"[b]{ctx.hostname}[/b]   {p.name if p else '—'}  "
                   f"{p.ipv4 if p else 'no IP'}{prof}\n"
                   f"Subnet: {ctx.subnet or '—'}   GW: {ctx.gateway or '—'}\n"
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
        for r in assessment.top[:13]:
            style = PRIORITY_STYLE.get(r.priority.name, "white")
            marker = "✓" if r.priority.name == "DONE" else "•"
            lines.append(f"[{style}]{marker} {r.text}[/]")
        self.query_one("#reco-list", Static).update("\n".join(lines))

    def _render_hosts(self, filter_text: str = "") -> None:
        table = self.query_one("#hosts-table", DataTable)
        table.clear()
        ft = filter_text.strip().lower()
        for h in self._hosts_all:
            hay = " ".join(str(x) for x in
                           (h.ip, h.name, h.mac, h.vendor, h.os)).lower()
            if ft and ft not in hay:
                continue
            table.add_row(h.ip, h.name or "—", h.mac or "—", h.vendor or "—",
                          h.os or "—", h.source)

    def _render_findings(self, filter_text: str = "") -> None:
        table = self.query_one("#sec-table", DataTable)
        table.clear()
        ft = filter_text.strip().lower()
        for f in sorted(self.state.security_findings):
            hay = f"{f.severity.label} {f.title} {f.target}".lower()
            if ft and ft not in hay:
                continue
            style = SEVERITY_STYLE.get(f.severity, "white")
            note = (f.recommendation or f.detail or "")[:48]
            table.add_row(f"[{style}]{f.severity.label}[/]", f.title,
                          f.target, note)

    def _refresh_security_table(self) -> None:
        self._render_findings(self.query_one("#sec-filter", Input).value)

    # ---- profile form helpers ----
    def _reload_profiles(self) -> None:
        names = profiles_mod.list_profiles()
        select = self.query_one("#site-select", Select)
        select.set_options([(n, n) for n in names])

    def _load_profile_into_form(self, name: str) -> None:
        prof = profiles_mod.load(name)
        if not prof:
            return
        self.query_one("#site-name", Input).value = prof.name
        self.query_one("#site-domain", Input).value = prof.domain
        self.query_one("#site-subnet", Input).value = prof.subnet
        self.query_one("#site-ntp", Input).value = prof.ntp_server
        self.query_one("#site-user", Input).value = prof.username
        self.query_one("#site-notes", Input).value = prof.notes
        self._set_status("site-status", f"Loaded '{name}'. Press Apply to use it.")

    def _form_profile(self) -> profiles_mod.Profile:
        return profiles_mod.Profile(
            name=self.query_one("#site-name", Input).value.strip() or "Unnamed",
            domain=self.query_one("#site-domain", Input).value.strip(),
            subnet=self.query_one("#site-subnet", Input).value.strip(),
            ntp_server=self.query_one("#site-ntp", Input).value.strip(),
            username=self.query_one("#site-user", Input).value.strip(),
            notes=self.query_one("#site-notes", Input).value.strip())

    # ----------------------------------------------------------------- #
    # Site / profile handlers (these are quick, run on the main thread)
    # ----------------------------------------------------------------- #
    def save_profile(self) -> None:
        prof = self._form_profile()
        profiles_mod.save(prof)
        self._reload_profiles()
        self._set_status("site-status", f"Saved profile '{prof.name}'.")

    def apply_profile(self) -> None:
        prof = self._form_profile()
        self.state.apply_profile(prof)
        if prof.subnet:
            self.query_one("#hosts-target", Input).value = prof.subnet
        if prof.domain:
            self.query_one("#dc-target", Input).value = prof.domain
        if prof.username:
            self.query_one("#shares-user", Input).value = prof.username
        self._update_header()
        self._refresh_dashboard()
        self._set_status("site-status",
                         f"Applied '{prof.name}'. Domain/subnet pushed to tabs.")

    def delete_profile(self) -> None:
        name = self.query_one("#site-name", Input).value.strip()
        if name and profiles_mod.delete(name):
            self._reload_profiles()
            self._set_status("site-status", f"Deleted profile '{name}'.")
        else:
            self._set_status("site-status", "No matching profile to delete.")

    def save_baseline(self) -> None:
        if not self.state.profile:
            self._set_status("base-status",
                             "[yellow]Apply a profile first to anchor the baseline.[/]")
            return
        if not self.state.hosts:
            self._set_status("base-status",
                             "[yellow]Run a host discovery first.[/]")
            return
        path = self.state.save_baseline()
        self._set_status("base-status",
                         f"Baseline saved ({len(self.state.hosts)} hosts).")

    def compare_baseline(self) -> None:
        if not self.state.profile:
            self._set_status("base-status",
                             "[yellow]Apply a profile first.[/]")
            return
        diff = self.state.compare_baseline()
        table = self.query_one("#base-table", DataTable)
        table.clear()
        if diff is None or not diff.had_baseline:
            self._set_status("base-status",
                             "[yellow]No baseline saved for this profile yet.[/]")
            return
        for h in diff.new_hosts:
            table.add_row("[red]NEW[/]", h.ip, h.name or "—", h.mac or "—")
        for h in diff.missing_hosts:
            table.add_row("[dark_orange]MISSING[/]", h.ip, h.name or "—",
                          h.mac or "—")
        for c in diff.changed_hosts:
            table.add_row("[cyan]CHANGED[/]", c, "", "")
        self._set_status("base-status", f"Baseline diff: {diff.summary}")
        self._refresh_dashboard()

    # ----------------------------------------------------------------- #
    # Workers — blocking core code off the UI thread
    # ----------------------------------------------------------------- #
    @work(thread=True, exclusive=False)
    def run_refresh_net(self) -> None:
        self.state.refresh_netinfo()
        if not self.state.domain:
            self.state.domain = self.state._guess_domain()
        self.call_from_thread(self._after_net)

    def _after_net(self) -> None:
        self._refresh_dashboard()
        if self.state.domain and not self.query_one("#dc-target", Input).value:
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
        self._hosts_all = list(hosts)
        self._render_hosts(self.query_one("#hosts-filter", Input).value)
        self._set_status("hosts-status",
                         f"Found {len(hosts)} host(s). Select a row to target it; "
                         "type above to filter.")
        self._refresh_dashboard()

    @work(thread=True)
    def run_os_fingerprint(self) -> None:
        if not self.state.hosts:
            self.call_from_thread(self.notify, "Discover hosts first.",
                                  severity="warning")
            return

        def progress(ip: str) -> None:
            self.call_from_thread(self._set_status, "hosts-status",
                                  f"OS fingerprinting {ip}… (needs root; slow)")

        self.state.run_os_fingerprint(progress=progress)
        self.call_from_thread(self._after_hosts, self.state.hosts)

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
            table.add_row(p.host, p.name or "—", ", ".join(p.protocols),
                          p.model or "—")
        self._set_status("printers-status", f"Found {len(printers)} printer(s).")
        self._refresh_dashboard()

    @work(thread=True)
    def run_dc(self) -> None:
        target = self.query_one("#dc-target", Input).value.strip()
        if not target:
            self.call_from_thread(self.notify, "Enter a domain or DC IP.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "dc-status", f"Checking {target}…")
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

    @work(thread=True, exclusive=True, group="wifi")
    def run_wifi(self) -> None:
        self.call_from_thread(self._set_status, "wifi-status", "Surveying Wi-Fi…")
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
        live = " · LIVE" if self._wifi_timer else ""
        self._set_status("wifi-status",
                         f"{len(survey.access_points)} AP(s); {link_txt}{live}")
        self._refresh_security_table()
        self._refresh_dashboard()

    @work(thread=True, exclusive=True, group="wifi")
    def run_channels(self) -> None:
        if self.state.wifi is None or self.state.wifi.error:
            self.call_from_thread(self._set_status, "wifi-status",
                                  "Surveying Wi-Fi for channel analysis…")
            self.state.run_wifi()
        survey = self.state.wifi
        if survey is None or survey.error:
            self.call_from_thread(self._set_status, "wifi-status",
                                  f"[red]{survey.error if survey else 'no survey'}[/]")
            return
        advice = wifi_mod.analyse_channels(survey)
        self.call_from_thread(self._after_channels, survey, advice)

    def _after_channels(self, survey, advice) -> None:
        self._after_wifi(survey)
        text = "[b]Channel analysis[/b]\n" + "\n".join(
            f"• {n}" for n in advice.notes)
        self.query_one("#wifi-advice", Static).update(text)

    def toggle_wifi_live(self) -> None:
        if self._wifi_timer is not None:
            self._wifi_timer.stop()
            self._wifi_timer = None
            self._set_status("wifi-status", "Live survey stopped.")
            return
        self._wifi_timer = self.set_interval(5, self.run_wifi)
        self.run_wifi()
        self.notify("Live Wi-Fi survey on (press Live again to stop).")

    @work(thread=True)
    def run_speed_ping(self) -> None:
        self.call_from_thread(self._set_status, "speed-status", "Pinging gateway…")
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
                    f"[b green]{res.mbps:.1f} Mbit/s[/]  ({res.seconds:.1f}s)")
        self.query_one("#speed-result", Static).update(text)
        self._set_status("speed-status", "Throughput test complete.")

    # ---- security checks ----
    def _sec_target(self) -> tuple[str, int]:
        raw = self.query_one("#sec-target", Input).value.strip()
        if ":" in raw and not raw.count(":") > 1:
            host, _, port = raw.partition(":")
            try:
                return host, int(port)
            except ValueError:
                return raw, 443
        return raw, 443

    @work(thread=True)
    def run_tls_check(self) -> None:
        host, port = self._sec_target()
        if not host:
            self.call_from_thread(self.notify, "Enter host[:port] for TLS.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "sec-status",
                              f"Inspecting TLS on {host}:{port}…")
        res = self.state.run_tls(host, port)
        self.call_from_thread(self._after_tls, res)

    def _after_tls(self, res) -> None:
        if res.error:
            msg = f"[red]TLS: {res.error}[/]"
        else:
            days = f"{res.days_left}d left" if res.days_left is not None else "?"
            issues = ("; ".join(res.issues)) or "no issues"
            colour = {"ok": "green", "warning": "yellow",
                      "expired": "red", "error": "red"}.get(res.verdict, "white")
            msg = (f"[{colour}]{res.verdict.upper()}[/] {res.protocol} "
                   f"{res.cipher} · exp {res.not_after} ({days}) · {issues}")
        self._set_status("sec-status", msg)
        self._refresh_security_table()
        self._refresh_dashboard()

    @work(thread=True)
    def run_smb_check(self) -> None:
        host, _ = self._sec_target()
        if not host:
            self.call_from_thread(self.notify, "Enter a host to check.",
                                  severity="warning")
            return
        self.call_from_thread(self._set_status, "sec-status",
                              f"Deep SMB check on {host}…")
        self.state.run_smb_security(host)
        self.call_from_thread(self._after_sec_generic,
                              f"SMB check done on {host}.")

    @work(thread=True)
    def run_ntp_check(self) -> None:
        self.call_from_thread(self._set_status, "sec-status",
                              "Checking clock skew (NTP)…")
        host, _ = self._sec_target()
        res = self.state.run_ntp(host or None)
        if res is None:
            self.call_from_thread(self._after_sec_generic,
                                  "[yellow]No NTP target (set one in the profile "
                                  "or run a DC check).[/]")
            return
        if res.error:
            msg = f"[red]{res.error}[/]"
        else:
            ok = "within" if res.within_kerberos_skew else "[red]EXCEEDS[/]"
            msg = (f"NTP {res.host}: {res.summary} ({ok} Kerberos 5-min skew)")
        self.call_from_thread(self._after_sec_generic, msg)

    @work(thread=True)
    def run_dhcp_check(self) -> None:
        self.call_from_thread(self._set_status, "sec-status",
                              "Broadcasting DHCP DISCOVER (needs root)…")
        res = self.state.run_dhcp()
        if res.error:
            msg = f"[red]{res.error}[/]"
        elif res.rogue_suspected:
            msg = f"[red]Multiple DHCP servers:[/] {', '.join(res.server_ips)}"
        else:
            msg = f"DHCP server(s): {', '.join(res.server_ips) or 'none seen'}"
        self.call_from_thread(self._after_sec_generic, msg)

    @work(thread=True)
    def run_smb_sweep(self) -> None:
        self.call_from_thread(self._set_status, "sec-status",
                              "Sweeping hosts for SMBv1 / signing…")

        def progress(host: str) -> None:
            self.call_from_thread(self._set_status, "sec-status",
                                  f"SMB sweep: {host}…")

        self.state.run_smb_sweep(progress=progress)
        self.call_from_thread(self._after_sec_generic, "SMBv1/signing sweep done.")

    def _after_sec_generic(self, message: str) -> None:
        self._refresh_security_table()
        self._set_status("sec-status",
                         f"{message}  ({len(self.state.security_findings)} findings)")
        self._refresh_dashboard()

    # ---- reports ----
    @work(thread=True)
    def run_report(self, *, pdf: bool) -> None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        if pdf:
            path = str(Path.home() / f"hackberrypios-report-{ts}.pdf")
            ok, msg = self.state.export_pdf_report(path)
            self.call_from_thread(self._set_status, "rep-status",
                                  (f"PDF saved: {msg}" if ok else f"[yellow]{msg}[/]"))
        else:
            path = str(Path.home() / f"hackberrypios-report-{ts}.html")
            self.state.export_html_report(path)
            self.call_from_thread(self._set_status, "rep-status",
                                  f"HTML report saved: {path}")

    @work(thread=True)
    def run_scan_all(self) -> None:
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

        self.state.run_ntp()

        if self.state.profile:
            self.state.compare_baseline()

        self.call_from_thread(self._after_sec_generic, "Full scan complete.")
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
