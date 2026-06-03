"""Self-contained HTML (and optional PDF) report generation.

Produces a single styled HTML file summarising a full audit — health score,
network context, hosts, DCs, shares, printers, Wi-Fi, security findings and any
baseline diff — suitable for handing to a client or colleague. The styling
mirrors the project website and is fully inline so the file is portable.

PDF export is offered when ``wkhtmltopdf`` is installed; otherwise the HTML can
simply be "printed to PDF" from any browser.
"""

from __future__ import annotations

import html
import os
from datetime import datetime

from .utils import have, run

_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--border:#222b36;--text:#e6edf3;
--muted:#9da7b3;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:28px 22px}
h1{font-size:1.9rem;margin:0 0 4px}h2{font-size:1.25rem;margin:32px 0 10px;
border-bottom:1px solid var(--border);padding-bottom:6px}
.muted{color:var(--muted)}
.score{display:inline-block;font-size:2.2rem;font-weight:700;padding:6px 18px;
border-radius:12px;border:2px solid}
table{width:100%;border-collapse:collapse;margin:8px 0;font-size:.92rem}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:.72rem;letter-spacing:.04em}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--panel);padding:1px 5px;border-radius:4px}
.pill{display:inline-block;padding:1px 9px;border-radius:20px;font-size:.78rem;font-weight:600}
.b-crit{background:rgba(248,81,73,.15);color:var(--bad)}
.b-high{background:rgba(248,81,73,.12);color:var(--bad)}
.b-med{background:rgba(210,153,34,.15);color:var(--warn)}
.b-low{background:rgba(210,153,34,.1);color:var(--warn)}
.b-info{background:rgba(88,166,255,.12);color:var(--accent)}
.b-ok{background:rgba(63,185,80,.14);color:var(--ok)}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 20px;margin:10px 0}
.kv{display:grid;grid-template-columns:160px 1fr;gap:4px 16px}
.kv div:nth-child(odd){color:var(--muted)}
.reco li{margin:4px 0}
footer{margin-top:40px;color:var(--muted);font-size:.82rem;border-top:1px solid var(--border);padding-top:14px}
"""


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _sev_pill(label: str) -> str:
    cls = {"Critical": "b-crit", "High": "b-high", "Medium": "b-med",
           "Low": "b-low", "Info": "b-info"}.get(label, "b-info")
    return f'<span class="pill {cls}">{_e(label)}</span>'


def _table(headers: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{_e(empty)}</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = ""
    for r in rows:
        body += "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def build_html(state, *, profile_name: str = "") -> str:
    assessment = state.assess()
    s = state
    col = "var(--ok)" if assessment.score >= 80 else (
        "var(--warn)" if assessment.score >= 55 else "var(--bad)")

    ctx = s.netctx
    net_kv = ""
    if ctx:
        p = ctx.primary
        items = [
            ("Hostname", ctx.hostname),
            ("Interface", f"{p.name} ({p.ipv4})" if p else "—"),
            ("Subnet", ctx.subnet or "—"),
            ("Gateway", ctx.gateway or "—"),
            ("DNS", ", ".join(ctx.dns_servers) or "—"),
            ("Domain", s.domain or "—"),
        ]
        net_kv = '<div class="kv">' + "".join(
            f"<div>{_e(k)}</div><div>{_e(v)}</div>" for k, v in items) + "</div>"

    # Recommendations
    reco = "".join(
        f"<li>[{_e(r.priority.label)}] {_e(r.text)}</li>"
        for r in assessment.top)

    # Hosts
    host_rows = [[_e(h.ip), _e(h.name or "—"), f"<code>{_e(h.mac or '—')}</code>",
                  _e(h.vendor or "—"), _e(getattr(h, "os", "") or "—")]
                 for h in s.hosts]

    # DCs
    dc_rows = [[_e(d.name or d.host), _e(d.health),
                f"{d.latency_ms:.0f} ms" if d.latency_ms is not None else "—",
                _e(", ".join(d.open_service_names))]
               for d in s.dc_statuses]

    # Shares
    share_rows = []
    for r in s.share_results:
        for sh in r.shares:
            anon = ('<span class="pill b-high">yes</span>' if sh.anonymous
                    else "no")
            share_rows.append([_e(r.host), _e(sh.name), _e(sh.type), anon,
                               _e(sh.comment or "—")])

    # Printers
    printer_rows = [[_e(p.host), _e(p.name or "—"), _e(", ".join(p.protocols)),
                     _e(p.model or "—")] for p in s.printers]

    # Wi-Fi
    wifi_rows = []
    if s.wifi and not s.wifi.error:
        for ap in s.wifi.access_points:
            sec = ap.security
            if ap.is_open:
                sec = '<span class="pill b-med">Open</span>'
            elif ap.is_weak_crypto:
                sec = f'<span class="pill b-high">{_e(ap.security)}</span>'
            wifi_rows.append([_e(ap.ssid), _e(ap.signal), _e(ap.channel),
                              _e(ap.band), sec])

    # Findings
    finding_rows = [[_sev_pill(f.severity.label), _e(f.title), _e(f.target),
                     _e(f.recommendation or f.detail)]
                    for f in sorted(s.security_findings)]

    # Baseline diff
    baseline_html = ""
    diff = getattr(s, "baseline_diff", None)
    if diff is not None and diff.had_baseline:
        rows = []
        for h in diff.new_hosts:
            rows.append(['<span class="pill b-high">NEW</span>', _e(h.ip),
                         _e(h.name or "—"), f"<code>{_e(h.mac or '—')}</code>"])
        for h in diff.missing_hosts:
            rows.append(['<span class="pill b-med">MISSING</span>', _e(h.ip),
                         _e(h.name or "—"), f"<code>{_e(h.mac or '—')}</code>"])
        for c in diff.changed_hosts:
            rows.append(['<span class="pill b-info">CHANGED</span>',
                         _e(c), "", ""])
        baseline_html = (
            f"<h2>Baseline diff</h2><p class='muted'>vs {_e(diff.baseline_date)}"
            f" — {_e(diff.summary)}</p>"
            + _table(["Change", "IP / detail", "Name", "MAC"], rows,
                     "No changes since baseline."))

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"HackberryPiOS report{(' — ' + profile_name) if profile_name else ''}"

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_e(title)}</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>{_e(title)}</h1>
<p class="muted">Generated {generated} · HackberryPiOS network audit</p>
<div class="card"><span class="score" style="border-color:{col};color:{col}">
{assessment.score}/100</span>
<span class="muted" style="margin-left:14px">network health score</span></div>

<h2>Network</h2>{net_kv or '<p class="muted">No network context.</p>'}

<h2>Recommendations</h2><ul class="reco">{reco}</ul>
{baseline_html}
<h2>Hosts ({len(s.hosts)})</h2>
{_table(["IP", "Name", "MAC", "Vendor", "OS"], host_rows, "No hosts discovered.")}

<h2>Domain controllers</h2>
{_table(["Host", "Health", "Latency", "Services"], dc_rows, "No DC checks run.")}

<h2>Shares</h2>
{_table(["Host", "Share", "Type", "Anonymous", "Comment"], share_rows, "No shares found.")}

<h2>Printers</h2>
{_table(["Host", "Name", "Protocols", "Model"], printer_rows, "No printers found.")}

<h2>Wi-Fi</h2>
{_table(["SSID", "Signal %", "Channel", "Band", "Security"], wifi_rows, "No Wi-Fi survey run.")}

<h2>Security findings ({len(s.security_findings)})</h2>
{_table(["Severity", "Finding", "Target", "Recommendation"], finding_rows, "No findings.")}

<footer>Authorised-use defensive audit · HackberryPiOS ·
<a style="color:var(--accent)" href="https://github.com/fmatsch/HackberryPiOS">github.com/fmatsch/HackberryPiOS</a></footer>
</div></body></html>"""


def write_html(state, path: str, *, profile_name: str = "") -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_html(state, profile_name=profile_name))
    return path


def write_pdf(state, path: str, *, profile_name: str = "") -> tuple[bool, str]:
    """Write a PDF if wkhtmltopdf is available. Returns (ok, message)."""
    html_path = path.rsplit(".", 1)[0] + ".html"
    write_html(state, html_path, profile_name=profile_name)
    if not have("wkhtmltopdf"):
        return (False, f"wkhtmltopdf not installed; wrote HTML instead: "
                       f"{os.path.basename(html_path)} (print to PDF from a browser)")
    res = run(["wkhtmltopdf", "-q", html_path, path], timeout=60)
    if res.ok and os.path.exists(path):
        return (True, path)
    return (False, res.stderr.strip() or "wkhtmltopdf failed")
