# Usage guide

This guide walks through each tab of HackberryPiOS and the recommended
workflow when you drop into a network.

## Quick start

1. Connect the HackberryPi to the target network (Ethernet via dongle, or
   Wi-Fi).
2. Launch the UI: `hackberrypios` (or your `hpi` alias).
3. The **Home** tab auto-detects your interface, subnet, gateway, DNS and any
   AD domain it can infer.
4. Press **`a`** to run a full sweep, or use individual tabs for targeted work.
5. Read the **health score** and **recommendations** on Home; press **`e`** to
   export a JSON report.

## The tabs

### Home (dashboard)
A compact summary card (host/interface/subnet/gateway/DNS/domain), a 0–100
**network health score**, and a colour-coded, prioritised recommendation list.
The score starts at 100 and is reduced by issues found (unreachable DCs,
anonymous shares, weak Wi-Fi, high-severity findings, packet loss, …).

### Site
Manages everything that makes repeat visits fast.

- **Profiles** — save per-network context (name, AD domain, subnet, NTP server,
  optional SMB username, notes). Pick a saved profile from the dropdown to load
  it, then **Apply** to push the domain/subnet/username into the other tabs.
  Passwords are never stored.
- **Baseline** — **Save baseline** records the currently discovered hosts for
  the active profile. On a later visit, **Compare** shows what changed:
  **NEW** (possible rogue device), **MISSING**, or **CHANGED** (IP/MAC/name).
- **Report** — **Export HTML** (always) or **Export PDF** writes a styled,
  self-contained report to your home folder. PDF uses `wkhtmltopdf` if present,
  otherwise Chromium headless; if neither is available it writes the HTML so you
  can print to PDF from a browser.

### Hosts
Discovers live hosts on the local subnet.

- Leave the input empty to auto-use the detected CIDR, or type a specific
  range like `10.0.5.0/24`.
- Discovery tries `arp-scan` (fastest, gives MAC + vendor), then `nmap -sn`,
  then the passive ARP cache. Names are resolved via reverse DNS and NetBIOS;
  vendors via nmap's full OUI database when available.
- **OS scan** runs nmap OS detection (`-O`, needs root; slow) and fills the OS
  column.
- Type in the **filter** box to narrow the table by IP, name, vendor or OS.
- **Select a row** to pre-fill the **Ports** and **Sec** tabs with that host.

### Ports
Scans a single target.

- **Fast** = nmap top-200 ports (or the curated common-port list without nmap).
- **Full** = all 65 535 ports (slower).
- Service/version detection runs automatically when nmap is present.
- Risky services discovered here feed the **Sec** tab automatically.

### Services
Scans **every host on the subnet** and lists the services running across the
whole network, **grouped by service** — the fast way to answer "what's actually
running out there, and where?".

- **Scan** = fast sweep (nmap top-200 ports, light version detection) over all
  discovered hosts. **Deep** = all ports (much slower on a busy network).
- Leave **CIDR** empty to use the current subnet; if no hosts have been
  discovered yet, discovery runs first automatically.
- Results are grouped by service name (ssh, http, smb, rdp…), showing how many
  hosts expose each one plus the per-host port and detected version. Type in the
  filter box to narrow by service, host or version.
- Open ports found here feed the **Sec** tab (risky services, version CVE hints)
  and appear in exported reports.
- With nmap installed the whole subnet is scanned in one efficient pass; without
  it, a built-in pure-Python TCP scanner is used as a fallback.

### Shares
Enumerates SMB/Windows file shares across discovered hosts.

- Leave user/password empty for an **anonymous/guest** probe — this is exactly
  what you want to flag in an audit (world-readable shares show `Anon = yes`).
- Provide credentials to enumerate authenticated shares.

### Print
Finds printers via mDNS/Bonjour announcements and by probing IPP (631),
LPD (515) and raw JetDirect (9100) ports on discovered hosts.

### DC/AD
Locates and health-checks Active Directory Domain Controllers.

- Enter a **domain** (e.g. `corp.example.com`) to discover DCs via the
  `_ldap._tcp.dc._msdcs.<domain>` SRV records, or enter a **DC IP** directly.
- Checks the canonical AD port set (Kerberos 88, LDAP 389/636, SMB 445,
  Global Catalog 3268/3269, DNS, kpasswd) and reports a health verdict
  (`healthy` / `degraded` / `reachable` / `down`) plus latency.

### Wi-Fi
Surveys nearby access points (SSID, signal %, channel, band, security) and
reports your current link quality. Open and WEP/WPA1 networks are highlighted
in red and raised as security findings.

- **Channels** analyses congestion and recommends the least-used 2.4 GHz
  (1/6/11) and 5 GHz channel.
- **Live** toggles a continuous re-survey (every few seconds) — handy as a
  signal meter while you walk a site. Press again to stop.

### Speed
- **LAN ping** — RTT min/avg/max, jitter and packet loss to the gateway, with
  a quality verdict.
- **iperf3** — throughput against an iperf3 server you control (enter its IP).
- **WAN** — quick internet download throughput sanity check.

### Sec
Aggregated, severity-sorted security findings from every scan (risky open
services, version-based CVE hints, anonymous shares, weak Wi-Fi). Type in the
**filter** box to narrow the findings. Buttons:

- **TLS** — inspect the certificate at `host[:port]` (default 443): expiry/days
  left, protocol, cipher; flags expired/soon-expiring, self-signed and obsolete
  protocols. Works for HTTPS, LDAPS (`dc:636`), etc.
- **SMB** — deep nmap NSE check (SMBv1 dialect, SMB signing) on one host.
- **NTP skew** — compares the local clock against the target / profile NTP
  server / a DC, and flags drift beyond the 5-minute Kerberos tolerance.
- **Rogue DHCP** — broadcasts a DHCP DISCOVER and lists every responding server
  (more than one = investigate). Needs root.
- **SMBv1 sweep** — runs the SMBv1/signing check across all discovered hosts.

## Reports

- **HTML/PDF** — the Site tab (or `--html PATH` in CLI mode) writes a styled,
  shareable report: score, network, recommendations, baseline diff, hosts, DCs,
  shares, printers, Wi-Fi and findings.
- **JSON** — `e` in the UI, or `--json PATH` in CLI mode, writes the complete
  machine-readable report for diffing over time or feeding other tooling
  (`--print-json | jq`).

## Tips

- Run **Hosts** first; **Services**, **Shares** and **Print** reuse the
  discovered host list (otherwise they enumerate the whole subnet, which is
  slower). The **Services** tab will run discovery for you if you skip it.
- If a tab shows "tool not installed", install the package named on the **Home**
  tab's missing-tools line, or re-run `install.sh`.
