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

### Hosts
Discovers live hosts on the local subnet.

- Leave the input empty to auto-use the detected CIDR, or type a specific
  range like `10.0.5.0/24`.
- Discovery tries `arp-scan` (fastest, gives MAC + vendor), then `nmap -sn`,
  then the passive ARP cache. Names are resolved via reverse DNS and NetBIOS.
- **Select a row** to pre-fill the **Ports** and **Sec** tabs with that host.

### Ports
Scans a single target.

- **Fast** = nmap top-200 ports (or the curated common-port list without nmap).
- **Full** = all 65 535 ports (slower).
- Service/version detection runs automatically when nmap is present.
- Risky services discovered here feed the **Sec** tab automatically.

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

### Speed
- **LAN ping** — RTT min/avg/max, jitter and packet loss to the gateway, with
  a quality verdict.
- **iperf3** — throughput against an iperf3 server you control (enter its IP).
- **WAN** — quick internet download throughput sanity check.

### Sec
Aggregated, severity-sorted security findings from every scan (risky open
services, anonymous shares, weak Wi-Fi). The **SMB check** button runs deeper
nmap NSE checks (SMBv1 dialect, SMB signing) against a specific host.

## Reports

`e` in the UI, or `--json PATH` in CLI mode, writes a complete JSON report:
network context, hosts, DCs, shares, printers, Wi-Fi, port scans, findings,
and the scored recommendations. Use it for documentation, diffing over time,
or feeding into other tooling (`--print-json | jq`).

## Tips

- Run **Hosts** first; **Shares** and **Print** reuse the discovered host list
  (otherwise they enumerate the whole subnet, which is slower).
- If a tab shows "tool not installed", install the package named on the **Home**
  tab's missing-tools line, or re-run `install.sh`.
