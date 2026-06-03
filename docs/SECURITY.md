# Security, scope & legal notes

## Authorised use only

HackberryPiOS is built for **administrators and defenders** auditing networks
they own or are explicitly authorised to assess. Active discovery and port
scanning can trip intrusion-detection systems and, in some jurisdictions,
scanning networks without permission is illegal. Get written authorisation
before assessing networks that are not your own.

## What the tool does — and does not — do

**It does (non-intrusive enumeration & identification):**

- ARP/ping host discovery, reverse-DNS / NetBIOS name resolution
- TCP port scanning and service/version banner reading
- SMB share *listing* (including anonymous/guest probes — read-only)
- DC location via public DNS SRV records and TCP reachability checks
- Reading SMB protocol/signing capability via nmap's standard NSE scripts
- Passive Wi-Fi survey and link-quality measurement
- Latency / throughput measurement

**It does NOT:**

- Exploit any vulnerability
- Brute-force or guess credentials
- Modify, write to, or delete anything on remote hosts
- Perform denial-of-service, flooding, or deauthentication attacks
- Capture or crack Wi-Fi handshakes

The "security" findings are **posture observations** (e.g. "SMBv1 is enabled",
"this share allows anonymous access", "this Wi-Fi network is open"), each with
a remediation hint — not attacks.

## Anonymous SMB probing

The Shares tab probes for guest/anonymous access by default because
world-readable shares are a common, high-impact misconfiguration. This only
*lists* what an unauthenticated user could already see; it never downloads or
alters content.

## Credentials

If you supply SMB credentials (Shares tab), they are passed directly to
`smbclient` for that scan and are **not persisted**. Exported JSON reports do
**not** contain credentials. Be mindful that command arguments can be visible
in the local process list while a scan runs.

## Capabilities & privileges

- `arp-scan` and raw `nmap` scans need `CAP_NET_RAW`. The installer grants this
  with `setcap` so you don't run the whole app as root. If you prefer, run the
  specific scans under `sudo`; otherwise the tool falls back to unprivileged
  methods.
- Run the **application itself as an unprivileged user**. Nothing here requires
  a root UI.

## Reports

Exported reports describe your network in detail (hosts, services, findings).
Treat them as sensitive: store and share them accordingly.
