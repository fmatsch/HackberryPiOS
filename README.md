# HackberryPiOS

**A one-stop network audit toolkit for the HackberryPi CM5**, built as a
keyboard-driven terminal UI optimised for the device's small square display.

Walk into any network you manage — Linux, Windows Active Directory, or mixed —
and get an instant, compact overview plus prioritised recommendations for what
to check or fix next. Everything runs locally on the device; no cloud, no
agents on the targets.

> ⚠️ **Authorised use only.** HackberryPiOS is an administration and defensive
> auditing tool. Run it only against networks and devices you own or are
> explicitly authorised to assess. The security checks are non-intrusive
> (they enumerate and identify; they do not exploit or brute-force).

---

## What it does

| Capability | Tab | Details |
|---|---|---|
| **Local network context** | Home | Interface, IP/CIDR, gateway, DNS, hostname, detected AD domain |
| **Domain Controller checks** | DC/AD | Locate DCs via DNS SRV records, health-check Kerberos/LDAP/SMB/GC, latency |
| **Host discovery** | Hosts | IP + name (rDNS/NetBIOS) + MAC + vendor, via arp-scan → nmap → ARP cache |
| **Port scanning** | Ports | Fast (top ports) or full scan, service/version detection (nmap) |
| **Shared drives (SMB)** | Shares | Enumerate shares per host; flags **anonymous/guest-readable** shares |
| **Printer discovery** | Print | mDNS/Bonjour + IPP/LPD/JetDirect port probes |
| **Security posture** | Sec | SMBv1 / SMB-signing checks, risky services, weak Wi-Fi, aggregated findings |
| **Speed & latency** | Speed | Gateway RTT/jitter/loss, iperf3 LAN throughput, WAN download |
| **Wi-Fi survey** | Wi-Fi | Nearby APs (signal, channel, band, security), current link quality |
| **Health score + actions** | Home | 0–100 score and a prioritised recommendation list |

The **recommendation engine** ties it together: after each scan it re-evaluates
everything gathered so far and tells you, in plain language, what deserves
attention — unreachable DCs, anonymous shares, open Wi-Fi, weak crypto,
unmanaged hosts, congested links, and so on.

---

## Hardware & OS

- **Device:** HackberryPi CM5 (Compute Module 5), 720×720 display, physical keyboard
- **OS:** Raspberry Pi OS (Bookworm or newer), 64-bit recommended
- **Python:** 3.9+ (3.11 ships with current Raspberry Pi OS)

The UI is laid out for a small, roughly square terminal and is fully keyboard
operable — ideal for the HackberryPi's hardware keyboard.

---

## Installation

```bash
git clone https://github.com/fmatsch/HackberryPiOS.git
cd HackberryPiOS
./install.sh
```

> 🌐 **Project website:** <https://fmatsch.github.io/HackberryPiOS/>

`install.sh` will:

1. `apt-get install` the scanning tools (see [Dependencies](#external-tools)).
2. Create a Python virtual environment in `./.venv` and install the app.
3. Grant `cap_net_raw` to `arp-scan`/`nmap` so they can run **without sudo**
   (optional but recommended; it falls back gracefully otherwise).

Skip the system packages with `./install.sh --no-apt` if you manage them
yourself.

### Manual install

```bash
sudo apt-get install -y nmap arp-scan smbclient samba-common-bin \
    avahi-utils iw network-manager iproute2 dnsutils iperf3 curl
python3 -m venv .venv
.venv/bin/pip install -e .
```

---

## Usage

### Terminal UI (default)

```bash
.venv/bin/hackberrypios
```

Add a shortcut to `~/.bashrc`:

```bash
alias hpi='~/HackberryPiOS/.venv/bin/hackberrypios'
```

#### Key bindings

| Key | Action |
|---|---|
| `←`/`→` or click | Switch tabs |
| `r` | Run the current tab's default scan |
| `a` | **Scan all** — full sweep across every capability |
| `d` | Jump to the Home dashboard |
| `Ctrl+R` | Re-read local network info |
| `e` | Export a JSON report to your home directory |
| `q` | Quit |

Typical flow: open the app → it auto-detects your network → press **`a`** for a
full sweep → read the score and recommendations on **Home** → drill into any tab
for detail. Selecting a host on the **Hosts** tab pre-fills the **Ports** and
**Sec** tabs so you can immediately scan it.

### Headless / CLI mode

Great over SSH or for scripted/scheduled audits:

```bash
hackberrypios --cli                       # full sweep, prints score + actions
hackberrypios --cli --domain corp.example.com
hackberrypios --cli --json report.json    # also write a full JSON report
hackberrypios --cli --print-json | jq .   # pipe JSON to other tools
```

---

## External tools

HackberryPiOS delegates the heavy lifting to well-tested CLI tools and parses
their output. Each feature checks for its dependency first and **degrades
gracefully** with a clear message if something is missing.

| Tool | apt package | Used for |
|---|---|---|
| `nmap` | `nmap` | Host discovery, port/service scanning, SMB NSE checks |
| `arp-scan` | `arp-scan` | Fast L2 host discovery with MAC/vendor |
| `smbclient`, `nmblookup` | `smbclient`, `samba-common-bin` | SMB share enumeration, NetBIOS names |
| `avahi-browse` | `avahi-utils` | mDNS/Bonjour printer & service discovery |
| `iw`, `nmcli` | `iw`, `network-manager` | Wi-Fi survey and link quality |
| `ip` | `iproute2` | Interfaces, routes, ARP cache |
| `dig`/`host` | `dnsutils` | AD DC discovery via DNS SRV records |
| `iperf3` | `iperf3` | LAN throughput testing |
| `ping`, `curl` | `iputils-ping`, `curl` | Latency and WAN tests |

The **Home** dashboard surfaces any missing tools so you know what to install.

---

## Architecture

```
hackberrypios/
├── __main__.py          # entry point: TUI (default) + --cli mode
├── app.py               # Textual UI (tabs, workers, dashboard)
├── app.tcss             # styling tuned for the 720×720 display
└── core/                # UI-agnostic scanning logic
    ├── utils.py         # command runner, tool detection, parsers
    ├── netinfo.py       # interfaces / gateway / DNS context
    ├── discovery.py     # host discovery + name resolution
    ├── ports.py         # nmap + pure-Python port scanner
    ├── shares.py        # SMB share enumeration
    ├── dc.py            # Domain Controller location & health
    ├── printers.py      # printer discovery
    ├── wifi.py          # Wi-Fi survey
    ├── speedtest.py     # latency / iperf3 / WAN throughput
    ├── security.py      # findings + severity model
    ├── recommendations.py  # scoring + prioritised advice
    └── state.py         # shared state + scan orchestration + export
```

The **core** package is deliberately decoupled from the UI: every function
returns plain dataclasses, so it can be driven by the Textual UI, the `--cli`
mode, or your own scripts equally well.

See [`docs/`](docs/) for the [usage guide](docs/USAGE.md), the
[architecture notes](docs/ARCHITECTURE.md), and the
[security & legal notes](docs/SECURITY.md).

---

## Permissions

- `arp-scan` and raw `nmap` scans need `CAP_NET_RAW`. `install.sh` grants this
  via `setcap`; otherwise the tool falls back to an unprivileged `nmap -sn`
  ping sweep or the passive ARP cache.
- Wi-Fi scanning works unprivileged through `nmcli`; the `iw` fallback may
  require `sudo`.

---

## License

MIT — see [LICENSE](LICENSE).
