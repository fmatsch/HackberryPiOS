"""Throughput and latency tests.

Three independent measurements, each useful on its own:
  * ``latency(host)``     — ping RTT min/avg/max + jitter + loss
  * ``iperf(server)``     — LAN throughput against an iperf3 server you control
  * ``internet_download`` — quick WAN sanity check via an HTTP byte stream

The HTTP test avoids external dependencies; point it at a file you trust.
"""

from __future__ import annotations

import re
import time
import urllib.request
from dataclasses import dataclass

from .utils import have, run


@dataclass
class LatencyResult:
    host: str
    sent: int = 0
    received: int = 0
    loss_pct: float = 0.0
    rtt_min: float | None = None
    rtt_avg: float | None = None
    rtt_max: float | None = None
    jitter: float | None = None
    error: str | None = None

    @property
    def quality(self) -> str:
        if self.error or self.received == 0:
            return "unreachable"
        if (self.rtt_avg or 0) < 5 and self.loss_pct == 0:
            return "excellent"
        if (self.rtt_avg or 0) < 30 and self.loss_pct < 2:
            return "good"
        if (self.rtt_avg or 0) < 100 and self.loss_pct < 5:
            return "fair"
        return "poor"


@dataclass
class ThroughputResult:
    target: str
    mbps: float | None = None
    method: str = ""
    seconds: float = 0.0
    bytes_transferred: int = 0
    error: str | None = None


def latency(host: str, count: int = 10) -> LatencyResult:
    result = LatencyResult(host=host)
    res = run(["ping", "-c", str(count), "-i", "0.2", host],
              timeout=count * 1 + 8)
    if not res.stdout:
        result.error = res.stderr.strip() or "ping failed"
        return result

    tx = re.search(r"(\d+) packets transmitted, (\d+) received", res.stdout)
    if tx:
        result.sent = int(tx.group(1))
        result.received = int(tx.group(2))
    loss = re.search(r"([\d.]+)% packet loss", res.stdout)
    if loss:
        result.loss_pct = float(loss.group(1))
    stats = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)\s*ms", res.stdout)
    if stats:
        result.rtt_min = float(stats.group(1))
        result.rtt_avg = float(stats.group(2))
        result.rtt_max = float(stats.group(3))
        result.jitter = float(stats.group(4))
    if result.received == 0 and not result.error:
        result.error = "100% packet loss"
    return result


def iperf(server: str, *, duration: int = 5, reverse: bool = False) -> ThroughputResult:
    result = ThroughputResult(target=server, method="iperf3")
    if not have("iperf3"):
        result.error = "iperf3 not installed"
        return result
    args = ["iperf3", "-c", server, "-t", str(duration), "-f", "m"]
    if reverse:
        args.append("-R")
    res = run(args, timeout=duration + 15)
    if not res.ok and "iperf3:" in res.stderr:
        result.error = res.stderr.strip().splitlines()[-1]
        return result
    m = re.findall(r"([\d.]+)\s+Mbits/sec\s+.*?(?:receiver|sender)", res.stdout)
    if not m:
        m = re.findall(r"([\d.]+)\s+Mbits/sec", res.stdout)
    if m:
        result.mbps = float(m[-1])
        result.seconds = duration
    else:
        result.error = "could not parse iperf3 output"
    return result


def internet_download(url: str = "https://speed.cloudflare.com/__down?bytes=25000000",
                      *, timeout: int = 30) -> ThroughputResult:
    """Measure WAN download speed by streaming bytes from *url*."""
    result = ThroughputResult(target=url, method="http")
    try:
        start = time.monotonic()
        total = 0
        req = urllib.request.Request(url, headers={"User-Agent": "HackberryPiOS"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if time.monotonic() - start > timeout:
                    break
        elapsed = time.monotonic() - start
        result.seconds = elapsed
        result.bytes_transferred = total
        if elapsed > 0:
            result.mbps = (total * 8) / (elapsed * 1_000_000)
    except Exception as exc:  # network errors are expected & varied
        result.error = str(exc)
    return result
