"""Clock-skew / NTP check.

Active Directory (Kerberos) rejects authentication when a client's clock drifts
more than the allowed skew (5 minutes by default), so a quick offset check
against the DC or an NTP server is a high-value, fast diagnostic.

Implemented with a raw SNTP query over UDP — no external dependency.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

# Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
_NTP_DELTA = 2208988800

# Kerberos default maximum tolerance for computer clock synchronization.
KERBEROS_SKEW_LIMIT = 300.0


@dataclass
class TimeResult:
    host: str
    offset_seconds: float | None = None   # server_time - local_time
    rtt_ms: float | None = None
    error: str | None = None

    @property
    def within_kerberos_skew(self) -> bool:
        return (self.offset_seconds is not None
                and abs(self.offset_seconds) <= KERBEROS_SKEW_LIMIT)

    @property
    def summary(self) -> str:
        if self.error:
            return self.error
        sign = "+" if (self.offset_seconds or 0) >= 0 else "-"
        return f"offset {sign}{abs(self.offset_seconds):.3f}s vs local"


def query(host: str, *, timeout: float = 3.0) -> TimeResult:
    """Query *host* for its time via SNTP and compute the local clock offset."""
    result = TimeResult(host=host)
    packet = b"\x1b" + 47 * b"\0"   # LI=0, VN=3, Mode=3 (client)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        t1 = time.time()
        sock.sendto(packet, (host, 123))
        data, _ = sock.recvfrom(48)
        t4 = time.time()
    except (socket.timeout, OSError) as exc:
        result.error = f"no NTP response from {host}: {exc}"
        return result
    finally:
        sock.close()

    if len(data) < 48:
        result.error = "short NTP response"
        return result

    # Transmit timestamp is at byte offset 40 (seconds + fraction).
    secs, frac = struct.unpack("!II", data[40:48])
    server_time = (secs - _NTP_DELTA) + frac / 2**32
    rtt = t4 - t1
    # Offset estimate accounting for half the round trip.
    result.offset_seconds = server_time - (t1 + rtt / 2)
    result.rtt_ms = rtt * 1000
    return result
