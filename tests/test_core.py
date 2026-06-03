"""Lightweight tests for the UI-agnostic core.

These exercise the pure logic (parsers, scoring, serialisation) without needing
any external network tools, so they run anywhere — including CI and the device.

Run with:  python -m pytest        (or)  python tests/test_core.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hackberrypios.core import recommendations as reco
from hackberrypios.core import shares, utils, wifi
from hackberrypios.core.security import Severity


def test_mac_and_ip_parsers():
    text = "host 192.168.1.10 at aa:bb:cc:dd:ee:ff via 10.0.0.1"
    assert utils.find_ipv4(text) == ["192.168.1.10", "10.0.0.1"]
    assert utils.find_macs(text) == ["aa:bb:cc:dd:ee:ff"]


def test_target_validation():
    assert utils.valid_target("192.168.1.0/24")
    assert utils.valid_target("10.0.0.5")
    assert utils.valid_target("dc01.corp.example.com")
    assert not utils.valid_target("")
    assert not utils.valid_target("not a host!")


def test_vendor_hint():
    assert "Raspberry Pi" in utils.humanise_mac_vendor("b8:27:eb:00:11:22")
    assert utils.humanise_mac_vendor("ff:ff:ff:00:00:00") == ""


def test_smbclient_table_parser():
    sample = """
        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      World readable
        IPC$            IPC       IPC Service
        HPLaser         Printer   Office printer

        Server               Comment
    """
    parsed = shares._parse_smbclient_list(sample)
    names = {s.name: s.type for s in parsed}
    assert names["public"] == "Disk"
    assert names["IPC$"] == "IPC"
    assert names["HPLaser"] == "Printer"


def test_wifi_security_classification():
    open_ap = wifi.AccessPoint(ssid="Guest", security="Open")
    wep_ap = wifi.AccessPoint(ssid="Old", security="WEP")
    wpa2 = wifi.AccessPoint(ssid="Corp", security="WPA2")
    assert open_ap.is_open and not open_ap.is_weak_crypto
    assert wep_ap.is_weak_crypto
    assert not wpa2.is_open and not wpa2.is_weak_crypto


def test_recommendation_scoring_penalises_issues():
    # Fabricate a couple of result objects with the attributes the engine reads.
    class FakeShareResult:
        def __init__(self):
            self.guest_allowed = True
            self.host = "192.168.1.5"
            self.shares = [shares.Share(name="public", type="Disk",
                                        anonymous=True)]

    healthy = reco.build()
    assert healthy.score == 100

    risky = reco.build(share_results=[FakeShareResult()])
    assert risky.score < 100
    assert any("anonymous" in r.text.lower() for r in risky.top)


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} test(s) passed.")


if __name__ == "__main__":
    _run_all()
