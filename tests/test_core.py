"""Lightweight tests for the UI-agnostic core.

These exercise the pure logic (parsers, scoring, serialisation) without needing
any external network tools, so they run anywhere — including CI and the device.

Run with:  python -m pytest        (or)  python tests/test_core.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile

from hackberrypios.core import baseline, profiles
from hackberrypios.core import recommendations as reco
from hackberrypios.core import discovery, ports, security, shares, utils, wifi
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


def test_profile_roundtrip(tmp_path_dir=None):
    profiles.PROFILE_DIR = tempfile.mkdtemp()
    p = profiles.Profile(name="Acme HQ", domain="acme.local",
                         subnet="10.0.0.0/24", ntp_server="10.0.0.10")
    profiles.save(p)
    assert "Acme HQ" in profiles.list_profiles()
    loaded = profiles.load("Acme HQ")
    assert loaded is not None and loaded.domain == "acme.local"
    assert profiles.delete("Acme HQ")
    assert "Acme HQ" not in profiles.list_profiles()


def test_baseline_diff_detects_changes():
    profiles.PROFILE_DIR = tempfile.mkdtemp()
    H = discovery.Host
    baseline.save("net", [H("10.0.0.5", mac="aa:aa:aa:aa:aa:01", name="pc1"),
                          H("10.0.0.6", mac="aa:aa:aa:aa:aa:02", name="pc2")])
    diff = baseline.compare("net", [
        H("10.0.0.5", mac="aa:aa:aa:aa:aa:01", name="pc1"),   # unchanged
        H("10.0.0.7", mac="aa:aa:aa:aa:aa:99", name="rogue"),  # new
    ])
    assert diff.had_baseline
    assert len(diff.new_hosts) == 1 and diff.new_hosts[0].name == "rogue"
    assert len(diff.missing_hosts) == 1 and diff.missing_hosts[0].name == "pc2"
    assert not diff.clean


def test_baseline_without_prior_is_flagged():
    profiles.PROFILE_DIR = tempfile.mkdtemp()
    diff = baseline.compare("never-saved", [])
    assert diff.had_baseline is False


def test_channel_recommendation():
    sv = wifi.WifiSurvey()
    sv.access_points = [wifi.AccessPoint("a", channel="1"),
                        wifi.AccessPoint("b", channel="1"),
                        wifi.AccessPoint("c", channel="6"),
                        wifi.AccessPoint("d", channel="44")]
    advice = wifi.analyse_channels(sv)
    assert advice.best_24 == 11          # least congested non-overlapping
    assert advice.best_5 == 44


def test_version_cve_hint():
    findings = security.evaluate_versions(
        "1.2.3.4", [ports.OpenPort(port=21, service="ftp", version="vsftpd 2.3.4")])
    assert findings and findings[0].severity == Severity.CRITICAL


def test_baseline_diff_recommendation_penalises_new_hosts():
    a = reco.build(baseline_diff=baseline.BaselineDiff(
        new_hosts=[baseline.BaselineHost("10.0.0.9", "mac", "rogue")]))
    assert a.score < 100
    assert any("new" in r.text.lower() for r in a.top)


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)} test(s) passed.")


if __name__ == "__main__":
    _run_all()
