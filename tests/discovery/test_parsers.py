"""Tests for the pure discovery parsers."""

from __future__ import annotations

import pytest

from wifiaudit.discovery.parsers import (
    freq_to_channel,
    parse_airodump_csv,
    parse_iw_scan,
)


@pytest.mark.parametrize(
    "mhz,channel",
    [
        (2412, 1),
        (2437, 6),
        (2462, 11),
        (2472, 13),
        (2484, 14),
        (5180, 36),
        (5955, 1),   # 6 GHz
        (2400, None),
        (9999, None),
        (None, None),
    ],
)
def test_freq_to_channel(mhz, channel):
    assert freq_to_channel(mhz) == channel


def test_parse_iw_scan_counts_and_fields(fixtures_dir):
    text = (fixtures_dir / "iw_scan_sample.txt").read_text(encoding="utf-8")
    result = parse_iw_scan(text)
    assert result.meta["format"] == "iw"
    assert len(result.access_points) == 3
    aps = {ap.bssid: ap for ap in result.access_points}

    ap1 = aps["DE:AD:BE:EF:00:01"]
    assert ap1.essid == "AuditLab-AP1"
    assert ap1.channel == 6
    assert ap1.frequency_mhz == 2437
    assert ap1.signal_dbm == -42.0
    assert ap1.encryption == "WPA2"
    assert ap1.cipher == "CCMP"
    assert ap1.auth == "PSK"

    neighbor = aps["AA:BB:CC:11:22:33"]
    assert neighbor.essid == "NeighborNet"
    assert neighbor.channel == 1
    assert neighbor.encryption == "WPA2"

    openap = aps["02:11:22:33:44:55"]
    assert openap.essid == "OpenCafe"
    assert openap.channel == 11
    assert openap.encryption == "OPEN"
    assert openap.auth is None


def test_parse_iw_scan_empty():
    result = parse_iw_scan("")
    assert result.access_points == []
    assert result.clients == []


def test_parse_iw_scan_channel_from_freq_without_ds():
    text = (
        "BSS 02:00:00:00:00:aa(on wlan0)\n"
        "\tfreq: 2412\n"
        "\tsignal: -50.00 dBm\n"
        "\tSSID: NoDsField\n"
    )
    result = parse_iw_scan(text)
    assert len(result.access_points) == 1
    assert result.access_points[0].channel == 1  # derived from freq


def test_parse_airodump_csv(fixtures_dir):
    text = (fixtures_dir / "airodump_sample.csv").read_text(encoding="utf-8")
    result = parse_airodump_csv(text)
    assert result.meta["format"] == "airodump-csv"
    assert len(result.access_points) == 3
    assert len(result.clients) == 2

    aps = {ap.bssid: ap for ap in result.access_points}
    ap1 = aps["DE:AD:BE:EF:00:01"]
    assert ap1.essid == "AuditLab-AP1"
    assert ap1.channel == 6
    assert ap1.signal_dbm == -42.0
    assert ap1.encryption == "WPA2"
    assert ap1.cipher == "CCMP"
    assert ap1.auth == "PSK"
    assert ap1.beacons == 120

    neighbor = aps["AA:BB:CC:11:22:33"]
    assert neighbor.essid == "NeighborNet"
    assert neighbor.channel == 1

    clients = {c.mac: c for c in result.clients}
    assoc = clients["11:22:33:44:55:66"]
    assert assoc.bssid == "DE:AD:BE:EF:00:01"
    assert assoc.packets == 42
    assert assoc.probes == ("AuditLab-AP1",)

    unassoc = clients["A0:00:11:22:33:44"]
    assert unassoc.bssid is None
    assert unassoc.probes == ("FreeWiFi", "CoffeeShop")


def test_parse_airodump_empty():
    assert parse_airodump_csv("").access_points == []


def test_parse_airodump_open_and_essid_with_comma():
    text = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "00:11:22:33:44:55, t1, t2, 6, 270, OPN, , , -50, 10, 0, 0.0.0.0, 6, My,Net, \n"
    )
    result = parse_airodump_csv(text)
    assert len(result.access_points) == 1
    ap = result.access_points[0]
    assert ap.encryption == "OPEN"
    assert ap.cipher is None
    assert ap.auth is None
    assert ap.essid == "My,Net"


def test_parse_airodump_maps_wpa2_wpa3():
    text = (
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, "
        "Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "00:11:22:33:44:66, t1, t2, 6, 270, WPA2 WPA3, CCMP, SAE, -50, 10, 0, 0.0.0.0, 8, MixedNet, \n"
    )
    ap = parse_airodump_csv(text).access_points[0]
    assert ap.encryption == "WPA2/WPA3"
    assert ap.auth == "SAE"
