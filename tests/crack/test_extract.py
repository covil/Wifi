"""Tests for pulling crackable material out of a capture."""

from __future__ import annotations

from wifiaudit.crack.extract import extract

AP = "DE:AD:BE:EF:00:01"
STA = "11:22:33:44:55:66"
SSID = "AuditLab-AP1"


def test_extract_handshake_material(make_valid, make_pcap):
    frames = make_valid("secretpass", SSID, AP, STA, handshake=True)
    handshakes, pmkids = extract(make_pcap(frames), SSID)
    assert len(handshakes) == 1
    hs = handshakes[0]
    assert hs.ap_bssid == AP and hs.client_mac == STA
    assert hs.ssid == SSID
    assert hs.key_version == 2
    assert len(hs.anonce) == 32 and len(hs.snonce) == 32
    assert len(hs.mic) == 16
    # MIC field inside the mic_input must be zeroed.
    assert hs.mic_input[81:97] == b"\x00" * 16
    assert pmkids == []


def test_extract_pmkid_material(make_valid, make_pcap):
    frames = make_valid("secretpass", SSID, AP, STA, handshake=False, pmkid=True)
    handshakes, pmkids = extract(make_pcap(frames), SSID)
    assert len(pmkids) == 1
    assert pmkids[0].ap_bssid == AP
    assert len(pmkids[0].pmkid) == 16


def test_m2_without_anonce_is_not_extracted(make_frame, make_pcap):
    # Only an M2 (SNonce) present, no M1/M3 -> no ANonce -> not crackable via MIC.
    frames = [make_frame(2, ap=AP, sta=STA)]
    handshakes, pmkids = extract(make_pcap(frames), SSID)
    assert handshakes == []
