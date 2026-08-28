"""Tests for the pure pcap/EAPOL analyzer."""

from __future__ import annotations

import pytest

from wifiaudit.capture.pcap import analyze
from wifiaudit.core.errors import BackendError

AP = "DE:AD:BE:EF:00:01"
STA = "11:22:33:44:55:66"


def test_full_four_way_handshake(make_frame, make_pcap):
    frames = [make_frame(n, ap=AP, sta=STA) for n in (1, 2, 3, 4)]
    hs = analyze(make_pcap(frames))
    assert len(hs) == 1
    h = hs[0]
    assert h.ap_bssid == AP
    assert h.client_mac == STA
    assert h.messages == {1, 2, 3, 4}
    assert h.is_complete
    assert h.is_crackable
    assert h.pmkid is None


def test_m1_m2_is_enough_to_be_complete(make_frame, make_pcap):
    frames = [make_frame(1, ap=AP, sta=STA), make_frame(2, ap=AP, sta=STA)]
    (h,) = analyze(make_pcap(frames))
    assert h.messages == {1, 2}
    assert h.is_complete


def test_m2_m3_is_enough_to_be_complete(make_frame, make_pcap):
    frames = [make_frame(2, ap=AP, sta=STA), make_frame(3, ap=AP, sta=STA)]
    (h,) = analyze(make_pcap(frames))
    assert h.is_complete


def test_lone_m2_is_partial_not_complete(make_frame, make_pcap):
    (h,) = analyze(make_pcap([make_frame(2, ap=AP, sta=STA)]))
    assert h.messages == {2}
    assert not h.is_complete
    assert not h.is_crackable


def test_pmkid_from_m1_is_crackable_without_m2(make_frame, make_pcap):
    pmkid = bytes(range(16))
    frames = [make_frame(1, ap=AP, sta=STA, pmkid=pmkid)]
    (h,) = analyze(make_pcap(frames))
    assert h.messages == {1}
    assert not h.is_complete          # no M2
    assert h.pmkid == pmkid.hex()
    assert h.is_crackable             # ...but the PMKID is


def test_qos_data_frames_are_parsed(make_frame, make_pcap):
    frames = [make_frame(n, ap=AP, sta=STA, qos=True) for n in (1, 2)]
    (h,) = analyze(make_pcap(frames))
    assert h.is_complete


def test_bare_802_11_linktype_no_radiotap(make_frame, make_pcap):
    frames = [make_frame(n, ap=AP, sta=STA) for n in (1, 2)]
    (h,) = analyze(make_pcap(frames, linktype=105))
    assert h.is_complete


def test_separates_distinct_station_pairs(make_frame, make_pcap):
    sta2 = "AA:AA:AA:AA:AA:AA"
    frames = [
        make_frame(1, ap=AP, sta=STA),
        make_frame(2, ap=AP, sta=STA),
        make_frame(1, ap=AP, sta=sta2),  # different client, only M1
    ]
    hs = {h.client_mac: h for h in analyze(make_pcap(frames))}
    assert hs[STA].is_complete
    assert not hs[sta2].is_complete


def test_non_eapol_traffic_is_ignored(make_pcap):
    # A data frame whose LLC ethertype is IPv4 (0x0800), not EAPOL.
    ipv4 = bytes.fromhex("0800")
    frame = (
        b"\x08\x02\x00\x00"
        + bytes.fromhex("112233445566")
        + bytes.fromhex("DEADBEEF0001")
        + bytes.fromhex("DEADBEEF0001")
        + b"\x00\x00"
        + b"\xaa\xaa\x03\x00\x00\x00" + ipv4 + b"payload"
    )
    assert analyze(make_pcap([frame])) == []


def test_empty_capture_yields_nothing(make_pcap):
    assert analyze(make_pcap([])) == []


def test_not_a_pcap_raises():
    with pytest.raises(BackendError):
        analyze(b"this is definitely not a pcap file")
