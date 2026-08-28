"""Tests for the pure WPA crypto primitives against known vectors."""

from __future__ import annotations

import hashlib

import pytest

from wifiaudit.core.errors import CrackError
from wifiaudit.crack import wpa


def test_pmk_is_deterministic_and_32_bytes():
    p1 = wpa.pmk("password123", "AuditLab-AP1")
    p2 = wpa.pmk("password123", "AuditLab-AP1")
    assert p1 == p2
    assert len(p1) == 32
    assert wpa.pmk("password123", "AuditLab-AP1") != wpa.pmk("password124", "AuditLab-AP1")
    assert wpa.pmk("password123", "AuditLab-AP1") != wpa.pmk("password123", "OtherSSID")


def test_pmk_pins_the_pbkdf2_algorithm():
    # PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32). Pin it independently.
    expect = hashlib.pbkdf2_hmac("sha1", b"password", b"IEEE", 4096, 32)
    assert wpa.pmk("password", "IEEE") == expect


def test_pmkid_roundtrip():
    pmk = wpa.pmk("hunter2", "Corp-WiFi")
    ap = bytes.fromhex("DEADBEEF0001")
    sta = bytes.fromhex("112233445566")
    pmkid = wpa.compute_pmkid(pmk, ap, sta)
    assert len(pmkid) == 16
    assert wpa.verify_pmkid("hunter2", ssid="Corp-WiFi", ap_mac=ap, sta_mac=sta, pmkid=pmkid)
    assert not wpa.verify_pmkid("wrongpass", ssid="Corp-WiFi", ap_mac=ap, sta_mac=sta, pmkid=pmkid)


def test_ptk_is_symmetric_in_mac_and_nonce_order():
    pmk = wpa.pmk("abcdefgh", "Net")
    a = bytes.fromhex("AA0000000001")
    b = bytes.fromhex("BB0000000002")
    n1 = b"\x01" * 32
    n2 = b"\x02" * 32
    # Swapping which side is "AP" vs "STA" / which nonce is A vs B must not matter,
    # because the KDF sorts them.
    assert wpa.ptk(pmk, a, b, n1, n2) == wpa.ptk(pmk, b, a, n2, n1)


def test_compute_mic_rejects_unsupported_version():
    with pytest.raises(CrackError):
        wpa.compute_mic(b"\x00" * 16, b"msg", key_version=3)


def test_mic_version_1_and_2_differ():
    kck = b"\x11" * 16
    msg = b"eapol-frame-bytes"
    assert wpa.compute_mic(kck, msg, 1) != wpa.compute_mic(kck, msg, 2)
    assert len(wpa.compute_mic(kck, msg, 1)) == 16
    assert len(wpa.compute_mic(kck, msg, 2)) == 16
