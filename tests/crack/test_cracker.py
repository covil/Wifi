"""Tests for the Cracker: gate, scope, dictionary recovery, audit redaction."""

from __future__ import annotations

import datetime as dt

import pytest

from wifiaudit.core.audit import read_records, verify_chain
from wifiaudit.core.config import Config
from wifiaudit.core.errors import AuthorizationError, CrackError, ScopeError
from wifiaudit.crack.cracker import Cracker

NOW = dt.date(2026, 8, 28)
AP = "DE:AD:BE:EF:00:01"
OUT = "AA:BB:CC:11:22:33"
STA = "11:22:33:44:55:66"
SSID = "AuditLab-AP1"
PW = "correcthorse"

WORDLIST = "wrong1\nwrong2\n" + PW + "\nwrong3\n"


def _cfg(config_data, **scope):
    s = {"bssids": [AP], "essids": ["AuditLab-*"], "channels": []}
    s.update(scope)
    return Config.from_dict(config_data(scope=s))


def test_requires_authorization(config_data, make_valid, make_pcap):
    cfg = Config.from_dict(config_data(authorization={"authorized": False}))
    with pytest.raises(AuthorizationError):
        Cracker.from_config(cfg, now=NOW)


def test_cracks_handshake_from_wordlist(config_data, make_valid, make_pcap):
    cfg = _cfg(config_data)
    pcap = make_pcap(make_valid(PW, SSID, AP, STA, handshake=True))
    cracker = Cracker.from_config(cfg, now=NOW)

    result = cracker.run(capture=pcap, wordlist=WORDLIST, ssid=SSID, bssid=AP)

    assert result.cracked
    assert result.passphrase == PW
    assert result.method == "handshake"
    assert result.attempts == 3          # found on the 3rd candidate
    assert result.candidates == 4


def test_cracks_via_pmkid(config_data, make_valid, make_pcap):
    cfg = _cfg(config_data)
    pcap = make_pcap(make_valid(PW, SSID, AP, STA, handshake=False, pmkid=True))
    result = Cracker.from_config(cfg, now=NOW).run(
        capture=pcap, wordlist=WORDLIST, ssid=SSID, bssid=AP
    )
    assert result.cracked
    assert result.method == "pmkid"
    assert result.passphrase == PW


def test_wrong_wordlist_does_not_crack(config_data, make_valid, make_pcap):
    cfg = _cfg(config_data)
    pcap = make_pcap(make_valid(PW, SSID, AP, STA, handshake=True))
    result = Cracker.from_config(cfg, now=NOW).run(
        capture=pcap, wordlist="nope1\nnope2\n", ssid=SSID, bssid=AP
    )
    assert not result.cracked
    assert result.passphrase is None
    assert result.attempts == 2


def test_out_of_scope_target_refused(config_data, make_valid, make_pcap):
    cfg = _cfg(config_data, bssids=[AP], essids=[])  # only AP in scope
    pcap = make_pcap(make_valid(PW, "Neighbor", OUT, STA, handshake=True))
    with pytest.raises(ScopeError):
        Cracker.from_config(cfg, now=NOW).run(
            capture=pcap, wordlist=WORDLIST, ssid="Neighbor", bssid=OUT
        )
    records = list(read_records(cfg.audit.path))
    assert records[-1]["action"] == "crack.refused"


def test_no_material_raises(config_data, make_pcap):
    cfg = _cfg(config_data)
    empty = make_pcap([])
    with pytest.raises(CrackError):
        Cracker.from_config(cfg, now=NOW).run(
            capture=empty, wordlist=WORDLIST, ssid=SSID, bssid=AP
        )


def test_audit_records_and_redacts_passphrase(config_data, make_valid, make_pcap):
    cfg = _cfg(config_data)
    pcap = make_pcap(make_valid(PW, SSID, AP, STA, handshake=True))
    Cracker.from_config(cfg, now=NOW).run(capture=pcap, wordlist=WORDLIST, ssid=SSID, bssid=AP)

    records = list(read_records(cfg.audit.path))
    actions = [r["action"] for r in records]
    assert actions == ["crack.start", "crack.complete"]
    complete = records[-1]["details"]
    assert complete["cracked"] is True
    assert complete["passphrase"] == "<redacted>"     # never the real passphrase
    assert PW not in str(records)                      # not anywhere in the log
    assert verify_chain(cfg.audit.path).ok is True


def test_material_filtered_to_target_bssid(config_data, make_valid, make_pcap):
    cfg = _cfg(config_data, bssids=[AP, OUT], essids=[])
    frames = make_valid(PW, SSID, AP, STA, handshake=True)
    frames += make_valid("otherpw", SSID, OUT, STA, handshake=True)
    pcap = make_pcap(frames)
    # Cracking AP with a wordlist that only has AP's passphrase still succeeds,
    # and the OUT material is ignored.
    result = Cracker.from_config(cfg, now=NOW).run(
        capture=pcap, wordlist=WORDLIST, ssid=SSID, bssid=AP
    )
    assert result.cracked and result.handshakes == 1
