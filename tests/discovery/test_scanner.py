"""Tests for the discovery Scanner: gate, scope tagging, sorting, audit."""

from __future__ import annotations

import datetime as dt

import pytest

from wifiaudit.core.audit import read_records, verify_chain
from wifiaudit.core.config import Config
from wifiaudit.core.errors import AuthorizationError
from wifiaudit.discovery.backends import FileBackend, ScanBackend
from wifiaudit.discovery.models import AccessPoint, ScanResult
from wifiaudit.discovery.scanner import Scanner

NOW = dt.date(2026, 8, 28)


class FakeBackend(ScanBackend):
    """Returns a pre-built ScanResult; no I/O."""

    name = "fake"

    def __init__(self, result: ScanResult) -> None:
        self._result = result

    def scan(self, *, iface=None, seconds=None) -> ScanResult:
        return self._result


def test_scanner_tags_scope_from_airodump(config_data, fixtures_dir):
    cfg = Config.from_dict(config_data())  # scope essids = AuditLab-*
    backend = FileBackend(fixtures_dir / "airodump_sample.csv", "airodump-csv")
    scanner = Scanner.from_config(cfg, backend, now=NOW)

    result = scanner.run()

    scoped = {ap.bssid: ap.in_scope for ap in result.access_points}
    assert scoped["DE:AD:BE:EF:00:01"] is True
    assert scoped["DE:AD:BE:EF:00:02"] is True
    assert scoped["AA:BB:CC:11:22:33"] is False
    assert result.summary()["in_scope"] == 2
    assert result.summary()["out_of_scope"] == 1


def test_scanner_sorts_by_signal_desc(config_data, fixtures_dir):
    cfg = Config.from_dict(config_data())
    backend = FileBackend(fixtures_dir / "airodump_sample.csv", "airodump-csv")
    result = Scanner.from_config(cfg, backend, now=NOW).run()
    signals = [ap.signal_dbm for ap in result.access_points]
    assert signals == sorted(signals, reverse=True)
    assert signals[0] == -42.0


def test_scanner_writes_audit_records(config_data, fixtures_dir, tmp_path):
    cfg = Config.from_dict(config_data())
    backend = FileBackend(fixtures_dir / "airodump_sample.csv", "airodump-csv")
    Scanner.from_config(cfg, backend, now=NOW).run()

    records = list(read_records(cfg.audit.path))
    actions = [r["action"] for r in records]
    assert actions == ["discovery.scan_start", "discovery.scan_complete"]
    assert records[1]["details"]["in_scope"] == 2
    assert set(records[1]["details"]["in_scope_bssids"]) == {
        "DE:AD:BE:EF:00:01",
        "DE:AD:BE:EF:00:02",
    }
    assert verify_chain(cfg.audit.path).ok is True


def test_scanner_requires_authorization(config_data, fixtures_dir):
    cfg = Config.from_dict(config_data(authorization={"authorized": False}))
    backend = FileBackend(fixtures_dir / "airodump_sample.csv", "airodump-csv")
    with pytest.raises(AuthorizationError):
        Scanner.from_config(cfg, backend, now=NOW)


def test_scanner_bssid_and_channel_scope(config_data):
    cfg = Config.from_dict(
        config_data(scope={"bssids": ["DE:AD:BE:EF:00:01"], "essids": [], "channels": [6]})
    )
    result = ScanResult(
        access_points=[
            AccessPoint(bssid="DE:AD:BE:EF:00:01", essid="X", channel=6, signal_dbm=-40),
            AccessPoint(bssid="DE:AD:BE:EF:00:01", essid="X", channel=11, signal_dbm=-50),
            AccessPoint(bssid="AA:BB:CC:11:22:33", essid="Y", channel=6, signal_dbm=-60),
        ]
    )
    scanner = Scanner.from_config(cfg, FakeBackend(result), now=NOW)
    out = scanner.run()
    tagged = {(ap.bssid, ap.channel): ap.in_scope for ap in out.access_points}
    assert tagged[("DE:AD:BE:EF:00:01", 6)] is True
    assert tagged[("DE:AD:BE:EF:00:01", 11)] is False  # right BSSID, wrong channel
    assert tagged[("AA:BB:CC:11:22:33", 6)] is False   # right channel, wrong BSSID


def test_scanner_empty_scope_runs_but_tags_none(config_data, fixtures_dir):
    cfg = Config.from_dict(
        config_data(scope={"bssids": [], "essids": [], "channels": []})
    )
    backend = FileBackend(fixtures_dir / "airodump_sample.csv", "airodump-csv")
    result = Scanner.from_config(cfg, backend, now=NOW).run()
    assert result.summary()["in_scope"] == 0
    assert len(result.access_points) == 3  # still enumerates everything
    assert verify_chain(cfg.audit.path).ok is True
