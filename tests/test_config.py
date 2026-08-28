"""Tests for config loading and validation."""

from __future__ import annotations

import datetime as dt

import pytest

from wifiaudit.core.config import Config, load_config, normalize_bssid
from wifiaudit.core.errors import ConfigError


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("de:ad:be:ef:00:01", "DE:AD:BE:EF:00:01"),
        ("de-ad-be-ef-00-01", "DE:AD:BE:EF:00:01"),
        ("DEADBEEF0001", "DE:AD:BE:EF:00:01"),
        ("de.ad.be.ef.00.01", "DE:AD:BE:EF:00:01"),
    ],
)
def test_normalize_bssid_valid(raw, expected):
    assert normalize_bssid(raw) == expected


@pytest.mark.parametrize("raw", ["", "not-a-mac", "de:ad:be:ef:00", "gg:ad:be:ef:00:01"])
def test_normalize_bssid_invalid(raw):
    with pytest.raises(ValueError):
        normalize_bssid(raw)


def test_load_example_config(repo_root):
    cfg = load_config(repo_root / "config.example.toml")
    assert cfg.authorization.authorized is False  # ships default-deny
    assert cfg.authorization.operator
    assert cfg.scope.essids == ("AuditLab-*",)
    assert cfg.authorization.starts == dt.date(2026, 8, 1)
    assert cfg.authorization.expires == dt.date(2026, 12, 31)
    assert cfg.audit.enabled is True


def test_from_dict_valid(config_data):
    cfg = Config.from_dict(config_data())
    assert cfg.authorization.authorized is True
    assert cfg.authorization.expires == dt.date(2099, 12, 31)
    assert cfg.scope.essids == ("AuditLab-*",)
    assert cfg.scope.is_empty is False


def test_missing_authorization_section():
    with pytest.raises(ConfigError, match="authorization"):
        Config.from_dict({"scope": {}})


def test_missing_required_field(config_data):
    data = config_data()
    del data["authorization"]["reference"]
    with pytest.raises(ConfigError, match="reference"):
        Config.from_dict(data)


def test_bad_bssid_in_scope(config_data):
    data = config_data(scope={"bssids": ["not-a-mac"], "essids": [], "channels": []})
    with pytest.raises(ConfigError, match=r"bssids\[0\]"):
        Config.from_dict(data)


def test_bssid_scope_is_normalized(config_data):
    data = config_data(scope={"bssids": ["de-ad-be-ef-00-01"], "essids": [], "channels": []})
    cfg = Config.from_dict(data)
    assert cfg.scope.bssids == ("DE:AD:BE:EF:00:01",)


def test_bad_date(config_data):
    data = config_data(authorization={"expires": "not-a-date"})
    with pytest.raises(ConfigError, match="expires"):
        Config.from_dict(data)


def test_channels_must_be_ints(config_data):
    data = config_data(scope={"bssids": [], "essids": [], "channels": ["six"]})
    with pytest.raises(ConfigError, match="channels"):
        Config.from_dict(data)


def test_empty_scope_reports_empty(config_data):
    data = config_data(scope={"bssids": [], "essids": [], "channels": []})
    cfg = Config.from_dict(data)
    assert cfg.scope.is_empty is True


def test_load_config_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.toml")
