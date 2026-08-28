"""Tests for the authorization gate and scope matching."""

from __future__ import annotations

import datetime as dt

import pytest

from wifiaudit.core.authorization import require_authorization
from wifiaudit.core.config import Config
from wifiaudit.core.errors import AuthorizationError


def ctx(config_data, **overrides):
    return require_authorization(
        Config.from_dict(config_data(**overrides)),
        now=dt.date(2026, 8, 28),
    )


def test_gate_passes_when_authorized(config_data):
    c = ctx(config_data)
    assert c.operator.startswith("Tester")
    assert c.reference == "TEST-001"


def test_gate_blocks_when_not_authorized(config_data):
    with pytest.raises(AuthorizationError, match="authorized is false"):
        ctx(config_data, authorization={"authorized": False})


def test_gate_blocks_empty_operator(config_data):
    with pytest.raises(AuthorizationError, match="operator"):
        ctx(config_data, authorization={"operator": "   "})


def test_gate_blocks_empty_reference(config_data):
    with pytest.raises(AuthorizationError, match="reference"):
        ctx(config_data, authorization={"reference": ""})


def test_gate_blocks_expired(config_data):
    with pytest.raises(AuthorizationError, match="expired"):
        ctx(config_data, authorization={"expires": "2026-01-01"})


def test_gate_blocks_before_start(config_data):
    with pytest.raises(AuthorizationError, match="does not start"):
        ctx(config_data, authorization={"starts": "2026-12-01"})


def test_gate_ok_within_window(config_data):
    c = ctx(config_data, authorization={"starts": "2026-08-01", "expires": "2026-12-31"})
    assert c.expires == dt.date(2026, 12, 31)


def test_in_scope_essid_wildcard(config_data):
    c = ctx(config_data)  # scope essids = AuditLab-*
    assert c.is_in_scope(bssid="DE:AD:BE:EF:00:01", essid="AuditLab-AP1") is True
    assert c.is_in_scope(bssid="AA:BB:CC:11:22:33", essid="NeighborNet") is False


def test_in_scope_essid_case_insensitive(config_data):
    c = ctx(config_data)
    assert c.is_in_scope(essid="auditlab-guest") is True


def test_in_scope_bssid_exact(config_data):
    c = ctx(config_data, scope={"bssids": ["de:ad:be:ef:00:01"], "essids": [], "channels": []})
    assert c.is_in_scope(bssid="DE-AD-BE-EF-00-01") is True
    assert c.is_in_scope(bssid="AA:BB:CC:11:22:33") is False


def test_in_scope_channel_restriction(config_data):
    c = ctx(config_data, scope={"bssids": [], "essids": ["AuditLab-*"], "channels": [6]})
    assert c.is_in_scope(essid="AuditLab-AP1", channel=6) is True
    assert c.is_in_scope(essid="AuditLab-AP1", channel=11) is False
    # Unknown channel cannot satisfy a channel restriction.
    assert c.is_in_scope(essid="AuditLab-AP1", channel=None) is False


def test_empty_scope_denies_everything(config_data):
    c = ctx(config_data, scope={"bssids": [], "essids": [], "channels": []})
    assert c.is_in_scope(bssid="DE:AD:BE:EF:00:01", essid="AuditLab-AP1") is False


def test_hidden_ssid_out_of_scope_when_only_essids(config_data):
    c = ctx(config_data)  # only essids scoped
    assert c.is_in_scope(bssid="DE:AD:BE:EF:00:01", essid=None) is False


def test_channels_only_scope_matches_by_channel(config_data):
    c = ctx(config_data, scope={"bssids": [], "essids": [], "channels": [36]})
    assert c.is_in_scope(essid="Anything", channel=36) is True
    assert c.is_in_scope(essid="Anything", channel=6) is False
