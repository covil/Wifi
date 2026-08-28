"""Tests for the Capturer: gate, hard scope refusal, deauth guard, audit."""

from __future__ import annotations

import datetime as dt

import pytest

from wifiaudit.capture.backends import CaptureBackend, ReplayBackend
from wifiaudit.capture.capturer import Capturer
from wifiaudit.capture.models import CaptureResult, CaptureTarget, Handshake
from wifiaudit.core.audit import read_records, verify_chain
from wifiaudit.core.config import Config
from wifiaudit.core.errors import AuthorizationError, ScopeError

NOW = dt.date(2026, 8, 28)
AP = "DE:AD:BE:EF:00:01"          # matches scope essid AuditLab-* via essid below
OUT = "AA:BB:CC:11:22:33"
STA = "11:22:33:44:55:66"


class FakeBackend(CaptureBackend):
    """Returns a canned result; records what it was asked to do."""

    name = "fake"

    def __init__(self, result: CaptureResult) -> None:
        self._result = result
        self.calls: list[dict] = []

    def capture(self, *, target, iface=None, seconds=None, deauth=False) -> CaptureResult:
        self.calls.append({"target": target, "iface": iface, "seconds": seconds, "deauth": deauth})
        self._result.target = target
        return self._result


def _result_with_handshake(ap=AP, sta=STA) -> CaptureResult:
    h = Handshake(ap_bssid=ap, client_mac=sta, messages={1, 2, 3, 4})
    return CaptureResult(target=CaptureTarget(bssid=ap), handshakes=[h])


def test_requires_authorization(config_data):
    cfg = Config.from_dict(config_data(authorization={"authorized": False}))
    with pytest.raises(AuthorizationError):
        Capturer.from_config(cfg, FakeBackend(_result_with_handshake()), now=NOW)


def test_in_scope_target_captures_and_audits(config_data):
    # scope essids = AuditLab-*, so match by essid
    cfg = Config.from_dict(config_data(scope={"bssids": [AP], "essids": [], "channels": []}))
    backend = FakeBackend(_result_with_handshake())
    capturer = Capturer.from_config(cfg, backend, now=NOW)

    result = capturer.run(CaptureTarget(bssid=AP), seconds=10)

    assert result.got_handshake
    assert len(backend.calls) == 1
    records = list(read_records(cfg.audit.path))
    assert [r["action"] for r in records] == ["capture.start", "capture.complete"]
    assert records[1]["details"]["got_handshake"] is True
    assert verify_chain(cfg.audit.path).ok is True


def test_out_of_scope_target_is_refused_before_backend(config_data):
    cfg = Config.from_dict(config_data(scope={"bssids": [AP], "essids": [], "channels": []}))
    backend = FakeBackend(_result_with_handshake(ap=OUT))
    capturer = Capturer.from_config(cfg, backend, now=NOW)

    with pytest.raises(ScopeError):
        capturer.run(CaptureTarget(bssid=OUT))

    assert backend.calls == []  # backend never invoked
    records = list(read_records(cfg.audit.path))
    assert records[-1]["action"] == "capture.refused"
    assert records[-1]["details"]["reason"] == "out_of_scope"
    assert verify_chain(cfg.audit.path).ok is True


def test_deauth_refused_unless_allowed(config_data):
    cfg = Config.from_dict(
        config_data(
            scope={"bssids": [AP], "essids": [], "channels": []},
            capture={"allow_deauth": False},
        )
    )
    backend = FakeBackend(_result_with_handshake())
    capturer = Capturer.from_config(cfg, backend, now=NOW)

    with pytest.raises(AuthorizationError):
        capturer.run(CaptureTarget(bssid=AP), deauth=True)

    assert backend.calls == []
    records = list(read_records(cfg.audit.path))
    assert records[-1]["details"]["reason"] == "deauth_not_allowed"


def test_deauth_allowed_when_configured(config_data):
    cfg = Config.from_dict(
        config_data(
            scope={"bssids": [AP], "essids": [], "channels": []},
            capture={"allow_deauth": True},
        )
    )
    backend = FakeBackend(_result_with_handshake())
    capturer = Capturer.from_config(cfg, backend, now=NOW)

    capturer.run(CaptureTarget(bssid=AP), deauth=True)
    assert backend.calls[0]["deauth"] is True


def test_replay_backend_end_to_end(config_data, tmp_path, make_frame, make_pcap):
    cfg = Config.from_dict(config_data(scope={"bssids": [AP], "essids": [], "channels": []}))
    pcap = make_pcap([make_frame(n, ap=AP, sta=STA) for n in (1, 2, 3, 4)])
    cap_file = tmp_path / "target.pcap"
    cap_file.write_bytes(pcap)

    capturer = Capturer.from_config(cfg, ReplayBackend(cap_file), now=NOW)
    result = capturer.run(CaptureTarget(bssid=AP))

    assert result.got_handshake
    assert result.summary()["complete_handshakes"] == 1
    assert result.capture_path == str(cap_file)


def test_replay_filters_to_target_bssid(config_data, tmp_path, make_frame, make_pcap):
    # scope both APs so scope isn't what filters; the backend should filter by target.
    cfg = Config.from_dict(config_data(scope={"bssids": [AP, OUT], "essids": [], "channels": []}))
    frames = [make_frame(n, ap=AP, sta=STA) for n in (1, 2)]
    frames += [make_frame(n, ap=OUT, sta=STA) for n in (1, 2)]
    cap_file = tmp_path / "mixed.pcap"
    cap_file.write_bytes(make_pcap(frames))

    result = Capturer.from_config(cfg, ReplayBackend(cap_file), now=NOW).run(CaptureTarget(bssid=AP))
    assert {h.ap_bssid for h in result.handshakes} == {AP}
