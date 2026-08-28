"""Tests for capture backend selection and pcapng handling."""

from __future__ import annotations

from wifiaudit.capture.backends import (
    AirodumpBackend,
    HcxDumpToolBackend,
    ReplayBackend,
    _hcx_output_flag,
    capture_backend,
)
from wifiaudit.capture.models import CaptureTarget

AP = "DE:AD:BE:EF:00:01"
STA = "11:22:33:44:55:66"


def test_capture_backend_factory_selects_tool():
    assert isinstance(capture_backend("airodump-ng"), AirodumpBackend)
    assert isinstance(capture_backend("hcxdumptool"), HcxDumpToolBackend)
    assert isinstance(capture_backend("hcx"), HcxDumpToolBackend)
    # anything else falls back to airodump
    assert isinstance(capture_backend("something-else"), AirodumpBackend)


def test_monitor_mode_ownership_flags():
    # airodump needs the caller to pre-set monitor mode; hcxdumptool sets up the
    # interface itself and must NOT be pre-set (this was the "shared interface" bug).
    assert capture_backend("airodump-ng").self_manages_monitor is False
    assert capture_backend("hcxdumptool").self_manages_monitor is True


def test_airodump_deauth_interval_has_a_floor():
    b = capture_backend("airodump-ng", deauth_interval=1)  # below the floor
    assert b.deauth_interval >= 3


def test_hcx_output_flag_by_version():
    assert _hcx_output_flag("hcxdumptool 6.2.7") == "-o"
    assert _hcx_output_flag("hcxdumptool 6.3.0") == "-w"
    assert _hcx_output_flag("hcxdumptool 6.3.4-...") == "-w"
    assert _hcx_output_flag("hcxdumptool 7.0.0") == "-w"
    assert _hcx_output_flag("no version here") == "-w"   # safe default


def test_replay_backend_reads_pcapng(tmp_path, make_valid, make_pcapng):
    # A ReplayBackend given an hcxdumptool-style pcapng should analyze it.
    data = make_pcapng(make_valid("pw", "AuditLab-AP1", AP, STA, handshake=False, pmkid=True))
    f = tmp_path / "pmkid.pcapng"
    f.write_bytes(data)
    result = ReplayBackend(f).capture(target=CaptureTarget(bssid=AP))
    assert result.got_pmkid
