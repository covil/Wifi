"""Tests for stage 4: report builder, renderer, and reporter."""

from __future__ import annotations

import datetime as dt

from wifiaudit.core.audit import AuditVerification
from wifiaudit.core.config import Config
from wifiaudit.report.builder import build_report
from wifiaudit.report.render import render_markdown
from wifiaudit.report.reporter import Reporter

AP = "DE:AD:BE:EF:00:01"
GEN_AT = "2026-08-30T12:00:00+00:00"


def _records():
    return [
        {"seq": 1, "ts": "2026-08-28T10:00:00", "action": "discovery.scan_complete",
         "details": {"access_points": 3, "in_scope": 2}},
        {"seq": 2, "ts": "2026-08-28T10:01:00", "action": "capture.complete",
         "details": {"got_handshake": True, "got_pmkid": False,
                     "target": {"bssid": AP, "essid": "AuditLab-AP1"}}},
        {"seq": 3, "ts": "2026-08-28T10:02:00", "action": "crack.complete",
         "details": {"cracked": True, "method": "handshake", "attempts": 3,
                     "target": {"ssid": "AuditLab-AP1", "bssid": AP}}},
    ]


def test_cracked_target_is_a_high_finding(config_data):
    cfg = Config.from_dict(config_data())
    ver = AuditVerification(ok=True, count=3)
    report = build_report(_records(), ver, config=cfg, generated_at=GEN_AT)

    assert len(report.findings) == 1                 # capture folded into the crack
    f = report.findings[0]
    assert f.severity == "high"
    assert AP in f.target
    assert f.evidence == [3]
    assert report.activity == {"scans": 1, "captures": 1, "cracks": 1,
                               "refusals": 0, "records": 3}


def test_captured_not_cracked_is_medium(config_data):
    cfg = Config.from_dict(config_data())
    records = [
        {"seq": 1, "ts": "t", "action": "capture.complete",
         "details": {"got_pmkid": True, "got_handshake": False,
                     "target": {"bssid": AP, "essid": "Net"}}},
    ]
    report = build_report(records, AuditVerification(ok=True, count=1), config=cfg, generated_at=GEN_AT)
    assert len(report.findings) == 1
    assert report.findings[0].severity == "medium"
    assert "PMKID" in report.findings[0].title


def test_no_activity_no_findings(config_data):
    cfg = Config.from_dict(config_data())
    report = build_report([], AuditVerification(ok=True, count=0), config=cfg, generated_at=GEN_AT)
    assert report.findings == []
    md = render_markdown(report)
    assert "No exploitable findings" in md


def test_render_flags_broken_chain(config_data):
    cfg = Config.from_dict(config_data())
    ver = AuditVerification(ok=False, count=2, at_seq=2, error="hash mismatch")
    report = build_report(_records(), ver, config=cfg, generated_at=GEN_AT)
    md = render_markdown(report)
    assert "verification FAILED" in md
    assert "hash mismatch" in md


def test_render_markdown_has_sections_and_severity(config_data):
    cfg = Config.from_dict(config_data())
    report = build_report(_records(), AuditVerification(ok=True, count=3),
                          config=cfg, generated_at=GEN_AT)
    md = render_markdown(report)
    for heading in ("# WiFi Security Assessment Report", "## Findings",
                    "## Recommendations", "## Audit trail integrity"):
        assert heading in md
    assert "[HIGH]" in md
    assert "WPA3" in md  # recommendations present


def test_reporter_writes_markdown_and_json(config_data, tmp_path):
    # Drive a real crack so the audit log has evidence, then report on it.
    from wifiaudit.crack.cracker import Cracker
    from _pcapgen import build_pcap, valid_frames

    cfg = Config.from_dict(
        config_data(scope={"bssids": [AP], "essids": [], "channels": []})
    )
    pcap = build_pcap(valid_frames("Summer2026!", "AuditLab-AP1", AP, "11:22:33:44:55:66"))
    Cracker.from_config(cfg, now=dt.date(2026, 8, 28)).run(
        capture=pcap, wordlist="a\nSummer2026!\n", ssid="AuditLab-AP1", bssid=AP
    )

    report, path = Reporter(cfg).generate(output_path=tmp_path / "r.md")
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "passphrase recovered" in text.lower()
    assert report.audit_ok is True

    report_j, path_j = Reporter(cfg).generate(output_path=tmp_path / "r.json", fmt="json")
    assert path_j.is_file()
    assert '"severity": "high"' in path_j.read_text(encoding="utf-8")
