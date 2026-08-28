"""Tests for the tamper-evident audit log."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from wifiaudit.core.audit import (
    GENESIS_HASH,
    AuditLogger,
    NullAuditLogger,
    open_audit,
    read_records,
    verify_chain,
)
from wifiaudit.core.config import Config


class FixedClock:
    """Deterministic, monotonically increasing UTC clock for tests."""

    def __init__(self) -> None:
        self._n = 0

    def __call__(self) -> dt.datetime:
        self._n += 1
        return dt.datetime(2026, 8, 28, 12, 0, self._n, tzinfo=dt.timezone.utc)


def test_log_writes_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(path, operator="op", reference="ref", clock=FixedClock())
    rec = log.log("test.action", foo="bar", count=3)
    assert rec["seq"] == 1
    assert rec["operator"] == "op"
    assert rec["action"] == "test.action"
    assert rec["details"] == {"foo": "bar", "count": 3}
    assert rec["prev_hash"] == GENESIS_HASH
    assert path.is_file()


def test_seq_increments_and_chain_links(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(path, clock=FixedClock())
    r1 = log.log("a")
    r2 = log.log("b")
    r3 = log.log("c")
    assert [r1["seq"], r2["seq"], r3["seq"]] == [1, 2, 3]
    assert r2["prev_hash"] == r1["hash"]
    assert r3["prev_hash"] == r2["hash"]


def test_verify_chain_ok(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(path, clock=FixedClock())
    for i in range(5):
        log.log("event", i=i)
    result = verify_chain(path)
    assert result.ok is True
    assert result.count == 5


def test_verify_detects_content_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(path, clock=FixedClock())
    log.log("a", value=1)
    log.log("b", value=2)
    log.log("c", value=3)

    records = list(read_records(path))
    records[1]["details"]["value"] = 999  # edit a past record, keep its hash
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok is False
    assert result.at_seq == 2
    assert "tampered" in result.error


def test_verify_detects_deleted_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLogger(path, clock=FixedClock())
    log.log("a")
    log.log("b")
    log.log("c")

    records = list(read_records(path))
    del records[1]  # drop seq 2; now seq jumps 1 -> 3
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")

    result = verify_chain(path)
    assert result.ok is False
    assert result.at_seq == 2  # expected seq 2, found 3


def test_logger_resumes_existing_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditLogger(path, clock=FixedClock())
    first.log("a")
    first.log("b")

    # A brand-new logger over the same file must continue the chain.
    second = AuditLogger(path, clock=FixedClock())
    r3 = second.log("c")
    assert r3["seq"] == 3
    assert verify_chain(path).ok is True


def test_null_logger_writes_nothing(tmp_path, config_data):
    data = config_data(audit={"enabled": False, "path": str(tmp_path / "audit.jsonl")})
    logger = open_audit(Config.from_dict(data))
    assert isinstance(logger, NullAuditLogger)
    assert logger.log("a", x=1) is None
    assert not (tmp_path / "audit.jsonl").exists()


def test_open_audit_returns_real_logger(tmp_path, config_data):
    data = config_data(audit={"enabled": True, "path": str(tmp_path / "audit.jsonl")})
    logger = open_audit(Config.from_dict(data), operator="op", reference="ref")
    assert isinstance(logger, AuditLogger)
    logger.log("started")
    assert verify_chain(tmp_path / "audit.jsonl").ok is True


def test_verify_empty_file_is_ok(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("", encoding="utf-8")
    result = verify_chain(path)
    assert result.ok is True
    assert result.count == 0
