"""Shared test fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the shared pcap builder (_pcapgen.py, alongside this file) importable from
# every test directory regardless of pytest's per-dir path insertion.
sys.path.insert(0, str(Path(__file__).parent))

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture
def config_data(tmp_path: Path):
    """A valid, authorized config dict factory.

    Returns a callable so individual tests can override sections. The audit path
    defaults into the test's tmp dir so nothing leaks between tests.
    """

    def _make(**overrides):
        data = {
            "authorization": {
                "authorized": True,
                "operator": "Tester <tester@example.com>",
                "organization": "Example Sec",
                "reference": "TEST-001",
                "expires": "2099-12-31",
            },
            "scope": {"bssids": [], "essids": ["AuditLab-*"], "channels": []},
            "discovery": {"default_iface": "wlan0", "scan_seconds": 5},
            "audit": {"enabled": True, "path": str(tmp_path / "audit.jsonl")},
            "output": {"dir": str(tmp_path / "out")},
        }
        for section, values in overrides.items():
            if isinstance(values, dict) and isinstance(data.get(section), dict):
                data[section] = {**data[section], **values}
            else:
                data[section] = values
        return data

    return _make
