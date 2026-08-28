"""Fixtures for capture tests."""

from __future__ import annotations

import pytest

from _pcapgen import build_pcap, eapol_frame


@pytest.fixture
def make_frame():
    return eapol_frame


@pytest.fixture
def make_pcap():
    return build_pcap
