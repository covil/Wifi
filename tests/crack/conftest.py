"""Fixtures for crack tests."""

from __future__ import annotations

import pytest

from _pcapgen import build_pcap, eapol_frame, valid_frames


@pytest.fixture
def make_pcap():
    return build_pcap


@pytest.fixture
def make_frame():
    return eapol_frame


@pytest.fixture
def make_valid():
    return valid_frames
