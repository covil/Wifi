"""Data models for stage 3 (offline cracking).

``Crackable*`` records are the self-contained crypto material extracted from a
capture — enough to test a passphrase, and nothing more. :class:`CrackResult`
is the outcome of a dictionary run against them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", "").replace("-", ""))


@dataclass
class CrackableHandshake:
    """A 4-way-handshake instance reduced to what verifying a passphrase needs."""

    ssid: str
    ap_bssid: str
    client_mac: str
    anonce: bytes
    snonce: bytes
    key_version: int
    mic: bytes
    mic_input: bytes   # EAPOL-Key frame with the MIC field zeroed

    kind = "handshake"

    @property
    def ap_mac(self) -> bytes:
        return _mac_bytes(self.ap_bssid)

    @property
    def sta_mac(self) -> bytes:
        return _mac_bytes(self.client_mac)

    def label(self) -> str:
        return f"handshake {self.ap_bssid} <-> {self.client_mac}"


@dataclass
class CrackablePMKID:
    """A captured RSN PMKID reduced to what verifying a passphrase needs."""

    ssid: str
    ap_bssid: str
    client_mac: str
    pmkid: bytes

    kind = "pmkid"

    @property
    def ap_mac(self) -> bytes:
        return _mac_bytes(self.ap_bssid)

    @property
    def sta_mac(self) -> bytes:
        return _mac_bytes(self.client_mac)

    def label(self) -> str:
        return f"pmkid {self.ap_bssid} <-> {self.client_mac}"


@dataclass
class CrackResult:
    """Outcome of a dictionary run against one target's material."""

    ssid: str
    bssid: str
    cracked: bool = False
    passphrase: str | None = None
    method: str | None = None        # "handshake" or "pmkid"
    matched: str | None = None       # human label of the material that broke
    attempts: int = 0
    candidates: int = 0              # total candidates available in the wordlist
    handshakes: int = 0
    pmkids: int = 0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "cracked": self.cracked,
            "passphrase": self.passphrase,
            "method": self.method,
            "matched": self.matched,
            "attempts": self.attempts,
            "candidates": self.candidates,
            "material": {"handshakes": self.handshakes, "pmkids": self.pmkids},
        }


__all__ = ["CrackableHandshake", "CrackablePMKID", "CrackResult"]
