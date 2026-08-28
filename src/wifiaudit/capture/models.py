"""Data models for stage 2 (handshake / PMKID capture).

Backend-agnostic, mirroring ``discovery.models``: whether a capture came from a
live ``airodump-ng`` run or an offline replay of a saved ``.pcap``, the EAPOL
evidence lands in the same :class:`Handshake` shape.

A "usable" WPA2 handshake for offline cracking needs, at minimum, message 2 of
the 4-way handshake (it carries the client's SNonce and the MIC) plus a source
of the AP's ANonce, which is message 1 or message 3. A captured RSN **PMKID**
(advertised by the AP in message 1) is independently crackable on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CaptureTarget:
    """The single in-scope BSS a capture pass is aimed at."""

    bssid: str
    essid: str | None = None
    channel: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"bssid": self.bssid, "essid": self.essid, "channel": self.channel}


@dataclass
class Handshake:
    """EAPOL evidence observed for one (AP, client) pair."""

    ap_bssid: str
    client_mac: str
    messages: set[int] = field(default_factory=set)  # subset of {1, 2, 3, 4}
    pmkid: str | None = None                          # hex PMKID from M1, if any

    @property
    def is_complete(self) -> bool:
        """True if enough of the 4-way handshake is present to crack WPA2.

        Message 2 (SNonce + MIC) plus an ANonce source (message 1 or 3).
        """
        return 2 in self.messages and (1 in self.messages or 3 in self.messages)

    @property
    def is_crackable(self) -> bool:
        """A full handshake *or* a lone PMKID is crackable material."""
        return self.is_complete or self.pmkid is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ap_bssid": self.ap_bssid,
            "client_mac": self.client_mac,
            "messages": sorted(self.messages),
            "pmkid": self.pmkid,
            "complete": self.is_complete,
            "crackable": self.is_crackable,
        }


@dataclass
class CaptureResult:
    """The full result of one capture pass against a target."""

    target: CaptureTarget
    handshakes: list[Handshake] = field(default_factory=list)
    capture_path: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def complete_handshakes(self) -> list[Handshake]:
        return [h for h in self.handshakes if h.is_complete]

    def pmkid_handshakes(self) -> list[Handshake]:
        return [h for h in self.handshakes if h.pmkid]

    @property
    def got_handshake(self) -> bool:
        return any(h.is_complete for h in self.handshakes)

    @property
    def got_pmkid(self) -> bool:
        return any(h.pmkid for h in self.handshakes)

    @property
    def got_crackable(self) -> bool:
        return any(h.is_crackable for h in self.handshakes)

    def summary(self) -> dict[str, int]:
        return {
            "pairs": len(self.handshakes),
            "complete_handshakes": len(self.complete_handshakes()),
            "pmkids": len(self.pmkid_handshakes()),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "target": self.target.to_dict(),
            "summary": self.summary(),
            "capture_path": self.capture_path,
            "handshakes": [h.to_dict() for h in self.handshakes],
        }


__all__ = ["CaptureTarget", "Handshake", "CaptureResult"]
