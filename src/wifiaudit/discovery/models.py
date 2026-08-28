"""Data models for discovery results.

Deliberately backend-agnostic: whether an access point came from ``iw scan`` or
an ``airodump-ng`` CSV, it lands in the same :class:`AccessPoint` shape. Fields
are ``None`` when a given backend cannot supply them (e.g. ``iw scan`` has no
client list), which keeps parsers honest about what they actually observed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AccessPoint:
    """A single observed 802.11 access point / BSS."""

    bssid: str
    essid: str | None = None
    channel: int | None = None
    frequency_mhz: int | None = None
    signal_dbm: float | None = None
    encryption: str = "UNKNOWN"          # OPEN / WEP / WPA / WPA2 / WPA3 / ...
    cipher: str | None = None            # CCMP / TKIP / ...
    auth: str | None = None             # PSK / SAE / 802.1X / ...
    beacons: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    in_scope: bool = False              # set by the scanner against the auth context

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "channel": self.channel,
            "frequency_mhz": self.frequency_mhz,
            "signal_dbm": self.signal_dbm,
            "encryption": self.encryption,
            "cipher": self.cipher,
            "auth": self.auth,
            "beacons": self.beacons,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "in_scope": self.in_scope,
        }


@dataclass
class Client:
    """A single observed station/client, optionally associated with a BSSID."""

    mac: str
    bssid: str | None = None            # associated AP, None if unassociated
    signal_dbm: float | None = None
    packets: int | None = None
    probes: tuple[str, ...] = ()        # probed ESSIDs
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "mac": self.mac,
            "bssid": self.bssid,
            "signal_dbm": self.signal_dbm,
            "packets": self.packets,
            "probes": list(self.probes),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class ScanResult:
    """The full result of one enumeration pass."""

    access_points: list[AccessPoint] = field(default_factory=list)
    clients: list[Client] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def in_scope_aps(self) -> list[AccessPoint]:
        return [ap for ap in self.access_points if ap.in_scope]

    def out_of_scope_aps(self) -> list[AccessPoint]:
        return [ap for ap in self.access_points if not ap.in_scope]

    def sort_by_signal(self) -> None:
        """Strongest signal first; unknown signal sorted last. In place."""
        self.access_points.sort(
            key=lambda ap: (ap.signal_dbm is None, -(ap.signal_dbm or 0.0))
        )

    def summary(self) -> dict[str, int]:
        return {
            "access_points": len(self.access_points),
            "clients": len(self.clients),
            "in_scope": len(self.in_scope_aps()),
            "out_of_scope": len(self.out_of_scope_aps()),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "meta": self.meta,
            "summary": self.summary(),
            "access_points": [ap.to_dict() for ap in self.access_points],
            "clients": [c.to_dict() for c in self.clients],
        }


__all__ = ["AccessPoint", "Client", "ScanResult"]
