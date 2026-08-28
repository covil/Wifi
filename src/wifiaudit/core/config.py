"""Configuration loading and validation.

Reads a TOML config (Python 3.11+ stdlib ``tomllib``) into a tree of frozen
dataclasses. Responsibilities are split deliberately:

* **This module** validates *shape and types* — required sections exist, dates
  parse, BSSIDs are well-formed. It succeeds even when ``authorized = false``.
* **authorization.py** validates *semantics* — is the operator actually
  authorized, is the window current, is a target in scope.

Frozen dataclasses give us cheap immutability: config is read once and never
mutated, so no stage can accidentally widen its own scope at runtime.
"""

from __future__ import annotations

import datetime as _dt
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from wifiaudit.core.errors import ConfigError

_HEX = frozenset("0123456789abcdefABCDEF")


def normalize_bssid(value: str) -> str:
    """Normalize a MAC/BSSID to canonical ``AA:BB:CC:DD:EE:FF`` form.

    Accepts common separators (``:``, ``-``, ``.``) or none. Raises
    :class:`ValueError` if the value is not 12 hex digits.
    """
    raw = re.sub(r"[\s:\-.]", "", str(value).strip())
    if len(raw) != 12 or any(c not in _HEX for c in raw):
        raise ValueError(f"invalid BSSID/MAC address: {value!r}")
    raw = raw.upper()
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def _coerce_date(value: Any, field_name: str) -> _dt.date | None:
    """Accept a TOML date/datetime or an ISO ``YYYY-MM-DD`` string."""
    if value is None:
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str):
        try:
            return _dt.date.fromisoformat(value.strip())
        except ValueError as exc:
            raise ConfigError(
                f"[authorization] {field_name}: not a valid ISO date "
                f"(YYYY-MM-DD): {value!r}"
            ) from exc
    raise ConfigError(f"[authorization] {field_name}: expected a date, got {type(value).__name__}")


def _require(section: dict[str, Any], key: str, where: str) -> Any:
    if key not in section:
        raise ConfigError(f"[{where}] missing required key: {key!r}")
    return section[key]


def _as_str(value: Any, where: str, key: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"[{where}] {key}: expected a string, got {type(value).__name__}")
    return value


def _as_str_list(value: Any, where: str, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"[{where}] {key}: expected a list of strings")
    return tuple(value)


def _as_int_list(value: Any, where: str, key: str) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(
        isinstance(v, int) and not isinstance(v, bool) for v in value
    ):
        raise ConfigError(f"[{where}] {key}: expected a list of integers")
    return tuple(value)


@dataclass(frozen=True)
class AuthorizationConfig:
    """The engagement's authorization attestation."""

    authorized: bool
    operator: str
    reference: str
    organization: str | None = None
    starts: _dt.date | None = None
    expires: _dt.date | None = None
    notes: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuthorizationConfig":
        authorized = data.get("authorized", False)
        if not isinstance(authorized, bool):
            raise ConfigError("[authorization] authorized: expected true/false")
        return cls(
            authorized=authorized,
            operator=_as_str(_require(data, "operator", "authorization"), "authorization", "operator"),
            reference=_as_str(_require(data, "reference", "authorization"), "authorization", "reference"),
            organization=(
                _as_str(data["organization"], "authorization", "organization")
                if data.get("organization") is not None
                else None
            ),
            starts=_coerce_date(data.get("starts"), "starts"),
            expires=_coerce_date(data.get("expires"), "expires"),
            notes=(
                _as_str(data["notes"], "authorization", "notes")
                if data.get("notes") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class ScopeConfig:
    """Authorized targets. Empty scope means default-deny (nothing in scope)."""

    bssids: tuple[str, ...] = ()
    essids: tuple[str, ...] = ()
    channels: tuple[int, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.bssids or self.essids or self.channels)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScopeConfig":
        raw_bssids = _as_str_list(data.get("bssids"), "scope", "bssids")
        normalized: list[str] = []
        for i, b in enumerate(raw_bssids):
            try:
                normalized.append(normalize_bssid(b))
            except ValueError as exc:
                raise ConfigError(f"[scope] bssids[{i}]: {exc}") from exc
        return cls(
            bssids=tuple(normalized),
            essids=_as_str_list(data.get("essids"), "scope", "essids"),
            channels=_as_int_list(data.get("channels"), "scope", "channels"),
        )


@dataclass(frozen=True)
class DiscoveryConfig:
    default_backend: str = "iw"
    default_iface: str = "wlan0"
    scan_seconds: int = 15

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DiscoveryConfig":
        seconds = data.get("scan_seconds", 15)
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
            raise ConfigError("[discovery] scan_seconds: expected a positive integer")
        return cls(
            default_backend=_as_str(data.get("default_backend", "iw"), "discovery", "default_backend"),
            default_iface=_as_str(data.get("default_iface", "wlan0"), "discovery", "default_iface"),
            scan_seconds=seconds,
        )


@dataclass(frozen=True)
class CaptureConfig:
    """Stage 2 defaults. ``allow_deauth`` is a hard guard on active transmission."""

    default_iface: str = "wlan0"
    capture_seconds: int = 60
    output_dir: str = "captures"
    tool: str = "airodump-ng"
    allow_deauth: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CaptureConfig":
        seconds = data.get("capture_seconds", 60)
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds <= 0:
            raise ConfigError("[capture] capture_seconds: expected a positive integer")
        allow_deauth = data.get("allow_deauth", False)
        if not isinstance(allow_deauth, bool):
            raise ConfigError("[capture] allow_deauth: expected true/false")
        return cls(
            default_iface=_as_str(data.get("default_iface", "wlan0"), "capture", "default_iface"),
            capture_seconds=seconds,
            output_dir=_as_str(data.get("output_dir", "captures"), "capture", "output_dir"),
            tool=_as_str(data.get("tool", "airodump-ng"), "capture", "tool"),
            allow_deauth=allow_deauth,
        )


@dataclass(frozen=True)
class CrackConfig:
    """Stage 3 defaults. ``wordlist`` is an optional default dictionary path."""

    wordlist: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CrackConfig":
        return cls(wordlist=_as_str(data.get("wordlist", ""), "crack", "wordlist"))


@dataclass(frozen=True)
class AuditConfig:
    enabled: bool = True
    path: str = "audit.log.jsonl"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditConfig":
        enabled = data.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError("[audit] enabled: expected true/false")
        return cls(
            enabled=enabled,
            path=_as_str(data.get("path", "audit.log.jsonl"), "audit", "path"),
        )


@dataclass(frozen=True)
class Config:
    """Top-level configuration."""

    authorization: AuthorizationConfig
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    crack: CrackConfig = field(default_factory=CrackConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    output_dir: str = "output"
    source_path: Path | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, source_path: Path | None = None) -> "Config":
        if not isinstance(data, dict):
            raise ConfigError("config root must be a table")
        if "authorization" not in data:
            raise ConfigError("missing required section: [authorization]")
        if not isinstance(data["authorization"], dict):
            raise ConfigError("[authorization] must be a table")

        output = data.get("output", {})
        if not isinstance(output, dict):
            raise ConfigError("[output] must be a table")

        return cls(
            authorization=AuthorizationConfig.from_dict(data["authorization"]),
            scope=ScopeConfig.from_dict(data.get("scope", {}) or {}),
            discovery=DiscoveryConfig.from_dict(data.get("discovery", {}) or {}),
            capture=CaptureConfig.from_dict(data.get("capture", {}) or {}),
            crack=CrackConfig.from_dict(data.get("crack", {}) or {}),
            audit=AuditConfig.from_dict(data.get("audit", {}) or {}),
            output_dir=_as_str(output.get("dir", "output"), "output", "dir"),
            source_path=source_path,
        )

    @classmethod
    def load(cls, path: str | Path) -> "Config":
        return load_config(path)


def load_config(path: str | Path) -> Config:
    """Load and validate a TOML config file into a :class:`Config`."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        with p.open("rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {p}: {exc}") from exc
    return Config.from_dict(data, source_path=p)


__all__ = [
    "normalize_bssid",
    "AuthorizationConfig",
    "ScopeConfig",
    "DiscoveryConfig",
    "CaptureConfig",
    "CrackConfig",
    "AuditConfig",
    "Config",
    "load_config",
]
