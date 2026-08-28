"""Typed exception hierarchy for wifiaudit.

A single base (:class:`WifiAuditError`) lets the CLI catch everything we raise
deliberately and turn it into a clean, non-tracebacky exit, while callers that
care about a specific failure mode (bad config vs. missing authorization vs. an
out-of-scope target) can still catch the precise subclass.
"""

from __future__ import annotations


class WifiAuditError(Exception):
    """Base class for all errors raised intentionally by wifiaudit."""


class ConfigError(WifiAuditError):
    """The configuration is missing, malformed, or fails validation."""


class AuthorizationError(WifiAuditError):
    """The authorization gate refused to run (not authorized / expired / incomplete)."""


class ScopeError(WifiAuditError):
    """An operation was attempted against a target outside the authorized scope."""


class BackendError(WifiAuditError):
    """A scan/capture backend failed (tool missing, non-zero exit, bad output)."""


class CrackError(WifiAuditError):
    """Cracking could not proceed (no usable material, unsupported algorithm, ...)."""


__all__ = [
    "WifiAuditError",
    "ConfigError",
    "AuthorizationError",
    "ScopeError",
    "BackendError",
    "CrackError",
]
