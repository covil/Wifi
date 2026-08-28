"""Core services shared by every stage: config, authorization, audit, errors."""

from wifiaudit.core.errors import (
    AuthorizationError,
    BackendError,
    ConfigError,
    ScopeError,
    WifiAuditError,
)

__all__ = [
    "WifiAuditError",
    "ConfigError",
    "AuthorizationError",
    "ScopeError",
    "BackendError",
]
