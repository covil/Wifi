"""The authorization gate and scope matching.

`require_authorization(config)` is the single choke point every stage must pass
through. It refuses to return a usable context unless the engagement is
attested (`authorized = true`), attributable (operator + reference present), and
current (within the optional start/expiry window).

The returned :class:`AuthorizationContext` answers one question for the rest of
the toolkit: *is this specific target in scope?* Active stages (capture/crack)
must treat a ``False`` here as a hard stop.
"""

from __future__ import annotations

import datetime as _dt
import fnmatch
from dataclasses import dataclass

from wifiaudit.core.config import Config, ScopeConfig, normalize_bssid
from wifiaudit.core.errors import AuthorizationError


@dataclass(frozen=True)
class AuthorizationContext:
    """A validated authorization, plus scope-matching for individual targets."""

    operator: str
    reference: str
    scope: ScopeConfig
    organization: str | None = None
    starts: _dt.date | None = None
    expires: _dt.date | None = None

    def is_in_scope(
        self,
        *,
        bssid: str | None = None,
        essid: str | None = None,
        channel: int | None = None,
    ) -> bool:
        """Return True if a target identified by these attributes is authorized.

        Semantics:

        * An empty scope is default-deny — nothing is in scope.
        * Identity match: if BSSIDs and/or ESSIDs are listed, the target must
          match at least one (BSSID exact; ESSID shell-wildcard, case-insensitive).
          If neither identity list is set, identity is unrestricted.
        * Channel restriction: if channels are listed, the target must be on one
          of them. An unknown channel cannot satisfy a channel restriction.
        """
        s = self.scope
        if s.is_empty:
            return False

        if s.bssids or s.essids:
            identity_ok = False
            if bssid is not None and s.bssids:
                try:
                    identity_ok = normalize_bssid(bssid) in s.bssids
                except ValueError:
                    identity_ok = False
            if not identity_ok and essid is not None and s.essids:
                target = essid.lower()
                identity_ok = any(fnmatch.fnmatchcase(target, p.lower()) for p in s.essids)
            if not identity_ok:
                return False

        if s.channels:
            if channel is None:
                return False
            return channel in s.channels

        return True

    def summary(self) -> dict[str, object]:
        """A compact, log-friendly description of who is authorized to do what."""
        return {
            "operator": self.operator,
            "organization": self.organization,
            "reference": self.reference,
            "starts": self.starts.isoformat() if self.starts else None,
            "expires": self.expires.isoformat() if self.expires else None,
            "scope": {
                "bssids": list(self.scope.bssids),
                "essids": list(self.scope.essids),
                "channels": list(self.scope.channels),
            },
        }


def require_authorization(
    config: Config,
    *,
    now: _dt.date | None = None,
) -> AuthorizationContext:
    """Enforce the authorization gate, or raise :class:`AuthorizationError`.

    ``now`` may be supplied (a :class:`datetime.date`) to make window checks
    deterministic in tests; it defaults to today's date.
    """
    a = config.authorization

    if not a.authorized:
        raise AuthorizationError(
            "authorization gate: [authorization] authorized is false. "
            "Set it to true only when you hold written permission to test the "
            "targets in [scope]."
        )
    if not a.operator.strip():
        raise AuthorizationError("authorization gate: [authorization] operator must not be empty.")
    if not a.reference.strip():
        raise AuthorizationError(
            "authorization gate: [authorization] reference must not be empty "
            "(cite the SOW / permission that authorizes this work)."
        )

    today = now if now is not None else _dt.date.today()
    if a.starts is not None and today < a.starts:
        raise AuthorizationError(
            f"authorization gate: authorization does not start until {a.starts.isoformat()} "
            f"(today is {today.isoformat()})."
        )
    if a.expires is not None and today > a.expires:
        raise AuthorizationError(
            f"authorization gate: authorization expired on {a.expires.isoformat()} "
            f"(today is {today.isoformat()}). Renew it before continuing."
        )

    return AuthorizationContext(
        operator=a.operator.strip(),
        reference=a.reference.strip(),
        scope=config.scope,
        organization=a.organization,
        starts=a.starts,
        expires=a.expires,
    )


__all__ = ["AuthorizationContext", "require_authorization"]
