"""The discovery orchestrator.

`Scanner` is the seam where a raw :class:`ScanResult` from a backend becomes an
*audited, scope-tagged* result:

1. Authorization is enforced before a scanner can even be built (via
   :meth:`Scanner.from_config`).
2. Each observed AP is tagged ``in_scope`` against the authorization context.
   Discovery is passive, so it enumerates everything visible — it does not hide
   out-of-scope networks, it labels them. Active stages are the ones that must
   refuse out-of-scope targets.
3. Start and completion are written to the audit log with counts.
"""

from __future__ import annotations

from wifiaudit.core.audit import open_audit
from wifiaudit.core.authorization import AuthorizationContext, require_authorization
from wifiaudit.core.config import Config
from wifiaudit.discovery.backends import ScanBackend
from wifiaudit.discovery.models import ScanResult


class Scanner:
    def __init__(self, backend: ScanBackend, auth: AuthorizationContext, audit) -> None:
        self.backend = backend
        self.auth = auth
        self.audit = audit

    @classmethod
    def from_config(cls, config: Config, backend: ScanBackend, *, now=None) -> "Scanner":
        """Build a scanner, enforcing the authorization gate first."""
        auth = require_authorization(config, now=now)
        audit = open_audit(config, operator=auth.operator, reference=auth.reference)
        return cls(backend, auth, audit)

    def run(self, *, iface: str | None = None, seconds: int | None = None) -> ScanResult:
        self.audit.log(
            "discovery.scan_start",
            backend=self.backend.name,
            iface=iface,
            seconds=seconds,
            scope=self.auth.summary()["scope"],
        )

        result = self.backend.scan(iface=iface, seconds=seconds)

        for ap in result.access_points:
            ap.in_scope = self.auth.is_in_scope(
                bssid=ap.bssid, essid=ap.essid, channel=ap.channel
            )
        result.sort_by_signal()

        summary = result.summary()
        result.meta.update(
            {
                "operator": self.auth.operator,
                "reference": self.auth.reference,
                "in_scope": summary["in_scope"],
                "out_of_scope": summary["out_of_scope"],
            }
        )

        self.audit.log(
            "discovery.scan_complete",
            backend=self.backend.name,
            iface=iface,
            **summary,
            in_scope_bssids=[ap.bssid for ap in result.in_scope_aps()],
        )
        return result


__all__ = ["Scanner"]
