"""The capture orchestrator.

:class:`Capturer` is the seam where a raw :class:`CaptureResult` from a backend
becomes an *authorized, audited* one. Unlike discovery — which is passive and
merely *tags* out-of-scope networks — capture is an **active** stage, so the
scope check here is a hard stop:

1. Authorization is enforced before a capturer can be built
   (:meth:`Capturer.from_config`).
2. The target is checked against the authorization context; an out-of-scope
   target is refused (audited, then :class:`ScopeError`) — the backend is never
   invoked.
3. Deauth is doubly gated: it requires both an explicit ``deauth=True`` request
   *and* ``[capture] allow_deauth = true`` in config.
4. Start / completion / refusal are written to the tamper-evident audit log.
"""

from __future__ import annotations

from wifiaudit.capture.backends import CaptureBackend
from wifiaudit.capture.models import CaptureResult, CaptureTarget
from wifiaudit.core.audit import open_audit
from wifiaudit.core.authorization import AuthorizationContext, require_authorization
from wifiaudit.core.config import Config
from wifiaudit.core.errors import AuthorizationError, ScopeError


class Capturer:
    def __init__(
        self,
        backend: CaptureBackend,
        auth: AuthorizationContext,
        audit,
        *,
        allow_deauth: bool = False,
    ) -> None:
        self.backend = backend
        self.auth = auth
        self.audit = audit
        self.allow_deauth = allow_deauth

    @classmethod
    def from_config(
        cls, config: Config, backend: CaptureBackend, *, now=None,
        allow_deauth: bool | None = None,
    ) -> "Capturer":
        """Build a capturer, enforcing the authorization gate first.

        ``allow_deauth`` overrides ``[capture] allow_deauth`` when given — the
        interactive menu passes ``True`` after an explicit, warned confirmation,
        so a beta user need not edit the config to enable deauth.
        """
        auth = require_authorization(config, now=now)
        audit = open_audit(config, operator=auth.operator, reference=auth.reference)
        ad = config.capture.allow_deauth if allow_deauth is None else allow_deauth
        return cls(backend, auth, audit, allow_deauth=ad)

    def run(
        self,
        target: CaptureTarget,
        *,
        iface: str | None = None,
        seconds: int | None = None,
        deauth: bool = False,
    ) -> CaptureResult:
        target_desc = target.to_dict()

        if not self.auth.is_in_scope(
            bssid=target.bssid, essid=target.essid, channel=target.channel
        ):
            self.audit.log("capture.refused", reason="out_of_scope", target=target_desc)
            raise ScopeError(
                f"capture refused: target {target.bssid} "
                f"(essid={target.essid!r}, channel={target.channel}) is not in the "
                "authorized [scope]. Active stages only ever act on in-scope targets."
            )

        if deauth and not self.allow_deauth:
            self.audit.log("capture.refused", reason="deauth_not_allowed", target=target_desc)
            raise AuthorizationError(
                "capture refused: deauth requested but [capture] allow_deauth is false. "
                "Deauthentication is an active transmission; enable it explicitly only "
                "when your rules of engagement permit it."
            )

        self.audit.log(
            "capture.start",
            backend=self.backend.name,
            iface=iface,
            seconds=seconds,
            deauth=deauth,
            target=target_desc,
        )

        result = self.backend.capture(
            target=target, iface=iface, seconds=seconds, deauth=deauth
        )

        summary = result.summary()
        result.meta.update(
            {
                "operator": self.auth.operator,
                "reference": self.auth.reference,
                **summary,
            }
        )

        self.audit.log(
            "capture.complete",
            backend=self.backend.name,
            iface=iface,
            target=target_desc,
            got_handshake=result.got_handshake,
            got_pmkid=result.got_pmkid,
            capture_path=result.capture_path,
            **summary,
        )
        return result


__all__ = ["Capturer"]
