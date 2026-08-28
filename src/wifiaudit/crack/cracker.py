"""The crack orchestrator.

Offline cracking touches no radio, but it is still an engagement action against
a specific network, so it passes the same boundary as the active stages:

1. Authorization is enforced before a cracker can be built
   (:meth:`Cracker.from_config`).
2. The target (ssid/bssid) must be in scope, or the run is refused (audited,
   then :class:`ScopeError`) — you only crack material you are authorized for.
3. Start / completion / refusal are written to the audit log. The recovered
   passphrase is a secret: the audit log records only *that* a key was found
   (plus method and attempts), never the passphrase itself. The passphrase is
   returned to the caller for display / JSON export.
"""

from __future__ import annotations

from wifiaudit.core.audit import open_audit
from wifiaudit.core.authorization import AuthorizationContext, require_authorization
from wifiaudit.core.config import Config
from wifiaudit.core.errors import CrackError, ScopeError
from wifiaudit.crack.engine import iter_wordlist, search
from wifiaudit.crack.extract import extract
from wifiaudit.crack.models import CrackResult


class Cracker:
    def __init__(self, config: Config, auth: AuthorizationContext, audit) -> None:
        self.config = config
        self.auth = auth
        self.audit = audit

    @classmethod
    def from_config(cls, config: Config, *, now=None) -> "Cracker":
        auth = require_authorization(config, now=now)
        audit = open_audit(config, operator=auth.operator, reference=auth.reference)
        return cls(config, auth, audit)

    def run(
        self,
        *,
        capture: bytes,
        wordlist: str,
        ssid: str,
        bssid: str,
        channel: int | None = None,
    ) -> CrackResult:
        target_desc = {"ssid": ssid, "bssid": bssid, "channel": channel}

        if not self.auth.is_in_scope(bssid=bssid, essid=ssid, channel=channel):
            self.audit.log("crack.refused", reason="out_of_scope", target=target_desc)
            raise ScopeError(
                f"crack refused: target {bssid} (ssid={ssid!r}) is not in the authorized "
                "[scope]. You may only crack material for in-scope targets."
            )

        handshakes, pmkids = extract(capture, ssid)
        # Keep only material for the named target BSSID.
        want = bssid.upper()
        handshakes = [h for h in handshakes if h.ap_bssid.upper() == want]
        pmkids = [p for p in pmkids if p.ap_bssid.upper() == want]

        result = CrackResult(
            ssid=ssid, bssid=bssid, handshakes=len(handshakes), pmkids=len(pmkids)
        )

        if not handshakes and not pmkids:
            self.audit.log("crack.complete", target=target_desc, cracked=False,
                           reason="no_material")
            raise CrackError(
                f"crack: no crackable handshake or PMKID for {bssid} (ssid={ssid!r}) "
                "was found in the capture. Run stage 2 until a handshake is captured."
            )

        self.audit.log(
            "crack.start",
            target=target_desc,
            handshakes=len(handshakes),
            pmkids=len(pmkids),
        )

        candidates = list(iter_wordlist(wordlist))
        result.candidates = len(candidates)
        hit, attempts = search(candidates, handshakes, pmkids)
        result.attempts = attempts

        if hit is not None:
            result.cracked = True
            result.passphrase = hit.passphrase
            result.method = hit.method
            result.matched = hit.matched

        self.audit.log(
            "crack.complete",
            target=target_desc,
            cracked=result.cracked,
            method=result.method,
            attempts=result.attempts,
            candidates=result.candidates,
            passphrase="<redacted>" if result.cracked else None,
        )
        return result


__all__ = ["Cracker"]
