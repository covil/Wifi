"""Stage 2: targeted handshake / PMKID capture for in-scope networks.

Every capture operation passes through the authorization gate
(:func:`wifiaudit.core.authorization.require_authorization`), **refuses any
target that is not in scope**, gates deauthentication behind an explicit
opt-in, and records start / completion / refusal to the tamper-evident audit
log. See :class:`wifiaudit.capture.capturer.Capturer`.

The heavy lifting of turning captured frames into crackable evidence is a pure,
deterministic parser (:mod:`wifiaudit.capture.pcap`), so the stage can be
developed and tested offline with no wireless adapter by replaying a saved
``.pcap`` via :class:`wifiaudit.capture.backends.ReplayBackend`.
"""

from wifiaudit.capture.backends import (
    AirodumpBackend,
    CaptureBackend,
    ReplayBackend,
    get_backend,
)
from wifiaudit.capture.capturer import Capturer
from wifiaudit.capture.models import CaptureResult, CaptureTarget, Handshake
from wifiaudit.capture.pcap import analyze

__all__ = [
    "CaptureTarget",
    "Handshake",
    "CaptureResult",
    "analyze",
    "CaptureBackend",
    "ReplayBackend",
    "AirodumpBackend",
    "get_backend",
    "Capturer",
]
