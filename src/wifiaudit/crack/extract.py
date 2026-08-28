"""Extract crackable material (handshakes + PMKIDs) from a capture.

Pure and deterministic, built on :func:`wifiaudit.capture.pcap.iter_eapol`. The
SSID is not carried in EAPOL frames, so it is supplied by the caller (it is the
PBKDF2 salt) — typically the target's ESSID from scope/discovery.
"""

from __future__ import annotations

from wifiaudit.capture.pcap import iter_eapol
from wifiaudit.crack.models import CrackableHandshake, CrackablePMKID


def extract(data: bytes, ssid: str) -> tuple[list[CrackableHandshake], list[CrackablePMKID]]:
    """Return ``(handshakes, pmkids)`` recoverable from pcap ``data`` for ``ssid``."""
    anonce: dict[tuple[str, str], bytes] = {}
    m2: dict[tuple[str, str], object] = {}
    pmkids: list[CrackablePMKID] = []

    for ef in iter_eapol(data):
        key = (ef.ap, ef.client)
        if ef.msg in (1, 3):
            anonce.setdefault(key, ef.nonce)  # M1/M3 both carry the AP's ANonce
            pmkid = ef.pmkid()
            if pmkid is not None:
                pmkids.append(
                    CrackablePMKID(
                        ssid=ssid,
                        ap_bssid=ef.ap,
                        client_mac=ef.client,
                        pmkid=bytes.fromhex(pmkid),
                    )
                )
        elif ef.msg == 2:
            m2.setdefault(key, ef)  # first M2 per pair is enough

    handshakes: list[CrackableHandshake] = []
    for key, ef in m2.items():
        if key not in anonce:
            continue  # no ANonce source -> not crackable via MIC
        handshakes.append(
            CrackableHandshake(
                ssid=ssid,
                ap_bssid=ef.ap,
                client_mac=ef.client,
                anonce=anonce[key],
                snonce=ef.nonce,
                key_version=ef.key_version,
                mic=ef.mic,
                mic_input=ef.mic_input(),
            )
        )
    return handshakes, pmkids


__all__ = ["extract"]
