"""Dictionary search engine.

Iterates candidate passphrases and tests each against the extracted material.
PMKIDs are cheapest to test (one PMK derivation, no PTK), so they go first. The
PMK for a candidate is derived once per distinct SSID and reused across all
material, since PBKDF2 dominates the cost.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Iterable

from wifiaudit.crack.models import CrackableHandshake, CrackablePMKID
from wifiaudit.crack import wpa


@dataclass
class Hit:
    passphrase: str
    method: str            # "handshake" or "pmkid"
    matched: str           # label of the material that verified
    attempts: int          # candidates tried up to and including the hit


def iter_wordlist(text: str) -> Iterable[str]:
    """Yield candidate passphrases from wordlist text (one per line, blanks skipped)."""
    for line in text.splitlines():
        cand = line.rstrip("\r\n")
        if cand:
            yield cand


def search(
    candidates: Iterable[str],
    handshakes: list[CrackableHandshake],
    pmkids: list[CrackablePMKID],
) -> tuple[Hit | None, int]:
    """Try each candidate; return ``(hit_or_None, attempts_tried)``."""
    ssids = {m.ssid for m in (*handshakes, *pmkids)}
    attempts = 0
    for cand in candidates:
        attempts += 1
        pmks = {ssid: wpa.pmk(cand, ssid) for ssid in ssids}

        for pm in pmkids:
            expected = wpa.compute_pmkid(pmks[pm.ssid], pm.ap_mac, pm.sta_mac)
            if hmac.compare_digest(expected, pm.pmkid):
                return Hit(cand, "pmkid", pm.label(), attempts), attempts

        for hs in handshakes:
            kck = wpa.ptk(pmks[hs.ssid], hs.ap_mac, hs.sta_mac, hs.anonce, hs.snonce)[:16]
            got = wpa.compute_mic(kck, hs.mic_input, hs.key_version)
            if hmac.compare_digest(got, hs.mic):
                return Hit(cand, "handshake", hs.label(), attempts), attempts

    return None, attempts


__all__ = ["Hit", "iter_wordlist", "search"]
