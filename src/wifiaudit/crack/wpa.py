"""Pure WPA/WPA2-PSK cryptographic primitives for offline passphrase testing.

Everything here is standard-library crypto (:func:`hashlib.pbkdf2_hmac`,
:mod:`hmac`) and completely deterministic, so a candidate passphrase can be
verified against a captured handshake or PMKID with no external tools — and the
whole thing is trivially unit-testable.

The chain, for WPA2-PSK:

    PMK   = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 32)
    PTK   = PRF-512(PMK, "Pairwise key expansion",
                    min(APmac,STAmac) | max(APmac,STAmac) |
                    min(ANonce,SNonce) | max(ANonce,SNonce))
    KCK   = PTK[0:16]
    MIC   = HMAC(KCK, eapol_frame_with_mic_zeroed)[0:16]

A candidate is correct when the recomputed MIC equals the captured MIC. The
alternative PMKID path skips the 4-way handshake entirely:

    PMKID = HMAC-SHA1(PMK, "PMK Name" | APmac | STAmac)[0:16]
"""

from __future__ import annotations

import hashlib
import hmac

from wifiaudit.core.errors import CrackError

_PTK_LABEL = b"Pairwise key expansion"
_PMKID_LABEL = b"PMK Name"


def pmk(passphrase: str, ssid: str) -> bytes:
    """Derive the 256-bit Pairwise Master Key from passphrase + SSID."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"), ssid.encode("utf-8"), 4096, 32)


def _prf512(key: bytes, label: bytes, data: bytes) -> bytes:
    out = b""
    i = 0
    while len(out) < 64:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:64]


def ptk(pmk_bytes: bytes, ap_mac: bytes, sta_mac: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """Derive the 512-bit Pairwise Transient Key."""
    data = min(ap_mac, sta_mac) + max(ap_mac, sta_mac) + min(anonce, snonce) + max(anonce, snonce)
    return _prf512(pmk_bytes, _PTK_LABEL, data)


def compute_mic(kck: bytes, mic_input: bytes, key_version: int) -> bytes:
    """Compute the 16-byte EAPOL-Key MIC for the given descriptor version."""
    if key_version == 1:  # WPA / TKIP -> HMAC-MD5
        return hmac.new(kck, mic_input, hashlib.md5).digest()[:16]
    if key_version == 2:  # WPA2 / CCMP -> HMAC-SHA1, truncated
        return hmac.new(kck, mic_input, hashlib.sha1).digest()[:16]
    raise CrackError(
        f"unsupported EAPOL key descriptor version {key_version} "
        "(only 1=HMAC-MD5 and 2=HMAC-SHA1 are supported; "
        "version 3/AES-CMAC would need a CMAC implementation)."
    )


def compute_pmkid(pmk_bytes: bytes, ap_mac: bytes, sta_mac: bytes) -> bytes:
    """Compute the 16-byte RSN PMKID from the PMK and the two MACs."""
    return hmac.new(pmk_bytes, _PMKID_LABEL + ap_mac + sta_mac, hashlib.sha1).digest()[:16]


def verify_handshake(
    candidate: str,
    *,
    ssid: str,
    ap_mac: bytes,
    sta_mac: bytes,
    anonce: bytes,
    snonce: bytes,
    mic: bytes,
    mic_input: bytes,
    key_version: int,
) -> bool:
    """True if ``candidate`` reproduces the captured handshake MIC."""
    kck = ptk(pmk(candidate, ssid), ap_mac, sta_mac, anonce, snonce)[:16]
    return hmac.compare_digest(compute_mic(kck, mic_input, key_version), mic)


def verify_pmkid(
    candidate: str, *, ssid: str, ap_mac: bytes, sta_mac: bytes, pmkid: bytes
) -> bool:
    """True if ``candidate`` reproduces the captured PMKID."""
    return hmac.compare_digest(compute_pmkid(pmk(candidate, ssid), ap_mac, sta_mac), pmkid)


__all__ = [
    "pmk",
    "ptk",
    "compute_mic",
    "compute_pmkid",
    "verify_handshake",
    "verify_pmkid",
]
