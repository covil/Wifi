"""Synthetic pcap builder for capture/crack tests.

Builds classic-pcap bytes containing radiotap + 802.11 data frames carrying
EAPOL-Key messages, so the pure analyzer and cracker can be tested without real
hardware. ``eapol_frame`` builds structurally-valid frames (fake MIC) for the
stage-2 analyzer; ``valid_frames`` builds a *cryptographically consistent*
handshake/PMKID for a known passphrase, for stage-3 cracking. Test scaffolding,
kept out of the production package on purpose.
"""

from __future__ import annotations

import struct

# EAPOL-Key key-information bits
_PAIRWISE = 0x0008
_INSTALL = 0x0040
_ACK = 0x0080
_MIC = 0x0100
_SECURE = 0x0200
_VER2 = 0x0002  # descriptor version 2 (WPA2 / HMAC-SHA1 MIC)

_LLC_EAPOL = bytes.fromhex("aaaa030000008 88e".replace(" ", ""))


def mac(s: str) -> bytes:
    return bytes.fromhex(s.replace(":", ""))


def _radiotap() -> bytes:
    return struct.pack("<BBHI", 0, 0, 8, 0)  # version 0, pad, length 8, present 0


def _dot11_data(*, to_ds: bool, from_ds: bool, qos: bool, a1: str, a2: str, a3: str, body: bytes) -> bytes:
    b0 = 0x88 if qos else 0x08  # data frame; qos-data subtype 8 -> 0x88
    b1 = (0x01 if to_ds else 0) | (0x02 if from_ds else 0)
    hdr = bytes([b0, b1]) + b"\x00\x00" + mac(a1) + mac(a2) + mac(a3) + b"\x00\x00"
    if qos:
        hdr += b"\x00\x00"
    return hdr + body


def _eapol_key(key_info: int, *, key_data: bytes = b"", nonce: bytes = b"\x11" * 32,
               mic: bytes = b"\x00" * 16) -> bytes:
    kb = bytes([2])                        # descriptor type (RSN)
    kb += struct.pack(">H", key_info)
    kb += struct.pack(">H", 16)            # key length
    kb += b"\x00" * 8                      # replay counter
    kb += nonce                            # 32-byte nonce
    kb += b"\x00" * 16                     # key IV
    kb += b"\x00" * 8                      # key RSC
    kb += b"\x00" * 8                      # key ID
    kb += mic                              # 16-byte MIC
    kb += struct.pack(">H", len(key_data))
    kb += key_data
    return bytes([2, 3]) + struct.pack(">H", len(kb)) + kb  # EAPOL v2, type 3 (Key)


def _pmkid_kde(pmkid: bytes) -> bytes:
    return bytes([0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04]) + pmkid


def eapol_frame(msg: int, *, ap: str, sta: str, pmkid: bytes | None = None, qos: bool = False) -> bytes:
    """Build a structurally-valid 802.11 frame carrying EAPOL message ``msg`` (fake MIC)."""
    rsn_ie = b"\x30\x14" + b"\x00" * 20
    if msg == 1:
        ki = _PAIRWISE | _ACK
        kd = _pmkid_kde(pmkid) if pmkid else b""
        body = _LLC_EAPOL + _eapol_key(ki, key_data=kd, nonce=b"\xa1" * 32)
        return _dot11_data(to_ds=False, from_ds=True, qos=qos, a1=sta, a2=ap, a3=ap, body=body)
    if msg == 2:
        ki = _PAIRWISE | _MIC
        body = _LLC_EAPOL + _eapol_key(ki, key_data=rsn_ie, nonce=b"\x2b" * 32, mic=b"\x22" * 16)
        return _dot11_data(to_ds=True, from_ds=False, qos=qos, a1=ap, a2=sta, a3=ap, body=body)
    if msg == 3:
        ki = _PAIRWISE | _MIC | _ACK | _INSTALL | _SECURE
        body = _LLC_EAPOL + _eapol_key(ki, key_data=rsn_ie, nonce=b"\xa1" * 32, mic=b"\x33" * 16)
        return _dot11_data(to_ds=False, from_ds=True, qos=qos, a1=sta, a2=ap, a3=ap, body=body)
    if msg == 4:
        ki = _PAIRWISE | _MIC | _SECURE
        body = _LLC_EAPOL + _eapol_key(ki, key_data=b"", mic=b"\x44" * 16)
        return _dot11_data(to_ds=True, from_ds=False, qos=qos, a1=ap, a2=sta, a3=ap, body=body)
    raise ValueError(f"bad msg {msg}")


def valid_frames(passphrase: str, ssid: str, ap: str, sta: str, *,
                 handshake: bool = True, pmkid: bool = False) -> list[bytes]:
    """Build a cryptographically consistent handshake/PMKID for ``passphrase``.

    The M2 MIC and any PMKID are computed with the production crypto, so a
    cracker fed ``passphrase`` in its wordlist will recover it.
    """
    from wifiaudit.crack import wpa

    ab, sb = mac(ap), mac(sta)
    anonce = bytes([0xA1]) * 32
    snonce = bytes([0x2B]) * 32
    pmk = wpa.pmk(passphrase, ssid)
    frames: list[bytes] = []

    if pmkid:
        pk = wpa.compute_pmkid(pmk, ab, sb)
        ki = _VER2 | _PAIRWISE | _ACK  # M1
        eap = _eapol_key(ki, key_data=_pmkid_kde(pk), nonce=anonce)
        frames.append(_dot11_data(to_ds=False, from_ds=True, qos=False, a1=sta, a2=ap, a3=ap,
                                  body=_LLC_EAPOL + eap))

    if handshake:
        ki1 = _VER2 | _PAIRWISE | _ACK  # M1 (ANonce, no MIC)
        eap1 = _eapol_key(ki1, key_data=b"", nonce=anonce)
        frames.append(_dot11_data(to_ds=False, from_ds=True, qos=False, a1=sta, a2=ap, a3=ap,
                                  body=_LLC_EAPOL + eap1))

        kck = wpa.ptk(pmk, ab, sb, anonce, snonce)[:16]
        ki2 = _VER2 | _PAIRWISE | _MIC  # M2 (SNonce + MIC)
        rsn = b"\x30\x14" + b"\x00" * 20
        eap2_zero = _eapol_key(ki2, key_data=rsn, nonce=snonce, mic=b"\x00" * 16)
        mic = wpa.compute_mic(kck, eap2_zero, 2)
        eap2 = _eapol_key(ki2, key_data=rsn, nonce=snonce, mic=mic)
        frames.append(_dot11_data(to_ds=True, from_ds=False, qos=False, a1=ap, a2=sta, a3=ap,
                                  body=_LLC_EAPOL + eap2))

    return frames


def build_pcap(frames: list[bytes], *, linktype: int = 127) -> bytes:
    """Wrap 802.11 frames into classic-pcap bytes (radiotap-prefixed if 127)."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for f in frames:
        rec = (_radiotap() + f) if linktype == 127 else f
        out += struct.pack("<IIII", 0, 0, len(rec), len(rec)) + rec
    return out


def _pad4(b: bytes) -> bytes:
    pad = (-len(b)) % 4
    return b + b"\x00" * pad


def build_pcapng(frames: list[bytes], *, linktype: int = 127) -> bytes:
    """Wrap 802.11 frames into little-endian pcapng bytes (as hcxdumptool writes)."""
    # Section Header Block
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    shb = struct.pack("<II", 0x0A0D0D0A, 12 + len(shb_body)) + shb_body
    shb += struct.pack("<I", 12 + len(shb_body))
    # Interface Description Block
    idb_body = struct.pack("<HHI", linktype, 0, 65535)
    idb = struct.pack("<II", 0x00000001, 12 + len(idb_body)) + idb_body
    idb += struct.pack("<I", 12 + len(idb_body))
    out = shb + idb
    for f in frames:
        rec = (_radiotap() + f) if linktype == 127 else f
        payload = _pad4(rec)
        epb_body = struct.pack("<IIIII", 0, 0, 0, len(rec), len(rec)) + payload
        total = 12 + len(epb_body)
        out += struct.pack("<II", 0x00000006, total) + epb_body + struct.pack("<I", total)
    return out
