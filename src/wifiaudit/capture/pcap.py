"""Pure pcap reader + EAPOL parsing.

Give it the raw bytes of a classic ``.pcap`` file (as written by
``airodump-ng`` / ``hcxdumptool`` / ``tcpdump`` on an 802.11 monitor interface)
and it yields the EAPOL-Key frames it contains, fully parsed. Two views are
built on top of that:

* :func:`analyze` — the stage-2 summary: which 4-way-handshake messages and RSN
  PMKIDs are present, per (AP, client) pair (see :mod:`wifiaudit.capture`).
* :func:`iter_eapol` — the raw crypto material (nonces, MIC, key version, and
  the exact EAPOL-Key frame bytes) that stage 3 needs to test passphrases.

In the spirit of :mod:`wifiaudit.discovery.parsers`, this is a **pure parser**:
no I/O, no external tools, deterministic — and therefore trivially testable. The
messy live capture stays behind a backend.

Only unencrypted EAPOL frames are inspected (handshake frames are not protected);
supported link types are bare 802.11 (105) and radiotap-prefixed 802.11 (127).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

from wifiaudit.capture.models import Handshake
from wifiaudit.core.errors import BackendError

LINKTYPE_IEEE802_11 = 105
LINKTYPE_IEEE802_11_RADIOTAP = 127

# 802.11 Frame Control
_FTYPE_DATA = 2
_SUBTYPE_QOS_BIT = 0x08

# EAPOL-Key key-information bit flags (big-endian value)
_KI_INSTALL = 0x0040
_KI_ACK = 0x0080
_KI_MIC = 0x0100

# Byte offsets inside the EAPOL-Key descriptor body (after the 4-byte EAPOL hdr)
_OFF_NONCE = (13, 45)
_OFF_MIC = (77, 93)

# LLC/SNAP header carrying EAPOL (ethertype 0x888E)
_LLC_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
# RSN PMKID KDE selector: OUI 00-0F-AC, data type 0x04, then 16-byte PMKID
_PMKID_KDE = b"\x00\x0f\xac\x04"


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


@dataclass
class EapolFrame:
    """One parsed EAPOL-Key frame with everything cracking needs."""

    ap: str
    client: str
    msg: int | None            # 4-way message number 1-4, or None if unclassifiable
    key_info: int
    key_version: int           # descriptor version (low 3 bits of key_info)
    nonce: bytes               # 32-byte key nonce (ANonce for M1/M3, SNonce for M2/M4)
    mic: bytes                 # 16-byte key MIC as captured
    key_data: bytes
    eapol_bytes: bytes         # exact EAPOL-Key frame bytes (for MIC recomputation)

    def pmkid(self) -> str | None:
        """RSN PMKID advertised in an M1 key-data field, if present."""
        if self.msg != 1 or not self.key_data:
            return None
        idx = self.key_data.find(_PMKID_KDE)
        if idx != -1 and len(self.key_data) >= idx + 4 + 16:
            candidate = self.key_data[idx + 4 : idx + 20]
            if candidate != b"\x00" * 16:
                return candidate.hex()
        return None

    def mic_input(self) -> bytes:
        """The EAPOL-Key frame with the MIC field zeroed (the HMAC message)."""
        buf = bytearray(self.eapol_bytes)
        start, end = 4 + _OFF_MIC[0], 4 + _OFF_MIC[1]
        buf[start:end] = b"\x00" * (end - start)
        return bytes(buf)


_PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"


def iter_packets(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield ``(linktype, packet_bytes)`` for each record in a classic pcap or pcapng.

    Classic pcap (airodump-ng, tcpdump) and pcapng (hcxdumptool) are both handled,
    dispatched on the file's magic bytes.
    """
    if len(data) < 4:
        raise BackendError("capture: file too short to be a capture")
    if data[:4] == _PCAPNG_SHB:
        yield from _iter_pcapng(data)
        return
    if len(data) < 24:
        raise BackendError("capture: file too short to be a pcap")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise BackendError("capture: not a pcap/pcapng file (bad magic).")
    linktype = struct.unpack(endian + "I", data[20:24])[0]

    off = 24
    n = len(data)
    while off + 16 <= n:
        _ts_sec, _ts_usec, incl, _orig = struct.unpack(endian + "IIII", data[off : off + 16])
        off += 16
        if off + incl > n:
            break  # truncated final record
        yield linktype, data[off : off + incl]
        off += incl


def _iter_pcapng(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield ``(linktype, packet_bytes)`` from a pcapng capture (hcxdumptool)."""
    n = len(data)
    if n < 12:
        raise BackendError("capture: truncated pcapng")
    bom = data[8:12]
    if bom == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif bom == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise BackendError("capture: bad pcapng byte-order magic")

    interfaces: list[int] = []  # linktype per Interface Description Block, in order
    off = 0
    while off + 12 <= n:
        block_type = struct.unpack(endian + "I", data[off : off + 4])[0]
        total_len = struct.unpack(endian + "I", data[off + 4 : off + 8])[0]
        if total_len < 12 or off + total_len > n:
            break
        body = data[off + 8 : off + total_len - 4]
        if block_type == 0x00000001:  # Interface Description Block
            if len(body) >= 2:
                interfaces.append(struct.unpack(endian + "H", body[0:2])[0])
        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                iface_id = struct.unpack(endian + "I", body[0:4])[0]
                cap_len = struct.unpack(endian + "I", body[12:16])[0]
                pkt = body[20 : 20 + cap_len]
                if interfaces:
                    lt = interfaces[iface_id] if iface_id < len(interfaces) else interfaces[0]
                    yield lt, pkt
        elif block_type == 0x00000003:  # Simple Packet Block
            if len(body) >= 4 and interfaces:
                yield interfaces[0], body[4:]
        off += total_len


def _strip_link(linktype: int, pkt: bytes) -> bytes | None:
    """Return the 802.11 frame, stripping a radiotap header if present."""
    if linktype == LINKTYPE_IEEE802_11:
        return pkt
    if linktype == LINKTYPE_IEEE802_11_RADIOTAP:
        if len(pkt) < 4:
            return None
        it_len = struct.unpack("<H", pkt[2:4])[0]  # radiotap length is always little-endian
        return pkt[it_len:] if it_len <= len(pkt) else None
    return None  # unsupported link type


def _classify(key_info: int, key_data_len: int) -> int | None:
    """Map EAPOL-Key key-information bits to a 4-way message number (1-4)."""
    mic = key_info & _KI_MIC
    ack = key_info & _KI_ACK
    install = key_info & _KI_INSTALL
    if ack and not mic:
        return 1
    if mic and ack and install:
        return 3
    if mic and not ack:
        # M2 carries the RSN IE (key data present); M4 has empty key data.
        return 2 if key_data_len > 0 else 4
    return None


def _parse_eapol(frame: bytes) -> EapolFrame | None:
    """Parse one 802.11 frame into an :class:`EapolFrame`, or ``None``."""
    if len(frame) < 24:
        return None
    b0, b1 = frame[0], frame[1]
    if ((b0 >> 2) & 0x3) != _FTYPE_DATA:
        return None
    if b1 & 0x40:  # Protected: encrypted, no plaintext EAPOL
        return None
    subtype = (b0 >> 4) & 0xF
    to_ds = bool(b1 & 0x01)
    from_ds = bool(b1 & 0x02)

    addr1, addr2, addr3 = frame[4:10], frame[10:16], frame[16:22]
    hdrlen = 24
    if to_ds and from_ds:
        hdrlen += 6  # addr4 present (WDS)
    if subtype & _SUBTYPE_QOS_BIT:
        hdrlen += 2  # QoS control

    if to_ds and not from_ds:
        ap, client = addr1, addr2
    elif from_ds and not to_ds:
        ap, client = addr2, addr1
    else:
        ap = addr3
        client = addr2 if addr2 != addr3 else addr1

    if frame[hdrlen : hdrlen + 8] != _LLC_EAPOL:
        return None
    eapol = frame[hdrlen + 8 :]
    if len(eapol) < 4 or eapol[1] != 3:  # EAPOL type 3 = EAPOL-Key
        return None
    eapol_len = struct.unpack(">H", eapol[2:4])[0]
    eapol_frame = eapol[: 4 + eapol_len]

    kb = eapol_frame[4:]
    if len(kb) < 95:
        return None
    key_info = struct.unpack(">H", kb[1:3])[0]
    key_data_len = struct.unpack(">H", kb[93:95])[0]
    key_data = kb[95 : 95 + key_data_len]

    return EapolFrame(
        ap=_mac(ap),
        client=_mac(client),
        msg=_classify(key_info, key_data_len),
        key_info=key_info,
        key_version=key_info & 0x0007,
        nonce=kb[_OFF_NONCE[0] : _OFF_NONCE[1]],
        mic=kb[_OFF_MIC[0] : _OFF_MIC[1]],
        key_data=key_data,
        eapol_bytes=eapol_frame,
    )


def iter_eapol(data: bytes) -> Iterator[EapolFrame]:
    """Yield every parsed EAPOL-Key frame in a capture."""
    for linktype, pkt in iter_packets(data):
        frame = _strip_link(linktype, pkt)
        if frame is None:
            continue
        parsed = _parse_eapol(frame)
        if parsed is not None:
            yield parsed


def analyze(data: bytes) -> list[Handshake]:
    """Summarize a capture into a :class:`Handshake` per (AP, client) pair."""
    table: dict[tuple[str, str], Handshake] = {}
    for ef in iter_eapol(data):
        key = (ef.ap, ef.client)
        hs = table.get(key)
        if hs is None:
            hs = Handshake(ap_bssid=ef.ap, client_mac=ef.client)
            table[key] = hs
        if ef.msg is not None:
            hs.messages.add(ef.msg)
        pmkid = ef.pmkid()
        if pmkid is not None:
            hs.pmkid = pmkid
    return list(table.values())


__all__ = [
    "analyze",
    "iter_eapol",
    "iter_packets",
    "EapolFrame",
    "LINKTYPE_IEEE802_11",
    "LINKTYPE_IEEE802_11_RADIOTAP",
]
