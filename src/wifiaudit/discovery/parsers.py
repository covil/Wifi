"""Pure parsers for wireless enumeration output.

Two formats are supported:

* ``iw dev <iface> scan`` — the standard Linux single-shot scan (APs only).
* ``airodump-ng`` CSV — the ``-w`` capture CSV (APs *and* clients).

These functions take text and return a :class:`ScanResult`. They perform no I/O
and no subprocess calls, so they are fully deterministic and are the main unit
test target for discovery. Backends are thin shells that fetch text and hand it
here.
"""

from __future__ import annotations

import re

from wifiaudit.core.config import normalize_bssid
from wifiaudit.discovery.models import AccessPoint, Client, ScanResult

# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def freq_to_channel(mhz: int | None) -> int | None:
    """Convert a center frequency (MHz) to an 802.11 channel number."""
    if mhz is None:
        return None
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if 5150 <= mhz <= 5895:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:  # 6 GHz (Wi-Fi 6E)
        return (mhz - 5950) // 5
    return None


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(str(value).strip())
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# iw scan
# --------------------------------------------------------------------------- #

_BSS_RE = re.compile(r"^BSS\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
_SIGNAL_RE = re.compile(r"signal:\s*(-?\d+(?:\.\d+)?)\s*dBm")
_FREQ_RE = re.compile(r"freq:\s*(\d+)")
_DS_CHANNEL_RE = re.compile(r"DS Parameter set:\s*channel\s*(\d+)")
_PRIMARY_CHANNEL_RE = re.compile(r"\*?\s*primary channel:\s*(\d+)")


def _classify_iw_security(block: str) -> tuple[str, str | None, str | None]:
    """Return (encryption, cipher, auth) for one iw BSS block of text."""
    has_rsn = re.search(r"^\s*RSN:", block, re.MULTILINE) is not None
    has_wpa = re.search(r"^\s*WPA:", block, re.MULTILINE) is not None
    privacy = "Privacy" in block

    auth_text = block.upper()
    if "SAE" in auth_text:
        auth = "SAE" if "PSK" not in auth_text else "SAE/PSK"
    elif "PSK" in auth_text:
        auth = "PSK"
    elif "802.1X" in auth_text or "IEEE 802.1X" in auth_text:
        auth = "802.1X"
    else:
        auth = None

    cipher = None
    m = re.search(r"Pairwise ciphers:\s*(.+)", block)
    if m:
        tokens = m.group(1).upper()
        if "CCMP" in tokens:
            cipher = "CCMP"
        elif "TKIP" in tokens:
            cipher = "TKIP"

    if has_rsn:
        if "SAE" in auth_text and "PSK" in auth_text:
            enc = "WPA2/WPA3"
        elif "SAE" in auth_text:
            enc = "WPA3"
        elif auth == "802.1X":
            enc = "WPA2-Enterprise"
        else:
            enc = "WPA2"
    elif has_wpa:
        enc = "WPA"
    elif privacy:
        enc = "WEP"
    else:
        enc = "OPEN"
        auth = None
    return enc, cipher, auth


def parse_iw_scan(text: str) -> ScanResult:
    """Parse the output of ``iw dev <iface> scan`` into a :class:`ScanResult`."""
    result = ScanResult(meta={"format": "iw"})
    if not text:
        return result

    lines = text.splitlines()
    # Collect (bssid, block_text) pairs by slicing at each "BSS <mac>" header.
    starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = _BSS_RE.match(line.strip())
        if m:
            starts.append((i, m.group(1)))

    for idx, (line_no, bssid) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        block = "\n".join(lines[line_no:end])

        essid = None
        for bl in block.splitlines():
            s = bl.strip()
            if s.startswith("SSID:"):
                essid = s[len("SSID:"):].strip()
                essid = essid if essid else None
                break

        freq = _to_int(m.group(1)) if (m := _FREQ_RE.search(block)) else None
        channel = None
        if (m := _DS_CHANNEL_RE.search(block)) is not None:
            channel = _to_int(m.group(1))
        elif (m := _PRIMARY_CHANNEL_RE.search(block)) is not None:
            channel = _to_int(m.group(1))
        if channel is None:
            channel = freq_to_channel(freq)

        signal = _to_float(m.group(1)) if (m := _SIGNAL_RE.search(block)) else None
        enc, cipher, auth = _classify_iw_security(block)

        try:
            norm = normalize_bssid(bssid)
        except ValueError:
            norm = bssid.upper()

        result.access_points.append(
            AccessPoint(
                bssid=norm,
                essid=essid,
                channel=channel,
                frequency_mhz=freq,
                signal_dbm=signal,
                encryption=enc,
                cipher=cipher,
                auth=auth,
            )
        )
    return result


# --------------------------------------------------------------------------- #
# airodump-ng CSV
# --------------------------------------------------------------------------- #

_AP_COLUMNS = 15  # BSSID .. Key


def _normalize_privacy(value: str) -> str:
    """Map airodump privacy tokens to our vocabulary."""
    v = value.strip().upper()
    if not v:
        return "UNKNOWN"
    if v in {"OPN", "OPEN"}:
        return "OPEN"
    # airodump separates multiple with spaces, e.g. "WPA2 WPA3"
    return "/".join(v.split())


def parse_airodump_csv(text: str) -> ScanResult:
    """Parse an ``airodump-ng`` CSV (``-w`` output) into a :class:`ScanResult`."""
    result = ScanResult(meta={"format": "airodump-csv"})
    if not text:
        return result

    lines = text.splitlines()
    # The CSV has two sections; the second starts at the "Station MAC" header.
    station_header = None
    for i, line in enumerate(lines):
        if line.strip().lower().startswith("station mac"):
            station_header = i
            break

    ap_lines = lines[1 : (station_header if station_header is not None else len(lines))]
    for raw in ap_lines:
        if not raw.strip():
            continue
        parts = [p.strip() for p in raw.split(",")]
        if len(parts) < 14 or not parts[0]:
            continue
        # ESSID may itself contain commas; collapse the middle back together.
        if len(parts) > _AP_COLUMNS:
            essid = ",".join(parts[13 : len(parts) - 1]).strip()
        else:
            essid = parts[13] if len(parts) > 13 else ""

        try:
            bssid = normalize_bssid(parts[0])
        except ValueError:
            continue

        channel = _to_int(parts[3])
        if channel is not None and channel < 0:
            channel = None
        power = _to_int(parts[8])
        signal = float(power) if (power is not None and power != -1) else None

        result.access_points.append(
            AccessPoint(
                bssid=bssid,
                essid=essid or None,
                channel=channel,
                frequency_mhz=None,
                signal_dbm=signal,
                encryption=_normalize_privacy(parts[5]),
                cipher=(parts[6].strip() or None),
                auth=(parts[7].strip() or None),
                beacons=_to_int(parts[9]),
                first_seen=parts[1] or None,
                last_seen=parts[2] or None,
            )
        )

    if station_header is not None:
        for raw in lines[station_header + 1 :]:
            if not raw.strip():
                continue
            parts = [p.strip() for p in raw.split(",")]
            if len(parts) < 6 or not parts[0]:
                continue
            try:
                mac = normalize_bssid(parts[0])
            except ValueError:
                continue
            assoc = parts[5]
            bssid = None
            if assoc and "not associated" not in assoc.lower():
                try:
                    bssid = normalize_bssid(assoc)
                except ValueError:
                    bssid = None
            power = _to_int(parts[3])
            probes = tuple(p for p in (x.strip() for x in parts[6:]) if p)
            result.clients.append(
                Client(
                    mac=mac,
                    bssid=bssid,
                    signal_dbm=float(power) if (power is not None and power != -1) else None,
                    packets=_to_int(parts[4]),
                    probes=probes,
                    first_seen=parts[1] or None,
                    last_seen=parts[2] or None,
                )
            )
    return result


__all__ = ["freq_to_channel", "parse_iw_scan", "parse_airodump_csv"]
