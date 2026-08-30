"""Best-effort wireless interface management for live runs (Linux).

Kept tiny and behind a context manager so the wizard can set up monitor mode and
*always* restore managed mode afterwards, even on error. This is live-only code
(it shells out to ``ip``/``iw`` and needs root); the offline paths never touch it.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from wifiaudit.core.errors import BackendError

_IW_INTERFACE_RE = re.compile(r"^\s*Interface\s+(\S+)", re.MULTILINE)


def _run(cmd: list[str], *, check: bool) -> None:
    subprocess.run(cmd, check=check, capture_output=True, text=True)


def _parse_iw_dev(text: str) -> list[str]:
    """Extract interface names from ``iw dev`` output (pure, for testing)."""
    return _IW_INTERFACE_RE.findall(text)


def list_wireless_interfaces() -> list[str]:
    """Best-effort list of wireless interface names on this host (Linux).

    Prefers ``iw dev``; falls back to ``/sys/class/net/*/wireless``. Returns an
    empty list when nothing is found or the tools are unavailable (e.g. Windows),
    so callers can fall back to asking the user to type a name.
    """
    names: list[str] = []
    iw = shutil.which("iw")
    if iw:
        try:
            out = subprocess.run(
                [iw, "dev"], capture_output=True, text=True, timeout=5, check=False
            )
            names = _parse_iw_dev(out.stdout)
        except (OSError, subprocess.SubprocessError):
            names = []
    if not names:
        for path in glob.glob("/sys/class/net/*/wireless"):
            names.append(path.split("/")[-2])
    return sorted(dict.fromkeys(names))


@dataclass
class InterfaceInfo:
    """What we can tell the user about a wireless interface, to help them pick."""

    name: str
    phy: str | None = None
    driver: str | None = None
    bus: str | None = None          # "usb", "pci", or None if unknown
    monitor: bool | None = None     # True/False, or None if we couldn't tell

    def label(self) -> str:
        parts = [self.name]
        if self.bus:
            parts.append(f"[{self.bus.upper()}]")
        if self.driver:
            parts.append(f"driver={self.driver}")
        if self.monitor is True:
            parts.append("monitor=yes")
        elif self.monitor is False:
            parts.append("monitor=NO")
        return "  ".join(parts)


def _parse_monitor_support(iw_phy_info: str) -> bool:
    """True if an ``iw phy <phy> info`` dump lists 'monitor' among its modes."""
    lines = iw_phy_info.splitlines()
    in_modes = False
    for line in lines:
        if "Supported interface modes" in line:
            in_modes = True
            continue
        if in_modes:
            stripped = line.strip()
            if stripped.startswith("*"):
                if "monitor" in stripped.lower():
                    return True
            elif stripped and not stripped.startswith("*"):
                break  # left the modes block
    return False


def _read_first_line(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.readline().strip()
    except OSError:
        return None


def _iface_bus(name: str) -> str | None:
    try:
        target = os.path.realpath(f"/sys/class/net/{name}/device")
    except OSError:
        return None
    if "/usb" in target:
        return "usb"
    if "/pci" in target:
        return "pci"
    return None


def _iface_driver(name: str) -> str | None:
    try:
        drv = os.path.realpath(f"/sys/class/net/{name}/device/driver")
    except OSError:
        return None
    base = os.path.basename(drv)
    return base or None


def _iface_monitor(phy_index: str | None) -> bool | None:
    if phy_index is None:
        return None
    iw = shutil.which("iw")
    if not iw:
        return None
    try:
        out = subprocess.run(
            [iw, "phy", f"phy{phy_index}", "info"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return _parse_monitor_support(out.stdout)


def describe_interfaces() -> list[InterfaceInfo]:
    """Return :class:`InterfaceInfo` for each wireless interface (best effort)."""
    infos: list[InterfaceInfo] = []
    for name in list_wireless_interfaces():
        phy_index = _read_first_line(f"/sys/class/net/{name}/phy80211/index")
        infos.append(
            InterfaceInfo(
                name=name,
                phy=(f"phy{phy_index}" if phy_index is not None else None),
                driver=_iface_driver(name),
                bus=_iface_bus(name),
                monitor=_iface_monitor(phy_index),
            )
        )
    return infos


def ensure_up(iface: str) -> None:
    """Best-effort bring ``iface`` administratively up (``ip link set up``).

    A no-op if ``ip`` is missing or the command fails (e.g. not root); callers
    that truly need it up will surface a clearer error on the next operation.
    """
    ip = shutil.which("ip")
    if not ip:
        return
    try:
        subprocess.run([ip, "link", "set", iface, "up"],
                       capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


@contextmanager
def monitor_mode(iface: str) -> Iterator[str]:
    """Put ``iface`` into monitor mode for the duration, then restore managed mode.

    Yields the interface name to use for capture. Requires ``ip`` and ``iw`` on
    PATH and root privileges.
    """
    ip = shutil.which("ip")
    iw = shutil.which("iw")
    if not ip or not iw:
        raise BackendError(
            "monitor mode needs 'ip' and 'iw' on PATH (Linux). "
            "Install them, or run the offline flow with saved files."
        )
    try:
        _run([ip, "link", "set", iface, "down"], check=True)
        _run([iw, "dev", iface, "set", "type", "monitor"], check=True)
        _run([ip, "link", "set", iface, "up"], check=True)
    except subprocess.CalledProcessError as exc:
        raise BackendError(
            f"could not put {iface} into monitor mode (exit {exc.returncode}). "
            "This usually needs root (sudo) and a monitor-capable adapter. "
            f"stderr: {(exc.stderr or '').strip()}"
        ) from exc
    try:
        yield iface
    finally:
        # Best-effort restore; never mask the original error with cleanup noise.
        _run([ip, "link", "set", iface, "down"], check=False)
        _run([iw, "dev", iface, "set", "type", "managed"], check=False)
        _run([ip, "link", "set", iface, "up"], check=False)


__all__ = [
    "monitor_mode",
    "ensure_up",
    "list_wireless_interfaces",
    "describe_interfaces",
    "InterfaceInfo",
]
