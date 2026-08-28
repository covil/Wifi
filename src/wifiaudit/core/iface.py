"""Best-effort wireless interface management for live runs (Linux).

Kept tiny and behind a context manager so the wizard can set up monitor mode and
*always* restore managed mode afterwards, even on error. This is live-only code
(it shells out to ``ip``/``iw`` and needs root); the offline paths never touch it.
"""

from __future__ import annotations

import glob
import re
import shutil
import subprocess
from contextlib import contextmanager
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


__all__ = ["monitor_mode", "list_wireless_interfaces"]
