"""Best-effort wireless interface management for live runs (Linux).

Kept tiny and behind a context manager so the wizard can set up monitor mode and
*always* restore managed mode afterwards, even on error. This is live-only code
(it shells out to ``ip``/``iw`` and needs root); the offline paths never touch it.
"""

from __future__ import annotations

import shutil
import subprocess
from contextlib import contextmanager
from typing import Iterator

from wifiaudit.core.errors import BackendError


def _run(cmd: list[str], *, check: bool) -> None:
    subprocess.run(cmd, check=check, capture_output=True, text=True)


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


__all__ = ["monitor_mode"]
