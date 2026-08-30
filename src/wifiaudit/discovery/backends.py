"""Scan backends: where enumeration text actually comes from.

A backend's only job is to *produce* a :class:`ScanResult`, either by running a
tool or by reading a file. Keeping this behind an interface means:

* the scanner, scope-tagging, and audit logic are identical live or offline;
* tests can inject a trivial fake backend; and
* you can develop on a machine with no wireless adapter by replaying a saved
  ``iw scan`` dump or ``airodump-ng`` CSV via :class:`FileBackend`.
"""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from wifiaudit.core.errors import BackendError
from wifiaudit.discovery.models import ScanResult
from wifiaudit.discovery.parsers import parse_airodump_csv, parse_iw_scan

_PARSERS = {
    "iw": parse_iw_scan,
    "airodump-csv": parse_airodump_csv,
}


class ScanBackend(ABC):
    """Produces a :class:`ScanResult` for one enumeration pass."""

    name: str = "abstract"

    @abstractmethod
    def scan(self, *, iface: str | None = None, seconds: int | None = None) -> ScanResult:
        ...


class IwScanBackend(ScanBackend):
    """Live passive scan via ``iw dev <iface> scan`` (Linux + monitor/managed).

    Requires the ``iw`` binary on PATH and an interface name. A single ``iw``
    scan is a snapshot, so ``seconds`` is used only to bound the subprocess
    timeout, not to dwell.
    """

    name = "iw"

    def __init__(self, *, iw_path: str | None = None) -> None:
        self._iw = iw_path or shutil.which("iw")

    def scan(self, *, iface: str | None = None, seconds: int | None = None) -> ScanResult:
        if not iface:
            raise BackendError("iw backend requires an interface (--iface).")
        if not self._iw:
            raise BackendError(
                "iw backend: the 'iw' binary was not found on PATH. "
                "Install it (Linux) or use --input to replay a saved scan."
            )
        # A scan needs the interface administratively up. It is often left down
        # after 'airmon-ng check kill' or an interrupted capture, so bring it up.
        from wifiaudit.core.iface import ensure_up

        ensure_up(iface)

        timeout = max(seconds or 15, 10) + 10
        try:
            proc = subprocess.run(
                [self._iw, "dev", iface, "scan"],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise BackendError(f"iw backend: could not execute {self._iw!r}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise BackendError(f"iw backend: scan timed out after {timeout}s") from exc
        if proc.returncode != 0:
            err = proc.stderr.strip()
            hint = "On most systems this needs root (sudo)."
            if "Network is down" in err or "-100" in err:
                hint = (
                    f"The interface is down. Bring it up first: "
                    f"'sudo ip link set {iface} up' "
                    "(it is often left down after 'airmon-ng check kill')."
                )
            elif "resource busy" in err.lower() or "-16" in err:
                hint = (
                    "The interface is busy. Free it with 'sudo airmon-ng check kill', "
                    "or pick your external adapter instead of the one serving your connection."
                )
            raise BackendError(
                f"iw backend: 'iw dev {iface} scan' failed (exit {proc.returncode}). "
                f"{hint} stderr: {err}"
            )
        result = parse_iw_scan(proc.stdout)
        result.meta.update({"backend": self.name, "iface": iface})
        return result


class FileBackend(ScanBackend):
    """Offline backend that parses a previously saved scan file.

    ``fmt`` selects the parser: ``"iw"`` or ``"airodump-csv"``.
    """

    name = "file"

    def __init__(self, path: str | Path, fmt: str) -> None:
        self.path = Path(path)
        if fmt not in _PARSERS:
            raise BackendError(
                f"file backend: unknown format {fmt!r}; expected one of "
                f"{', '.join(sorted(_PARSERS))}."
            )
        self.fmt = fmt

    def scan(self, *, iface: str | None = None, seconds: int | None = None) -> ScanResult:
        if not self.path.is_file():
            raise BackendError(f"file backend: input file not found: {self.path}")
        text = self.path.read_text(encoding="utf-8", errors="replace")
        result = _PARSERS[self.fmt](text)
        result.meta.update({"backend": self.name, "source": str(self.path), "format": self.fmt})
        return result


def get_backend(name: str, **opts) -> ScanBackend:
    """Factory used by the CLI/config.

    ``name`` is ``"iw"`` for live scanning, or ``"file"`` with ``path`` and
    ``fmt`` options for offline replay.
    """
    if name == "iw":
        return IwScanBackend(iw_path=opts.get("iw_path"))
    if name == "file":
        try:
            return FileBackend(opts["path"], opts["fmt"])
        except KeyError as exc:
            raise BackendError(f"file backend requires option: {exc}") from exc
    raise BackendError(f"unknown backend: {name!r}")


__all__ = ["ScanBackend", "IwScanBackend", "FileBackend", "get_backend"]
