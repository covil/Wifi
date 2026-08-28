"""Capture backends: where handshake evidence actually comes from.

Same shape as :mod:`wifiaudit.discovery.backends`. A backend's only job is to
produce a :class:`~wifiaudit.capture.models.CaptureResult` for one target,
either by replaying a saved capture file (offline, no hardware) or by driving a
live tool.

* :class:`ReplayBackend` — analyze an existing ``.pcap``/``.cap``. Pure enough to
  develop and test on any OS with no wireless adapter.
* :class:`AirodumpBackend` — live capture via ``airodump-ng`` (Linux, monitor
  mode), with an optional, explicitly gated ``aireplay-ng`` deauth to speed up a
  handshake. This is the active path and is only exercised on real hardware.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path

from wifiaudit.capture.models import CaptureResult, CaptureTarget
from wifiaudit.capture.pcap import analyze
from wifiaudit.core.config import normalize_bssid
from wifiaudit.core.errors import BackendError


class CaptureBackend(ABC):
    """Produces a :class:`CaptureResult` for one capture pass."""

    name: str = "abstract"

    @abstractmethod
    def capture(
        self,
        *,
        target: CaptureTarget,
        iface: str | None = None,
        seconds: int | None = None,
        deauth: bool = False,
    ) -> CaptureResult:
        ...


def _result_from_pcap(
    data: bytes, target: CaptureTarget, *, path: str | None, backend: str, **meta
) -> CaptureResult:
    """Analyze pcap bytes and keep only handshakes for the target BSSID."""
    handshakes = analyze(data)
    try:
        want = normalize_bssid(target.bssid) if target.bssid else None
    except ValueError:
        want = None
    if want is not None:
        handshakes = [h for h in handshakes if h.ap_bssid.upper() == want]
    result = CaptureResult(target=target, handshakes=handshakes, capture_path=path)
    result.meta.update({"backend": backend, **meta})
    return result


class ReplayBackend(CaptureBackend):
    """Offline backend that analyzes a previously saved capture file."""

    name = "replay"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def capture(self, *, target, iface=None, seconds=None, deauth=False) -> CaptureResult:
        if deauth:
            raise BackendError("replay backend: --deauth is meaningless for offline replay.")
        if not self.path.is_file():
            raise BackendError(f"replay backend: capture file not found: {self.path}")
        data = self.path.read_bytes()
        return _result_from_pcap(
            data, target, path=str(self.path), backend=self.name, source=str(self.path)
        )


class AirodumpBackend(CaptureBackend):
    """Live handshake/PMKID capture via ``airodump-ng`` (+ optional deauth).

    Assumes ``iface`` is already in monitor mode (as discovery assumes the
    interface is up). ``airodump-ng`` runs until the timeout, is then stopped,
    and the ``.cap`` it wrote is analyzed by the same pure parser used offline.
    """

    name = "airodump"

    def __init__(
        self,
        *,
        output_dir: str | Path = "captures",
        airodump_path: str | None = None,
        aireplay_path: str | None = None,
    ) -> None:
        self.output_dir = Path(output_dir)
        self._airodump = airodump_path or shutil.which("airodump-ng")
        self._aireplay = aireplay_path or shutil.which("aireplay-ng")

    def capture(self, *, target, iface=None, seconds=None, deauth=False) -> CaptureResult:
        if not iface:
            raise BackendError("airodump backend requires an interface (--iface).")
        if not self._airodump:
            raise BackendError(
                "airodump backend: 'airodump-ng' was not found on PATH. "
                "Install aircrack-ng (Linux) or use --input to replay a saved capture."
            )
        if deauth and not self._aireplay:
            raise BackendError("airodump backend: --deauth needs 'aireplay-ng' on PATH.")

        self.output_dir.mkdir(parents=True, exist_ok=True)
        prefix = self.output_dir / f"capture_{normalize_bssid(target.bssid).replace(':', '')}"
        duration = max(seconds or 60, 5)

        cmd = [
            self._airodump,
            "--bssid", normalize_bssid(target.bssid),
            "-w", str(prefix),
            "--output-format", "pcap",
            "--write-interval", "1",
        ]
        if target.channel is not None:
            cmd += ["--channel", str(target.channel)]
        cmd.append(iface)

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            if deauth:
                # A short, bounded deauth burst to nudge a client into re-handshaking.
                # Bounded count (never continuous) keeps disruption minimal and auditable.
                dcmd = [self._aireplay, "--deauth", "5", "-a", normalize_bssid(target.bssid)]
                dcmd.append(iface)
                subprocess.run(dcmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            pass  # expected: airodump runs until we stop it
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        cap_file = self._newest_cap(prefix)
        if cap_file is None:
            raise BackendError(
                f"airodump backend: no capture file was produced under {prefix}*.cap "
                "(interface not in monitor mode, or wrong channel?)."
            )
        data = cap_file.read_bytes()
        return _result_from_pcap(
            data, target, path=str(cap_file), backend=self.name,
            iface=iface, seconds=duration, deauth=deauth,
        )

    @staticmethod
    def _newest_cap(prefix: Path) -> Path | None:
        caps = sorted(
            prefix.parent.glob(f"{prefix.name}-*.cap"),
            key=lambda p: p.stat().st_mtime,
        )
        return caps[-1] if caps else None


def get_backend(name: str, **opts) -> CaptureBackend:
    """Factory: ``"replay"`` with ``path``, or ``"airodump"`` for live capture."""
    if name == "replay":
        try:
            return ReplayBackend(opts["path"])
        except KeyError as exc:
            raise BackendError(f"replay backend requires option: {exc}") from exc
    if name in ("airodump", "airodump-ng"):
        return AirodumpBackend(
            output_dir=opts.get("output_dir", "captures"),
            airodump_path=opts.get("airodump_path"),
            aireplay_path=opts.get("aireplay_path"),
        )
    raise BackendError(f"unknown capture backend: {name!r}")


__all__ = ["CaptureBackend", "ReplayBackend", "AirodumpBackend", "get_backend"]
