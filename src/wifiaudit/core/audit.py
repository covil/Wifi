"""Tamper-evident, append-only audit logging.

Each engagement action is appended to a JSONL file as one record. Records form a
**hash chain**: every record stores the SHA-256 of the previous record in its
``prev_hash`` field, and its own ``hash`` covers all of its content including
that link. Consequently any later edit, insertion, deletion, or reordering of a
past record invalidates every hash from that point on — which
:func:`verify_chain` detects.

This is tamper-*evidence*, not tamper-*proofing*: someone who can rewrite the
whole file can recompute a consistent chain. For stronger guarantees, ship the
log's head hash somewhere append-only/external. The chain still makes accidental
corruption and casual editing obvious.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

GENESIS_HASH = "0" * 64

# Fields that participate in the hash, in a fixed conceptual set. We sort keys at
# serialization time, so the exact ordering here is not load-bearing — but the
# *set* of fields is: `hash` itself is excluded (it is the output).
_HASHED_FIELDS = ("seq", "ts", "operator", "reference", "action", "details", "prev_hash")


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _canonical(record: dict[str, Any]) -> bytes:
    """Deterministic serialization of the hashed portion of a record."""
    payload = {k: record[k] for k in _HASHED_FIELDS}
    return json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def _hash_record(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record)).hexdigest()


@dataclass(frozen=True)
class AuditVerification:
    """Result of walking an audit chain end to end."""

    ok: bool
    count: int
    error: str | None = None
    at_seq: int | None = None


class AuditLogger:
    """Append records to a hash-chained JSONL file.

    Parameters
    ----------
    path:
        Destination file. Parent directories are created as needed.
    operator, reference:
        Stamped onto every record for attribution (typically from the
        authorization context).
    clock:
        Callable returning a timezone-aware ``datetime``; injectable for tests.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        operator: str = "",
        reference: str = "",
        clock: Callable[[], _dt.datetime] = _utcnow,
    ) -> None:
        self.path = Path(path)
        self.operator = operator
        self.reference = reference
        self._clock = clock
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev_hash = self._resume()

    @property
    def enabled(self) -> bool:
        return True

    def _resume(self) -> tuple[int, str]:
        """Pick up the chain from the last existing record, if any."""
        if not self.path.is_file():
            return 0, GENESIS_HASH
        last: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last is None:
            return 0, GENESIS_HASH
        return int(last["seq"]), str(last["hash"])

    def log(self, action: str, **details: Any) -> dict[str, Any]:
        """Append one record and return it. Thread-safe."""
        with self._lock:
            seq = self._seq + 1
            record: dict[str, Any] = {
                "seq": seq,
                "ts": self._clock().isoformat(),
                "operator": self.operator,
                "reference": self.reference,
                "action": action,
                "details": details,
                "prev_hash": self._prev_hash,
            }
            record["hash"] = _hash_record(record)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
            self._seq = seq
            self._prev_hash = record["hash"]
            return record


class NullAuditLogger:
    """No-op logger used when auditing is disabled in config.

    Accepting the same ``log`` interface lets callers stay oblivious to whether
    auditing is on. Disabling the audit log is discouraged for real engagements.
    """

    enabled = False

    def log(self, action: str, **details: Any) -> None:  # noqa: D401 - interface parity
        return None


def open_audit(
    config,
    *,
    operator: str = "",
    reference: str = "",
    clock: Callable[[], _dt.datetime] = _utcnow,
):
    """Return an :class:`AuditLogger` or :class:`NullAuditLogger` per config."""
    if not config.audit.enabled:
        return NullAuditLogger()
    return AuditLogger(
        config.audit.path,
        operator=operator,
        reference=reference,
        clock=clock,
    )


def read_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield each audit record in file order."""
    p = Path(path)
    if not p.is_file():
        return
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def verify_chain(path: str | Path) -> AuditVerification:
    """Recompute the chain end to end and report the first inconsistency."""
    prev = GENESIS_HASH
    count = 0
    for expected_seq, record in enumerate(read_records(path), start=1):
        count += 1
        if int(record.get("seq", -1)) != expected_seq:
            return AuditVerification(
                ok=False,
                count=count,
                at_seq=expected_seq,
                error=f"seq mismatch: expected {expected_seq}, found {record.get('seq')!r}",
            )
        if record.get("prev_hash") != prev:
            return AuditVerification(
                ok=False,
                count=count,
                at_seq=expected_seq,
                error=f"broken link at seq {expected_seq}: prev_hash does not match prior record",
            )
        recomputed = _hash_record(record)
        if recomputed != record.get("hash"):
            return AuditVerification(
                ok=False,
                count=count,
                at_seq=expected_seq,
                error=f"content tampered at seq {expected_seq}: hash mismatch",
            )
        prev = record["hash"]
    return AuditVerification(ok=True, count=count)


__all__ = [
    "GENESIS_HASH",
    "AuditVerification",
    "AuditLogger",
    "NullAuditLogger",
    "open_audit",
    "read_records",
    "verify_chain",
]
