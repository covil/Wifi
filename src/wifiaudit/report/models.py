"""Data models for stage 4 (reporting).

A :class:`Report` is assembled from the engagement's audit log, so every
:class:`Finding` points back to the audit record(s) that evidence it. This keeps
the report tamper-evident: it is only as trustworthy as the hash chain it was
built from, and it says so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Lower rank sorts first (most severe first).
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    """One security outcome demonstrated during the engagement."""

    severity: str            # "high" | "medium" | "low" | "info"
    title: str
    target: str              # human label, e.g. "MyNet (DE:AD:BE:EF:00:01)"
    description: str
    evidence: list[int] = field(default_factory=list)  # audit record seq numbers

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 99)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "target": self.target,
            "description": self.description,
            "evidence": list(self.evidence),
        }


@dataclass
class Report:
    """A full engagement report built from the audit log."""

    generated_at: str
    operator: str
    reference: str
    organization: str | None
    scope: dict[str, Any]
    window: dict[str, Any]
    audit_ok: bool
    audit_count: int
    audit_error: str | None
    activity: dict[str, int]
    first_activity: str | None
    last_activity: str | None
    findings: list[Finding] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.rank, f.title))

    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "operator": self.operator,
            "reference": self.reference,
            "organization": self.organization,
            "scope": self.scope,
            "window": self.window,
            "audit": {"ok": self.audit_ok, "count": self.audit_count, "error": self.audit_error},
            "activity": self.activity,
            "activity_window": {"first": self.first_activity, "last": self.last_activity},
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "summary": self.counts_by_severity(),
        }


__all__ = ["Finding", "Report", "SEVERITY_RANK"]
