"""Stage 4: evidence-linked engagement report.

Assembles a report from the tamper-evident audit log — recovered passphrases
become HIGH findings, captured-but-not-cracked material becomes MEDIUM findings,
and every finding cites the audit record(s) that prove it. The report states
whether the audit hash chain verified, so it is only as trustworthy as its
evidence. Read-only: it summarizes the trail rather than acting on any network.
"""

from wifiaudit.report.builder import build_report
from wifiaudit.report.models import Finding, Report, SEVERITY_RANK
from wifiaudit.report.render import render_markdown
from wifiaudit.report.reporter import Reporter

__all__ = [
    "build_report",
    "render_markdown",
    "Reporter",
    "Finding",
    "Report",
    "SEVERITY_RANK",
]
