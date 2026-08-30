"""Render a :class:`Report` to Markdown — pure, no I/O."""

from __future__ import annotations

from wifiaudit.report.models import Report


def render_markdown(report: Report) -> str:
    L: list[str] = []
    L.append("# WiFi Security Assessment Report")
    L.append("")
    L.append(f"- **Operator:** {report.operator}")
    if report.organization:
        L.append(f"- **Organization:** {report.organization}")
    L.append(f"- **Authorization reference:** {report.reference}")
    w = report.window
    if w.get("starts") or w.get("expires"):
        L.append(f"- **Engagement window:** {w.get('starts') or '—'} to {w.get('expires') or '—'}")
    L.append(f"- **Report generated:** {report.generated_at}")
    if report.first_activity:
        L.append(f"- **Recorded activity:** {report.first_activity} to {report.last_activity}")
    L.append("")

    L.append("## Audit trail integrity")
    if report.audit_ok:
        L.append(
            f"The tamper-evident audit log verified **intact** "
            f"({report.audit_count} record(s)); the findings below are backed by it."
        )
    else:
        L.append(
            f"**WARNING — audit log verification FAILED** "
            f"({report.audit_error}). The record has been altered; treat the findings "
            "below as unreliable until the log is re-validated."
        )
    L.append("")

    sev = report.counts_by_severity()
    L.append("## Summary")
    if report.findings:
        parts = [f"{n} {s}" for s, n in sorted(sev.items())]
        L.append(f"{len(report.findings)} finding(s): " + ", ".join(parts) + ".")
    else:
        L.append("No exploitable findings were demonstrated.")
    L.append("")

    L.append("## Scope")
    s = report.scope
    L.append(f"- **BSSIDs:** {', '.join(s['bssids']) or '(none)'}")
    L.append(f"- **ESSIDs:** {', '.join(s['essids']) or '(none)'}")
    L.append(f"- **Channels:** {', '.join(map(str, s['channels'])) or '(any)'}")
    L.append("")

    act = report.activity
    L.append("## Activity")
    L.append(f"- Discovery scans: {act['scans']}")
    L.append(f"- Capture runs: {act['captures']}")
    L.append(f"- Crack runs: {act['cracks']}")
    L.append(f"- Refused (out-of-scope / gated) actions: {act['refusals']}")
    L.append(f"- Total audit records: {act['records']}")
    L.append("")

    L.append("## Findings")
    if not report.findings:
        L.append(
            "No exploitable findings were demonstrated. Any networks that were "
            "captured resisted the attempted attacks — a good outcome."
        )
        L.append("")
    else:
        for i, f in enumerate(report.sorted_findings(), 1):
            L.append(f"### {i}. [{f.severity.upper()}] {f.title}")
            L.append(f"- **Target:** {f.target}")
            ev = ", ".join(f"#{e}" for e in f.evidence)
            L.append(f"- **Evidence:** audit record(s) {ev}")
            L.append("")
            L.append(f.description)
            L.append("")

    L.append("## Recommendations")
    L.append("- Use a long, random WPA2/WPA3 passphrase (15+ characters, not dictionary words).")
    L.append("- Prefer **WPA3 (SAE)**, which resists offline dictionary attacks.")
    L.append("- Disable **WPS**, and change default router/administrative credentials.")
    L.append("- Enable **Protected Management Frames (802.11w)** to mitigate deauthentication.")
    L.append("")

    return "\n".join(L)


__all__ = ["render_markdown"]
