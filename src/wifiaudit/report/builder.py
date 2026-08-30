"""Build a :class:`Report` from audit records — pure and deterministic.

The audit log is the single source of truth for what an engagement did, so the
report is reconstructed entirely from it: cracked passphrases become HIGH
findings, captured-but-not-cracked material becomes MEDIUM findings, and each
finding cites the audit record(s) that prove it.
"""

from __future__ import annotations

from typing import Any, Iterable

from wifiaudit.core.audit import AuditVerification
from wifiaudit.core.config import Config
from wifiaudit.report.models import Finding, Report


def _target_label(target: dict[str, Any]) -> str:
    essid = target.get("essid") or target.get("ssid")
    bssid = target.get("bssid", "?")
    return f"{essid} ({bssid})" if essid else str(bssid)


def build_report(
    records: Iterable[dict[str, Any]],
    verification: AuditVerification,
    *,
    config: Config,
    generated_at: str,
) -> Report:
    records = list(records)
    a = config.authorization
    scope = {
        "bssids": list(config.scope.bssids),
        "essids": list(config.scope.essids),
        "channels": list(config.scope.channels),
    }
    window = {
        "starts": a.starts.isoformat() if a.starts else None,
        "expires": a.expires.isoformat() if a.expires else None,
    }

    counts = {"scans": 0, "captures": 0, "cracks": 0, "refusals": 0}
    timestamps: list[str] = []
    # One entry per target BSSID, accumulating evidence across repeated runs.
    cracked: dict[str, dict[str, Any]] = {}
    captured: dict[str, dict[str, Any]] = {}

    for r in records:
        action = r.get("action", "")
        d = r.get("details", {}) or {}
        seq = r.get("seq")
        ts = r.get("ts")
        if ts:
            timestamps.append(ts)

        if action == "discovery.scan_complete":
            counts["scans"] += 1
        elif action == "capture.complete":
            counts["captures"] += 1
        elif action == "crack.complete":
            counts["cracks"] += 1
        if action.endswith(".refused"):
            counts["refusals"] += 1

        if action == "crack.complete" and d.get("cracked"):
            tgt = d.get("target", {}) or {}
            e = cracked.setdefault(tgt.get("bssid"), {"tgt": tgt, "evidence": []})
            e["tgt"] = tgt
            e["method"] = d.get("method", "dictionary")
            e["attempts"] = d.get("attempts", "?")
            e["evidence"].append(seq)
        elif action == "capture.complete" and (d.get("got_handshake") or d.get("got_pmkid")):
            tgt = d.get("target", {}) or {}
            e = captured.setdefault(tgt.get("bssid"), {"tgt": tgt, "evidence": []})
            e["tgt"] = tgt
            e["kind"] = "4-way handshake" if d.get("got_handshake") else "PMKID"
            e["evidence"].append(seq)

    findings: list[Finding] = []
    for bssid, e in cracked.items():
        findings.append(
            Finding(
                severity="high",
                title="WPA/WPA2-PSK passphrase recovered",
                target=_target_label(e["tgt"]),
                description=(
                    f"The pre-shared key was recovered offline via a {e['method']} attack "
                    f"(fastest: {e['attempts']} candidate(s)). The network's password is "
                    "guessable with a wordlist and must be considered compromised; change "
                    "it to a long, random passphrase."
                ),
                evidence=sorted(e["evidence"]),
            )
        )
    for bssid, e in captured.items():
        if bssid in cracked:
            continue  # already reported as a HIGH finding
        findings.append(
            Finding(
                severity="medium",
                title=f"Crackable {e['kind']} captured",
                target=_target_label(e["tgt"]),
                description=(
                    "Authentication material was captured that permits an offline "
                    "password-guessing attack. The passphrase was not recovered in this "
                    "engagement, but a larger wordlist or more time could succeed. Ensure "
                    "the passphrase is long and random, and prefer WPA3."
                ),
                evidence=sorted(e["evidence"]),
            )
        )

    return Report(
        generated_at=generated_at,
        operator=a.operator,
        reference=a.reference,
        organization=a.organization,
        scope=scope,
        window=window,
        audit_ok=verification.ok,
        audit_count=verification.count,
        audit_error=verification.error,
        activity={**counts, "records": len(records)},
        first_activity=min(timestamps) if timestamps else None,
        last_activity=max(timestamps) if timestamps else None,
        findings=findings,
    )


__all__ = ["build_report"]
