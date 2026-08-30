"""The report orchestrator.

Reads the engagement's audit log, verifies its hash chain, builds a
:class:`Report`, and writes it out (Markdown or JSON). Reporting is read-only —
it summarizes the audit trail rather than acting on any network — so it does not
pass the authorization *window* gate (you may need to write the report after the
engagement window has closed).
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from wifiaudit.core.audit import read_records, verify_chain
from wifiaudit.core.config import Config
from wifiaudit.report.builder import build_report
from wifiaudit.report.models import Report
from wifiaudit.report.render import render_markdown


class Reporter:
    def __init__(self, config: Config) -> None:
        self.config = config

    @classmethod
    def from_config(cls, config: Config) -> "Reporter":
        return cls(config)

    def build(self, *, now: _dt.datetime | None = None) -> Report:
        generated_at = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
        verification = verify_chain(self.config.audit.path)
        records = read_records(self.config.audit.path)
        return build_report(records, verification, config=self.config, generated_at=generated_at)

    def generate(
        self,
        *,
        output_path: str | Path | None = None,
        fmt: str = "md",
        now: _dt.datetime | None = None,
    ) -> tuple[Report, Path]:
        report = self.build(now=now)
        if fmt == "json":
            text = json.dumps(report.to_dict(), indent=2)
            ext = "json"
        else:
            text = render_markdown(report)
            ext = "md"
        path = Path(output_path) if output_path else Path(self.config.output_dir) / f"report.{ext}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return report, path


__all__ = ["Reporter"]
