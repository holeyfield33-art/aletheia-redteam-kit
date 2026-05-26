from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path


@dataclass(frozen=True)
class ControlFailureSummary:
    owner: str
    exception_expiry: str | None
    total_failures: int

    def to_dict(self) -> dict[str, object]:
        return {
            "owner": self.owner,
            "exception_expiry": self.exception_expiry,
            "total_failures": self.total_failures,
        }


def _level_from_severity(severity: str) -> str:
    normalized = str(severity or "").upper()
    if normalized == "CRITICAL":
        return "error"
    if normalized == "HIGH":
        return "error"
    if normalized == "MEDIUM":
        return "warning"
    return "note"


def build_sarif_report(
    results: list[dict[str, object]],
    *,
    tool_name: str,
    owner: str,
    exception_expiry: str | None = None,
) -> dict[str, object]:
    runs: list[dict[str, object]] = []
    results_rows: list[dict[str, object]] = []
    for row in results:
        severity = str(row.get("severity") or "MEDIUM")
        results_rows.append(
            {
                "ruleId": str(row.get("case_id") or row.get("stage_id") or row.get("id") or "unknown"),
                "level": _level_from_severity(severity),
                "message": {"text": str(row.get("finding_type") or row.get("gate_decision") or "control failure")},
                "properties": {
                    "owner": owner,
                    "exception_expiry": exception_expiry,
                    "severity": severity,
                    "owasp_id": row.get("owasp_id"),
                    "nist_controls": row.get("nist_controls"),
                },
            }
        )

    runs.append(
        {
            "tool": {"driver": {"name": tool_name, "version": "1.0"}},
            "results": results_rows,
        }
    )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
        "control_failure_summary": ControlFailureSummary(owner=owner, exception_expiry=exception_expiry, total_failures=len(results)).to_dict(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def write_sarif_report(path: Path, report: dict[str, object]) -> None:
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")