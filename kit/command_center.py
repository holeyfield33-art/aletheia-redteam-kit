from __future__ import annotations

import csv
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _decision_label(raw: str | None) -> str:
    normalized = str(raw or "").strip().upper()
    if normalized == "DENIED":
        return "blocked"
    if normalized == "PROCEED":
        return "proceeded"
    if normalized in {"UNKNOWN", "ERROR"}:
        return "unknown"
    return "unknown"


def normalize_summary_to_command_center(
    summary: dict[str, Any],
    *,
    source_path: str | None = None,
    baseline_summary: dict[str, Any] | None = None,
    tool_version: str | None = None,
    git_commit: str | None = None,
) -> dict[str, Any]:
    run_id = str(uuid.uuid4())
    mode = str(summary.get("mode") or "api")
    started_at = str(summary.get("generated_at") or _now_iso())

    ci_verdict = str(summary.get("ci_verdict") or ("pass" if (summary.get("gates") or {}).get("pass", False) else "fail")).lower()
    ci_reason = str(summary.get("ci_verdict_reason") or "")

    runs = [
        {
            "id": run_id,
            "mode": mode,
            "target_url": summary.get("target_url"),
            "repo_path": summary.get("repo_root"),
            "status": "completed",
            "started_at": started_at,
            "finished_at": started_at,
            "duration_ms": None,
            "tool_version": tool_version,
            "git_commit": git_commit,
            "baseline_run_id": None,
            "ci_verdict": ci_verdict,
            "ci_reason": ci_reason,
            "created_by": "cli",
        }
    ]

    targets: list[dict[str, Any]] = []
    target_id = str(uuid.uuid4())
    targets.append(
        {
            "id": target_id,
            "run_id": run_id,
            "target_url": summary.get("target_url") or summary.get("engine_url"),
            "repo_path": summary.get("repo_root"),
            "scope": mode,
        }
    )

    findings: list[dict[str, Any]] = []
    findings_evidence: list[dict[str, Any]] = []
    tags: list[dict[str, Any]] = []
    finding_tags: list[dict[str, Any]] = []

    metrics: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    gate_results: list[dict[str, Any]] = []

    if mode == "api":
        rows = list(summary.get("results") or [])
        for row in rows:
            finding_id = str(uuid.uuid4())
            decision = _decision_label(row.get("actual_decision"))
            severity = str(row.get("severity") or "MEDIUM").lower()
            mismatch = not bool(row.get("match", False))
            finding_type = "anomaly" if str(row.get("actual_decision") or "").upper() in {"UNKNOWN", "ERROR"} else "attack"
            confidence = 0.9 if row.get("receipt") else 0.5
            exploitability = 1.0 if decision == "proceeded" and str(row.get("expected_decision") or "").upper() == "DENIED" else 0.2
            findings.append(
                {
                    "id": finding_id,
                    "run_id": run_id,
                    "target_id": target_id,
                    "category": row.get("category") or "unknown",
                    "technique": row.get("technique"),
                    "severity": severity,
                    "decision": decision,
                    "finding_type": finding_type,
                    "title": row.get("name") or row.get("id") or "attack finding",
                    "summary": row.get("reason") or row.get("error") or "",
                    "confidence": confidence,
                    "exploitability": exploitability,
                    "trust_score": None,
                    "created_at": started_at,
                    "mismatch": mismatch,
                }
            )

            finding_tags.append({"finding_id": finding_id, "tag": str(row.get("category") or "unknown")})
            if row.get("technique"):
                finding_tags.append({"finding_id": finding_id, "tag": str(row.get("technique"))})

            findings_evidence.append(
                {
                    "id": str(uuid.uuid4()),
                    "finding_id": finding_id,
                    "evidence_type": "receipt",
                    "data_json": row.get("receipt") or {},
                    "raw_text": json.dumps(row.get("receipt") or {}, indent=2),
                    "sha256": None,
                    "signature_valid": None,
                    "created_at": started_at,
                }
            )
            findings_evidence.append(
                {
                    "id": str(uuid.uuid4()),
                    "finding_id": finding_id,
                    "evidence_type": "response",
                    "data_json": {
                        "request_id": row.get("request_id"),
                        "actual_decision": row.get("actual_decision"),
                        "expected_decision": row.get("expected_decision"),
                        "error": row.get("error"),
                    },
                    "raw_text": row.get("reason") or row.get("error") or "",
                    "sha256": None,
                    "signature_valid": None,
                    "created_at": started_at,
                }
            )

        metrics.extend(
            [
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "run",
                    "scope_key": None,
                    "metric_name": "pass_rate",
                    "metric_value": _safe_float(summary.get("expectation_match_rate")),
                    "metric_unit": "percent",
                    "created_at": started_at,
                },
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "run",
                    "scope_key": None,
                    "metric_name": "blocked_rate",
                    "metric_value": _safe_float(summary.get("block_rate")),
                    "metric_unit": "percent",
                    "created_at": started_at,
                },
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "run",
                    "scope_key": None,
                    "metric_name": "unknown_count",
                    "metric_value": _safe_float(summary.get("unknown")),
                    "metric_unit": "count",
                    "created_at": started_at,
                },
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "run",
                    "scope_key": None,
                    "metric_name": "anomaly_count",
                    "metric_value": _safe_float(summary.get("empty_200_anomalies")),
                    "metric_unit": "count",
                    "created_at": started_at,
                },
            ]
        )

        for category, info in (summary.get("categories") or {}).items():
            metrics.append(
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "category",
                    "scope_key": category,
                    "metric_name": "blocked",
                    "metric_value": _safe_float((info or {}).get("blocked")),
                    "metric_unit": "count",
                    "created_at": started_at,
                }
            )

    elif mode in {"repo", "website"}:
        rows = list(summary.get("findings") or [])
        for row in rows:
            finding_id = str(uuid.uuid4())
            severity = str(row.get("severity") or "MEDIUM").lower()
            decision = "unknown"
            if severity in {"critical", "high"}:
                decision = "proceeded"
            findings.append(
                {
                    "id": finding_id,
                    "run_id": run_id,
                    "target_id": target_id,
                    "category": row.get("type") or "finding",
                    "technique": row.get("action") or row.get("type"),
                    "severity": severity,
                    "decision": decision,
                    "finding_type": "regression" if row.get("regression") else "attack",
                    "title": row.get("title") or row.get("id") or "finding",
                    "summary": row.get("observed") or row.get("message") or "",
                    "confidence": 0.8,
                    "exploitability": 0.8 if severity in {"critical", "high"} else 0.2,
                    "trust_score": _safe_float(summary.get("trust_score"), default=0.0),
                    "created_at": started_at,
                    "mismatch": severity in {"critical", "high"},
                }
            )
            findings_evidence.append(
                {
                    "id": str(uuid.uuid4()),
                    "finding_id": finding_id,
                    "evidence_type": "finding",
                    "data_json": row,
                    "raw_text": json.dumps(row, indent=2),
                    "sha256": None,
                    "signature_valid": None,
                    "created_at": started_at,
                }
            )

        metrics.extend(
            [
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "run",
                    "scope_key": None,
                    "metric_name": "pass_rate",
                    "metric_value": _safe_float(summary.get("pass_rate"), default=_safe_float(summary.get("risk_score"))),
                    "metric_unit": "percent",
                    "created_at": started_at,
                },
                {
                    "id": str(uuid.uuid4()),
                    "run_id": run_id,
                    "scope_type": "run",
                    "scope_key": None,
                    "metric_name": "findings_total",
                    "metric_value": _safe_float(summary.get("findings_total")),
                    "metric_unit": "count",
                    "created_at": started_at,
                },
            ]
        )

        if mode == "repo":
            dep_signals = ((summary.get("dependencies") or {}).get("signals") or {})
            metrics.extend(
                [
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "scope_type": "run",
                        "scope_key": None,
                        "metric_name": "dependency_malware_suspect_total",
                        "metric_value": _safe_float(dep_signals.get("malware_suspect_total")),
                        "metric_unit": "count",
                        "created_at": started_at,
                    },
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "scope_type": "run",
                        "scope_key": None,
                        "metric_name": "dependency_tampering_risk_total",
                        "metric_value": _safe_float(dep_signals.get("tampering_risk_total")),
                        "metric_unit": "count",
                        "created_at": started_at,
                    },
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "scope_type": "run",
                        "scope_key": None,
                        "metric_name": "suspicious_dependency_package_total",
                        "metric_value": _safe_float(dep_signals.get("suspicious_package_total")),
                        "metric_unit": "count",
                        "created_at": started_at,
                    },
                ]
            )

    elif mode == "combined":
        component_lookup = dict(summary.get("components") or {})
        target_rows = list(summary.get("targets") or [])
        if target_rows:
            # Batch-mode summaries carry explicit per-target rows; replace the
            # default single-target placeholder so we don't double-count.
            targets.clear()
            for index, target_row in enumerate(target_rows, 1):
                component_key = str(target_row.get("component_key") or target_row.get("id") or f"target-{index}")
                component = component_lookup.get(component_key) or {}
                target_record = {
                    "id": str(target_row.get("id") or uuid.uuid4()),
                    "run_id": run_id,
                    "target_url": target_row.get("target_url") or (component.get("target_url") if isinstance(component, dict) else None),
                    "repo_path": target_row.get("repo_path") or (component.get("repo_root") if isinstance(component, dict) else None),
                    "scope": str(target_row.get("type") or component_key),
                }
                targets.append(target_record)

                if isinstance(component, dict):
                    if str(component.get("mode") or "") == "api":
                        component_rows = list(component.get("results") or [])
                        for row in component_rows:
                            finding_id = str(uuid.uuid4())
                            decision = _decision_label(row.get("actual_decision"))
                            severity = str(row.get("severity") or "MEDIUM").lower()
                            mismatch = not bool(row.get("match", False))
                            finding_type = "anomaly" if str(row.get("actual_decision") or "").upper() in {"UNKNOWN", "ERROR"} else "attack"
                            findings.append(
                                {
                                    "id": finding_id,
                                    "run_id": run_id,
                                    "target_id": target_record["id"],
                                    "category": row.get("category") or component_key,
                                    "technique": row.get("technique"),
                                    "severity": severity,
                                    "decision": decision,
                                    "finding_type": finding_type,
                                    "title": row.get("name") or row.get("id") or "attack finding",
                                    "summary": row.get("reason") or row.get("error") or "",
                                    "confidence": 0.9 if row.get("receipt") else 0.5,
                                    "exploitability": 1.0 if decision == "proceeded" and str(row.get("expected_decision") or "").upper() == "DENIED" else 0.2,
                                    "trust_score": None,
                                    "created_at": started_at,
                                    "mismatch": mismatch,
                                }
                            )
                    else:
                        component_rows = list(component.get("findings") or [])
                        for row in component_rows:
                            finding_id = str(uuid.uuid4())
                            severity = str(row.get("severity") or "MEDIUM").lower()
                            decision = "proceeded" if severity in {"critical", "high"} else "unknown"
                            findings.append(
                                {
                                    "id": finding_id,
                                    "run_id": run_id,
                                    "target_id": target_record["id"],
                                    "category": row.get("type") or component_key,
                                    "technique": row.get("action") or row.get("type"),
                                    "severity": severity,
                                    "decision": decision,
                                    "finding_type": "regression" if row.get("regression") else "attack",
                                    "title": row.get("title") or row.get("id") or "finding",
                                    "summary": row.get("observed") or row.get("message") or "",
                                    "confidence": 0.8,
                                    "exploitability": 0.8 if severity in {"critical", "high"} else 0.2,
                                    "trust_score": _safe_float(component.get("trust_score"), default=0.0),
                                    "created_at": started_at,
                                    "mismatch": severity in {"critical", "high"},
                                }
                            )

                metrics.append(
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "scope_type": "component",
                        "scope_key": component_key,
                        "metric_name": "risk_score",
                        "metric_value": _safe_float((summary.get("normalized_signals") or {}).get("component_risk", {}).get(component_key)),
                        "metric_unit": "score",
                        "created_at": started_at,
                    }
                )
                metrics.append(
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "scope_type": "component",
                        "scope_key": component_key,
                        "metric_name": "exploitability_score",
                        "metric_value": _safe_float((summary.get("normalized_signals") or {}).get("component_exploitability", {}).get(component_key)),
                        "metric_unit": "score",
                        "created_at": started_at,
                    }
                )
        else:
            for component_name, component in component_lookup.items():
                metrics.append(
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "scope_type": "component",
                        "scope_key": component_name,
                        "metric_name": "risk_score",
                        "metric_value": _safe_float((summary.get("normalized_signals") or {}).get("component_risk", {}).get(component_name)),
                        "metric_unit": "score",
                        "created_at": started_at,
                    }
                )
                findings.append(
                    {
                        "id": str(uuid.uuid4()),
                        "run_id": run_id,
                        "target_id": target_id,
                        "category": component_name,
                        "technique": "component_gate",
                        "severity": "high" if not (component.get("gates") or {}).get("pass", True) else "low",
                        "decision": "blocked" if not (component.get("gates") or {}).get("pass", True) else "proceeded",
                        "finding_type": "regression",
                        "title": f"component summary: {component_name}",
                        "summary": json.dumps((component.get("gates") or {}), indent=2),
                        "confidence": 0.9,
                        "exploitability": _safe_float((summary.get("normalized_signals") or {}).get("component_exploitability", {}).get(component_name)),
                        "trust_score": None,
                        "created_at": started_at,
                        "mismatch": not (component.get("gates") or {}).get("pass", True),
                    }
                )

    gate_results.append(
        {
            "id": str(uuid.uuid4()),
            "run_id": run_id,
            "pass": bool((summary.get("gates") or {}).get("pass", True)),
            "violations": list((summary.get("gates") or {}).get("violations") or []),
            "ci_verdict": ci_verdict,
            "ci_reason": ci_reason,
        }
    )

    if source_path:
        artifacts.append(
            {
                "id": str(uuid.uuid4()),
                "run_id": run_id,
                "artifact_type": "summary_json",
                "path": source_path,
                "mime_type": "application/json",
                "sha256": None,
                "created_at": started_at,
            }
        )

    run_summary_view = {
        "run_id": run_id,
        "mode": mode,
        "started_at": started_at,
        "finished_at": started_at,
        "findings_total": len(findings),
        "blocked_count": sum(1 for f in findings if f.get("decision") == "blocked"),
        "proceeded_count": sum(1 for f in findings if f.get("decision") == "proceeded"),
        "unknown_count": sum(1 for f in findings if f.get("decision") == "unknown"),
        "avg_trust_score": (
            sum(_safe_float(f.get("trust_score")) for f in findings if f.get("trust_score") is not None)
            / max(1, sum(1 for f in findings if f.get("trust_score") is not None))
        ),
        "avg_exploitability": sum(_safe_float(f.get("exploitability")) for f in findings) / max(1, len(findings)),
    }

    category_rollup: dict[str, dict[str, Any]] = {}
    for finding in findings:
        category = str(finding.get("category") or "unknown")
        row = category_rollup.setdefault(
            category,
            {
                "run_id": run_id,
                "category": category,
                "total": 0,
                "blocked": 0,
                "proceeded": 0,
                "unknown": 0,
            },
        )
        row["total"] += 1
        row[finding.get("decision") or "unknown"] = row.get(finding.get("decision") or "unknown", 0) + 1

    return {
        "schema_version": 1,
        "generated_at": _now_iso(),
        "runs": runs,
        "targets": targets,
        "findings": findings,
        "findings_evidence": findings_evidence,
        "metrics": metrics,
        "artifacts": artifacts,
        "gate_results": gate_results,
        "tags": tags,
        "finding_tags": finding_tags,
        "notes": [],
        "views": {
            "v_run_summary": [run_summary_view],
            "v_category_summary": sorted(category_rollup.values(), key=lambda item: item["category"]),
        },
        "baseline": baseline_summary,
    }


def write_command_center_sqlite(model: dict[str, Any], db_path: str | Path) -> Path:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(path) as conn:
                conn.execute("PRAGMA foreign_keys = ON")
                conn.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS runs (
                            id TEXT PRIMARY KEY,
                            mode TEXT NOT NULL,
                            target_url TEXT,
                            repo_path TEXT,
                            status TEXT NOT NULL,
                            started_at TEXT NOT NULL,
                            finished_at TEXT,
                            duration_ms INTEGER,
                            tool_version TEXT,
                            git_commit TEXT,
                            baseline_run_id TEXT,
                            ci_verdict TEXT,
                            ci_reason TEXT,
                            created_by TEXT
                        );

                        CREATE TABLE IF NOT EXISTS targets (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            target_url TEXT,
                            repo_path TEXT,
                            scope TEXT,
                            FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
                        );

                        CREATE TABLE IF NOT EXISTS findings (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            target_id TEXT,
                            category TEXT NOT NULL,
                            technique TEXT,
                            severity TEXT NOT NULL,
                            decision TEXT NOT NULL,
                            finding_type TEXT NOT NULL,
                            title TEXT NOT NULL,
                            summary TEXT,
                            confidence REAL,
                            exploitability REAL,
                            trust_score REAL,
                            created_at TEXT NOT NULL,
                            mismatch INTEGER DEFAULT 0,
                            FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                            FOREIGN KEY(target_id) REFERENCES targets(id)
                        );

                        CREATE TABLE IF NOT EXISTS findings_evidence (
                            id TEXT PRIMARY KEY,
                            finding_id TEXT NOT NULL,
                            evidence_type TEXT NOT NULL,
                            data_json TEXT,
                            raw_text TEXT,
                            sha256 TEXT,
                            signature_valid INTEGER,
                            created_at TEXT NOT NULL,
                            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
                        );

                        CREATE TABLE IF NOT EXISTS metrics (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            scope_type TEXT NOT NULL,
                            scope_key TEXT,
                            metric_name TEXT NOT NULL,
                            metric_value REAL NOT NULL,
                            metric_unit TEXT,
                            created_at TEXT NOT NULL,
                            FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
                        );

                        CREATE TABLE IF NOT EXISTS artifacts (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            artifact_type TEXT NOT NULL,
                            path TEXT NOT NULL,
                            mime_type TEXT,
                            sha256 TEXT,
                            created_at TEXT NOT NULL,
                            FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
                        );

                        CREATE TABLE IF NOT EXISTS gate_results (
                            id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            pass INTEGER NOT NULL,
                            violations_json TEXT,
                            ci_verdict TEXT,
                            ci_reason TEXT,
                            FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
                        );

                        CREATE TABLE IF NOT EXISTS tags (
                            id TEXT PRIMARY KEY,
                            name TEXT NOT NULL UNIQUE
                        );

                        CREATE TABLE IF NOT EXISTS finding_tags (
                            finding_id TEXT NOT NULL,
                            tag_id TEXT NOT NULL,
                            PRIMARY KEY(finding_id, tag_id),
                            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE,
                            FOREIGN KEY(tag_id) REFERENCES tags(id) ON DELETE CASCADE
                        );

                        CREATE TABLE IF NOT EXISTS notes (
                            id TEXT PRIMARY KEY,
                            run_id TEXT,
                            finding_id TEXT,
                            note TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE,
                            FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE CASCADE
                        );

                        CREATE INDEX IF NOT EXISTS idx_findings_run_severity_decision ON findings(run_id, severity, decision);
                        CREATE INDEX IF NOT EXISTS idx_findings_run_category ON findings(run_id, category);
                        CREATE INDEX IF NOT EXISTS idx_findings_run_technique ON findings(run_id, technique);
                        CREATE INDEX IF NOT EXISTS idx_metrics_run_scope_metric ON metrics(run_id, scope_type, metric_name);
                        CREATE INDEX IF NOT EXISTS idx_artifacts_run_type ON artifacts(run_id, artifact_type);
                        CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);

                        DROP VIEW IF EXISTS v_run_summary;
                        CREATE VIEW v_run_summary AS
                        SELECT
                            r.id AS run_id,
                            r.mode,
                            r.started_at,
                            r.finished_at,
                            COUNT(f.id) AS findings_total,
                            COUNT(CASE WHEN f.decision = 'blocked' THEN 1 END) AS blocked_count,
                            COUNT(CASE WHEN f.decision = 'proceeded' THEN 1 END) AS proceeded_count,
                            COUNT(CASE WHEN f.decision = 'unknown' THEN 1 END) AS unknown_count,
                            AVG(f.trust_score) AS avg_trust_score,
                            AVG(f.exploitability) AS avg_exploitability
                        FROM runs r
                        LEFT JOIN findings f ON f.run_id = r.id
                        GROUP BY r.id, r.mode, r.started_at, r.finished_at;

                        DROP VIEW IF EXISTS v_category_summary;
                        CREATE VIEW v_category_summary AS
                        SELECT
                            run_id,
                            category,
                            COUNT(*) AS total,
                            COUNT(CASE WHEN decision = 'blocked' THEN 1 END) AS blocked,
                            COUNT(CASE WHEN decision = 'proceeded' THEN 1 END) AS proceeded,
                            COUNT(CASE WHEN decision = 'unknown' THEN 1 END) AS unknown
                        FROM findings
                        GROUP BY run_id, category;
                        """
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO runs (
                            id, mode, target_url, repo_path, status, started_at, finished_at,
                            duration_ms, tool_version, git_commit, baseline_run_id,
                            ci_verdict, ci_reason, created_by
                        ) VALUES (
                            :id, :mode, :target_url, :repo_path, :status, :started_at, :finished_at,
                            :duration_ms, :tool_version, :git_commit, :baseline_run_id,
                            :ci_verdict, :ci_reason, :created_by
                        )
                        """,
                        model.get("runs") or [],
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO targets (id, run_id, target_url, repo_path, scope)
                        VALUES (:id, :run_id, :target_url, :repo_path, :scope)
                        """,
                        model.get("targets") or [],
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO findings (
                            id, run_id, target_id, category, technique, severity, decision,
                            finding_type, title, summary, confidence, exploitability,
                            trust_score, created_at, mismatch
                        ) VALUES (
                            :id, :run_id, :target_id, :category, :technique, :severity, :decision,
                            :finding_type, :title, :summary, :confidence, :exploitability,
                            :trust_score, :created_at, :mismatch
                        )
                        """,
                        [
                                {
                                        **row,
                                        "mismatch": 1 if row.get("mismatch") else 0,
                                }
                                for row in (model.get("findings") or [])
                        ],
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO findings_evidence (
                            id, finding_id, evidence_type, data_json, raw_text, sha256,
                            signature_valid, created_at
                        ) VALUES (
                            :id, :finding_id, :evidence_type, :data_json, :raw_text, :sha256,
                            :signature_valid, :created_at
                        )
                        """,
                        [
                                {
                                        **row,
                                        "data_json": json.dumps(row.get("data_json")),
                                        "signature_valid": None if row.get("signature_valid") is None else (1 if row.get("signature_valid") else 0),
                                }
                                for row in (model.get("findings_evidence") or [])
                        ],
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO metrics (
                            id, run_id, scope_type, scope_key, metric_name, metric_value,
                            metric_unit, created_at
                        ) VALUES (
                            :id, :run_id, :scope_type, :scope_key, :metric_name, :metric_value,
                            :metric_unit, :created_at
                        )
                        """,
                        model.get("metrics") or [],
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO artifacts (
                            id, run_id, artifact_type, path, mime_type, sha256, created_at
                        ) VALUES (
                            :id, :run_id, :artifact_type, :path, :mime_type, :sha256, :created_at
                        )
                        """,
                        model.get("artifacts") or [],
                )

                conn.executemany(
                        """
                        INSERT OR REPLACE INTO gate_results (
                            id, run_id, pass, violations_json, ci_verdict, ci_reason
                        ) VALUES (
                            :id, :run_id, :pass, :violations_json, :ci_verdict, :ci_reason
                        )
                        """,
                        [
                                {
                                        "id": row.get("id"),
                                        "run_id": row.get("run_id"),
                                        "pass": 1 if row.get("pass") else 0,
                                        "violations_json": json.dumps(row.get("violations") or []),
                                        "ci_verdict": row.get("ci_verdict"),
                                        "ci_reason": row.get("ci_reason"),
                                }
                                for row in (model.get("gate_results") or [])
                        ],
                )

                tags_by_name: dict[str, str] = {}
                for item in model.get("tags") or []:
                        tag_id = str(item.get("id") or uuid.uuid4())
                        tag_name = str(item.get("name") or "").strip()
                        if not tag_name:
                                continue
                        tags_by_name[tag_name] = tag_id

                for relation in model.get("finding_tags") or []:
                        tag_name = str(relation.get("tag") or "").strip()
                        if not tag_name:
                                continue
                        tags_by_name.setdefault(tag_name, str(uuid.uuid4()))

                conn.executemany(
                        "INSERT OR REPLACE INTO tags (id, name) VALUES (:id, :name)",
                        [{"id": tag_id, "name": tag_name} for tag_name, tag_id in tags_by_name.items()],
                )

                conn.executemany(
                        "INSERT OR REPLACE INTO finding_tags (finding_id, tag_id) VALUES (:finding_id, :tag_id)",
                        [
                                {
                                        "finding_id": relation.get("finding_id"),
                                        "tag_id": tags_by_name[str(relation.get("tag") or "").strip()],
                                }
                                for relation in (model.get("finding_tags") or [])
                                if str(relation.get("tag") or "").strip() in tags_by_name
                        ],
                )

                conn.executemany(
                        "INSERT OR REPLACE INTO notes (id, run_id, finding_id, note, created_at) VALUES (:id, :run_id, :finding_id, :note, :created_at)",
                        [
                                {
                                        "id": str(item.get("id") or uuid.uuid4()),
                                        "run_id": item.get("run_id"),
                                        "finding_id": item.get("finding_id"),
                                        "note": item.get("note") or "",
                                        "created_at": item.get("created_at") or _now_iso(),
                                }
                                for item in (model.get("notes") or [])
                        ],
                )

                conn.commit()

        return path


def compare_summaries(current: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    current_mode = str(current.get("mode") or "unknown")
    baseline_mode = str(baseline.get("mode") or "unknown")

    def _api_counts(payload: dict[str, Any]) -> dict[str, int]:
        return {
            "blocked": _safe_int(payload.get("blocked")),
            "proceeded": _safe_int(payload.get("proceeded")),
            "unknown": _safe_int(payload.get("unknown")),
            "errors": _safe_int(payload.get("errors")),
            "anomalies": _safe_int(payload.get("empty_200_anomalies")),
        }

    current_counts = _api_counts(current)
    baseline_counts = _api_counts(baseline)
    deltas = {key: current_counts.get(key, 0) - baseline_counts.get(key, 0) for key in current_counts}

    regressions = []
    if deltas["proceeded"] > 0:
        regressions.append("proceeded_increase")
    if deltas["unknown"] > 0:
        regressions.append("unknown_increase")
    if deltas["errors"] > 0:
        regressions.append("errors_increase")
    if deltas["anomalies"] > 0:
        regressions.append("anomalies_increase")

    return {
        "generated_at": _now_iso(),
        "current_mode": current_mode,
        "baseline_mode": baseline_mode,
        "current_counts": current_counts,
        "baseline_counts": baseline_counts,
        "deltas": deltas,
        "active_regressions": regressions,
    }


def apply_finding_filter(rows: list[dict[str, Any]], filter_expr: str | None) -> list[dict[str, Any]]:
    if not filter_expr:
        return rows

    parts = {}
    for item in str(filter_expr).split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        parts[key.strip().lower()] = value.strip()

    category = parts.get("category")
    decision = parts.get("decision")
    technique = parts.get("technique")
    mismatch_only = parts.get("mismatch", "false").lower() in {"1", "true", "yes", "on"}
    query = parts.get("q") or parts.get("search")

    out: list[dict[str, Any]] = []
    for row in rows:
        row_category = str(row.get("category") or row.get("type") or "")
        row_decision = str(row.get("actual_decision") or row.get("decision") or row.get("severity") or "")
        row_technique = str(row.get("technique") or "")
        if category and row_category != category:
            continue
        if decision and row_decision.upper() != decision.upper():
            continue
        if technique and row_technique != technique:
            continue
        if mismatch_only and bool(row.get("match", True)):
            continue
        if query:
            blob = " ".join(
                [
                    str(row.get("id") or ""),
                    str(row.get("name") or ""),
                    str(row.get("title") or ""),
                    str(row.get("reason") or ""),
                    str(row.get("error") or ""),
                    str(row.get("evidence") or ""),
                    str(row.get("summary") or ""),
                ]
            ).lower()
            if query.lower() not in blob:
                continue
        out.append(row)
    return out


def export_rows(rows: list[dict[str, Any]], output_path: Path, output_format: str) -> None:
    output_format = output_format.lower()
    if output_format == "json":
        output_path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        return

    if output_format != "csv":
        raise ValueError(f"Unsupported export format: {output_format}")

    all_keys: list[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                all_keys.append(key)

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=all_keys)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def evaluate_gates(summary: dict[str, Any], thresholds_expr: str | None) -> dict[str, Any]:
    thresholds: dict[str, float] = {}
    if thresholds_expr:
        for item in str(thresholds_expr).split(","):
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            try:
                thresholds[key.strip()] = float(value.strip())
            except ValueError:
                continue

    checks: list[dict[str, Any]] = []
    violations: list[str] = []

    metrics = {
        "max_unknown": _safe_float(summary.get("unknown")),
        "max_errors": _safe_float(summary.get("errors")),
        "max_anomalies": _safe_float(summary.get("empty_200_anomalies")),
        "min_pass_rate": _safe_float(summary.get("expectation_match_rate"), 0.0),
        "max_repo_critical": _safe_float((summary.get("findings_by_severity") or {}).get("CRITICAL"), 0.0),
        "max_repo_high": _safe_float((summary.get("findings_by_severity") or {}).get("HIGH"), 0.0),
    }

    for key, threshold in thresholds.items():
        value = metrics.get(key)
        if value is None:
            continue
        passed = value >= threshold if key.startswith("min_") else value <= threshold
        checks.append({"metric": key, "value": value, "threshold": threshold, "pass": passed})
        if not passed:
            violations.append(key)

    return {
        "generated_at": _now_iso(),
        "checks": checks,
        "pass": not violations,
        "violations": violations,
    }
