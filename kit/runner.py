"""
Run the full attack catalog against the Aletheia API.

Usage:
    python -m kit.runner                         # full API catalog
    python -m kit.runner --category prompt_injection
    python -m kit.runner --mode agentic
    python -m kit.runner --mode combined --target-url https://example.com
    python -m kit.runner --output results.json   # default: summary.json
    python -m kit.runner --min-expectation-match-rate 50
    python -m kit.runner --mode repo --repo-path .
    python -m kit.runner --mode website --target-url https://example.com
    python -m kit.runner --mode website --target-url https://example.com --no-browser-fallback
    python -m kit.runner --mode website --target-url https://example.com --rules-file rules.json
    python -m kit.runner --mode website --target-url https://example.com --auth-workflow-file auth_flow.json
    python -m kit.runner --mode website --target-url https://example.com --prompt-tests-file prompt_tests.json
    python -m kit.runner --mode website --target-url https://example.com --protected-route /dashboard

API mode writes summary JSON with categories, results, and gap_report.
Dashboard auto-scan reads runs/index.json plus summary files under runs/.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from uuid import uuid4

import httpx

from engine.gap_analysis import build_gap_report
from engine.repo_audit import run_repo_audit
from engine.tests.auth_bypass import PROTECTED_ROUTE_PROFILES
from kit.agentic_runner import AgenticRunner, AgenticRunnerConfig
from kit.command_center import (
    apply_finding_filter,
    compare_summaries,
    evaluate_gates,
    export_rows,
    normalize_summary_to_command_center,
    write_command_center_sqlite,
)
from kit.dashboard_server import DashboardServerConfig, serve_dashboard
from kit.api_analysis import build_api_regression_summary, extract_multi_turn_steps
from kit.catalog import load_attacks as load_attacks_from_catalog
from kit.client import AletheiaClient
from kit.exit_codes import FAIL_ERROR, FAIL_THRESHOLD, PASS
from kit.web_audit import WebAuditConfig, run_website_audit
from kit.web_audit.config import AuthBypassTarget, AuthStep, CustomFindingRule, PromptInjectionTest

ATTACK_DIR = Path(__file__).parent.parent / "attacks"
DEFAULT_OUTPUT = Path("summary.json")
DEFAULT_AGENTIC_OUTPUT = Path("runs/agentic_results.json")
DEFAULT_REQUEST_DELAY_SEC = 1.0
DEFAULT_MAX_REQUEST_DELAY_SEC = 30.0
RECONCILIATION_COVERAGE_THRESHOLD_PCT = 95.0


def _parse_key_value_csv(raw: str | None) -> dict[str, str]:
    pairs: dict[str, str] = {}
    if not raw:
        return pairs
    for item in str(raw).split(","):
        if "=" not in item:
            continue
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            pairs[key] = value
    return pairs


def _apply_thresholds_to_legacy_args(legacy_args: list[str], thresholds_raw: str | None) -> None:
    thresholds = _parse_key_value_csv(thresholds_raw)
    mapping = {
        "min_pass_rate": "--min-pass-rate",
        "max_critical": "--max-critical",
        "max_high": "--max-high",
        "min_expectation_match_rate": "--min-expectation-match-rate",
        "max_repo_critical": "--max-repo-critical",
        "max_repo_high": "--max-repo-high",
        "max_deps_critical": "--max-deps-critical",
        "max_deps_high": "--max-deps-high",
    }
    for key, value in thresholds.items():
        flag = mapping.get(key)
        if flag:
            legacy_args.extend([flag, value])


def _write_command_center_artifacts(
    *,
    summary_path: Path,
    artifact_dir: Path,
    dashboard_file: Path | None,
    baseline_path: str | None,
) -> Path:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    baseline_summary = None
    if baseline_path:
        base = Path(baseline_path)
        if base.exists():
            try:
                baseline_summary = json.loads(base.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                baseline_summary = None

    artifact_dir.mkdir(parents=True, exist_ok=True)

    command_center = normalize_summary_to_command_center(
        summary,
        source_path=str(summary_path),
        baseline_summary=baseline_summary,
        tool_version="0.2.1",
        git_commit=os.environ.get("GIT_COMMIT"),
    )

    mode = str(summary.get("mode") or "api")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = artifact_dir / f"run-{mode}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    summary_copy = run_dir / "summary.json"
    summary_copy.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    sqlite_path = run_dir / "command_center.sqlite"
    command_center["artifacts"].append(
        {
            "id": str(uuid4()),
            "run_id": command_center["runs"][0]["id"],
            "artifact_type": "sqlite",
            "path": str(sqlite_path.relative_to(artifact_dir)),
            "mime_type": "application/vnd.sqlite3",
            "sha256": None,
            "created_at": command_center["generated_at"],
        }
    )

    write_command_center_sqlite(command_center, sqlite_path)

    command_center_path = run_dir / "command_center.json"
    command_center_path.write_text(json.dumps(command_center, indent=2), encoding="utf-8")

    index_path = artifact_dir / "index.json"
    index: list[dict] = []
    if index_path.exists():
        try:
            raw = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                index = [item for item in raw if isinstance(item, dict)]
        except json.JSONDecodeError:
            index = []

    index.append(
        {
            "generated_at": command_center.get("generated_at"),
            "mode": mode,
            "summary": str(summary_copy.relative_to(artifact_dir)),
            "command_center": str(command_center_path.relative_to(artifact_dir)),
            "sqlite": str(sqlite_path.relative_to(artifact_dir)),
        }
    )
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")

    if dashboard_file:
        dashboard_path = Path(dashboard_file)
        if dashboard_path.exists():
            shutil.copy2(dashboard_path, run_dir / dashboard_path.name)

    return command_center_path


def _open_dashboard_if_requested(open_dashboard: bool, dashboard_file: str | None) -> None:
    if not open_dashboard or not dashboard_file:
        return
    dashboard_path = Path(dashboard_file)
    if not dashboard_path.exists():
        return
    browser = os.environ.get("BROWSER")
    if browser:
        os.system(f'{browser} "{dashboard_path.resolve()}" >/dev/null 2>&1')


def _command_center_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Aletheia command-center control plane")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run API/website/repo/combined sweeps")
    run_parser.add_argument("--mode", choices=["api", "website", "repo", "combined", "agentic"], default="api")
    run_parser.add_argument("--baseline", help="Baseline summary path used for compare/regression")
    run_parser.add_argument("--thresholds", help="Comma-separated thresholds, e.g. max_unknown=2,max_repo_high=5")
    run_parser.add_argument("--filter", dest="filter_expr", help="Comma-separated filter (category, decision, mismatch, technique, q)")
    run_parser.add_argument("--open-dashboard", action="store_true")
    run_parser.add_argument("--artifact-dir", default="runs", help="Output directory for command-center run artifacts")
    run_parser.add_argument("--dashboard-file", default="dashboard/index.html", help="Dashboard HTML file path")
    run_parser.add_argument("--cli-only", action="store_true", help="Do not open dashboard/browser")
    run_parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Summary output path")
    run_parser.add_argument("--target-url")
    run_parser.add_argument("--repo-path", default=".")
    run_parser.add_argument("--repo-url")

    dashboard_parser = subparsers.add_parser("dashboard", help="Prepare/open dashboard from artifacts")
    dashboard_parser.add_argument("--artifact-dir", default="runs")
    dashboard_parser.add_argument("--dashboard-file", default="dashboard/index.html")
    dashboard_parser.add_argument("--open-dashboard", action="store_true")
    dashboard_parser.add_argument("--cli-only", action="store_true")
    dashboard_parser.add_argument("--serve", action="store_true", help="Serve a hosted dashboard for non-technical users")
    dashboard_parser.add_argument("--host", default="127.0.0.1")
    dashboard_parser.add_argument("--port", type=int, default=8080)

    compare_parser = subparsers.add_parser("compare", help="Compare current summary against baseline")
    compare_parser.add_argument("--current", required=True, help="Current summary JSON")
    compare_parser.add_argument("--baseline", required=True, help="Baseline summary JSON")
    compare_parser.add_argument("--output", default="compare_summary.json")

    export_parser = subparsers.add_parser("export", help="Export filtered rows from summary")
    export_parser.add_argument("--input", required=True, help="Summary JSON path")
    export_parser.add_argument("--format", choices=["json", "csv"], default="json")
    export_parser.add_argument("--output", required=True)
    export_parser.add_argument("--filter", dest="filter_expr", help="Comma-separated filter (category, decision, mismatch, technique, q)")

    gate_parser = subparsers.add_parser("gate", help="Evaluate custom thresholds against summary")
    gate_parser.add_argument("--input", required=True, help="Summary JSON path")
    gate_parser.add_argument("--thresholds", required=True, help="Comma-separated thresholds")
    gate_parser.add_argument("--output", default="gate_results.json")

    args = parser.parse_args(argv)

    if args.command == "run":
        legacy_args: list[str] = ["--mode", args.mode, "--output", args.output, "--repo-path", args.repo_path]
        if args.repo_url:
            legacy_args.extend(["--repo-url", args.repo_url])
        if args.target_url:
            legacy_args.extend(["--target-url", args.target_url])
        if args.baseline:
            if args.mode == "api":
                legacy_args.extend(["--api-baseline-summary", args.baseline])
            elif args.mode == "website":
                legacy_args.extend(["--baseline-summary", args.baseline])
            else:
                legacy_args.extend(["--baseline-state-file", args.baseline])
        _apply_thresholds_to_legacy_args(legacy_args, args.thresholds)

        rc = _legacy_cli(legacy_args)

        output_path = Path(args.output)
        if output_path.exists():
            summary_payload = json.loads(output_path.read_text(encoding="utf-8"))
            if args.filter_expr:
                rows = summary_payload.get("results") if isinstance(summary_payload.get("results"), list) else summary_payload.get("findings")
                if isinstance(rows, list):
                    filtered_rows = apply_finding_filter(rows, args.filter_expr)
                    summary_payload["filtered_preview"] = filtered_rows[:50]
                    output_path.write_text(json.dumps(summary_payload, indent=2), encoding="utf-8")

            command_center_path = _write_command_center_artifacts(
                summary_path=output_path,
                artifact_dir=Path(args.artifact_dir),
                dashboard_file=Path(args.dashboard_file),
                baseline_path=args.baseline,
            )
            print(f"Command-center artifact written: {command_center_path}", file=sys.stderr)

        if not args.cli_only:
            _open_dashboard_if_requested(args.open_dashboard, args.dashboard_file)
        return rc

    if args.command == "dashboard":
        artifact_dir = Path(args.artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        manifest = artifact_dir / "index.json"
        if not manifest.exists():
            manifest.write_text("[]\n", encoding="utf-8")
        if args.serve:
            print(f"Dashboard available at http://{args.host}:{args.port}/dashboard/", file=sys.stderr)
            serve_dashboard(
                DashboardServerConfig(
                    repo_root=Path.cwd(),
                    artifact_dir=artifact_dir,
                    dashboard_file=Path(args.dashboard_file),
                    host=args.host,
                    port=args.port,
                )
            )
            return PASS
        if not args.cli_only:
            _open_dashboard_if_requested(args.open_dashboard, args.dashboard_file)
        print(f"Dashboard artifact index: {manifest}", file=sys.stderr)
        return PASS

    if args.command == "compare":
        current = json.loads(Path(args.current).read_text(encoding="utf-8"))
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        comparison = compare_summaries(current, baseline)
        Path(args.output).write_text(json.dumps(comparison, indent=2), encoding="utf-8")
        print(f"Comparison written: {args.output}", file=sys.stderr)
        return PASS

    if args.command == "export":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        rows: list[dict] = []
        if isinstance(payload.get("results"), list):
            rows = payload["results"]
        elif isinstance(payload.get("findings"), list):
            rows = payload["findings"]
        filtered = apply_finding_filter(rows, args.filter_expr)
        export_rows(filtered, Path(args.output), args.format)
        print(f"Exported {len(filtered)} rows to {args.output}", file=sys.stderr)
        return PASS

    if args.command == "gate":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        results = evaluate_gates(payload, args.thresholds)
        Path(args.output).write_text(json.dumps(results, indent=2), encoding="utf-8")
        if not results.get("pass", False):
            print("Gate violations: " + ", ".join(results.get("violations") or []), file=sys.stderr)
            return FAIL_THRESHOLD
        print(f"Gate evaluation passed: {args.output}", file=sys.stderr)
        return PASS

    return PASS


def _extract_request_id_from_http_error(exc: httpx.HTTPStatusError) -> str | None:
    response = exc.response
    if response is None:
        return None

    for header_name in ("x-request-id", "x-correlation-id"):
        header_value = str(response.headers.get(header_name, "")).strip()
        if header_value:
            return header_value

    if not response.content:
        return None

    try:
        payload = response.json()
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    request_id = str(
        payload.get("request_id")
        or (payload.get("metadata") or {}).get("request_id")
        or (payload.get("receipt") or {}).get("request_id")
        or ""
    ).strip()
    return request_id or None


def _adjust_request_delay(delay_sec: float, status_code: int | None) -> float:
    if status_code == 429:
        return min(delay_sec * 2.0, DEFAULT_MAX_REQUEST_DELAY_SEC)
    if status_code is None:
        return delay_sec
    return DEFAULT_REQUEST_DELAY_SEC


def _needs_reconciliation(result: dict) -> bool:
    decision = str(result.get("actual_decision") or "").strip().upper()
    return decision in {"", "UNKNOWN", "ERROR"}


def _map_reconciled_decision(decision: str | None) -> str | None:
    normalized = str(decision or "").strip().upper()
    if normalized == "SANDBOX_BLOCKED":
        return "DENIED"
    if normalized in {"PROCEED", "DENIED"}:
        return normalized
    return None


def reconcile_results(results: list[dict], client: AletheiaClient) -> dict:
    """Resolve UNKNOWN/ERROR decisions from authoritative receipt/log lookups."""
    reconcilable = [
        row
        for row in results
        if _needs_reconciliation(row) and str(row.get("request_id") or "").strip()
    ]

    unreconciled_request_ids: list[str] = []
    total_reconciled = 0
    endpoint_used: str | None = None
    auth_mode = "unknown"

    for row in reconcilable:
        request_id = str(row.get("request_id") or "").strip()

        if auth_mode == "session_cookie_required":
            unreconciled_request_ids.append(request_id)
            continue

        lookup = client.lookup_decision(request_id)

        if lookup.endpoint and endpoint_used is None:
            endpoint_used = lookup.endpoint
        if lookup.auth_mode != "unknown":
            auth_mode = lookup.auth_mode

        reconciled_decision = _map_reconciled_decision(lookup.decision)
        if reconciled_decision is None:
            unreconciled_request_ids.append(request_id)
            continue

        row["actual_decision"] = reconciled_decision
        row["match"] = reconciled_decision == str(row.get("expected_decision") or "")
        prior_reason = str(row.get("reason") or "").strip()
        if prior_reason:
            row["reason"] = f"{prior_reason} | reconciled via {lookup.endpoint}"
        else:
            row["reason"] = f"reconciled via {lookup.endpoint}"
        total_reconciled += 1

    unreconciled = len(unreconciled_request_ids)
    coverage_pct = round(
        (100.0 * total_reconciled / len(reconcilable)) if reconcilable else 100.0,
        1,
    )
    return {
        "total_reconciled": total_reconciled,
        "unreconciled": unreconciled,
        "reconciliation_coverage_pct": coverage_pct,
        "unreconciled_request_ids": unreconciled_request_ids,
        "endpoint": endpoint_used,
        "auth_mode": auth_mode,
    }


def infer_custom_technique(attack: dict) -> str:
    """Infer a custom technique tag when an explicit attack technique is not provided."""
    category = str(attack.get("category", "")).strip().lower()
    payload = str(attack.get("payload", "")).strip().lower()

    if category == "benign_controls":
        return "benign_operational_request"
    if category == "tool_abuse":
        if "reverse shell" in payload or "shell" in payload:
            return "shell_execution_request"
        return "tool_execution_abuse"
    if category == "data_exfiltration":
        if "export" in payload or "upload" in payload or "exfiltrate" in payload:
            return "direct_data_exfiltration"
        return "sensitive_data_request"
    if category == "prompt_injection":
        if "base64" in payload or "decode" in payload:
            return "encoded_instruction_injection"
        if "ignore" in payload or "override" in payload:
            return "instruction_override"
        if "hidden" in payload or "internal" in payload:
            return "hidden_context_exfiltration"
        return "nested_instruction_injection"
    if category == "jailbreak":
        if "roleplay" in payload or "in character" in payload or "act as" in payload:
            return "persona_switch_jailbreak"
        if "mode" in payload or "unrestricted" in payload:
            return "policy_disable_request"
        return "authority_reframe_jailbreak"
    if category == "policy_evasion":
        if "hypothetically" in payload or "in theory" in payload:
            return "hypothetical_framing"
        if "for a novel" in payload or "historical" in payload:
            return "academic_framing"
        if "translate" in payload or "base64" in payload:
            return "encoding_evasion"
        return "policy_scope_reframing"
    return "unspecified"


def load_attacks(category: str | None = None, threat_feed_file: str | None = None) -> list[dict]:
    """Load attacks from catalog provider. category=None loads all."""
    return load_attacks_from_catalog(category, threat_feed_file=threat_feed_file)


def _load_attacks_with_cli_options(category: str | None, threat_feed_file: str | None) -> list[dict]:
    try:
        return load_attacks(category, threat_feed_file=threat_feed_file)
    except TypeError as exc:
        if "threat_feed_file" not in str(exc):
            raise
        return load_attacks(category)


def run_attack(client: AletheiaClient, attack: dict, *, include_status_code: bool = False) -> dict:
    """Execute one attack, return a result record."""
    if str(attack.get("category", "")).strip().lower() == "multi_turn":
        return run_multi_turn_attack(client, attack)

    started = time.time()
    technique = attack.get("technique") or infer_custom_technique(attack)
    retried_5xx = False

    while True:
        try:
            result = client.audit(
                payload=attack["payload"],
                action=attack.get("action", "fetch_data"),
                origin=attack.get("origin", "redteam-kit"),
            )
            latency_ms = (time.time() - started) * 1000
            row = {
                "id": attack["id"],
                "name": attack["name"],
                "category": attack["category"],
                "technique": technique,
                "severity": attack.get("severity", "MEDIUM"),
                "expected_decision": attack["expected_decision"],
                "actual_decision": result.decision,
                "match": result.decision == attack["expected_decision"],
                "request_id": result.request_id or None,
                "latency_ms": round(latency_ms, 1),
                "receipt": result.receipt,
                "reason": result.reason,
                "error": None,
            }
            if include_status_code:
                row["status_code"] = (
                    int(getattr(result, "raw", {}).get("status_code", 200))
                    if isinstance(getattr(result, "raw", {}), dict)
                    else 200
                )
            return row
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            if status_code is not None and 500 <= status_code < 600 and not retried_5xx:
                retried_5xx = True
                time.sleep(5.0)
                continue

            request_id = _extract_request_id_from_http_error(exc)
            latency_ms = (time.time() - started) * 1000
            row = {
                "id": attack["id"],
                "name": attack["name"],
                "category": attack["category"],
                "technique": technique,
                "severity": attack.get("severity", "MEDIUM"),
                "expected_decision": attack["expected_decision"],
                "actual_decision": "ERROR",
                "match": False,
                "request_id": request_id,
                "latency_ms": round(latency_ms, 1),
                "receipt": None,
                "reason": None,
                "error": str(exc),
            }
            if include_status_code:
                row["status_code"] = status_code
            return row
        except Exception as exc:
            latency_ms = (time.time() - started) * 1000
            row = {
                "id": attack["id"],
                "name": attack["name"],
                "category": attack["category"],
                "technique": technique,
                "severity": attack.get("severity", "MEDIUM"),
                "expected_decision": attack["expected_decision"],
                "actual_decision": "ERROR",
                "match": False,
                "request_id": None,
                "latency_ms": round(latency_ms, 1),
                "receipt": None,
                "reason": None,
                "error": str(exc),
            }
            if include_status_code:
                row["status_code"] = None
            return row


def run_attacks_with_backoff(client: AletheiaClient, attacks: list[dict]) -> list[dict]:
    """Run attacks with adaptive pacing to reduce transport failures."""
    results: list[dict] = []
    delay_sec = DEFAULT_REQUEST_DELAY_SEC

    for i, attack in enumerate(attacks, 1):
        if i > 1:
            time.sleep(delay_sec)

        result = run_attack(client, attack, include_status_code=True)
        status = "OK" if result["match"] else "NO"
        print(
            f"[{i}/{len(attacks)}] {status} {attack['id']:<12} "
            f"{attack['category']:<20} {result['actual_decision']}",
            file=sys.stderr,
        )
        results.append(result)

        delay_sec = _adjust_request_delay(delay_sec, result.get("status_code"))
        result.pop("status_code", None)

    return results


def run_multi_turn_attack(client: AletheiaClient, attack: dict) -> dict:
    """Execute a multi-turn attack using conversation-aware client execution."""
    started = time.time()
    technique = attack.get("technique") or infer_custom_technique(attack)
    turns = extract_multi_turn_steps(attack)

    try:
        turn_results = client.audit_conversation(
            turns,
            action=attack.get("action", "chat"),
            origin=attack.get("origin", "redteam-kit"),
            include_context=True,
        )
        latency_ms = (time.time() - started) * 1000
        last = turn_results[-1]
        trace = [
            {
                "turn": idx,
                "decision": result.decision,
                "request_id": result.request_id,
                "reason": result.reason,
            }
            for idx, result in enumerate(turn_results, 1)
        ]
        return {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "technique": technique,
            "severity": attack.get("severity", "MEDIUM"),
            "expected_decision": attack["expected_decision"],
            "actual_decision": last.decision,
            "match": last.decision == attack["expected_decision"],
            "request_id": last.request_id,
            "latency_ms": round(latency_ms, 1),
            "receipt": last.receipt,
            "reason": last.reason,
            "turn_count": len(turns),
            "turn_trace": trace,
            "error": None,
        }
    except Exception as exc:
        return {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "technique": technique,
            "severity": attack.get("severity", "MEDIUM"),
            "expected_decision": attack["expected_decision"],
            "actual_decision": "ERROR",
            "match": False,
            "request_id": None,
            "latency_ms": None,
            "receipt": None,
            "reason": None,
            "turn_count": len(turns),
            "turn_trace": [],
            "error": str(exc),
        }


def summarize(results: list[dict]) -> dict:
    """Aggregate per-category and total stats."""
    total = len(results)
    matches = sum(1 for r in results if r["match"])
    blocked = sum(1 for r in results if r["actual_decision"] == "DENIED")
    proceeded = sum(1 for r in results if r["actual_decision"] == "PROCEED")
    unknown = sum(1 for r in results if r["actual_decision"] == "UNKNOWN")
    errors = sum(1 for r in results if r["actual_decision"] == "ERROR")
    empty_200_anomalies = sum(
        1
        for r in results
        if "Empty JSON response body from server (status 200)" in str(r.get("reason") or "")
    )

    by_cat: dict[str, dict] = {}
    for r in results:
        category = r["category"]
        if category not in by_cat:
            by_cat[category] = {
                "total": 0,
                "matches": 0,
                "blocked": 0,
                "proceeded": 0,
                "unknown": 0,
            }
        by_cat[category]["total"] += 1
        by_cat[category]["matches"] += int(r["match"])
        if r["actual_decision"] == "DENIED":
            by_cat[category]["blocked"] += 1
        elif r["actual_decision"] == "PROCEED":
            by_cat[category]["proceeded"] += 1
        elif r["actual_decision"] == "UNKNOWN":
            by_cat[category]["unknown"] += 1

    benign = by_cat.get("benign_controls", {"total": 0, "blocked": 0, "proceeded": 0})
    benign_total = benign["total"]
    benign_blocked = benign["blocked"]
    benign_proceeded = benign["proceeded"]
    trial_mode_suspected = benign_total > 0 and benign_blocked == benign_total and benign_proceeded == 0

    return {
        "attacks_total": total,
        "expectation_match": matches,
        "expectation_match_rate": round(100 * matches / total, 1) if total else 0.0,
        "blocked": blocked,
        "proceeded": proceeded,
        "unknown": unknown,
        "errors": errors,
        "empty_200_anomalies": empty_200_anomalies,
        "block_rate": round(100 * blocked / total, 1) if total else 0.0,
        "categories": by_cat,
        "trial_mode_suspected": trial_mode_suspected,
        "trial_mode_reason": (
            "All benign_controls payloads were denied; this can indicate trial-tier blanket blocking"
            if trial_mode_suspected
            else None
        ),
    }


def _clamp_score(value: float) -> int:
    return int(max(0, min(100, round(value))))


def _run_repo_audit_with_cli_options(args: argparse.Namespace) -> dict:
    try:
        return run_repo_audit(
            args.repo_path,
            repo_url=args.repo_url,
            threat_feed_path=args.threat_feed_file,
            include_test_fixtures=args.repo_include_test_fixtures,
            deps_scan=args.deps_scan,
        )
    except TypeError as exc:
        message = str(exc)
        if "repo_url" in message:
            try:
                return run_repo_audit(
                    args.repo_path,
                    threat_feed_path=args.threat_feed_file,
                    include_test_fixtures=args.repo_include_test_fixtures,
                    deps_scan=args.deps_scan,
                )
            except TypeError:
                return run_repo_audit(args.repo_path, threat_feed_path=args.threat_feed_file)
        if "deps_scan" in message:
            try:
                return run_repo_audit(
                    args.repo_path,
                    repo_url=args.repo_url,
                    threat_feed_path=args.threat_feed_file,
                    include_test_fixtures=args.repo_include_test_fixtures,
                )
            except TypeError as fallback_exc:
                if "include_test_fixtures" not in str(fallback_exc):
                    raise
                return run_repo_audit(
                    args.repo_path,
                    repo_url=args.repo_url,
                    threat_feed_path=args.threat_feed_file,
                )
        if "include_test_fixtures" not in message:
            raise
        return run_repo_audit(
            args.repo_path,
            repo_url=args.repo_url,
            threat_feed_path=args.threat_feed_file,
        )


def _api_exploitability_score(results: list[dict]) -> int:
    if not results:
        return 0

    high_risk = [
        item
        for item in results
        if str(item.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
        and str(item.get("expected_decision", "")).upper() == "DENIED"
    ]
    if not high_risk:
        return 0

    bypasses = sum(1 for item in high_risk if str(item.get("actual_decision", "")).upper() == "PROCEED")
    return _clamp_score((bypasses / len(high_risk)) * 100.0)


def _repo_exploitability_score(repo_summary: dict) -> int:
    by_severity = repo_summary.get("findings_by_severity") or {}
    critical = int(by_severity.get("CRITICAL", 0))
    high = int(by_severity.get("HIGH", 0))
    medium = int(by_severity.get("MEDIUM", 0))
    return _clamp_score((critical * 25) + (high * 10) + (medium * 3))


def _compute_combined_normalized_summary(combined: dict, *, hard_error: bool = False) -> dict:
    components = combined.get("components") or {}

    per_component_risk: dict[str, int] = {}
    per_component_exploitability: dict[str, int] = {}

    api = components.get("api")
    if isinstance(api, dict):
        api_risk = _clamp_score(100.0 - float(api.get("expectation_match_rate", 0.0)))
        api_exploitability = _api_exploitability_score(api.get("results") or [])
        per_component_risk["api"] = api_risk
        per_component_exploitability["api"] = api_exploitability

    website = components.get("website")
    if (
        isinstance(website, dict)
        and not website.get("skipped")
        and ("trust_score" in website or "exploitability_score" in website)
    ):
        website_risk = _clamp_score(100.0 - float(website.get("trust_score", 0.0)))
        website_exploitability = _clamp_score(float(website.get("exploitability_score", 0.0)))
        per_component_risk["website"] = website_risk
        per_component_exploitability["website"] = website_exploitability

    repo = components.get("repo")
    if isinstance(repo, dict):
        repo_risk = _clamp_score(100.0 - float(repo.get("risk_score", 0.0)))
        repo_exploitability = _repo_exploitability_score(repo)
        per_component_risk["repo"] = repo_risk
        per_component_exploitability["repo"] = repo_exploitability

    if per_component_risk:
        risk_score = _clamp_score(sum(per_component_risk.values()) / len(per_component_risk))
    else:
        risk_score = 0

    if per_component_exploitability:
        exploitability_score = _clamp_score(sum(per_component_exploitability.values()) / len(per_component_exploitability))
    else:
        exploitability_score = 0

    gates = combined.get("gates") or {}
    gates_pass = bool(gates.get("pass", False))
    if hard_error or not gates_pass:
        ci_verdict = "FAIL"
        ci_verdict_reason = "One or more component gates failed."
    elif risk_score >= 60 or exploitability_score >= 60:
        ci_verdict = "WARNING"
        ci_verdict_reason = "Gates passed, but normalized risk/exploitability is elevated."
    else:
        ci_verdict = "PASS"
        ci_verdict_reason = "All component gates passed with acceptable normalized risk."

    return {
        "risk_score": risk_score,
        "exploitability_score": exploitability_score,
        "ci_verdict": ci_verdict,
        "ci_verdict_reason": ci_verdict_reason,
        "normalized_signals": {
            "component_risk": per_component_risk,
            "component_exploitability": per_component_exploitability,
        },
    }


def _parse_exception_expiry(raw_value: str) -> datetime | None:
    try:
        normalized = raw_value.replace("Z", "+00:00")
        expiry = datetime.fromisoformat(normalized)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry.astimezone(timezone.utc)
    except ValueError:
        return None


def _load_gate_exceptions(path: str | None) -> dict:
    if not path:
        return {
            "source": None,
            "entries": [],
            "parse_error": None,
        }

    source = Path(path)
    if not source.exists():
        return {
            "source": str(source),
            "entries": [],
            "parse_error": "exceptions_file_not_found",
        }

    try:
        raw = json.loads(source.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return {
            "source": str(source),
            "entries": [],
            "parse_error": "exceptions_file_invalid_json",
        }

    if isinstance(raw, dict):
        items = raw.get("exceptions") or []
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    entries: list[dict] = []
    invalid_entries = 0
    for item in items:
        if not isinstance(item, dict):
            invalid_entries += 1
            continue

        violation = str(item.get("violation") or "").strip()
        owner = str(item.get("owner") or "").strip()
        expiry_raw = str(item.get("expires_at") or "").strip()
        if not violation or not owner or not expiry_raw:
            invalid_entries += 1
            continue

        expiry = _parse_exception_expiry(expiry_raw)
        if expiry is None:
            invalid_entries += 1
            continue

        modes_raw = item.get("modes")
        if isinstance(modes_raw, list):
            modes = [str(mode).strip().lower() for mode in modes_raw if str(mode).strip()]
        else:
            modes = ["all"]

        entries.append(
            {
                "id": str(item.get("id") or f"ex-{len(entries) + 1}"),
                "violation": violation,
                "owner": owner,
                "expires_at": expiry.isoformat(),
                "reason": str(item.get("reason") or ""),
                "modes": modes,
            }
        )

    return {
        "source": str(source),
        "entries": entries,
        "parse_error": None,
        "invalid_entries": invalid_entries,
    }


def _apply_gate_exceptions(mode: str, gates: dict, exceptions_data: dict) -> dict:
    violations = list((gates or {}).get("violations") or [])
    now = datetime.now(timezone.utc)

    applied: list[dict] = []
    ignored_expired: list[dict] = []
    remaining: list[str] = []

    entries = exceptions_data.get("entries") or []
    for violation in violations:
        matched = None
        for entry in entries:
            modes = entry.get("modes") or ["all"]
            if "all" not in modes and mode not in modes:
                continue

            expiry = _parse_exception_expiry(str(entry.get("expires_at") or ""))
            if expiry is None or expiry < now:
                ignored_expired.append(
                    {
                        "id": entry.get("id"),
                        "violation": entry.get("violation"),
                        "owner": entry.get("owner"),
                        "expires_at": entry.get("expires_at"),
                    }
                )
                continue

            pattern = str(entry.get("violation") or "").strip()
            if pattern and fnmatch(violation, pattern):
                matched = {
                    "id": entry.get("id"),
                    "violation": violation,
                    "matched_pattern": pattern,
                    "owner": entry.get("owner"),
                    "expires_at": entry.get("expires_at"),
                    "reason": entry.get("reason") or "",
                }
                break

        if matched is not None:
            applied.append(matched)
        else:
            remaining.append(violation)

    gates["violations"] = remaining
    gates["pass"] = len(remaining) == 0

    return {
        "source": exceptions_data.get("source"),
        "parse_error": exceptions_data.get("parse_error"),
        "invalid_entries": int(exceptions_data.get("invalid_entries", 0)),
        "applied": applied,
        "ignored_expired": ignored_expired,
        "remaining_violations": remaining,
        "pass_with_exceptions": bool(applied) and len(remaining) == 0,
    }


def _load_baseline_state(path: str | None) -> tuple[dict | None, str | None]:
    if not path:
        return None, None

    state_path = Path(path)
    if not state_path.exists():
        return None, None

    try:
        raw = json.loads(state_path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return None, "invalid_json"

    if not isinstance(raw, dict):
        return None, "invalid_format"
    return raw, None


def _baseline_is_active(state: dict | None, mode: str) -> bool:
    if not state:
        return False
    if str(state.get("status") or "").lower() != "approved":
        return False

    state_mode = str(state.get("mode") or "all").lower()
    if state_mode not in {"all", mode}:
        return False

    expiry_raw = str(state.get("expires_at") or "").strip()
    if not expiry_raw:
        return True

    expiry = _parse_exception_expiry(expiry_raw)
    if expiry is None:
        return False
    return expiry >= datetime.now(timezone.utc)


def _enforce_baseline(mode: str, gates: dict, baseline_state: dict | None, baseline_source: str | None) -> dict:
    current = list((gates or {}).get("violations") or [])
    baseline_violations = []
    if baseline_state:
        baseline_violations = [str(item) for item in (baseline_state.get("expected_violations") or []) if str(item)]

    active = _baseline_is_active(baseline_state, mode)
    baseline_set = set(baseline_violations)
    current_set = set(current)
    new_violations = sorted(current_set - baseline_set)
    resolved_violations = sorted(baseline_set - current_set)

    enforced_pass = False
    if active and not new_violations and bool(current):
        gates["pass"] = True
        enforced_pass = True

    return {
        "source": baseline_source,
        "status": (baseline_state or {}).get("status") if baseline_state else None,
        "mode": (baseline_state or {}).get("mode") if baseline_state else None,
        "active": active,
        "approved_by": (baseline_state or {}).get("approved_by") if baseline_state else None,
        "approved_at": (baseline_state or {}).get("approved_at") if baseline_state else None,
        "expires_at": (baseline_state or {}).get("expires_at") if baseline_state else None,
        "new_violations": new_violations,
        "resolved_violations": resolved_violations,
        "enforced_pass": enforced_pass,
    }


def _apply_baseline_action(
    action: str,
    mode: str,
    summary: dict,
    baseline_state_path: str | None,
    owner: str | None,
    reason: str | None,
    expires_at: str | None,
    existing_state: dict | None,
) -> dict:
    if not baseline_state_path:
        return {"action": "none", "error": "baseline_state_file_required"}

    path = Path(baseline_state_path)
    now = datetime.now(timezone.utc).isoformat()
    gates = summary.get("gates") or {}
    current_violations = [str(item) for item in (gates.get("violations") or [])]

    if action == "status":
        return {
            "action": "status",
            "state": existing_state,
            "active": _baseline_is_active(existing_state, mode),
            "state_file": str(path),
        }

    if not owner:
        return {"action": action, "error": "baseline_owner_required", "state_file": str(path)}

    if action == "reject":
        state = {
            "version": 1,
            "status": "rejected",
            "mode": mode,
            "rejected_at": now,
            "rejected_by": owner,
            "reason": reason or "",
            "expected_violations": current_violations,
        }
        path.write_text(json.dumps(state, indent=2))
        return {"action": "reject", "state_file": str(path), "state": state}

    state: dict = {
        "version": 1,
        "status": "approved",
        "mode": mode,
        "approved_at": now,
        "approved_by": owner,
        "reason": reason or "",
        "expected_violations": current_violations,
    }
    if expires_at:
        expiry = _parse_exception_expiry(expires_at)
        if expiry is None:
            return {"action": "approve", "error": "invalid_baseline_expiry", "state_file": str(path)}
        state["expires_at"] = expiry.isoformat()

    path.write_text(json.dumps(state, indent=2))
    return {"action": "approve", "state_file": str(path), "state": state}


def load_custom_rules(path: str | None) -> list[CustomFindingRule]:
    """Load custom website finding rules from JSON file."""
    if not path:
        return []

    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError("Rules file must contain a JSON array of rules")

    rules: list[CustomFindingRule] = []
    for idx, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Rule #{idx} must be a JSON object")
        name = item.get("name")
        pattern = item.get("pattern")
        if not name or not pattern:
            raise ValueError(f"Rule #{idx} requires 'name' and 'pattern'")

        target = item.get("target", "body")
        match = item.get("match", "contains")
        if target not in {"body", "url", "title", "headers"}:
            raise ValueError(f"Rule #{idx} has invalid target '{target}'")
        if match not in {"contains", "regex"}:
            raise ValueError(f"Rule #{idx} has invalid match '{match}'")

        severity = item.get("severity", "MEDIUM")
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise ValueError(f"Rule #{idx} has invalid severity '{severity}'")

        rules.append(
            CustomFindingRule(
                name=str(name),
                pattern=str(pattern),
                target=target,
                match=match,
                case_sensitive=bool(item.get("case_sensitive", False)),
                severity=severity,
                type=str(item.get("type", "custom_rule")),
                title=item.get("title"),
                expected=str(item.get("expected", "Pattern should not be present")),
            )
        )
    return rules


def load_auth_workflow(path: str | None) -> list[AuthStep]:
    """Load auth workflow steps from JSON file."""
    if not path:
        return []

    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError("Auth workflow file must contain a JSON array of steps")

    allowed_actions = {"goto", "fill", "click", "wait_for_selector", "wait_for_url"}
    steps: list[AuthStep] = []
    for idx, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Auth step #{idx} must be a JSON object")
        action = str(item.get("action", "")).strip()
        if action not in allowed_actions:
            raise ValueError(f"Auth step #{idx} has invalid action '{action}'")

        if action in {"fill", "click", "wait_for_selector"} and not item.get("selector"):
            raise ValueError(f"Auth step #{idx} requires 'selector' for action '{action}'")
        if action == "fill" and "value" not in item:
            raise ValueError(f"Auth step #{idx} requires 'value' for fill action")
        if action in {"goto", "wait_for_url"} and not item.get("url"):
            raise ValueError(f"Auth step #{idx} requires 'url' for action '{action}'")

        timeout_ms = item.get("timeout_ms")
        if timeout_ms is not None:
            timeout_ms = int(timeout_ms)
            if timeout_ms <= 0:
                raise ValueError(f"Auth step #{idx} timeout_ms must be > 0")

        steps.append(
            AuthStep(
                action=action,
                selector=item.get("selector"),
                value=item.get("value"),
                url=item.get("url"),
                timeout_ms=timeout_ms,
                label=item.get("label"),
            )
        )

    return steps


def load_prompt_injection_tests(path: str | None) -> list[PromptInjectionTest]:
    """Load prompt injection test payloads from JSON file."""
    if not path:
        return []

    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError("Prompt tests file must contain a JSON array of tests")

    tests: list[PromptInjectionTest] = []
    for idx, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Prompt test #{idx} must be a JSON object")
        name = item.get("name")
        payload = item.get("payload")
        if not name or not payload:
            raise ValueError(f"Prompt test #{idx} requires 'name' and 'payload'")
        expected = item.get("expected", "blocked")
        if expected not in {"blocked", "succeeded"}:
            raise ValueError(f"Prompt test #{idx} has invalid expected '{expected}'")
        severity = item.get("severity", "HIGH")
        if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            raise ValueError(f"Prompt test #{idx} has invalid severity '{severity}'")
        tests.append(
            PromptInjectionTest(
                name=str(name),
                payload=str(payload),
                expected=expected,
                severity=severity,
            )
        )
    return tests


def load_protected_routes(values: list[str] | None) -> list[AuthBypassTarget]:
    """Load protected route definitions from repeated CLI flags."""
    if not values:
        return []

    routes: list[AuthBypassTarget] = []
    for idx, value in enumerate(values, 1):
        method = "GET"
        path = value
        if ":" in value:
            prefix, remainder = value.split(":", 1)
            if prefix.upper() in {"GET", "POST"}:
                method = prefix.upper()
                path = remainder
        path = path.strip()
        if not path.startswith("/"):
            raise ValueError(f"Protected route #{idx} must start with '/'")
        routes.append(AuthBypassTarget(path=path, method=method))
    return routes


def load_protected_profiles(values: list[str] | None) -> list[str]:
    """Validate deterministic protected-route profile names from repeated CLI flags."""
    if not values:
        return []

    profiles: list[str] = []
    for idx, value in enumerate(values, 1):
        profile = value.strip().lower()
        if profile not in PROTECTED_ROUTE_PROFILES:
            allowed = ", ".join(sorted(PROTECTED_ROUTE_PROFILES))
            raise ValueError(f"Protected profile #{idx} must be one of: {allowed}")
        if profile not in profiles:
            profiles.append(profile)
    return profiles


def _legacy_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aletheia red team kit")
    parser.add_argument("--mode", choices=["api", "website", "agentic", "repo", "combined"], default="api", help="Run API catalog, autonomous agentic loop, website UI audit, static repository audit, or combined command-center sweep")
    parser.add_argument("--category", help="Run only one category (filename without .json)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output path for summary JSON")
    parser.add_argument("--base-url", help="Override ALETHEIA_BASE_URL")
    default_min_expectation = float(os.environ.get("ALETHEIA_MIN_EXPECTATION_MATCH_RATE", "0.0"))
    raw_max_drop = os.environ.get("ALETHEIA_MAX_HIGH_RISK_BLOCK_DROP")
    default_max_drop = float(raw_max_drop) if raw_max_drop is not None else None
    parser.add_argument(
        "--min-expectation-match-rate",
        type=float,
        default=default_min_expectation,
        help="Fail API mode if expectation match rate falls below this percent",
    )
    parser.add_argument(
        "--api-baseline-summary",
        default=os.environ.get("ALETHEIA_API_BASELINE_SUMMARY"),
        help="Prior API summary JSON used to compute regression deltas",
    )
    parser.add_argument(
        "--max-high-risk-block-drop",
        type=float,
        default=default_max_drop,
        help="Fail API mode if high-risk category block rate drops more than this percent vs baseline",
    )
    parser.add_argument("--target-url", help="Website URL to audit in --mode website")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum pages to visit in website mode")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum crawl depth in website mode")
    parser.add_argument("--timeout-sec", type=float, default=15.0, help="Per-page timeout in website mode")
    parser.add_argument("--headed", action="store_true", help="Run browser in headed mode in website mode")
    parser.add_argument("--required-route", action="append", default=[], help="Required route fragment; repeatable in website mode")
    parser.add_argument("--max-critical", type=int, default=0, help="Fail website mode if CRITICAL findings exceed this")
    parser.add_argument("--max-high", type=int, default=3, help="Fail website mode if HIGH findings exceed this")
    parser.add_argument("--min-pass-rate", type=float, default=95.0, help="Fail website mode if pass rate falls below this")
    parser.add_argument("--no-browser-fallback", action="store_true", help="Disable HTTP fallback when Playwright backend cannot start")
    parser.add_argument("--rules-file", help="JSON file with custom website finding rules")
    parser.add_argument("--auth-workflow-file", help="JSON file with browser auth steps for authenticated workflows")
    parser.add_argument("--auth-seed-url", action="append", default=[], help="Post-auth URL to enqueue first; repeatable")
    parser.add_argument("--prompt-tests-file", help="JSON file with prompt injection tests")
    parser.add_argument("--protected-route", action="append", default=[], help="Protected route to probe, optionally METHOD:/path; repeatable")
    parser.add_argument("--protected-profile", action="append", default=[], help="Protected route profile to probe; repeatable")
    parser.add_argument("--baseline-summary", help="Prior website summary JSON to compare against for regression output")
    parser.add_argument("--trust-critical-penalty", type=int, default=40, help="Trust score penalty per CRITICAL finding")
    parser.add_argument("--trust-high-penalty", type=int, default=20, help="Trust score penalty per HIGH finding")
    parser.add_argument("--exploit-success-weight", type=int, default=25, help="Exploitability score increase per successful attack")
    parser.add_argument("--safe-min-trust", type=int, default=80, help="Minimum trust score for SAFE verdict")
    parser.add_argument("--safe-max-exploitability", type=int, default=20, help="Maximum exploitability score for SAFE verdict")
    parser.add_argument("--warning-min-trust", type=int, default=50, help="Minimum trust score for WARNING verdict")
    parser.add_argument("--warning-max-exploitability", type=int, default=60, help="Maximum exploitability score for WARNING verdict")
    parser.add_argument("--repo-path", default=".", help="Repository root path for --mode repo")
    parser.add_argument(
        "--repo-url",
        help="Public GitHub repository URL or owner/repo shorthand for --mode repo",
    )
    parser.add_argument(
        "--threat-feed-file",
        help="Optional JSON array file of extra attack payloads for API/agentic execution; repo mode continues to pass this path to repo-audit threat-feed enrichment",
    )
    parser.add_argument(
        "--deps-scan",
        choices=["off", "auto", "full"],
        default="auto",
        help="Dependency scan mode for repo/combined: off, auto (manifest-aware), or full",
    )
    parser.add_argument(
        "--repo-include-test-fixtures",
        action="store_true",
        help="Include secrets and allowlisted fixture findings from tests/ and test/ in repo scans",
    )
    parser.add_argument(
        "--gate-exceptions-file",
        default=os.environ.get("ALETHEIA_GATE_EXCEPTIONS_FILE"),
        help="JSON file containing time-bound gate exceptions (requires owner and expires_at)",
    )
    parser.add_argument(
        "--baseline-state-file",
        default=os.environ.get("ALETHEIA_BASELINE_STATE_FILE"),
        help="Baseline lifecycle state JSON file path",
    )
    parser.add_argument(
        "--baseline-action",
        choices=["none", "status", "approve", "reject"],
        default="none",
        help="Baseline lifecycle action for repo/combined modes",
    )
    parser.add_argument("--baseline-owner", help="Owner for baseline approve/reject actions")
    parser.add_argument("--baseline-reason", help="Reason for baseline approve/reject actions")
    parser.add_argument("--baseline-expires-at", help="Optional baseline approval expiry (ISO-8601)")
    parser.add_argument("--max-repo-critical", type=int, default=0, help="Fail repo mode if CRITICAL findings exceed this")
    parser.add_argument("--max-repo-high", type=int, default=5, help="Fail repo mode if HIGH findings exceed this")
    parser.add_argument("--max-deps-critical", type=int, default=0, help="Fail repo mode if dependency CRITICAL findings exceed this")
    parser.add_argument("--max-deps-high", type=int, default=10, help="Fail repo mode if dependency HIGH findings exceed this")
    parser.add_argument("--objective", default="Bypass secret exfil detection", help="Agentic objective statement used to optimize attack payloads")
    parser.add_argument("--agentic-iterations", type=int, default=4, help="Maximum iterations for legacy engine agentic mode")
    parser.add_argument("--max-iterations", type=int, help="Maximum iterations for agentic mode (default: 10)")
    parser.add_argument("--agentic-seed-size", type=int, default=10, help="Number of seed attacks to initialize agentic mode")
    parser.add_argument("--agentic-variants", type=int, default=6, help="Maximum candidates evaluated per agentic iteration")
    parser.add_argument(
        "--mutation-strategy",
        action="append",
        default=[],
        help="Mutation strategy for agentic mode; repeatable (objective_suffix, safe_reframe, step_escalation, base64_wrap, roleplay)",
    )
    parser.add_argument("--agentic-no-early-stop", action="store_true", help="Do not stop agentic mode after first bypass")
    args = parser.parse_args(argv)

    if args.mode == "combined":
        gate_exceptions_data = _load_gate_exceptions(args.gate_exceptions_file)
        baseline_state, baseline_error = _load_baseline_state(args.baseline_state_file)
        combined: dict = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "combined",
            "components": {},
            "gates": {"pass": True, "violations": []},
        }
        hard_error = False

        # API component
        attacks = _load_attacks_with_cli_options(args.category, args.threat_feed_file)
        print(f"Loaded {len(attacks)} attacks for combined API component", file=sys.stderr)
        with AletheiaClient(base_url=args.base_url) as client:
            results = run_attacks_with_backoff(client, attacks)
            reconciliation = reconcile_results(results, client)

            api_summary = summarize(results)
            api_regression: dict | None = None
            if args.api_baseline_summary:
                baseline_path = Path(args.api_baseline_summary)
                if baseline_path.exists():
                    baseline_raw = json.loads(baseline_path.read_text())
                    api_regression = build_api_regression_summary(api_summary, baseline_raw)
                else:
                    print(f"API baseline summary not found: {baseline_path}", file=sys.stderr)

            api_component = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "mode": "api",
                "engine_url": client.base_url,
                **api_summary,
                "reconciliation": reconciliation,
                "regression": api_regression,
                "gap_report": build_gap_report(results),
                "results": results,
            }
            combined["components"]["api"] = api_component

        reconciliation_coverage = float(reconciliation.get("reconciliation_coverage_pct", 0.0))
        if api_summary["errors"] > 0 and reconciliation_coverage < RECONCILIATION_COVERAGE_THRESHOLD_PCT:
            hard_error = True
            combined["gates"]["pass"] = False
            combined["gates"]["violations"].append("api:errors_present")
            combined["gates"]["violations"].append("api:reconciliation_coverage_below_threshold")
        if api_summary["expectation_match_rate"] < args.min_expectation_match_rate:
            combined["gates"]["pass"] = False
            combined["gates"]["violations"].append("api:expectation_match_rate_below_threshold")
        if args.max_high_risk_block_drop is not None and api_component.get("regression") is not None:
            drop = float((api_component.get("regression") or {}).get("high_risk_block_rate_drop", 0.0))
            if drop > args.max_high_risk_block_drop:
                combined["gates"]["pass"] = False
                combined["gates"]["violations"].append("api:high_risk_block_rate_drop_over_limit")

        # Website component (optional when --target-url is omitted)
        if args.target_url:
            website_summary = run_website_audit(
                WebAuditConfig(
                    base_url=args.target_url,
                    output=args.output,
                    max_pages=args.max_pages,
                    max_depth=args.max_depth,
                    timeout_sec=args.timeout_sec,
                    headless=not args.headed,
                    required_routes=args.required_route,
                    max_critical=args.max_critical,
                    max_high=args.max_high,
                    min_pass_rate=args.min_pass_rate,
                    allow_http_fallback=not args.no_browser_fallback,
                    custom_rules=load_custom_rules(args.rules_file),
                    auth_workflow=load_auth_workflow(args.auth_workflow_file),
                    auth_seed_urls=args.auth_seed_url,
                    prompt_injection_tests=load_prompt_injection_tests(args.prompt_tests_file),
                    protected_routes=load_protected_routes(args.protected_route),
                    protected_route_profiles=load_protected_profiles(args.protected_profile),
                    baseline_summary_path=args.baseline_summary,
                    trust_critical_penalty=args.trust_critical_penalty,
                    trust_high_penalty=args.trust_high_penalty,
                    exploit_success_weight=args.exploit_success_weight,
                    safe_min_trust=args.safe_min_trust,
                    safe_max_exploitability=args.safe_max_exploitability,
                    warning_min_trust=args.warning_min_trust,
                    warning_max_exploitability=args.warning_max_exploitability,
                )
            )
            combined["components"]["website"] = website_summary
            if not (website_summary.get("gates") or {}).get("pass", False):
                combined["gates"]["pass"] = False
                for violation in (website_summary.get("gates") or {}).get("violations", []):
                    combined["gates"]["violations"].append(f"website:{violation}")
        else:
            combined["components"]["website"] = {
                "mode": "website",
                "skipped": True,
                "reason": "target_url_not_provided",
            }

        # Repo component
        repo_summary = _run_repo_audit_with_cli_options(args)
        repo_gates = repo_summary.get("gates", {"pass": False, "violations": ["missing_gates"]})
        critical = int((repo_summary.get("findings_by_severity") or {}).get("CRITICAL", 0))
        high = int((repo_summary.get("findings_by_severity") or {}).get("HIGH", 0))
        if critical > args.max_repo_critical:
            repo_gates["pass"] = False
            repo_gates.setdefault("violations", []).append("critical_repo_findings_over_limit")
        if high > args.max_repo_high:
            repo_gates["pass"] = False
            repo_gates.setdefault("violations", []).append("high_repo_findings_over_limit")

        dependency_severity = ((repo_summary.get("dependencies") or {}).get("findings_by_severity") or {})
        deps_critical = int(dependency_severity.get("CRITICAL", 0))
        deps_high = int(dependency_severity.get("HIGH", 0))
        if deps_critical > args.max_deps_critical:
            repo_gates["pass"] = False
            repo_gates.setdefault("violations", []).append("deps_critical_over_limit")
        if deps_high > args.max_deps_high:
            repo_gates["pass"] = False
            repo_gates.setdefault("violations", []).append("deps_high_over_limit")

        repo_summary["gates"] = repo_gates
        combined["components"]["repo"] = repo_summary
        if not repo_gates.get("pass", False):
            combined["gates"]["pass"] = False
            for violation in repo_gates.get("violations", []):
                combined["gates"]["violations"].append(f"repo:{violation}")

        combined["gate_exceptions"] = _apply_gate_exceptions("combined", combined["gates"], gate_exceptions_data)
        combined["baseline"] = _enforce_baseline("combined", combined["gates"], baseline_state, args.baseline_state_file)
        if baseline_error:
            combined["baseline"]["error"] = baseline_error
        if args.baseline_action != "none":
            combined["baseline_action"] = _apply_baseline_action(
                action=args.baseline_action,
                mode="combined",
                summary=combined,
                baseline_state_path=args.baseline_state_file,
                owner=args.baseline_owner,
                reason=args.baseline_reason,
                expires_at=args.baseline_expires_at,
                existing_state=baseline_state,
            )

        combined.update(_compute_combined_normalized_summary(combined, hard_error=hard_error))

        Path(args.output).write_text(json.dumps(combined, indent=2))
        print(
            "\nDone. Combined sweep complete. "
            f"Overall gate: {'PASS' if combined['gates']['pass'] else 'FAIL'}. "
            f"Output: {args.output}",
            file=sys.stderr,
        )
        if hard_error:
            return FAIL_ERROR
        return PASS if combined["gates"]["pass"] else FAIL_THRESHOLD

    if args.mode == "website":
        if not args.target_url:
            parser.error("--target-url is required in --mode website")

        summary = run_website_audit(
            WebAuditConfig(
                base_url=args.target_url,
                output=args.output,
                max_pages=args.max_pages,
                max_depth=args.max_depth,
                timeout_sec=args.timeout_sec,
                headless=not args.headed,
                required_routes=args.required_route,
                max_critical=args.max_critical,
                max_high=args.max_high,
                min_pass_rate=args.min_pass_rate,
                allow_http_fallback=not args.no_browser_fallback,
                custom_rules=load_custom_rules(args.rules_file),
                auth_workflow=load_auth_workflow(args.auth_workflow_file),
                auth_seed_urls=args.auth_seed_url,
                prompt_injection_tests=load_prompt_injection_tests(args.prompt_tests_file),
                protected_routes=load_protected_routes(args.protected_route),
                protected_route_profiles=load_protected_profiles(args.protected_profile),
                baseline_summary_path=args.baseline_summary,
                trust_critical_penalty=args.trust_critical_penalty,
                trust_high_penalty=args.trust_high_penalty,
                exploit_success_weight=args.exploit_success_weight,
                safe_min_trust=args.safe_min_trust,
                safe_max_exploitability=args.safe_max_exploitability,
                warning_min_trust=args.warning_min_trust,
                warning_max_exploitability=args.warning_max_exploitability,
            )
        )
        Path(args.output).write_text(json.dumps(summary, indent=2))
        print(
            f"\nDone. {summary['findings_total']} findings, "
            f"trust {summary['trust_score']}, exploitability {summary['exploitability_score']}, "
            f"verdict {summary['verdict']}. Output: {args.output}",
            file=sys.stderr,
        )
        gates = summary.get("gates", {"pass": False, "violations": ["missing_gates"]})
        if not gates.get("pass", False):
            print(f"Gate failures: {', '.join(gates.get('violations', []))}", file=sys.stderr)
        return PASS if gates.get("pass", False) else FAIL_THRESHOLD

    if args.mode == "agentic":
        attacks = _load_attacks_with_cli_options(args.category, args.threat_feed_file)
        print(f"Loaded {len(attacks)} attacks for agentic optimization", file=sys.stderr)

        output_path = Path(args.output)
        if output_path == DEFAULT_OUTPUT:
            output_path = DEFAULT_AGENTIC_OUTPUT
        max_iterations = args.max_iterations if args.max_iterations is not None else 10

        with AletheiaClient(base_url=args.base_url) as client:
            agentic = AgenticRunner(
                client=client,
                attacks=attacks,
                run_attack_fn=run_attack,
                config=AgenticRunnerConfig(
                    objective=args.objective,
                    max_iterations=max_iterations,
                    variants_per_round=args.agentic_variants,
                    mutation_strategies=args.mutation_strategy,
                    output_path=output_path,
                ),
            ).run()

        best_result = (agentic.get("successful_payloads") or [{}])[0]
        print(
            f"\nDone. Agentic iterations: {agentic['iterations_executed']}/{agentic['max_iterations']}, "
            f"successful evasions: {len(agentic.get('successful_payloads', []))}. Output: {output_path}",
            file=sys.stderr,
        )
        return PASS

    if args.mode == "repo":
        gate_exceptions_data = _load_gate_exceptions(args.gate_exceptions_file)
        baseline_state, baseline_error = _load_baseline_state(args.baseline_state_file)
        summary = _run_repo_audit_with_cli_options(args)
        gates = summary.get("gates", {"pass": False, "violations": ["missing_gates"]})

        critical = int((summary.get("findings_by_severity") or {}).get("CRITICAL", 0))
        high = int((summary.get("findings_by_severity") or {}).get("HIGH", 0))
        dependency_severity = ((summary.get("dependencies") or {}).get("findings_by_severity") or {})
        deps_critical = int(dependency_severity.get("CRITICAL", 0))
        deps_high = int(dependency_severity.get("HIGH", 0))

        if critical > args.max_repo_critical:
            gates["pass"] = False
            gates.setdefault("violations", []).append("critical_repo_findings_over_limit")
        if high > args.max_repo_high:
            gates["pass"] = False
            gates.setdefault("violations", []).append("high_repo_findings_over_limit")
        if deps_critical > args.max_deps_critical:
            gates["pass"] = False
            gates.setdefault("violations", []).append("deps_critical_over_limit")
        if deps_high > args.max_deps_high:
            gates["pass"] = False
            gates.setdefault("violations", []).append("deps_high_over_limit")

        summary["gates"] = gates
        summary["gate_exceptions"] = _apply_gate_exceptions("repo", summary["gates"], gate_exceptions_data)
        summary["baseline"] = _enforce_baseline("repo", summary["gates"], baseline_state, args.baseline_state_file)
        if baseline_error:
            summary["baseline"]["error"] = baseline_error
        if args.baseline_action != "none":
            summary["baseline_action"] = _apply_baseline_action(
                action=args.baseline_action,
                mode="repo",
                summary=summary,
                baseline_state_path=args.baseline_state_file,
                owner=args.baseline_owner,
                reason=args.baseline_reason,
                expires_at=args.baseline_expires_at,
                existing_state=baseline_state,
            )
        Path(args.output).write_text(json.dumps(summary, indent=2))

        print(
            f"\nDone. Repo findings: {summary['findings_total']} "
            f"(critical={critical}, high={high}, deps_critical={deps_critical}, deps_high={deps_high}), "
            f"risk {summary.get('risk_score', 0)}. "
            f"Output: {args.output}",
            file=sys.stderr,
        )
        if not gates.get("pass", False):
            print(f"Repo gate failures: {', '.join(gates.get('violations', []))}", file=sys.stderr)
            return FAIL_THRESHOLD
        return PASS

    attacks = _load_attacks_with_cli_options(args.category, args.threat_feed_file)
    print(f"Loaded {len(attacks)} attacks", file=sys.stderr)

    with AletheiaClient(base_url=args.base_url) as client:
        results = run_attacks_with_backoff(client, attacks)
        reconciliation = reconcile_results(results, client)

    summary = summarize(results)
    api_regression: dict | None = None
    if args.api_baseline_summary:
        baseline_path = Path(args.api_baseline_summary)
        if baseline_path.exists():
            baseline_raw = json.loads(baseline_path.read_text())
            api_regression = build_api_regression_summary(summary, baseline_raw)
        else:
            print(f"API baseline summary not found: {baseline_path}", file=sys.stderr)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine_url": client.base_url,
        **summary,
        "reconciliation": reconciliation,
        "regression": api_regression,
        "gap_report": build_gap_report(results),
        "results": results,
    }
    Path(args.output).write_text(json.dumps(output, indent=2))
    print(
        f"\nDone. {summary['blocked']}/{summary['attacks_total']} blocked, "
        f"expectation match {summary['expectation_match_rate']}%. "
        f"Output: {args.output}",
        file=sys.stderr,
    )
    reconciliation_coverage = float(reconciliation.get("reconciliation_coverage_pct", 0.0))
    if summary["errors"] > 0 and reconciliation_coverage < RECONCILIATION_COVERAGE_THRESHOLD_PCT:
        print(
            "API reconciliation gate failure: coverage "
            f"{reconciliation_coverage}% < {RECONCILIATION_COVERAGE_THRESHOLD_PCT}%",
            file=sys.stderr,
        )
        if reconciliation.get("unreconciled_request_ids"):
            print(
                "Unreconciled request_ids: " + ", ".join(reconciliation["unreconciled_request_ids"]),
                file=sys.stderr,
            )
        return FAIL_ERROR
    if summary["expectation_match_rate"] < args.min_expectation_match_rate:
        print(
            "API gate failure: expectation_match_rate "
            f"{summary['expectation_match_rate']} < {args.min_expectation_match_rate}",
            file=sys.stderr,
        )
        return FAIL_THRESHOLD
    if args.max_high_risk_block_drop is not None and api_regression is not None:
        drop = float(api_regression.get("high_risk_block_rate_drop", 0.0))
        if drop > args.max_high_risk_block_drop:
            print(
                "API regression gate failure: high-risk block-rate drop "
                f"{drop} > {args.max_high_risk_block_drop}",
                file=sys.stderr,
            )
            return FAIL_THRESHOLD
    return PASS


def cli() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] in {"run", "dashboard", "compare", "export", "gate"}:
        return _command_center_cli(argv)
    return _legacy_cli(argv)


if __name__ == "__main__":
    sys.exit(cli())