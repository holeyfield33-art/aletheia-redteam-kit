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
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from uuid import uuid4

import httpx

from engine.gap_analysis import build_category_gap_report, build_gap_report
from engine.mutation import expand_attack_families
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
from kit.campaign_planner import build_campaign_plan
from kit.dashboard_server import DashboardServerConfig, serve_dashboard
from kit.external_corpus import load_external_corpus_attacks
from kit.api_analysis import build_api_regression_summary, extract_multi_turn_steps
from kit.catalog import load_attacks as load_attacks_from_catalog
from kit.client import AletheiaClient, TargetProfile, load_target_profile
from kit.exit_codes import FAIL_ERROR, FAIL_THRESHOLD, PASS
from kit.probes import ProbeCase, execute_probe_cases, load_probe_cases, summarize_probe_results
from kit.plugins import load_runner_plugins, plugin_name
from kit.payload_quality import dedupe_attacks_semantic, limit_attacks_with_benign_ratio
from kit.reporters.sarif import build_sarif_report, write_sarif_report
from kit.scenarios import run_scenario
from kit.web_audit import WebAuditConfig, run_website_audit
from kit.web_audit.config import AuthBypassTarget, AuthStep, CustomFindingRule, PromptInjectionTest

ATTACK_DIR = Path(__file__).parent.parent / "attacks"
DEFAULT_OUTPUT = Path("summary.json")
DEFAULT_AGENTIC_OUTPUT = Path("runs/agentic_results.json")
DEFAULT_REQUEST_DELAY_SEC = 1.0
DEFAULT_MAX_REQUEST_DELAY_SEC = 30.0
RECONCILIATION_COVERAGE_THRESHOLD_PCT = 95.0
TOOL_VERSION = "1.2.0"


def _sanitize_user_string(value: str | None, *, field_name: str, max_length: int = 2048) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    if len(normalized) > max_length:
        raise ValueError(f"{field_name} is too long")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in normalized):
        raise ValueError(f"{field_name} contains invalid control characters")
    return normalized


def _sanitize_json_path(value: str | None, *, field_name: str) -> str | None:
    normalized = _sanitize_user_string(value, field_name=field_name, max_length=4096)
    if not normalized:
        return None
    if not normalized.endswith(".json"):
        raise ValueError(f"{field_name} must point to a .json file")
    return normalized


def _sanitize_repo_url(value: str | None) -> str | None:
    normalized = _sanitize_user_string(value, field_name="repo_url", max_length=512)
    if not normalized:
        return None
    if normalized.startswith("file://"):
        raise ValueError("repo_url must be a public GitHub URL or owner/repo shorthand")
    return normalized


def _sanitize_legacy_args(args: argparse.Namespace) -> argparse.Namespace:
    """Sanitize and normalize legacy CLI arguments for runner compatibility."""
    if not getattr(args, "repo_token", None):
        args.repo_token = os.environ.get("ALETHEIA_GITHUB_TOKEN") or None

    for field_name in (
        "threat_feed_file",
        "rules_file",
        "auth_workflow_file",
        "prompt_tests_file",
        "conversation_file",
        "targets_file",
    ):
        value = getattr(args, field_name, None)
        if value:
            setattr(args, field_name, _sanitize_json_path(value, field_name=field_name))

    if hasattr(args, "repo_url"):
        args.repo_url = _sanitize_repo_url(getattr(args, "repo_url", None))

    return args


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


def load_attacks(category: str | None = None, threat_feed_file: str | None = None) -> list[dict]:
    """Load attacks from the catalog provider."""
    return load_attacks_from_catalog(category, threat_feed_file=threat_feed_file)


def load_conversation_attacks(path: str | None) -> list[dict]:
    path = _sanitize_json_path(path, field_name="conversation_file")
    if not path:
        return []

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        rows = raw.get("conversations") or raw.get("attacks") or [raw]
    else:
        rows = raw

    if not isinstance(rows, list):
        raise ValueError("Conversation file must contain a JSON array or an object with conversations/attacks")

    attacks: list[dict] = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"Conversation attack #{index} must be a JSON object")
        attack = dict(row)
        attack.setdefault("id", f"CF_{index:03d}")
        attack.setdefault("name", f"Conversation file attack {index}")
        attack.setdefault("category", "multi_turn")
        attack.setdefault("action", "chat")
        attack.setdefault("origin", "redteam-kit")
        attack.setdefault("expected_decision", attack.get("expected_verdict") or "DENIED")
        attack.setdefault("severity", "HIGH")
        attacks.append(attack)
    return attacks


def infer_custom_technique(attack: dict) -> str:
    category = str(attack.get("category", "")).strip().lower()
    payload = str(attack.get("payload", "")).strip().lower()

    if category in {"multi_turn", "session_campaigns"}:
        return "campaign_escalation"
    if category == "context_poisoning":
        return "context_injection"
    if category == "embedding_evasion":
        return "semantic_evasion"
    if category == "agent_conflict":
        return "agent_disagreement"
    if category == "economic_pressure":
        return "resource_amplification"
    if category == "side_channel":
        return "side_channel_fingerprinting"
    if category == "semantic_drift":
        return "trajectory_drift"

    if "hypothetical" in payload or "suppose" in payload:
        return "hypothetical_framing"
    if "ignore previous" in payload or "override" in payload:
        return "instruction_override"
    if "base64" in payload:
        return "encoding_evasion"
    return "unspecified"


def _extract_request_id_from_http_error(exc: httpx.HTTPStatusError) -> str | None:
    response = getattr(exc, "response", None)
    if response is None:
        return None
    return response.headers.get("x-request-id") or response.headers.get("request-id") or None


def _categorize_attack_error(exc: Exception, *, status_code: int | None) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.HTTPStatusError):
        if status_code == 429:
            return "rate_limited"
        if status_code is not None and status_code >= 500:
            return "server_error"
        if status_code in {401, 403}:
            return "auth_error"
        return "http_error"
    return "unknown_error"


def _is_transient_error(error_category: str) -> bool:
    return error_category in {"timeout", "rate_limited", "server_error"}


def _adjust_request_delay_from_result(delay_sec: float, result: dict) -> float:
    error_category = str(result.get("error_category") or "").strip().lower()
    if result.get("actual_decision") == "ERROR" and _is_transient_error(error_category):
        multiplier = 2.0 if error_category == "rate_limited" else 1.5
        return min(DEFAULT_MAX_REQUEST_DELAY_SEC, max(DEFAULT_REQUEST_DELAY_SEC, delay_sec * multiplier))
    if result.get("actual_decision") in {"DENIED", "PROCEED"} and delay_sec > DEFAULT_REQUEST_DELAY_SEC:
        return max(DEFAULT_REQUEST_DELAY_SEC, delay_sec * 0.9)
    return delay_sec


def run_attack(
    client: AletheiaClient,
    attack: dict,
    *,
    include_status_code: bool = False,
    plugins: list[object] | None = None,
    plugin_args: argparse.Namespace | None = None,
) -> dict:
    """Execute one attack, return a result record."""
    if str(attack.get("category", "")).strip().lower() == "multi_turn":
        return _apply_result_plugins(run_multi_turn_attack(client, attack), attack, plugin_args, plugins)

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
                "variant_kind": attack.get("variant_kind", "seed"),
                "effectiveness_tier": attack.get("effectiveness_tier", "baseline"),
                "target_surface": attack.get("target_surface", "prompt_interface"),
                "mutation_strategy": attack.get("mutation_strategy"),
                "family_id": attack.get("family_id"),
                "source": attack.get("source"),
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
            return _apply_result_plugins(row, attack, plugin_args, plugins)
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            if status_code is not None and 500 <= status_code < 600 and not retried_5xx:
                retried_5xx = True
                time.sleep(5.0)
                continue

            request_id = _extract_request_id_from_http_error(exc)
            error_category = _categorize_attack_error(exc, status_code=status_code)
            latency_ms = (time.time() - started) * 1000
            row = {
                "id": attack["id"],
                "name": attack["name"],
                "category": attack["category"],
                "technique": technique,
                "severity": attack.get("severity", "MEDIUM"),
                "variant_kind": attack.get("variant_kind", "seed"),
                "effectiveness_tier": attack.get("effectiveness_tier", "baseline"),
                "target_surface": attack.get("target_surface", "prompt_interface"),
                "mutation_strategy": attack.get("mutation_strategy"),
                "family_id": attack.get("family_id"),
                "source": attack.get("source"),
                "expected_decision": attack["expected_decision"],
                "actual_decision": "ERROR",
                "match": False,
                "request_id": request_id,
                "latency_ms": round(latency_ms, 1),
                "receipt": None,
                "reason": None,
                "error": str(exc),
                "error_category": error_category,
                "error_is_transient": _is_transient_error(error_category),
            }
            if include_status_code:
                row["status_code"] = status_code
            return _apply_result_plugins(row, attack, plugin_args, plugins)
        except Exception as exc:
            error_category = _categorize_attack_error(exc, status_code=None)
            latency_ms = (time.time() - started) * 1000
            row = {
                "id": attack["id"],
                "name": attack["name"],
                "category": attack["category"],
                "technique": technique,
                "severity": attack.get("severity", "MEDIUM"),
                "variant_kind": attack.get("variant_kind", "seed"),
                "effectiveness_tier": attack.get("effectiveness_tier", "baseline"),
                "target_surface": attack.get("target_surface", "prompt_interface"),
                "mutation_strategy": attack.get("mutation_strategy"),
                "family_id": attack.get("family_id"),
                "source": attack.get("source"),
                "expected_decision": attack["expected_decision"],
                "actual_decision": "ERROR",
                "match": False,
                "request_id": None,
                "latency_ms": round(latency_ms, 1),
                "receipt": None,
                "reason": None,
                "error": str(exc),
                "error_category": error_category,
                "error_is_transient": _is_transient_error(error_category),
            }
            if include_status_code:
                row["status_code"] = None
            return _apply_result_plugins(row, attack, plugin_args, plugins)


def run_attacks_with_backoff(
    client: AletheiaClient,
    attacks: list[dict],
    *,
    plugins: list[object] | None = None,
    plugin_args: argparse.Namespace | None = None,
) -> list[dict]:
    """Run attacks with adaptive pacing to reduce transport failures."""
    results: list[dict] = []
    delay_sec = DEFAULT_REQUEST_DELAY_SEC

    for i, attack in enumerate(attacks, 1):
        if i > 1:
            time.sleep(delay_sec)

        result = run_attack(
            client,
            attack,
            include_status_code=True,
            plugins=plugins,
            plugin_args=plugin_args,
        )
        status = "OK" if result["match"] else "NO"
        print(
            f"[{i}/{len(attacks)}] {status} {attack['id']:<12} "
            f"{attack['category']:<20} {result['actual_decision']}",
            file=sys.stderr,
        )
        results.append(result)

        delay_sec = _adjust_request_delay_from_result(delay_sec, result)
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
            "variant_kind": attack.get("variant_kind", "seed"),
            "effectiveness_tier": attack.get("effectiveness_tier", "baseline"),
            "target_surface": attack.get("target_surface", "conversation"),
            "mutation_strategy": attack.get("mutation_strategy"),
            "family_id": attack.get("family_id"),
            "source": attack.get("source"),
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
            "variant_kind": attack.get("variant_kind", "seed"),
            "effectiveness_tier": attack.get("effectiveness_tier", "baseline"),
            "target_surface": attack.get("target_surface", "conversation"),
            "mutation_strategy": attack.get("mutation_strategy"),
            "family_id": attack.get("family_id"),
            "source": attack.get("source"),
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
    error_categories: dict[str, int] = {}
    for r in results:
        if str(r.get("actual_decision") or "").upper() != "ERROR":
            continue
        category = str(r.get("error_category") or "unknown_error").strip().lower() or "unknown_error"
        error_categories[category] = error_categories.get(category, 0) + 1

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

    tier_counts: dict[str, int] = {"baseline": 0, "elevated": 0, "advanced": 0, "unknown": 0}
    for r in results:
        tier = str(r.get("effectiveness_tier") or "baseline").strip().lower()
        if tier not in tier_counts:
            tier = "unknown"
        tier_counts[tier] += 1
    tier_rates = {
        key: (round(100 * value / total, 1) if total else 0.0)
        for key, value in tier_counts.items()
    }

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
        "error_categories": error_categories,
        "empty_200_anomalies": empty_200_anomalies,
        "block_rate": round(100 * blocked / total, 1) if total else 0.0,
        "categories": by_cat,
        "effectiveness_tiers": {
            "counts": tier_counts,
            "rates": tier_rates,
        },
        "trial_mode_suspected": trial_mode_suspected,
        "trial_mode_reason": (
            "All benign_controls payloads were denied; this can indicate trial-tier blanket blocking"
            if trial_mode_suspected
            else None
        ),
    }


def reconcile_results(rows: list[dict], client: object) -> dict:
    """Attempt to resolve UNKNOWN/ERROR decisions via async receipt lookup.

    Mutates *rows* in-place with the resolved decision when one is found.
    Returns a summary dict describing reconciliation coverage.
    """
    _SESSION_AUTH_MODES = {"session_cookie_required"}
    # SANDBOX_BLOCKED is an API-layer alias for DENIED
    _DECISION_MAP = {"SANDBOX_BLOCKED": "DENIED"}
    _UNRESOLVED = {"UNKNOWN", "ERROR"}

    # Build a deduplicated map of request_id → row indices that need lookup
    by_request_id: dict[str, list[int]] = {}
    for idx, row in enumerate(rows):
        rid = row.get("request_id")
        if rid and row.get("actual_decision") in _UNRESOLVED:
            by_request_id.setdefault(rid, []).append(idx)

    if not by_request_id:
        return {
            "total_reconciled": 0,
            "reconcilable_total": 0,
            "unreconciled": 0,
            "reconciliation_coverage_pct": 100.0,
            "unreconciled_request_ids": [],
            "skipped_request_ids": [],
            "endpoint": None,
            "auth_mode": None,
        }

    reconciled_ids: list[str] = []
    unreconciled_ids: list[str] = []
    skipped_request_ids: list[str] = []
    last_endpoint: str | None = None
    last_auth_mode: str | None = None

    for request_id, indices in by_request_id.items():
        lookup = client.lookup_decision(request_id)
        auth_mode = str(getattr(lookup, "auth_mode", None) or "unknown")
        endpoint = getattr(lookup, "endpoint", None)
        last_endpoint = endpoint
        last_auth_mode = auth_mode

        if auth_mode in _SESSION_AUTH_MODES:
            skipped_request_ids.append(request_id)
            continue

        decision = getattr(lookup, "decision", None)
        if decision is not None:
            normalized = _DECISION_MAP.get(str(decision), str(decision))
            for i in indices:
                rows[i]["actual_decision"] = normalized
                rows[i]["match"] = rows[i].get("expected_decision") == normalized
            reconciled_ids.append(request_id)
        else:
            unreconciled_ids.append(request_id)

    reconcilable_total = len(reconciled_ids) + len(unreconciled_ids)
    coverage = (len(reconciled_ids) / reconcilable_total * 100.0) if reconcilable_total > 0 else 100.0

    return {
        "total_reconciled": len(reconciled_ids),
        "reconcilable_total": reconcilable_total,
        "unreconciled": len(unreconciled_ids),
        "reconciliation_coverage_pct": round(coverage, 1),
        "unreconciled_request_ids": unreconciled_ids,
        "skipped_request_ids": skipped_request_ids,
        "endpoint": last_endpoint,
        "auth_mode": last_auth_mode,
    }


def _clamp_score(value: float) -> int:
    return int(max(0, min(100, round(value))))


def _run_repo_audit_with_cli_options(args: argparse.Namespace) -> dict:
    return run_repo_audit(
        args.repo_path,
        repo_url=args.repo_url,
        threat_feed_path=args.threat_feed_file,
        include_test_fixtures=getattr(args, "repo_include_test_fixtures", False),
        deps_scan=getattr(args, "deps_scan", "auto"),
        repo_token=getattr(args, "repo_token", None),
        scan_profile=getattr(args, "scan_profile", None),
        scan_profile_file=getattr(args, "scan_profile_file", None),
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
    path = _sanitize_json_path(path, field_name="gate_exceptions_file")
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
    path = _sanitize_json_path(path, field_name="rules_file")
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
    path = _sanitize_json_path(path, field_name="auth_workflow_file")
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
    path = _sanitize_json_path(path, field_name="prompt_tests_file")
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


def _load_runner_plugins_from_args(args: argparse.Namespace) -> list[object]:
    return load_runner_plugins(getattr(args, "plugin", []) or [])


def _apply_attack_plugins(attacks: list[dict], args: argparse.Namespace, plugins: list[object]) -> list[dict]:
    updated = [dict(attack) for attack in attacks]
    for plugin in plugins:
        hook = getattr(plugin, "transform_attacks", None)
        if not callable(hook):
            continue
        maybe_updated = hook(updated, args)
        if maybe_updated is not None:
            updated = maybe_updated
        if not isinstance(updated, list):
            raise TypeError(f"Plugin {plugin_name(plugin)} transform_attacks must return a list of attacks")
    return updated


def _apply_result_plugins(result: dict, attack: dict, args: argparse.Namespace | None, plugins: list[object] | None) -> dict:
    updated = dict(result)
    for plugin in plugins or []:
        hook = getattr(plugin, "transform_result", None)
        if not callable(hook):
            continue
        maybe_updated = hook(updated, attack, args)
        if maybe_updated is not None:
            updated = maybe_updated
        if not isinstance(updated, dict):
            raise TypeError(f"Plugin {plugin_name(plugin)} transform_result must return a dict result")
    return updated


def _finalize_summary_with_plugins(
    summary: dict,
    results: list[dict],
    args: argparse.Namespace | None,
    plugins: list[object] | None,
) -> dict:
    updated = dict(summary)
    for plugin in plugins or []:
        hook = getattr(plugin, "finalize_summary", None)
        if not callable(hook):
            continue
        maybe_updated = hook(updated, results, args)
        if maybe_updated is not None:
            updated = maybe_updated
        if not isinstance(updated, dict):
            raise TypeError(f"Plugin {plugin_name(plugin)} finalize_summary must return a dict summary")
    if plugins:
        updated["plugins"] = [plugin_name(plugin) for plugin in plugins]
    return updated


def _load_attacks_with_cli_options(category: str | None, threat_feed_file: str | None) -> list[dict]:
    try:
        return load_attacks(category, threat_feed_file=threat_feed_file)
    except TypeError as exc:
        if "threat_feed_file" not in str(exc):
            raise
        return load_attacks(category)


def _parse_category_filters(raw: str | None) -> set[str]:
    if not raw:
        return set()
    values: set[str] = set()
    for chunk in str(raw).split(","):
        value = chunk.strip().lower()
        if value:
            values.add(value)
    return values


def _filter_attacks_by_categories(attacks: list[dict], categories_raw: str | None) -> list[dict]:
    categories = _parse_category_filters(categories_raw)
    if not categories:
        return [dict(attack) for attack in attacks]
    return [dict(attack) for attack in attacks if str(attack.get("category", "")).strip().lower() in categories]


def _limit_attacks(attacks: list[dict], max_attacks: int | None) -> list[dict]:
    limit = int(max_attacks or 0)
    if limit <= 0:
        return [dict(attack) for attack in attacks]
    return [dict(attack) for attack in attacks[:limit]]


def _count_by_key(rows: list[dict], key: str, fallback: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key, fallback) or fallback).strip() or fallback
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _benign_ratio(rows: list[dict]) -> float:
    if not rows:
        return 0.0
    benign_total = sum(1 for row in rows if str(row.get("category", "")).strip().lower() == "benign_controls")
    return round(float(benign_total) / float(len(rows)), 4)


def _run_attacks_with_cli_options(
    client: AletheiaClient,
    attacks: list[dict],
    *,
    plugins: list[object] | None,
    plugin_args: argparse.Namespace | None,
) -> list[dict]:
    try:
        return run_attacks_with_backoff(client, attacks, plugins=plugins, plugin_args=plugin_args)
    except TypeError as exc:
        if "plugins" not in str(exc) and "plugin_args" not in str(exc):
            raise
        return run_attacks_with_backoff(client, attacks)


def _prepare_attacks_for_execution(args: argparse.Namespace, plugins: list[object] | None = None) -> list[dict]:
    catalog_attacks = _load_attacks_with_cli_options(args.category, args.threat_feed_file)
    external_attacks = load_external_corpus_attacks(
        getattr(args, "external_corpus_file", []) or [],
        default_category=getattr(args, "external_corpus_category", "prompt_injection"),
    )
    conversation_attacks = load_conversation_attacks(getattr(args, "conversation_file", None))

    attacks = [*catalog_attacks, *external_attacks, *conversation_attacks]
    filtered = _filter_attacks_by_categories(attacks, getattr(args, "categories", None))
    expanded = expand_attack_families(
        filtered,
        objective=getattr(args, "objective", "Bypass secret exfil detection"),
        intensity=getattr(args, "attack_intensity", "medium"),
    )
    plugin_expanded = _apply_attack_plugins(expanded, args, plugins or _load_runner_plugins_from_args(args))
    deduped = dedupe_attacks_semantic(
        plugin_expanded,
        threshold=float(getattr(args, "dedupe_semantic_threshold", 0.92) or 0.92),
    )
    limited = limit_attacks_with_benign_ratio(
        deduped,
        max_attacks=int(getattr(args, "max_attacks", 0) or 0),
        benign_ratio=float(getattr(args, "benign_ratio", 0.2) or 0.2),
    )
    final_attacks = _limit_attacks(limited, getattr(args, "max_attacks", None))

    campaign_mode = str(getattr(args, "campaign_mode", "none") or "none").strip().lower()
    category_hints = _parse_category_filters(getattr(args, "categories", None))
    final_attacks, campaign_manifest = build_campaign_plan(
        final_attacks,
        mode=campaign_mode,
        category_hints=category_hints,
        max_targets=int(getattr(args, "campaign_max_targets", 0) or 0),
    )
    setattr(args, "_campaign_manifest", campaign_manifest)

    setattr(
        args,
        "_payload_corpus_diagnostics",
        {
            "catalog_loaded": len(catalog_attacks),
            "external_loaded": len(external_attacks),
            "conversation_loaded": len(conversation_attacks),
            "pre_filter_total": len(attacks),
            "post_category_filter": len(filtered),
            "expanded_total": len(expanded),
            "post_plugin_total": len(plugin_expanded),
            "post_dedupe_total": len(deduped),
            "final_total": len(final_attacks),
            "max_attacks": int(getattr(args, "max_attacks", 0) or 0),
            "benign_ratio_target": float(getattr(args, "benign_ratio", 0.2) or 0.2),
            "benign_ratio_achieved": _benign_ratio(final_attacks),
            "dropped_by_category_filter": max(0, len(attacks) - len(filtered)),
            "dropped_by_dedupe": max(0, len(plugin_expanded) - len(deduped)),
            "dropped_by_cap": max(0, len(deduped) - len(final_attacks)),
            "source_mix": _count_by_key(final_attacks, "source", "catalog"),
            "category_mix": _count_by_key(final_attacks, "category", "unknown"),
            "adapter_mix": _count_by_key(final_attacks, "source_adapter", "none"),
            "campaign_enabled": bool(campaign_manifest.get("enabled")),
            "campaign_mode": campaign_manifest.get("campaign_mode"),
            "campaign_selected": int(campaign_manifest.get("selected", 0)),
        },
    )
    return final_attacks


def _write_campaign_manifest_if_enabled(args: argparse.Namespace, output_path: Path) -> str | None:
    manifest = getattr(args, "_campaign_manifest", None)
    if not isinstance(manifest, dict) or not manifest.get("enabled"):
        return None

    destination = output_path.resolve().parent / "campaign_manifest.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return str(destination)


def _write_command_center_artifacts(
    summary_path: Path,
    artifact_dir: Path,
    dashboard_file: Path | None,
    baseline_path: str | None,
) -> Path:
    """Read summary_path, write SQLite + JSON command-center artifacts, update index.json."""
    artifact_dir = Path(artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    mode = str(summary.get("mode") or "api")
    generated_at = str(summary.get("generated_at") or datetime.now(timezone.utc).isoformat())

    run_dir = _make_unique_run_dir(artifact_dir, f"run-{mode}")

    baseline_summary: dict | None = None
    if baseline_path:
        bp = Path(baseline_path)
        if bp.exists():
            try:
                baseline_summary = json.loads(bp.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    model = normalize_summary_to_command_center(
        summary,
        source_path=str(summary_path),
        baseline_summary=baseline_summary,
    )

    sqlite_path = run_dir / "command_center.sqlite"

    # Inject a self-referential sqlite artifact so callers can locate the db
    _now = datetime.now(timezone.utc).isoformat()
    run_id = (model.get("runs") or [{}])[0].get("id") or ""
    seen_keys: set[tuple[str, str]] = {(a["artifact_type"], a["path"]) for a in model.get("artifacts") or []}
    sqlite_key = ("sqlite", str(sqlite_path))
    if sqlite_key not in seen_keys:
        import uuid as _uuid
        (model.setdefault("artifacts", [])).append({
            "id": str(_uuid.uuid4()),
            "run_id": run_id,
            "artifact_type": "sqlite",
            "path": str(sqlite_path),
            "mime_type": "application/x-sqlite3",
            "sha256": None,
            "created_at": _now,
        })

    write_command_center_sqlite(model, sqlite_path)

    cc_json_path = run_dir / "command_center.json"
    cc_json_path.write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")

    # Update index.json
    index_path = artifact_dir / "index.json"
    index: list[dict] = []
    if index_path.exists():
        try:
            raw = json.loads(index_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                index = raw
        except json.JSONDecodeError:
            pass

    try:
        summary_rel = str(summary_path.resolve().relative_to(artifact_dir))
    except ValueError:
        summary_rel = str(summary_path.resolve())

    entry: dict = {
        "generated_at": generated_at,
        "mode": mode,
        "summary": summary_rel,
        "command_center": str(cc_json_path.relative_to(artifact_dir)),
        "sqlite": str(sqlite_path.relative_to(artifact_dir)),
    }
    index.append(entry)
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    return run_dir


def _merge_batch_models(models: list[dict]) -> dict:
    """Merge multiple command-center models into one combined model."""
    merged: dict = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "runs": [],
        "targets": [],
        "findings": [],
        "findings_evidence": [],
        "metrics": [],
        "artifacts": [],
        "gate_results": [],
        "tags": [],
        "finding_tags": [],
        "notes": [],
        "views": {"v_run_summary": [], "v_category_summary": []},
        "baseline": None,
    }
    for model in models:
        for key in ("runs", "targets", "findings", "findings_evidence", "metrics",
                    "artifacts", "gate_results", "tags", "finding_tags", "notes"):
            merged[key].extend(model.get(key) or [])
    return merged


def _make_unique_run_dir(parent: Path, prefix: str) -> Path:
    """Create a timestamped run directory that cannot collide within the same second."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_dir = parent / f"{prefix}-{stamp}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def _run_targets_batch(args: argparse.Namespace, plugins: list[object] | None = None) -> tuple[dict, Path]:
    """Execute a batch of heterogeneous targets from a targets-file and aggregate results."""
    targets_raw: list[dict] = json.loads(Path(args.targets_file).read_text(encoding="utf-8"))
    artifact_dir = Path(args.artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)

    batch_root = _make_unique_run_dir(artifact_dir, "run-batch")

    components: dict = {}
    target_summaries: list[dict] = []
    all_models: list[dict] = []

    for idx, target in enumerate(targets_raw, 1):
        target_type = str(target.get("type") or "api").lower()
        label = str(target.get("label") or f"target-{idx:02d}")
        component_key = f"{label}-{idx:02d}"
        target_artifact_dir = batch_root / "targets" / label / "artifacts"
        target_artifact_dir.mkdir(parents=True, exist_ok=True)

        if target_type == "api":
            target_url = str(target.get("url") or "")
            attacks = _prepare_attacks_for_execution(args, plugins=plugins or [])
            with AletheiaClient(base_url=target_url) as client:
                results = run_attacks_with_backoff(client, attacks, plugins=plugins, plugin_args=args)
                reconciliation = reconcile_results(results, client)
            component_summary: dict = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "mode": "api",
                "engine_url": target_url,
                "target_url": target_url,
                "reconciliation": reconciliation,
                "gap_report": build_gap_report(results),
                "category_gap_report": build_category_gap_report(results),
                **summarize(results),
                "results": results,
                "gates": {"pass": True, "violations": []},
            }
        elif target_type == "repo":
            repo_path = Path(str(target.get("path") or ".")).resolve()
            component_summary = run_repo_audit(
                repo_path,
                repo_url=str(target.get("url") or "") or None,
                threat_feed_path=getattr(args, "threat_feed_file", None),
                include_test_fixtures=getattr(args, "repo_include_test_fixtures", False),
                deps_scan=getattr(args, "deps_scan", "auto"),
            )
            if "mode" not in component_summary:
                component_summary["mode"] = "repo"
        else:
            component_summary = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "mode": target_type,
                "error": f"Unknown target type: {target_type}",
                "gates": {"pass": False, "violations": [f"unknown_type:{target_type}"]},
            }

        components[component_key] = component_summary

        run_dir = _make_unique_run_dir(target_artifact_dir, f"run-{target_type}")
        summary_path = run_dir / "summary.json"
        summary_path.write_text(json.dumps(component_summary, indent=2, default=str), encoding="utf-8")

        model = normalize_summary_to_command_center(component_summary, source_path=str(summary_path))
        sqlite_path = run_dir / "command_center.sqlite"
        write_command_center_sqlite(model, sqlite_path)
        all_models.append(model)

        target_summaries.append({
            "label": label,
            "type": target_type,
            "component_key": component_key,
            "status": "completed",
            "sqlite": str(sqlite_path),
        })

    # Build combined model and write to a separate run-combined-* dir
    combined_run_dir = _make_unique_run_dir(artifact_dir, "run-combined")

    combined_model = _merge_batch_models(all_models)
    combined_sqlite_path = combined_run_dir / "command_center.sqlite"
    write_command_center_sqlite(combined_model, combined_sqlite_path)

    all_gates_pass = all(
        (comp.get("gates") or {}).get("pass", True)
        for comp in components.values()
    )
    batch_summary: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "combined",
        "batch_mode": "targets-file",
        "targets_total": len(targets_raw),
        "targets_completed": len(target_summaries),
        "targets": target_summaries,
        "components": components,
        "gates": {"pass": all_gates_pass, "violations": []},
    }

    return batch_summary, batch_root



def _build_target_profile_from_args(args: argparse.Namespace) -> TargetProfile:
    return load_target_profile(
        preset=getattr(args, "target_preset", "aletheia"),
        profile_file=getattr(args, "target_profile_file", None),
        base_url=getattr(args, "base_url", None) or getattr(args, "target_url", None),
        model=getattr(args, "target_model", None),
        auth_header=getattr(args, "auth_header", None),
        auth_scheme=getattr(args, "auth_scheme", None),
        extra_headers=getattr(args, "header", None),
    )


def _create_api_client(args: argparse.Namespace) -> AletheiaClient:
    return AletheiaClient(
        base_url=getattr(args, "base_url", None) or getattr(args, "target_url", None),
        target_profile=_build_target_profile_from_args(args),
    )


def _load_zero_trust_policy(path: str | None) -> dict[str, object]:
    if not path:
        return {}
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("zero trust policy file must contain a JSON object")
    return raw


def _run_probe_registry(
    client: AletheiaClient,
    probe_names: list[str],
    *,
    policy_file: str | None = None,
    evidence_root: Path | None = None,
) -> dict[str, object]:
    policy = _load_zero_trust_policy(policy_file)
    cases = load_probe_cases(probe_names)

    override_rows = policy.get("probes") if isinstance(policy.get("probes"), list) else []
    override_map: dict[str, bool] = {}
    for row in override_rows:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id") or "").strip()
        family = str(row.get("family") or "").strip()
        expected_block = bool(row.get("expected_block", True))
        if case_id:
            override_map[case_id] = expected_block
        if family:
            override_map[family] = expected_block

    effective_cases: list[ProbeCase] = []
    for case in cases:
        override = override_map.get(case.case_id)
        if override is None:
            override = override_map.get(case.family)
        if override is None or override == case.expected_block:
            effective_cases.append(case)
            continue
        effective_cases.append(
            ProbeCase(
                case_id=case.case_id,
                name=case.name,
                family=case.family,
                payload=case.payload,
                expected_block=override,
                owasp_id=case.owasp_id,
                nist_controls=case.nist_controls,
                target_surface=case.target_surface,
                action=case.action,
                risk_class=case.risk_class,
                tool_name=case.tool_name,
                arguments=dict(case.arguments),
            )
        )

    results = execute_probe_cases(
        client,
        effective_cases,
        evidence_root=evidence_root or Path("evidence"),
    )
    summary = summarize_probe_results(results)
    summary["results"] = [result.to_dict() for result in results]
    summary["policy_source"] = policy_file
    summary["probe_names"] = probe_names
    summary["evidence_root"] = str((evidence_root or Path("evidence")).resolve())
    return summary


def _legacy_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aletheia red team kit")
    parser.add_argument("--mode", choices=["api", "website", "agentic", "repo", "combined"], default="api", help="Run API catalog, autonomous agentic loop, website UI audit, static repository audit, or combined command-center sweep")
    parser.add_argument("--category", help="Run only one category (filename without .json)")
    parser.add_argument(
        "--categories",
        help="Comma-separated category filter applied after catalog load (example: prompt_injection,exfil)",
    )
    parser.add_argument(
        "--max-attacks",
        type=int,
        default=0,
        help="Maximum attacks to execute after expansion and plugin transforms (0 means no cap)",
    )
    parser.add_argument(
        "--probes",
        help="Comma-separated probe families to execute instead of the attack catalog (normalization,output,tool)",
    )
    parser.add_argument(
        "--scenario",
        help="Run a declarative kill-chain scenario by id (A, B, C, D, or E)",
    )
    parser.add_argument(
        "--zero-trust-policy-file",
        help="Optional JSON policy file mapping probe cases to expected_block contracts",
    )
    parser.add_argument(
        "--evidence-dir",
        default="evidence",
        help="Directory used to persist probe evidence JSONL traces",
    )
    parser.add_argument(
        "--sarif-output",
        help="Optional SARIF output path for probe or scenario runs",
    )
    parser.add_argument(
        "--dedupe-semantic-threshold",
        type=float,
        default=0.92,
        help="Semantic dedupe threshold (0 disables semantic dedupe, 1 requires exact token overlap)",
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=0.2,
        help="Target benign_controls ratio when max-attacks is set (0.2 means ~20 percent)",
    )
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output path for summary JSON")
    parser.add_argument("--base-url", help="Override ALETHEIA_BASE_URL")
    parser.add_argument("--target-preset", choices=["aletheia", "openai"], default="aletheia", help="Target preset for API-compatible audits")
    parser.add_argument("--target-profile-file", help="JSON target profile file for custom API targets")
    parser.add_argument("--target-model", help="Model name for OpenAI-compatible chat-completion targets")
    parser.add_argument("--auth-header", help="Override auth header name for custom target profiles")
    parser.add_argument("--auth-scheme", help="Override auth scheme prefix, for example Bearer")
    parser.add_argument("--header", action="append", default=[], help="Extra request header in KEY=VALUE format; repeatable")
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
        help="GitHub repository URL (public or private) or owner/repo shorthand for --mode repo",
    )
    parser.add_argument(
        "--repo-token",
        default=None,
        help="GitHub personal-access token for private repo cloning (or set ALETHEIA_GITHUB_TOKEN env var; token is never logged)",
    )
    parser.add_argument(
        "--scan-profile",
        choices=["light", "medium", "full", "custom"],
        default=None,
        help="Scanning depth for repo mode: light (secrets+CI+language), medium (default, adds dep hygiene+advisories), full (medium + semgrep/bandit/trivy/npm-audit), or custom (requires --scan-profile-file)",
    )
    parser.add_argument(
        "--scan-profile-file",
        default=None,
        help='JSON file with {"scanners": [...]} list when --scan-profile custom',
    )
    parser.add_argument(
        "--targets-file",
        help="JSON array of targets to execute in batch (type/api|website|repo plus per-target settings)",
    )
    parser.add_argument(
        "--artifact-dir",
        default="runs",
        help="Directory used for batch and command-center artifacts",
    )
    parser.add_argument(
        "--max-parallel-targets",
        type=int,
        default=2,
        help="Maximum number of targets to execute concurrently when --targets-file is provided",
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
    parser.add_argument(
        "--campaign-mode",
        choices=["none", "auto", "focused"],
        default="none",
        help="Optional campaign planning mode applied to prepared attack corpus",
    )
    parser.add_argument(
        "--campaign-max-targets",
        type=int,
        default=0,
        help="Optional maximum attacks selected by campaign planner (0 keeps all prepared attacks)",
    )
    parser.add_argument("--attack-intensity", choices=["light", "medium", "aggressive"], default="medium", help="Payload family expansion intensity for API and agentic attack generation")
    parser.add_argument("--conversation-file", help="JSON file of multi-turn conversation attacks to append to the run")
    parser.add_argument("--agentic-iterations", type=int, default=4, help="Maximum iterations for legacy engine agentic mode")
    parser.add_argument("--max-iterations", type=int, help="Maximum iterations for agentic mode (default: 10)")
    parser.add_argument("--agentic-seed-size", type=int, default=10, help="Number of seed attacks to initialize agentic mode")
    parser.add_argument("--agentic-variants", type=int, default=6, help="Maximum candidates evaluated per agentic iteration")
    parser.add_argument("--agentic-max-time-sec", type=int, help="Optional maximum wall-clock time budget for agentic mode")
    parser.add_argument("--agentic-risk-budget", type=float, help="Optional maximum accumulated risk budget for successful bypasses")
    parser.add_argument("--agentic-success-budget", type=int, help="Optional cap on successful bypass count before stopping")
    parser.add_argument("--agentic-diminishing-window", type=int, default=3, help="Window size for diminishing-return stop detection")
    parser.add_argument("--agentic-diminishing-min-delta", type=int, default=1, help="Minimum successes across the diminishing window")
    parser.add_argument(
        "--mutation-strategy",
        action="append",
        default=[],
        help="Mutation strategy for agentic mode; repeatable (objective_suffix, safe_reframe, step_escalation, base64_wrap, roleplay)",
    )
    parser.add_argument(
        "--plugin",
        action="append",
        default=[],
        help="Runner plugin module, module:object, or file.py[:object]; repeatable",
    )
    parser.add_argument(
        "--payload-mutation-plugin",
        action="store_true",
        help="Enable built-in payload-mutation plugin behavior when plugin module is loaded",
    )
    parser.add_argument(
        "--payload-expand-to",
        type=int,
        default=0,
        help="Target number of total attacks after payload-mutation plugin expansion (0 keeps default plugin behavior)",
    )
    parser.add_argument(
        "--payload-seed-limit",
        type=int,
        default=80,
        help="Maximum seed attacks used by payload-mutation plugin for dynamic generation",
    )
    parser.add_argument(
        "--payload-family-file",
        help="Optional JSON file of additional seed payload families consumed by payload-mutation plugin",
    )
    parser.add_argument(
        "--external-corpus-file",
        action="append",
        default=[],
        help="Optional external payload corpus JSON file; repeatable",
    )
    parser.add_argument(
        "--external-corpus-category",
        default="prompt_injection",
        help="Default category for external corpus entries without explicit category",
    )
    parser.add_argument(
        "--variants-per-seed",
        type=int,
        default=0,
        help="Override payload-mutation plugin variants generated per seed (0 uses intensity defaults)",
    )
    parser.add_argument("--agentic-no-early-stop", action="store_true", help="Do not stop agentic mode after first bypass")
    args = parser.parse_args(argv)
    args = _sanitize_legacy_args(args)
    plugins = _load_runner_plugins_from_args(args)

    if args.scenario:
        with _create_api_client(args) as client:
            scenario_result = run_scenario(
                client,
                str(args.scenario).strip().upper(),
                evidence_root=Path(args.evidence_dir),
            )

        scenario_summary = scenario_result.to_dict()
        Path(args.output).write_text(json.dumps(scenario_summary, indent=2), encoding="utf-8")
        if args.sarif_output:
            sarif_report = build_sarif_report(
                [
                    {
                        "case_id": stage.stage.stage_id,
                        "finding_type": scenario_result.finding_type,
                        "severity": scenario_result.severity,
                        "owasp_id": stage.stage.owasp_id,
                        "nist_controls": list(stage.stage.nist_controls),
                        "gate_decision": stage.gate_decision,
                    }
                    for stage in scenario_result.stages
                ],
                tool_name="aletheia-redteam-kit",
                owner="redteam-kit",
                exception_expiry=None,
            )
            write_sarif_report(Path(args.sarif_output), sarif_report)
        if any(stage.gate_decision != "blocked" for stage in scenario_result.stages):
            return FAIL_THRESHOLD
        return PASS

    if args.probes:
        probe_names = [item.strip() for item in str(args.probes).split(",") if item.strip()]
        with _create_api_client(args) as client:
            probe_summary = _run_probe_registry(
                client,
                probe_names,
                policy_file=args.zero_trust_policy_file,
                evidence_root=Path(args.evidence_dir),
            )

        Path(args.output).write_text(json.dumps(probe_summary, indent=2), encoding="utf-8")
        if not probe_summary.get("pass", False):
            print(
                f"Probe gate failure: {len(probe_summary.get('violations', []))} violated expected_block contracts.",
                file=sys.stderr,
            )
            return FAIL_THRESHOLD
        return PASS

    if args.mode == "combined":
        if args.targets_file:
            batch_summary, _batch_root = _run_targets_batch(args, plugins=plugins)
            Path(args.output).write_text(json.dumps(batch_summary, indent=2), encoding="utf-8")
            print(
            f"\nDone. Batch targets complete. Overall gate: {'PASS' if batch_summary['gates']['pass'] else 'FAIL'}. Output: {args.output}",
            file=sys.stderr,
            )
            return PASS if batch_summary["gates"]["pass"] else FAIL_THRESHOLD

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
        attacks = _prepare_attacks_for_execution(args, plugins=plugins)
        print(f"Loaded {len(attacks)} attacks for combined API component", file=sys.stderr)
        with _create_api_client(args) as client:
            results = _run_attacks_with_cli_options(client, attacks, plugins=plugins, plugin_args=args)
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
                "corpus_diagnostics": getattr(args, "_payload_corpus_diagnostics", {}),
                "reconciliation": reconciliation,
                "regression": api_regression,
                "gap_report": build_gap_report(results),
                "category_gap_report": build_category_gap_report(results),
                "results": results,
            }
            campaign_manifest_path = _write_campaign_manifest_if_enabled(args, Path(args.output))
            if campaign_manifest_path:
                api_component["campaign"] = {
                    **(getattr(args, "_campaign_manifest", {}) or {}),
                    "manifest_path": campaign_manifest_path,
                }
            api_component = _finalize_summary_with_plugins(api_component, results, args, plugins)
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
        gate_scope = (repo_summary.get("first_party_non_test_by_severity") or repo_summary.get("findings_by_severity") or {})
        critical = int(gate_scope.get("CRITICAL", 0))
        high = int(gate_scope.get("HIGH", 0))
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
        attacks = _prepare_attacks_for_execution(args, plugins=plugins)
        print(f"Loaded {len(attacks)} attacks for agentic optimization", file=sys.stderr)

        output_path = Path(args.output)
        if output_path == DEFAULT_OUTPUT:
            output_path = DEFAULT_AGENTIC_OUTPUT
        max_iterations = args.max_iterations if args.max_iterations is not None else 10

        with _create_api_client(args) as client:
            agentic = AgenticRunner(
                client=client,
                attacks=attacks,
                run_attack_fn=lambda current_client, attack: run_attack(
                    current_client,
                    attack,
                    plugins=plugins,
                    plugin_args=args,
                ),
                config=AgenticRunnerConfig(
                    objective=args.objective,
                    max_iterations=max_iterations,
                    variants_per_round=args.agentic_variants,
                    mutation_strategies=args.mutation_strategy,
                    output_path=output_path,
                    max_time_seconds=args.agentic_max_time_sec,
                    risk_budget=args.agentic_risk_budget,
                    success_budget=args.agentic_success_budget,
                    diminishing_window=args.agentic_diminishing_window,
                    diminishing_min_delta=args.agentic_diminishing_min_delta,
                ),
            ).run()

        campaign_manifest_path = _write_campaign_manifest_if_enabled(args, output_path)
        if campaign_manifest_path:
            agentic["campaign"] = {
                **(getattr(args, "_campaign_manifest", {}) or {}),
                "manifest_path": campaign_manifest_path,
            }
            output_path.write_text(json.dumps(agentic, indent=2), encoding="utf-8")

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

        gate_scope = (summary.get("first_party_non_test_by_severity") or summary.get("findings_by_severity") or {})
        critical = int(gate_scope.get("CRITICAL", 0))
        high = int(gate_scope.get("HIGH", 0))
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

    attacks = _prepare_attacks_for_execution(args, plugins=plugins)
    print(f"Loaded {len(attacks)} attacks", file=sys.stderr)

    with _create_api_client(args) as client:
        results = _run_attacks_with_cli_options(client, attacks, plugins=plugins, plugin_args=args)
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
        "corpus_diagnostics": getattr(args, "_payload_corpus_diagnostics", {}),
        "reconciliation": reconciliation,
        "regression": api_regression,
        "gap_report": build_gap_report(results),
        "category_gap_report": build_category_gap_report(results),
        "results": results,
    }
    campaign_manifest_path = _write_campaign_manifest_if_enabled(args, Path(args.output))
    if campaign_manifest_path:
        output["campaign"] = {
            **(getattr(args, "_campaign_manifest", {}) or {}),
            "manifest_path": campaign_manifest_path,
        }
    output = _finalize_summary_with_plugins(output, results, args, plugins)
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


def _launch_runner_subprocess(mode: str, parsed_args: dict) -> tuple[int, dict]:
    """Launch a runner subprocess and return exit code and result metadata."""
    artifact_root = Path(parsed_args.get("artifact_dir") or "runs").resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    launch_id = f"{mode}-{stamp}-{uuid4().hex[:8]}"
    launch_root = artifact_root / ".launches" / launch_id
    launch_root.mkdir(parents=True, exist_ok=True)
    
    output_path = launch_root / "summary.json"
    log_path = launch_root / "launch.log"
    
    # Launch legacy CLI args directly to avoid recursively invoking the `run` wrapper.
    command = [
        sys.executable,
        "-m",
        "kit.runner",
        "--mode",
        mode,
    ]
    
    # Map common arguments to --mode args
    if mode in {"api", "agentic"}:
        if parsed_args.get("base_url"):
            command.extend(["--base-url", parsed_args["base_url"]])
        if parsed_args.get("max_attacks"):
            command.extend(["--max-attacks", str(parsed_args["max_attacks"])])
        if parsed_args.get("category"):
            command.extend(["--category", parsed_args["category"]])
    
    if mode in {"website", "combined"}:
        if parsed_args.get("target_url"):
            command.extend(["--target-url", parsed_args["target_url"]])
        if parsed_args.get("max_pages"):
            command.extend(["--max-pages", str(parsed_args["max_pages"])])
        if parsed_args.get("max_depth"):
            command.extend(["--max-depth", str(parsed_args["max_depth"])])
    
    if mode in {"repo", "combined"}:
        if parsed_args.get("repo_url"):
            command.extend(["--repo-url", parsed_args["repo_url"]])
        elif parsed_args.get("repo_path"):
            command.extend(["--repo-path", parsed_args["repo_path"]])
    
    command.extend([
        "--artifact-dir",
        str(artifact_root),
        "--output",
        str(output_path),
        "--cli-only",
    ])
    
    # Capture environment for subprocess
    env = os.environ.copy()
    
    result_meta = {
        "ok": True,
        "status": "started",
        "launch_id": launch_id,
        "mode": mode,
        "output_path": str(output_path.relative_to(artifact_root)),
        "log_path": str(log_path.relative_to(artifact_root)),
        "dashboard": "/dashboard/",
    }
    
    try:
        with open(log_path, "ab") as log_file:
            process = subprocess.Popen(
                command,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                env=env,
            )
        result_meta["pid"] = process.pid
        result_meta["started_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        result_meta["ok"] = False
        result_meta["error"] = str(exc)
        result_meta["status"] = "failed"
        return 1, result_meta
    
    # If --cli-only is set in the parsed args, wait for subprocess
    if parsed_args.get("cli_only"):
        try:
            exit_code = process.wait(timeout=None)
            result_meta["exit_code"] = exit_code
            result_meta["status"] = "completed"
            
            # Load output if available
            if output_path.exists():
                try:
                    result_meta["output"] = json.loads(output_path.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, IOError):
                    pass
            
            return exit_code, result_meta
        except Exception as exc:
            result_meta["error"] = str(exc)
            result_meta["status"] = "wait_failed"
            return 1, result_meta
    else:
        # For async dashboard submission, return immediately
        return 0, result_meta


def _command_center_cli(argv: list[str]) -> int:
    """Handle new command-center CLI commands: run, dashboard, compare, export, gate."""
    if not argv:
        print("Usage: python -m kit.runner {run,dashboard,compare,export,gate} ...", file=sys.stderr)
        return 1
    
    command = argv[0]
    args = argv[1:]
    
    # Parse common arguments for all commands
    parser = argparse.ArgumentParser(description=f"Aletheia {command} command")
    parser.add_argument("--artifact-dir", default="runs", help="Directory for artifacts and runs")
    parser.add_argument("--host", default="127.0.0.1", help="Server host for dashboard")
    parser.add_argument("--port", type=int, default=8080, help="Server port for dashboard")
    parser.add_argument("--serve", action="store_true", help="Serve dashboard via HTTP")
    parser.add_argument("--auth-mode", default="auto", help="Dashboard auth mode: auto, disabled, basic, api-key, proxy")
    parser.add_argument("--cli-only", action="store_true", help="Block until subprocess completes (for CI)")
    
    if command == "run":
        # Subparser for run modes
        parser.add_argument("--mode", choices=["api", "website", "agentic", "repo", "combined"], default="api")
        parser.add_argument("--targets-file", default=None, help="JSON file listing multiple targets to batch")

        # Mode-specific arguments
        parser.add_argument("--base-url", help="API base URL for api/agentic modes")
        parser.add_argument("--target-url", help="Website URL for website/combined modes")
        parser.add_argument("--repo-url", help="GitHub repo URL for repo/combined modes")
        parser.add_argument("--repo-path", default=".", help="Local repo path for repo mode")
        parser.add_argument("--category", help="Attack category filter")
        parser.add_argument("--max-attacks", type=int, help="Maximum attacks to run")
        parser.add_argument("--max-pages", type=int, help="Max pages for website audit")
        parser.add_argument("--max-depth", type=int, help="Max depth for website audit")
        parser.add_argument("--output", default="summary.json", help="Output file path")
        parser.add_argument("--baseline", default=None, help="Baseline summary.json for regression comparison")

        parsed = parser.parse_args(args)
        mode = parsed.mode

        if parsed.cli_only:
            # Run in-process via _legacy_cli then write command-center artifacts
            legacy_argv: list[str] = ["--mode", mode, "--output", parsed.output]
            if getattr(parsed, "base_url", None):
                legacy_argv += ["--base-url", parsed.base_url]
            if getattr(parsed, "target_url", None):
                legacy_argv += ["--target-url", parsed.target_url]
            if getattr(parsed, "repo_url", None):
                legacy_argv += ["--repo-url", parsed.repo_url]
            if getattr(parsed, "repo_path", None) and parsed.repo_path != ".":
                legacy_argv += ["--repo-path", parsed.repo_path]
            if getattr(parsed, "category", None):
                legacy_argv += ["--category", parsed.category]
            if getattr(parsed, "max_attacks", None):
                legacy_argv += ["--max-attacks", str(parsed.max_attacks)]
            rc = _legacy_cli(legacy_argv)
            if rc == 0:
                summary_path = Path(parsed.output)
                if summary_path.exists():
                    artifact_dir = Path(parsed.artifact_dir).resolve()
                    _write_command_center_artifacts(
                        summary_path,
                        artifact_dir,
                        dashboard_file=None,
                        baseline_path=getattr(parsed, "baseline", None),
                    )
            return rc
        elif getattr(parsed, "targets_file", None):
            batch_summary, batch_root = _run_targets_batch(parsed)
            output_path = Path(parsed.output)
            output_path.write_text(json.dumps(batch_summary, indent=2, default=str), encoding="utf-8")
            print(json.dumps({"status": "batch_complete", "batch_root": str(batch_root)}, indent=2))
            return 0
        else:
            # Async subprocess launch
            parsed_dict = vars(parsed)
            exit_code, result = _launch_runner_subprocess(mode, parsed_dict)
            print(json.dumps(result, indent=2))
            return exit_code
    
    elif command == "dashboard":
        parser.add_argument("--dashboard-file", default=None, help="Path to dashboard index.html")
        parser.set_defaults(auth_mode="basic")

        parsed = parser.parse_args(args)

        artifact_dir = Path(parsed.artifact_dir).resolve()
        artifact_dir.mkdir(parents=True, exist_ok=True)

        repo_root = Path.cwd()
        if parsed.dashboard_file:
            dashboard_file = Path(parsed.dashboard_file)
        else:
            dashboard_file = repo_root / "dashboard" / "index.html"

        if not dashboard_file.exists():
            print(f"Dashboard file not found: {dashboard_file}", file=sys.stderr)
            return 1

        config = DashboardServerConfig(
            repo_root=repo_root,
            artifact_dir=artifact_dir,
            dashboard_file=dashboard_file,
            host=parsed.host,
            port=parsed.port,
            auth_mode=parsed.auth_mode,
        )
        
        try:
            serve_dashboard(config)
            return 0
        except KeyboardInterrupt:
            print("\nDashboard server stopped.", file=sys.stderr)
            return 0
        except Exception as exc:
            print(f"Dashboard error: {exc}", file=sys.stderr)
            return 1
    
    elif command == "compare":
        parser.add_argument("--baseline", required=True, help="Baseline summary.json")
        parser.add_argument("--current", required=True, help="Current summary.json")
        parser.add_argument("--output", help="Output comparison JSON")
        
        parsed = parser.parse_args(args)
        
        baseline_path = Path(parsed.baseline)
        current_path = Path(parsed.current)
        
        if not baseline_path.exists() or not current_path.exists():
            print("Baseline or current file not found", file=sys.stderr)
            return 1
        
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        current = json.loads(current_path.read_text(encoding="utf-8"))
        
        comparison = compare_summaries(current, baseline)
        
        if parsed.output:
            Path(parsed.output).write_text(json.dumps(comparison, indent=2), encoding="utf-8")
            print(f"Comparison written to {parsed.output}", file=sys.stderr)
        else:
            print(json.dumps(comparison, indent=2))
        
        return 0
    
    elif command == "export":
        parser.add_argument("--input", required=True, help="Input summary.json")
        parser.add_argument("--format", choices=["csv", "json"], default="csv", help="Export format")
        parser.add_argument("--output", required=True, help="Output file")
        parser.add_argument("--filter", dest="filter_expr", default=None, help="Filter expression e.g. category=prompt_injection")

        parsed = parser.parse_args(args)

        input_path = Path(parsed.input)
        if not input_path.exists():
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return 1

        summary = json.loads(input_path.read_text(encoding="utf-8"))
        results = summary.get("results") or summary.get("components", {}).get("api", {}).get("results", [])

        if parsed.filter_expr:
            results = apply_finding_filter(results, parsed.filter_expr)

        output_path = Path(parsed.output)
        export_rows(results, output_path, parsed.format)
        print(f"Exported {len(results)} rows to {parsed.output}", file=sys.stderr)

        return 0
    
    elif command == "gate":
        parser.add_argument("--input", required=True, help="Input summary.json")
        parser.add_argument("--thresholds", default=None, help="Threshold expression e.g. max_unknown=5,min_pass_rate=80")
        parser.add_argument("--output", help="Output gate result JSON")

        parsed = parser.parse_args(args)

        input_path = Path(parsed.input)
        if not input_path.exists():
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return 1

        summary = json.loads(input_path.read_text(encoding="utf-8"))

        gate_result = evaluate_gates(summary, parsed.thresholds)

        if parsed.output:
            Path(parsed.output).write_text(json.dumps(gate_result, indent=2), encoding="utf-8")
            print(f"Gate result written to {parsed.output}", file=sys.stderr)
        else:
            print(json.dumps(gate_result, indent=2))

        gate_pass = gate_result.get("pass", False)
        return 0 if gate_pass else 1
    
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        return 1


def cli() -> int:
    argv = sys.argv[1:]
    if argv and argv[0] in {"run", "dashboard", "compare", "export", "gate"}:
        return _command_center_cli(argv)
    return _legacy_cli(argv)


if __name__ == "__main__":
    sys.exit(cli())