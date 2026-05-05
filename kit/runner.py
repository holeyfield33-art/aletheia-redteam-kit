"""
Run the full attack catalog against the Aletheia API.

Usage:
    python -m kit.runner                         # full API catalog
    python -m kit.runner --category prompt_injection
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
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from engine.agentic import AgenticConfig, run_agentic_loop
from engine.gap_analysis import build_gap_report
from engine.repo_audit import run_repo_audit
from engine.tests.auth_bypass import PROTECTED_ROUTE_PROFILES
from kit.api_analysis import build_api_regression_summary, extract_multi_turn_steps
from kit.catalog import load_attacks as load_attacks_from_catalog
from kit.client import AletheiaClient
from kit.exit_codes import FAIL_ERROR, FAIL_THRESHOLD, PASS
from kit.web_audit import WebAuditConfig, run_website_audit
from kit.web_audit.config import AuthBypassTarget, AuthStep, CustomFindingRule, PromptInjectionTest

ATTACK_DIR = Path(__file__).parent.parent / "attacks"
DEFAULT_OUTPUT = Path("summary.json")


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


def load_attacks(category: str | None = None) -> list[dict]:
    """Load attacks from catalog provider. category=None loads all."""
    return load_attacks_from_catalog(category)


def run_attack(client: AletheiaClient, attack: dict) -> dict:
    """Execute one attack, return a result record."""
    if str(attack.get("category", "")).strip().lower() == "multi_turn":
        return run_multi_turn_attack(client, attack)

    started = time.time()
    try:
        technique = attack.get("technique") or infer_custom_technique(attack)
        result = client.audit(
            payload=attack["payload"],
            action=attack.get("action", "fetch_data"),
            origin=attack.get("origin", "redteam-kit"),
        )
        latency_ms = (time.time() - started) * 1000
        return {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
            "technique": technique,
            "severity": attack.get("severity", "MEDIUM"),
            "expected_decision": attack["expected_decision"],
            "actual_decision": result.decision,
            "match": result.decision == attack["expected_decision"],
            "request_id": result.request_id,
            "latency_ms": round(latency_ms, 1),
            "receipt": result.receipt,
            "reason": result.reason,
            "error": None,
        }
    except Exception as exc:
        technique = attack.get("technique") or infer_custom_technique(attack)
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
            "error": str(exc),
        }


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


def cli() -> int:
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
    parser.add_argument("--threat-feed-file", help="Optional threat feed JSON for repo and combined modes")
    parser.add_argument("--max-repo-critical", type=int, default=0, help="Fail repo mode if CRITICAL findings exceed this")
    parser.add_argument("--max-repo-high", type=int, default=5, help="Fail repo mode if HIGH findings exceed this")
    parser.add_argument("--objective", default="Bypass secret exfil detection", help="Agentic objective statement used to optimize attack payloads")
    parser.add_argument("--agentic-iterations", type=int, default=4, help="Maximum iterations for agentic mode")
    parser.add_argument("--agentic-seed-size", type=int, default=10, help="Number of seed attacks to initialize agentic mode")
    parser.add_argument("--agentic-variants", type=int, default=6, help="Maximum candidates evaluated per agentic iteration")
    parser.add_argument(
        "--mutation-strategy",
        action="append",
        default=[],
        help="Mutation strategy for agentic mode; repeatable (objective_suffix, safe_reframe, step_escalation, base64_wrap, roleplay)",
    )
    parser.add_argument("--agentic-no-early-stop", action="store_true", help="Do not stop agentic mode after first bypass")
    args = parser.parse_args()

    if args.mode == "combined":
        combined: dict = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "combined",
            "components": {},
            "gates": {"pass": True, "violations": []},
        }
        hard_error = False

        # API component
        attacks = load_attacks(args.category)
        print(f"Loaded {len(attacks)} attacks for combined API component", file=sys.stderr)
        with AletheiaClient(base_url=args.base_url) as client:
            results = []
            for i, attack in enumerate(attacks, 1):
                result = run_attack(client, attack)
                status = "OK" if result["match"] else "NO"
                print(
                    f"[api {i}/{len(attacks)}] {status} {attack['id']:<12} "
                    f"{attack['category']:<20} {result['actual_decision']}",
                    file=sys.stderr,
                )
                results.append(result)

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
                "regression": api_regression,
                "gap_report": build_gap_report(results),
                "results": results,
            }
            combined["components"]["api"] = api_component

        if api_summary["errors"] > 0:
            hard_error = True
            combined["gates"]["pass"] = False
            combined["gates"]["violations"].append("api:errors_present")
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
        repo_summary = run_repo_audit(args.repo_path, threat_feed_path=args.threat_feed_file)
        repo_gates = repo_summary.get("gates", {"pass": False, "violations": ["missing_gates"]})
        critical = int((repo_summary.get("findings_by_severity") or {}).get("CRITICAL", 0))
        high = int((repo_summary.get("findings_by_severity") or {}).get("HIGH", 0))
        if critical > args.max_repo_critical:
            repo_gates["pass"] = False
            repo_gates.setdefault("violations", []).append("critical_repo_findings_over_limit")
        if high > args.max_repo_high:
            repo_gates["pass"] = False
            repo_gates.setdefault("violations", []).append("high_repo_findings_over_limit")
        repo_summary["gates"] = repo_gates
        combined["components"]["repo"] = repo_summary
        if not repo_gates.get("pass", False):
            combined["gates"]["pass"] = False
            for violation in repo_gates.get("violations", []):
                combined["gates"]["violations"].append(f"repo:{violation}")

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
        attacks = load_attacks(args.category)
        print(f"Loaded {len(attacks)} attacks for agentic optimization", file=sys.stderr)

        with AletheiaClient(base_url=args.base_url) as client:
            agentic = run_agentic_loop(
                client=client,
                attacks=attacks,
                run_attack_fn=run_attack,
                config=AgenticConfig(
                    objective=args.objective,
                    iterations=args.agentic_iterations,
                    seed_size=args.agentic_seed_size,
                    variants_per_round=args.agentic_variants,
                    stop_on_first_bypass=not args.agentic_no_early_stop,
                    mutation_strategies=args.mutation_strategy,
                ),
            )
            output = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "engine_url": client.base_url,
                "mode": "agentic",
                "agentic": agentic,
            }

        Path(args.output).write_text(json.dumps(output, indent=2))
        best_result = agentic.get("best_result") or {}
        print(
            f"\nDone. Agentic iterations: {agentic['iterations_executed']}/{agentic['iterations_requested']}, "
            f"best decision: {best_result.get('actual_decision', 'N/A')}. Output: {args.output}",
            file=sys.stderr,
        )
        if agentic.get("execution_errors", 0) > 0:
            return FAIL_ERROR
        return PASS

    if args.mode == "repo":
        summary = run_repo_audit(args.repo_path, threat_feed_path=args.threat_feed_file)
        gates = summary.get("gates", {"pass": False, "violations": ["missing_gates"]})

        critical = int((summary.get("findings_by_severity") or {}).get("CRITICAL", 0))
        high = int((summary.get("findings_by_severity") or {}).get("HIGH", 0))

        if critical > args.max_repo_critical:
            gates["pass"] = False
            gates.setdefault("violations", []).append("critical_repo_findings_over_limit")
        if high > args.max_repo_high:
            gates["pass"] = False
            gates.setdefault("violations", []).append("high_repo_findings_over_limit")

        summary["gates"] = gates
        Path(args.output).write_text(json.dumps(summary, indent=2))

        print(
            f"\nDone. Repo findings: {summary['findings_total']} "
            f"(critical={critical}, high={high}), risk {summary.get('risk_score', 0)}. "
            f"Output: {args.output}",
            file=sys.stderr,
        )
        if not gates.get("pass", False):
            print(f"Repo gate failures: {', '.join(gates.get('violations', []))}", file=sys.stderr)
            return FAIL_THRESHOLD
        return PASS

    attacks = load_attacks(args.category)
    print(f"Loaded {len(attacks)} attacks", file=sys.stderr)

    with AletheiaClient(base_url=args.base_url) as client:
        results = []
        for i, attack in enumerate(attacks, 1):
            result = run_attack(client, attack)
            status = "OK" if result["match"] else "NO"
            print(
                f"[{i}/{len(attacks)}] {status} {attack['id']:<12} "
                f"{attack['category']:<20} {result['actual_decision']}",
                file=sys.stderr,
            )
            results.append(result)

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
    if summary["errors"] > 0:
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


if __name__ == "__main__":
    sys.exit(cli())