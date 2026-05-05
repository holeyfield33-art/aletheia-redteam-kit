"""
Run the full attack catalog against the Aletheia API.

Usage:
    python -m kit.runner                         # all categories
    python -m kit.runner --category prompt_injection
    python -m kit.runner --output results.json   # default: summary.json
    python -m kit.runner --mode website --target-url https://example.com
    python -m kit.runner --mode website --target-url https://example.com --no-browser-fallback
    python -m kit.runner --mode website --target-url https://example.com --rules-file rules.json
    python -m kit.runner --mode website --target-url https://example.com --auth-workflow-file auth_flow.json
    python -m kit.runner --mode website --target-url https://example.com --prompt-tests-file prompt_tests.json
    python -m kit.runner --mode website --target-url https://example.com --protected-route /dashboard
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from engine.tests.auth_bypass import PROTECTED_ROUTE_PROFILES
from kit.client import AletheiaClient
from kit.web_audit import WebAuditConfig, run_website_audit
from kit.web_audit.config import AuthBypassTarget, AuthStep, CustomFindingRule, PromptInjectionTest

ATTACK_DIR = Path(__file__).parent.parent / "attacks"
DEFAULT_OUTPUT = Path("summary.json")


def load_attacks(category: str | None = None) -> list[dict]:
    """Load attacks from JSON catalog. category=None loads all."""
    files = [ATTACK_DIR / f"{category}.json"] if category else sorted(ATTACK_DIR.glob("*.json"))
    attacks: list[dict] = []
    for path in files:
        if not path.exists():
            raise FileNotFoundError(f"Attack catalog not found: {path}")
        attacks.extend(json.loads(path.read_text()))
    return attacks


def run_attack(client: AletheiaClient, attack: dict) -> dict:
    """Execute one attack, return a result record."""
    started = time.time()
    try:
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
        return {
            "id": attack["id"],
            "name": attack["name"],
            "category": attack["category"],
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


def summarize(results: list[dict]) -> dict:
    """Aggregate per-category and total stats."""
    total = len(results)
    matches = sum(1 for r in results if r["match"])
    blocked = sum(1 for r in results if r["actual_decision"] == "DENIED")
    proceeded = sum(1 for r in results if r["actual_decision"] == "PROCEED")
    errors = sum(1 for r in results if r["actual_decision"] == "ERROR")

    by_cat: dict[str, dict] = {}
    for r in results:
        category = r["category"]
        if category not in by_cat:
            by_cat[category] = {"total": 0, "matches": 0, "blocked": 0, "proceeded": 0}
        by_cat[category]["total"] += 1
        by_cat[category]["matches"] += int(r["match"])
        if r["actual_decision"] == "DENIED":
            by_cat[category]["blocked"] += 1
        elif r["actual_decision"] == "PROCEED":
            by_cat[category]["proceeded"] += 1

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
        "errors": errors,
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
    parser.add_argument("--mode", choices=["api", "website"], default="api", help="Run API attack catalog or website UI audit")
    parser.add_argument("--category", help="Run only one category (filename without .json)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output path for summary JSON")
    parser.add_argument("--base-url", help="Override ALETHEIA_BASE_URL")
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
    args = parser.parse_args()

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
        return 0 if gates.get("pass", False) else 1

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
    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "engine_url": client.base_url,
        **summary,
        "results": results,
    }
    Path(args.output).write_text(json.dumps(output, indent=2))
    print(
        f"\nDone. {summary['blocked']}/{summary['attacks_total']} blocked, "
        f"expectation match {summary['expectation_match_rate']}%. "
        f"Output: {args.output}",
        file=sys.stderr,
    )
    return 0 if summary["errors"] == 0 else 1


if __name__ == "__main__":
    sys.exit(cli())