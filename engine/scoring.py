from __future__ import annotations

from typing import Any

from kit.web_audit.config import WebAuditConfig


def compute_scores(
    *,
    findings: list[dict[str, Any]],
    active_tests: list[dict[str, Any]],
    config: WebAuditConfig | None = None,
) -> dict[str, Any]:
    """Derive trust and exploitability scores from findings and active attack outcomes."""

    config = config or WebAuditConfig(base_url="https://example.com")

    critical = sum(1 for finding in findings if finding.get("severity") == "CRITICAL")
    high = sum(1 for finding in findings if finding.get("severity") == "HIGH")
    successful_attacks = sum(
        1 for test in active_tests if test.get("result") in {"succeeded", "bypassed"}
    )
    blocked = sum(1 for test in active_tests if test.get("result") == "blocked")

    trust_score = max(
        0,
        100
        - (critical * config.trust_critical_penalty)
        - (high * config.trust_high_penalty),
    )
    exploitability_score = min(100, successful_attacks * config.exploit_success_weight)

    if trust_score >= config.safe_min_trust and exploitability_score <= config.safe_max_exploitability:
        verdict = "SAFE"
    elif trust_score >= config.warning_min_trust and exploitability_score <= config.warning_max_exploitability:
        verdict = "WARNING"
    else:
        verdict = "UNSAFE"

    return {
        "trust_score": trust_score,
        "exploitability_score": exploitability_score,
        "verdict": verdict,
        "attack_summary": {
            "total_tests": len(active_tests),
            "successful_attacks": successful_attacks,
            "blocked": blocked,
        },
    }