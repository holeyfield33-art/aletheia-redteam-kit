from __future__ import annotations

import json

from kit.web_audit.config import WebAuditConfig
from kit.web_audit import runner
from kit.web_audit.config import AuthStep, CustomFindingRule
from kit.web_audit.runner import _apply_custom_rules, _extract_hrefs, _is_safe_button_action, _normalize_auth_seed_urls, evaluate_gates


def test_safe_button_action_blocks_destructive_labels() -> None:
    assert _is_safe_button_action("Delete Account") is False
    assert _is_safe_button_action("Log Out") is False
    assert _is_safe_button_action("Pay Now") is False
    assert _is_safe_button_action("View Docs") is True


def test_evaluate_gates_detects_violations() -> None:
    gates = evaluate_gates(
        findings_by_severity={"CRITICAL": 1, "HIGH": 4},
        pass_rate=88.0,
        required_routes_failed=["/pricing"],
        max_critical=0,
        max_high=3,
        min_pass_rate=95.0,
    )
    assert gates["pass"] is False
    assert "critical>0" in gates["violations"]
    assert "high>3" in gates["violations"]
    assert "pass_rate<95.0" in gates["violations"]
    assert "required_routes_failed" in gates["violations"]


def test_evaluate_gates_passes_when_within_thresholds() -> None:
    gates = evaluate_gates(
        findings_by_severity={"CRITICAL": 0, "HIGH": 1},
        pass_rate=99.0,
        required_routes_failed=[],
        max_critical=0,
        max_high=3,
        min_pass_rate=95.0,
    )
    assert gates["pass"] is True
    assert gates["violations"] == []


def test_extract_hrefs_filters_non_navigable_targets() -> None:
    html = '<a href="/docs">Docs</a><a href="#x">Fragment</a><a href="javascript:void(0)">X</a>'
    assert _extract_hrefs(html) == ["/docs"]


def test_run_website_audit_falls_back_when_browser_backend_fails(monkeypatch) -> None:
    config = WebAuditConfig(base_url="https://example.com", allow_http_fallback=True)

    def _raise_backend(_: WebAuditConfig):
        raise RuntimeError("browser failed")

    def _fake_http(_: WebAuditConfig):
        return {
            "generated_at": "2026-05-05T00:00:00+00:00",
            "target_url": "https://example.com",
            "crawl_stats": {"pages_discovered": 0, "pages_visited": 1, "interactions_tested": 0, "skipped_actions": 0},
            "findings_total": 0,
            "findings_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "findings_by_type": {
                "route_error": 0,
                "dead_click": 0,
                "tab_failure": 0,
                "js_error": 0,
                "network_error": 0,
                "perf_timeout": 0,
                "auth_failure": 0,
                "prompt_injection": 0,
                "signature_failure": 0,
                "auth_bypass": 0,
            },
            "pass_rate": 100.0,
            "trust_score": 100,
            "exploitability_score": 0,
            "verdict": "SAFE",
            "attack_summary": {"total_tests": 0, "successful_attacks": 0, "blocked": 0},
            "required_routes": [],
            "required_routes_failed": [],
            "auth": {"configured": False, "attempted": False, "success": False, "steps_total": 0, "steps_completed": 0, "failed_step": None, "error": None},
            "gates": {"pass": True, "violations": []},
            "active_tests": [],
            "findings": [],
        }

    monkeypatch.setattr(runner, "_run_playwright_audit", _raise_backend)
    monkeypatch.setattr(runner, "_run_http_fallback", _fake_http)

    summary = runner.run_website_audit(config)
    assert summary["audit_backend"] == "http_fallback"
    assert "Playwright backend unavailable" in summary["backend_warning"]


def test_apply_custom_rules_contains_match_builds_finding() -> None:
    rules = [
        CustomFindingRule(
            name="Suspicious marker",
            pattern="debug-token",
            target="body",
            severity="HIGH",
            title="Debug token exposed",
            expected="Debug markers are not exposed in HTML",
        )
    ]
    findings = _apply_custom_rules(
        rules=rules,
        page_url="https://example.com",
        title="Example",
        body="<html><body>debug-token=abc123</body></html>",
        headers={},
    )
    assert len(findings) == 1
    assert findings[0]["type"] == "custom_rule"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["action"] == "custom_rule_check"


def test_apply_custom_rules_regex_match_in_url() -> None:
    rules = [
        CustomFindingRule(
            name="Admin path",
            pattern=r"/admin($|/)",
            target="url",
            match="regex",
            severity="MEDIUM",
        )
    ]
    findings = _apply_custom_rules(
        rules=rules,
        page_url="https://example.com/admin",
        title="",
        body="<html></html>",
        headers={},
    )
    assert len(findings) == 1
    assert findings[0]["observed"] == "Rule 'Admin path' matched in url"


def test_normalize_auth_seed_urls_filters_external_urls() -> None:
    seeds = _normalize_auth_seed_urls(
        "https://example.com",
        ["/dashboard", "https://example.com/account", "https://evil.test/phish"],
    )
    assert "/dashboard" in seeds[0]
    assert "https://example.com/account" in seeds
    assert all("evil.test" not in s for s in seeds)


def test_http_fallback_reports_auth_unavailable() -> None:
    summary = runner._run_http_fallback(
        WebAuditConfig(
            base_url="https://example.com",
            max_pages=1,
            max_depth=0,
            timeout_sec=0.01,
            auth_workflow=[AuthStep(action="goto", url="/login")],
        )
    )
    assert summary["auth"]["configured"] is True
    assert summary["auth"]["error"] == "auth_workflow_requires_browser_backend"
    assert summary["findings_by_type"]["auth_failure"] >= 1


def test_finalize_summary_includes_active_test_scores(monkeypatch) -> None:
    monkeypatch.setattr(
        runner,
        "_run_active_tests",
        lambda config, auth_cookies: {
            "active_tests": [
                {"type": "prompt_injection", "test_name": "basic_override", "result": "succeeded", "severity": "HIGH"},
                {"type": "signature_check", "test_name": "receipt_key", "result": "failed", "severity": "CRITICAL"},
            ],
            "findings": [
                {
                    "id": "WA_TEST123456",
                    "severity": "CRITICAL",
                    "type": "signature_failure",
                    "title": "Trust chain verification failed",
                    "page_url": "https://example.com/.well-known/aletheia-receipt-key.pem",
                    "element_selector": None,
                    "action": "trust_verification",
                    "expected": "Receipt key endpoint returns a valid PEM",
                    "observed": "Trust chain cannot be verified",
                    "evidence": {"status_code": 503},
                    "reproducible_steps": ["Navigate to https://example.com/.well-known/aletheia-receipt-key.pem"],
                }
            ],
        },
    )

    summary = runner._finalize_summary(
        config=WebAuditConfig(base_url="https://example.com"),
        findings=[],
        visited={"https://example.com"},
        discovered={"https://example.com"},
        interactions_tested=0,
        skipped_actions=0,
        auth={"configured": False, "attempted": False, "success": False, "steps_total": 0, "steps_completed": 0, "failed_step": None, "error": None},
        auth_cookies=[],
    )

    assert summary["trust_score"] == 60
    assert summary["exploitability_score"] == 25
    assert summary["verdict"] == "WARNING"
    assert summary["attack_summary"]["total_tests"] == 2
    assert summary["findings_by_type"]["signature_failure"] == 1


def test_finalize_summary_includes_regression_comparison(monkeypatch, tmp_path) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "trust_score": 80,
                "exploitability_score": 25,
                "findings_total": 3,
                "verdict": "WARNING",
                "attack_summary": {"successful_attacks": 1},
                "active_tests": [
                    {"type": "prompt_injection", "test_name": "basic_override", "result": "succeeded"},
                    {"type": "signature_check", "test_name": "receipt_key", "result": "passed"},
                ],
            }
        )
    )

    monkeypatch.setattr(
        runner,
        "_run_active_tests",
        lambda config, auth_cookies: {
            "active_tests": [
                {"type": "prompt_injection", "test_name": "basic_override", "result": "blocked", "severity": "HIGH"},
                {"type": "signature_check", "test_name": "receipt_key", "result": "failed", "severity": "CRITICAL"},
            ],
            "findings": [
                {
                    "id": "WA_TEST999999",
                    "severity": "CRITICAL",
                    "type": "signature_failure",
                    "title": "Trust chain verification failed",
                    "page_url": "https://example.com/.well-known/aletheia-receipt-key.pem",
                    "element_selector": None,
                    "action": "trust_verification",
                    "expected": "Receipt key endpoint returns a valid PEM",
                    "observed": "Trust chain cannot be verified",
                    "evidence": {"status_code": 503},
                    "reproducible_steps": ["Navigate to https://example.com/.well-known/aletheia-receipt-key.pem"],
                }
            ],
        },
    )

    summary = runner._finalize_summary(
        config=WebAuditConfig(base_url="https://example.com", baseline_summary_path=str(baseline)),
        findings=[],
        visited={"https://example.com"},
        discovered={"https://example.com"},
        interactions_tested=0,
        skipped_actions=0,
        auth={"configured": False, "attempted": False, "success": False, "steps_total": 0, "steps_completed": 0, "failed_step": None, "error": None},
        auth_cookies=[],
    )

    assert summary["regression"]["trust_score_delta"] == -20
    assert summary["regression"]["exploitability_score_delta"] == -25
    assert summary["regression"]["findings_total_delta"] == -2
    assert summary["regression"]["successful_attacks_delta"] == -1
    assert summary["regression"]["new_failed_active_tests"] == ["signature_check:receipt_key"]
    assert summary["regression"]["resolved_failed_active_tests"] == ["prompt_injection:basic_override"]
