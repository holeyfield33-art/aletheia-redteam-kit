from __future__ import annotations

from dataclasses import dataclass

import pytest

from kit import runner
from kit.runner import load_auth_workflow, run_attack, summarize


@dataclass
class _AuditResult:
    decision: str
    request_id: str
    receipt: dict
    reason: str | None


def test_summarize_math_is_correct() -> None:
    results = [
        {"category": "prompt_injection", "actual_decision": "DENIED", "match": True},
        {"category": "prompt_injection", "actual_decision": "DENIED", "match": True},
        {"category": "benign_controls", "actual_decision": "PROCEED", "match": True},
        {"category": "tool_abuse", "actual_decision": "ERROR", "match": False},
        {"category": "jailbreak", "actual_decision": "DENIED", "match": False},
    ]
    summary = summarize(results)
    assert summary["attacks_total"] == 5
    assert summary["expectation_match"] == 3
    assert summary["blocked"] == 3
    assert summary["proceeded"] == 1
    assert summary["errors"] == 1
    assert summary["trial_mode_suspected"] is False
    assert summary["trial_mode_reason"] is None


def test_summarize_flags_trial_mode_when_all_benign_are_denied() -> None:
    results = [
        {"category": "benign_controls", "actual_decision": "DENIED", "match": False},
        {"category": "benign_controls", "actual_decision": "DENIED", "match": False},
        {"category": "prompt_injection", "actual_decision": "DENIED", "match": True},
    ]
    summary = summarize(results)
    assert summary["trial_mode_suspected"] is True
    assert "benign_controls" in (summary["trial_mode_reason"] or "")


def test_run_attack_returns_error_record_without_crashing() -> None:
    class FakeClient:
        def audit(self, payload: str, action: str, origin: str):
            raise RuntimeError("rate limited")

    attack = {
        "id": "TA_999",
        "name": "tool abuse test",
        "category": "tool_abuse",
        "expected_decision": "DENIED",
        "payload": "run shell",
    }
    result = run_attack(FakeClient(), attack)
    assert result["actual_decision"] == "ERROR"
    assert result["match"] is False
    assert "rate limited" in result["error"]


def test_micro_catalog_category_totals_add_up() -> None:
    class FakeClient:
        def audit(self, payload: str, action: str, origin: str) -> _AuditResult:
            if "benign" in payload:
                return _AuditResult("PROCEED", "req-b", {"sig": "x"}, None)
            if "error" in payload:
                raise RuntimeError("network")
            return _AuditResult("DENIED", "req-d", {"sig": "x"}, "policy")

    attacks = [
        {"id": "PI_001", "name": "a", "category": "prompt_injection", "expected_decision": "DENIED", "payload": "attack one"},
        {"id": "PI_002", "name": "b", "category": "prompt_injection", "expected_decision": "DENIED", "payload": "attack two"},
        {"id": "BC_001", "name": "c", "category": "benign_controls", "expected_decision": "PROCEED", "payload": "benign request"},
        {"id": "TA_001", "name": "d", "category": "tool_abuse", "expected_decision": "DENIED", "payload": "error please"},
        {"id": "PE_001", "name": "e", "category": "policy_evasion", "expected_decision": "DENIED", "payload": "attack three"},
    ]

    results = [run_attack(FakeClient(), attack) for attack in attacks]
    summary = summarize(results)

    cat_total = sum(c["total"] for c in summary["categories"].values())
    assert summary["attacks_total"] == 5
    assert cat_total == 5
    assert summary["categories"]["prompt_injection"]["total"] == 2
    assert summary["categories"]["benign_controls"]["proceeded"] == 1
    assert summary["errors"] == 1


def test_cli_website_mode_requires_target_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["kit.runner", "--mode", "website"])
    with pytest.raises(SystemExit):
        runner.cli()


def test_cli_website_mode_writes_summary(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    output = tmp_path / "website_summary.json"

    fake_summary = {
        "generated_at": "2026-05-05T00:00:00+00:00",
        "target_url": "https://example.com",
        "crawl_stats": {"pages_discovered": 1, "pages_visited": 1, "interactions_tested": 1, "skipped_actions": 0},
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
        },
        "pass_rate": 100.0,
        "required_routes": [],
        "required_routes_failed": [],
        "auth": {"configured": False, "attempted": False, "success": False, "steps_total": 0, "steps_completed": 0, "failed_step": None, "error": None},
        "gates": {"pass": True, "violations": []},
        "findings": [],
    }

    monkeypatch.setattr(runner, "run_website_audit", lambda config: fake_summary)
    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode",
            "website",
            "--target-url",
            "https://example.com",
            "--output",
            str(output),
            "--max-high",
            "5",
        ],
    )

    rc = runner.cli()
    assert rc == 0
    assert output.exists()


def test_cli_website_mode_loads_rules_file(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    output = tmp_path / "website_summary.json"
    rules_file = tmp_path / "rules.json"
    rules_file.write_text(
        '[{"name":"Leaked marker","pattern":"debug-token","severity":"HIGH","target":"body"}]'
    )

    captured = {}

    def _fake_run(config):
        captured["rules"] = config.custom_rules
        return {
            "generated_at": "2026-05-05T00:00:00+00:00",
            "target_url": "https://example.com",
            "crawl_stats": {"pages_discovered": 1, "pages_visited": 1, "interactions_tested": 0, "skipped_actions": 0},
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
            },
            "pass_rate": 100.0,
            "required_routes": [],
            "required_routes_failed": [],
            "auth": {"configured": False, "attempted": False, "success": False, "steps_total": 0, "steps_completed": 0, "failed_step": None, "error": None},
            "gates": {"pass": True, "violations": []},
            "findings": [],
        }

    monkeypatch.setattr(runner, "run_website_audit", _fake_run)
    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode",
            "website",
            "--target-url",
            "https://example.com",
            "--output",
            str(output),
            "--rules-file",
            str(rules_file),
        ],
    )

    rc = runner.cli()
    assert rc == 0
    assert captured["rules"] is not None
    assert len(captured["rules"]) == 1
    assert captured["rules"][0].name == "Leaked marker"


def test_load_auth_workflow_parses_steps(tmp_path) -> None:
    auth_file = tmp_path / "auth_flow.json"
    auth_file.write_text(
        """[
  {"action": "goto", "url": "/login"},
  {"action": "fill", "selector": "input[name='email']", "value": "user@example.com"},
  {"action": "click", "selector": "button[type='submit']"},
  {"action": "wait_for_url", "url": "/dashboard", "timeout_ms": 8000}
]"""
    )

    steps = load_auth_workflow(str(auth_file))
    assert len(steps) == 4
    assert steps[0].action == "goto"
    assert steps[1].selector == "input[name='email']"
    assert steps[2].action == "click"
    assert steps[3].timeout_ms == 8000