from __future__ import annotations

from dataclasses import dataclass

import pytest

from kit.runner import run_attack, summarize


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