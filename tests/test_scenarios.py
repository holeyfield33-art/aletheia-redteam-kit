from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from kit.reporters.sarif import build_sarif_report
from kit.scenarios.registry import load_scenario_definition
from kit.scenarios.runner import execute_scenario_definition


def test_scenario_a_executes_chain_and_writes_evidence(tmp_path: Path) -> None:
    scenario = load_scenario_definition("A")

    class FakeClient:
        def audit(self, payload: str, action: str, origin: str):
            return SimpleNamespace(decision="DENIED", raw={"retrieved_docs": [], "tool_calls": [], "payload": payload})

    result = execute_scenario_definition(FakeClient(), scenario, evidence_root=tmp_path / "evidence", run_id="scenario-a")

    assert result.scenario.scenario_id == "A"
    assert result.chain_completed is True
    assert result.blast_radius.stages_reached == 3
    assert result.blast_radius.highest_risk_class == "exec"
    assert result.finding_type == "chain_complete"

    evidence_file = tmp_path / "evidence" / "scenario-a" / "evidence.jsonl"
    assert evidence_file.exists()
    assert len(evidence_file.read_text(encoding="utf-8").splitlines()) == 3


def test_scenario_d_marks_multimodal_stub_not_implemented(tmp_path: Path) -> None:
    scenario = load_scenario_definition("D")

    class FakeClient:
        def audit(self, payload: str, action: str, origin: str):
            raise AssertionError("multimodal stub should not call client")

    result = execute_scenario_definition(FakeClient(), scenario, evidence_root=tmp_path / "evidence", run_id="scenario-d")

    assert result.scenario.scenario_id == "D"
    assert result.stages[0].actual_decision == "NOT_IMPLEMENTED"
    assert result.stages[0].gate_decision == "error"
    assert result.finding_type == "chain_blocked"


def test_build_sarif_report_includes_control_summary() -> None:
    report = build_sarif_report(
        [
            {
                "case_id": "A-1",
                "finding_type": "chain_complete",
                "severity": "CRITICAL",
                "owasp_id": "LLM01",
                "nist_controls": ["NIST-800-207:never_trust_input"],
                "gate_decision": "leaked",
            }
        ],
        tool_name="aletheia-redteam-kit",
        owner="redteam-kit",
        exception_expiry=None,
    )

    assert report["control_failure_summary"]["owner"] == "redteam-kit"
    assert report["control_failure_summary"]["total_failures"] == 1
    assert report["runs"][0]["results"][0]["properties"]["owasp_id"] == "LLM01"