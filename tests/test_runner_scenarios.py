from __future__ import annotations

from types import SimpleNamespace

import pytest

from kit import runner


def test_cli_scenario_mode_writes_summary_and_sarif(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    output = tmp_path / "scenario-summary.json"
    sarif_output = tmp_path / "scenario.sarif.json"

    class FakeStage:
        def __init__(self, stage_id: str, gate_decision: str) -> None:
            self.stage = SimpleNamespace(stage_id=stage_id, owasp_id="LLM01", nist_controls=("NIST-800-207:never_trust_input",))
            self.gate_decision = gate_decision

    class FakeScenarioResult:
        def __init__(self) -> None:
            self.scenario = SimpleNamespace(scenario_id="A")
            self.stages = [FakeStage("A-1", "blocked"), FakeStage("A-2", "blocked")]
            self.blast_radius = SimpleNamespace(stages_reached=2, highest_risk_class="exec", score=6)
            self.chain_completed = True
            self.finding_type = "chain_complete"
            self.severity = "CRITICAL"

        def to_dict(self):
            return {
                "scenario": {"scenario_id": "A"},
                "stages": [{"gate_decision": stage.gate_decision} for stage in self.stages],
                "blast_radius": {"stages_reached": 2, "highest_risk_class": "exec", "score": 6},
                "chain_completed": True,
                "finding_type": "chain_complete",
                "severity": "CRITICAL",
            }

    class FakeClientContext:
        def __enter__(self):
            return SimpleNamespace()

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(runner, "_create_api_client", lambda args: FakeClientContext())
    monkeypatch.setattr(runner, "run_scenario", lambda client, scenario_id, evidence_root=None, run_id=None: FakeScenarioResult())
    monkeypatch.setattr("sys.argv", ["kit.runner", "--scenario", "A", "--output", str(output), "--sarif-output", str(sarif_output)])

    rc = runner.cli()

    assert rc == 0
    assert output.exists()
    assert sarif_output.exists()