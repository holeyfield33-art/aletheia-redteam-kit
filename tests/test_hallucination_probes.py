from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from kit.probes.hallucination_probe import variants
from kit.probes.registry import execute_probe_cases, load_probe_cases, summarize_probe_results


def test_hallucination_variants_are_expected_block() -> None:
    probe_variants = variants()
    assert probe_variants, "expected at least one hallucination variant"
    assert all(v.expected_block for v in probe_variants)


def test_hallucination_variants_owasp_mapping() -> None:
    probe_variants = variants()
    assert all(v.owasp == "LLM09" for v in probe_variants)


def test_hallucination_variants_have_distinct_families() -> None:
    probe_variants = variants()
    families = [v.family for v in probe_variants]
    assert len(families) == len(set(families)), "each variant should have a unique family name"


def test_hallucination_probe_cases_load_via_registry() -> None:
    cases = load_probe_cases(["hallucination"])
    assert cases
    ids = [c.case_id for c in cases]
    assert all(cid.startswith("HALL_") for cid in ids)


def test_execute_hallucination_probe_cases_flags_leak(tmp_path: Path) -> None:
    class FakeClient:
        def audit(self, payload: str, action: str, origin: str):
            return SimpleNamespace(decision="PROCEED", raw={"tool_calls": [], "retrieved_docs": []})

    cases = load_probe_cases(["hallucination"])
    results = execute_probe_cases(FakeClient(), cases, evidence_root=tmp_path / "evidence", run_id="hall-test-1")

    assert all(r.gate_decision == "leaked" for r in results)

    evidence_path = tmp_path / "evidence" / "hall-test-1" / "evidence.jsonl"
    assert evidence_path.exists()
    assert evidence_path.read_text(encoding="utf-8").strip()

    summary = summarize_probe_results(results)
    assert summary["pass"] is False
    assert len(summary["violations"]) == len(cases)


def test_execute_hallucination_probe_cases_passes_when_blocked(tmp_path: Path) -> None:
    class FakeClient:
        def audit(self, payload: str, action: str, origin: str):
            return SimpleNamespace(decision="DENIED", raw={"tool_calls": [], "retrieved_docs": []})

    cases = load_probe_cases(["hallucination"])
    results = execute_probe_cases(FakeClient(), cases, evidence_root=tmp_path / "evidence", run_id="hall-test-2")

    assert all(r.gate_decision == "blocked" for r in results)

    summary = summarize_probe_results(results)
    assert summary["pass"] is True
    assert summary["violations"] == []
