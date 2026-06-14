from __future__ import annotations

import json

from engine.remediation import (
    generate_proposals,
    merge_manifest,
    merge_zero_trust_policy,
    proposal_id_for,
    render_system_prompt_clause,
)
from kit.remediation_store import (
    MANIFEST_FILE,
    SYSTEM_PROMPT_FILE,
    ZERO_TRUST_FILE,
    apply_proposal,
    load_proposals,
    save_proposals,
)


def _row(rid, technique, *, expected="DENIED", actual="PROCEED", category="agentic_planning_hijack", severity="CRITICAL"):
    return {
        "id": rid,
        "technique": technique,
        "category": category,
        "severity": severity,
        "expected_decision": expected,
        "actual_decision": actual,
    }


def test_generate_proposals_only_for_bypasses() -> None:
    rows = [
        _row("APH_002", "tool_selection_override"),
        _row("APH_001", "planning_loop_injection", actual="DENIED"),  # blocked -> no proposal
    ]
    proposals = generate_proposals(rows)
    assert len(proposals) == 1
    assert proposals[0]["technique"] == "tool_selection_override"
    assert proposals[0]["status"] == "pending"


def test_proposal_has_three_artifacts_and_matched_template() -> None:
    proposals = generate_proposals([_row("APH_005", "recursive_self_improvement_bait")])
    artifacts = proposals[0]["artifacts"]
    assert set(artifacts) == {"system_prompt_constraint", "manifest_rule", "zero_trust_policy_entry"}
    assert "self-modification" in artifacts["system_prompt_constraint"].lower() \
        or "improve" in artifacts["system_prompt_constraint"].lower()
    assert artifacts["manifest_rule"]["decision"] == "DENY"
    assert artifacts["zero_trust_policy_entry"]["expected_block"] is True


def test_generic_fallback_for_unknown_technique() -> None:
    proposals = generate_proposals([_row("X", "some_novel_attack")])
    assert proposals[0]["artifacts"]["manifest_rule"]["applies_to_technique"] == ["some_novel_attack"]


def test_proposal_id_is_stable() -> None:
    assert proposal_id_for("tool_selection_override") == proposal_id_for("Tool_Selection_Override")
    p1 = generate_proposals([_row("a", "tool_selection_override")])[0]["proposal_id"]
    p2 = generate_proposals([_row("b", "tool_selection_override")])[0]["proposal_id"]
    assert p1 == p2


def test_focus_techniques_filter() -> None:
    rows = [
        _row("APH_002", "tool_selection_override"),
        _row("HE_001", "false_authority_citation", category="hallucination_exploitation"),
    ]
    proposals = generate_proposals(rows, focus_techniques=["tool_selection"])
    assert {p["technique"] for p in proposals} == {"tool_selection_override"}


def test_merge_zero_trust_policy_idempotent() -> None:
    proposal = generate_proposals([_row("APH_002", "tool_selection_override")])[0]
    policy = merge_zero_trust_policy({"probes": []}, proposal)
    policy = merge_zero_trust_policy(policy, proposal)  # re-apply
    techniques = [p["technique"] for p in policy["probes"]]
    assert techniques == ["tool_selection_override"]


def test_merge_manifest_idempotent_by_rule_id() -> None:
    proposal = generate_proposals([_row("APH_002", "tool_selection_override")])[0]
    manifest = merge_manifest({"rules": []}, proposal)
    manifest = merge_manifest(manifest, proposal)
    assert len(manifest["rules"]) == 1
    assert manifest["policy_version"].endswith("remediation")


def test_render_system_prompt_clause_includes_id_and_triggers() -> None:
    proposal = generate_proposals([_row("APH_002", "tool_selection_override")])[0]
    clause = render_system_prompt_clause(proposal)
    assert proposal["proposal_id"] in clause
    assert "APH_002" in clause


def test_store_save_and_load_roundtrip(tmp_path) -> None:
    proposals = generate_proposals([_row("APH_002", "tool_selection_override")])
    save_proposals(tmp_path, proposals)
    loaded = load_proposals(tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["proposal_id"] == proposals[0]["proposal_id"]


def test_apply_proposal_writes_three_artifacts(tmp_path) -> None:
    proposals = generate_proposals([_row("APH_002", "tool_selection_override")])
    save_proposals(tmp_path, proposals)
    pid = proposals[0]["proposal_id"]

    result = apply_proposal(tmp_path, pid)
    assert result["ok"] is True
    rdir = tmp_path / "remediation"
    assert (rdir / SYSTEM_PROMPT_FILE).exists()
    manifest = json.loads((rdir / MANIFEST_FILE).read_text())
    policy = json.loads((rdir / ZERO_TRUST_FILE).read_text())
    assert manifest["rules"][0]["decision"] == "DENY"
    assert policy["probes"][0]["expected_block"] is True

    # status persisted as approved
    assert load_proposals(tmp_path)[0]["status"] == "approved"


def test_apply_proposal_unknown_id(tmp_path) -> None:
    save_proposals(tmp_path, [])
    result = apply_proposal(tmp_path, "REM-deadbeef")
    assert result["ok"] is False
    assert result["reason"] == "proposal_not_found"


def test_apply_is_idempotent(tmp_path) -> None:
    proposals = generate_proposals([_row("APH_002", "tool_selection_override")])
    save_proposals(tmp_path, proposals)
    pid = proposals[0]["proposal_id"]
    apply_proposal(tmp_path, pid)
    apply_proposal(tmp_path, pid)
    manifest = json.loads((tmp_path / "remediation" / MANIFEST_FILE).read_text())
    assert len(manifest["rules"]) == 1
    # system prompt clause not duplicated
    body = (tmp_path / "remediation" / SYSTEM_PROMPT_FILE).read_text()
    assert body.count(pid) == 1
