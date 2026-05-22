from __future__ import annotations

from kit.campaign_planner import build_campaign_plan


def test_build_campaign_plan_none_mode_is_noop() -> None:
    attacks = [{"id": "A1", "category": "prompt_injection", "severity": "HIGH"}]

    selected, manifest = build_campaign_plan(attacks, mode="none")

    assert len(selected) == 1
    assert selected[0]["id"] == "A1"
    assert manifest["enabled"] is False
    assert manifest["campaign_id"] is None


def test_build_campaign_plan_auto_adds_campaign_annotations() -> None:
    attacks = [
        {"id": "B1", "category": "benign_controls", "severity": "LOW", "source": "catalog"},
        {"id": "T1", "category": "prompt_injection", "severity": "HIGH", "source": "threat_feed"},
        {"id": "E1", "category": "jailbreak", "severity": "MEDIUM", "source": "external_corpus:file"},
    ]

    selected, manifest = build_campaign_plan(attacks, mode="auto", max_targets=2)

    assert manifest["enabled"] is True
    assert manifest["campaign_mode"] == "auto"
    assert manifest["selected"] == 2
    assert len(selected) == 2
    assert selected[0]["campaign_id"]
    assert selected[0]["selection_reason"]
    assert selected[0]["source_signal"] in {"threat_feed", "external_corpus", "catalog", "adapter"}
    assert all(row["campaign_id"] == selected[0]["campaign_id"] for row in selected)
