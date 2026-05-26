from __future__ import annotations

from pathlib import Path
import json


def test_policy_baseline_covers_all_probe_and_scenario_families() -> None:
    policy_path = Path(__file__).resolve().parents[1] / "kit" / "policy" / "baseline.yaml"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    entries = policy.get("probes")
    assert isinstance(entries, list)
    assert len(entries) == 20
    assert all(isinstance(item, dict) for item in entries)
    assert all(item.get("owasp_id") for item in entries)
    assert all(item.get("nist_controls") for item in entries)
    assert all(item.get("expected_block") is True for item in entries)
    assert not any("UNMAPPED" in json.dumps(item) for item in entries)