from __future__ import annotations

import json

import pytest

from kit.catalog import FileSystemCatalogProvider, load_attacks


def test_filesystem_provider_supports_expected_verdict_alias(tmp_path) -> None:
    attack_dir = tmp_path / "attacks"
    attack_dir.mkdir()
    (attack_dir / "obfuscated.json").write_text(
        json.dumps(
            [
                {
                    "id": "OB_001",
                    "name": "Alias field attack",
                    "payload": "encoded override",
                    "expected_verdict": "DENIED",
                    "severity": "HIGH",
                }
            ]
        )
    )

    provider = FileSystemCatalogProvider(attack_dir)
    attacks = provider.fetch_attacks("obfuscated")

    assert len(attacks) == 1
    assert attacks[0].category == "obfuscated"
    assert attacks[0].expected_decision == "DENIED"


def test_filesystem_provider_rejects_missing_required_fields(tmp_path) -> None:
    attack_dir = tmp_path / "attacks"
    attack_dir.mkdir()
    (attack_dir / "broken.json").write_text(
        json.dumps(
            [
                {
                    "id": "BR_001",
                    "payload": "missing name",
                    "expected_decision": "DENIED",
                }
            ]
        )
    )

    provider = FileSystemCatalogProvider(attack_dir)
    with pytest.raises(ValueError):
        provider.fetch_attacks("broken")


def test_load_attacks_returns_runner_compatible_dicts(tmp_path) -> None:
    attack_dir = tmp_path / "attacks"
    attack_dir.mkdir()
    (attack_dir / "sample.json").write_text(
        json.dumps(
            [
                {
                    "id": "S_001",
                    "name": "Sample",
                    "category": "sample",
                    "payload": "test payload",
                    "expected_decision": "PROCEED",
                    "risk_category": "control",
                    "difficulty": "easy",
                }
            ]
        )
    )

    provider = FileSystemCatalogProvider(attack_dir)
    rows = load_attacks("sample", provider)

    assert len(rows) == 1
    assert rows[0]["expected_decision"] == "PROCEED"
    assert rows[0]["risk_category"] == "control"
    assert rows[0]["difficulty"] == "easy"
