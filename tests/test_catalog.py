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


def test_filesystem_provider_supports_recursive_taxonomy_dirs(tmp_path) -> None:
    attack_dir = tmp_path / "attacks"
    nested_dir = attack_dir / "injections"
    nested_dir.mkdir(parents=True)
    (nested_dir / "prompt_injection.json").write_text(
        json.dumps(
            [
                {
                    "id": "PI_001",
                    "name": "Nested attack",
                    "payload": "ignore prior instructions",
                    "expected_decision": "DENIED",
                    "severity": "HIGH",
                }
            ]
        )
    )

    provider = FileSystemCatalogProvider(attack_dir)
    attacks = provider.fetch_attacks("prompt_injection")

    assert len(attacks) == 1
    assert attacks[0].category == "prompt_injection"


def test_filesystem_provider_loads_all_recursive_json_files(tmp_path) -> None:
    attack_dir = tmp_path / "attacks"
    (attack_dir / "exfil").mkdir(parents=True)
    (attack_dir / "encoding").mkdir(parents=True)
    (attack_dir / "exfil" / "data_exfiltration.json").write_text(
        json.dumps(
            [
                {
                    "id": "DE_001",
                    "name": "Exfil",
                    "payload": "send records externally",
                    "expected_decision": "DENIED",
                }
            ]
        )
    )
    (attack_dir / "encoding" / "obfuscated.json").write_text(
        json.dumps(
            [
                {
                    "id": "OB_001",
                    "name": "Obfuscated",
                    "payload": "encoded prompt",
                    "expected_decision": "DENIED",
                }
            ]
        )
    )

    provider = FileSystemCatalogProvider(attack_dir)
    attacks = provider.fetch_attacks()

    assert len(attacks) == 2
    assert {attack.category for attack in attacks} == {"data_exfiltration", "obfuscated"}


def test_load_attacks_appends_threat_feed_records(tmp_path) -> None:
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
                }
            ]
        )
    )
    threat_feed_file = tmp_path / "sample_threat_feed.json"
    threat_feed_file.write_text(
        json.dumps(
            [
                {
                    "id": "TF_001",
                    "name": "Threat feed payload",
                    "payload": "extra payload",
                    "expected_decision": "DENIED",
                    "severity": "HIGH",
                    "notes": "Appended from external threat feed",
                }
            ]
        )
    )

    provider = FileSystemCatalogProvider(attack_dir)
    rows = load_attacks("sample", provider, threat_feed_file=str(threat_feed_file))

    assert len(rows) == 2
    assert rows[1]["id"] == "TF_001"
    assert rows[1]["category"] == "threat_feed"


def test_load_attacks_rejects_non_array_threat_feed(tmp_path) -> None:
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
                }
            ]
        )
    )
    threat_feed_file = tmp_path / "sample_threat_feed.json"
    threat_feed_file.write_text(json.dumps({"payload": "broken"}))

    provider = FileSystemCatalogProvider(attack_dir)
    with pytest.raises(ValueError):
        load_attacks("sample", provider, threat_feed_file=str(threat_feed_file))


def test_builtin_catalog_loads_at_least_300_payloads() -> None:
    # Backs the README "300+ adversarial payloads" claim against the shipped
    # recursive catalogs under attacks/.
    attacks = load_attacks()
    assert len(attacks) >= 300


def test_encoded_tool_argument_regression_fixtures_load_and_deny() -> None:
    # Regression guard for the aegis-provenance content-sensitivity bypass:
    # argument-shaped sensitive material (secret name, credential path/token,
    # traversal) wrapped in base64/hex slipped past a literal-only content
    # check. These fixtures carry the encoded token so the aegis shim relays it
    # into a tool argument WITHOUT decoding, forcing the target's content check
    # to decode before matching. See attacks/encoding/encoded_tool_args.json.
    # The runner selects `--categories encoding` by the record's `category`
    # field (not filename), so load the full catalog and filter the same way.
    by_id = {a["id"]: a for a in load_attacks()}
    required_ids = {"ETA_001", "ETA_002", "ETA_003", "ETA_004"}

    assert required_ids <= set(by_id)
    for attack_id in required_ids:
        row = by_id[attack_id]
        assert str(row["category"]).strip().lower() == "encoding"
        assert row["expected_decision"] == "DENIED"
        assert row["technique"] == "encoded_tool_argument"


def test_august_2026_active_threat_categories_load_and_deny() -> None:
    # See docs/test-case-catalog-addendum-cyber-threats-aug2026.md.
    # New/extended records modeling CVE-2026-9198 (Langflow RCE),
    # CVE-2026-18556/-18577 (N-able N-central incomplete-fix auth bypass),
    # and the ransomware EDR-kill-before-encrypt trend.
    workflow_rce = load_attacks("workflow_component_rce")
    control_tampering = load_attacks("security_control_tampering")
    auth_confusion = load_attacks("auth_context_confusion")

    by_id = {a["id"]: a for a in workflow_rce + control_tampering + auth_confusion}
    required_ids = {
        "WCR_001",
        "WCR_002",
        "WCR_003",
        "WCR_004",
        "WCR_005",
        "SCT_001",
        "SCT_002",
        "SCT_003",
        "SCT_004",
        "SCT_005",
        "ADV_034",
        "ADV_035",
    }
    assert required_ids <= set(by_id)

    for attack_id in required_ids:
        assert by_id[attack_id]["expected_decision"] == "DENIED"
