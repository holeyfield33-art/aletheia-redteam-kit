from __future__ import annotations

import sqlite3

from kit.command_center import normalize_summary_to_command_center, write_command_center_sqlite


def test_normalize_summary_to_command_center_registers_campaign_and_learning_artifacts(tmp_path) -> None:
    summary = {
        "generated_at": "2026-05-16T00:00:00+00:00",
        "mode": "agentic",
        "gates": {"pass": True, "violations": []},
        "campaign": {
            "enabled": True,
            "campaign_mode": "focused",
            "manifest_path": str(tmp_path / "campaign_manifest.json"),
        },
        "learning_snapshot_path": str(tmp_path / "learning_snapshot.json"),
        "mutation_effectiveness_path": str(tmp_path / "mutation_effectiveness.json"),
    }

    model = normalize_summary_to_command_center(
        summary,
        source_path=str(tmp_path / "agentic_results.json"),
    )

    artifacts = model["artifacts"]
    artifact_types = {row["artifact_type"] for row in artifacts}

    assert "summary_json" in artifact_types
    assert "campaign_manifest_json" in artifact_types
    assert "learning_snapshot_json" in artifact_types
    assert "mutation_effectiveness_json" in artifact_types


def test_write_command_center_sqlite_persists_enriched_artifacts(tmp_path) -> None:
    summary = {
        "generated_at": "2026-05-16T00:00:00+00:00",
        "mode": "combined",
        "gates": {"pass": True, "violations": []},
        "components": {
            "api": {
                "mode": "api",
                "campaign": {
                    "enabled": True,
                    "manifest_path": str(tmp_path / "campaign_manifest.json"),
                },
            }
        },
        "learning_snapshot_path": str(tmp_path / "learning_snapshot.json"),
        "mutation_effectiveness_path": str(tmp_path / "mutation_effectiveness.json"),
    }

    model = normalize_summary_to_command_center(
        summary,
        source_path=str(tmp_path / "combined_summary.json"),
    )

    db_path = write_command_center_sqlite(model, tmp_path / "command_center.sqlite")

    with sqlite3.connect(db_path) as conn:
        artifact_types = {row[0] for row in conn.execute("SELECT artifact_type FROM artifacts")}

    assert "summary_json" in artifact_types
    assert "campaign_manifest_json" in artifact_types
    assert "learning_snapshot_json" in artifact_types
    assert "mutation_effectiveness_json" in artifact_types
