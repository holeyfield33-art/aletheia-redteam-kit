from __future__ import annotations

import json
from pathlib import Path

from kit.dashboard_server import DashboardServerConfig, _normalize_run_entries


def test_normalize_run_entries_emits_hosted_artifact_urls(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "runs"
    artifact_dir.mkdir()
    (artifact_dir / "index.json").write_text(
        json.dumps(
            [
                {
                    "generated_at": "2026-05-07T00:00:00+00:00",
                    "mode": "combined",
                    "summary": "run-combined-1/summary.json",
                    "command_center": "run-combined-1/command_center.json",
                    "sqlite": "run-combined-1/command_center.sqlite",
                }
            ]
        ),
        encoding="utf-8",
    )

    entries = _normalize_run_entries(
        DashboardServerConfig(
            repo_root=tmp_path,
            artifact_dir=artifact_dir,
            dashboard_file=tmp_path / "dashboard/index.html",
        )
    )

    assert entries == [
        {
            "generated_at": "2026-05-07T00:00:00+00:00",
            "mode": "combined",
            "summary": "/runs/run-combined-1/summary.json",
            "command_center": "/runs/run-combined-1/command_center.json",
            "sqlite": "/runs/run-combined-1/command_center.sqlite",
        }
    ]