from __future__ import annotations

import base64
import json
from pathlib import Path

from kit.dashboard_server import DashboardServerConfig, _launch_public_repo_audit, _normalize_run_entries, _parse_basic_auth_header


def test_parse_basic_auth_header_round_trips_credentials() -> None:
    token = base64.b64encode(b"aletheia:secret").decode("ascii")
    assert _parse_basic_auth_header(f"Basic {token}") == ("aletheia", "secret")


def test_launch_public_repo_audit_builds_runner_command(monkeypatch, tmp_path: Path) -> None:
    captured = {}

    class FakeProcess:
        pid = 4242

    def _fake_popen(command, cwd, stdout, stderr):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["stdout_name"] = getattr(stdout, "name", "")
        captured["stderr"] = stderr
        return FakeProcess()

    monkeypatch.setattr("kit.dashboard_server.subprocess.Popen", _fake_popen)

    config = DashboardServerConfig(
        repo_root=tmp_path,
        artifact_dir=tmp_path / "runs",
        dashboard_file=tmp_path / "dashboard/index.html",
    )

    result = _launch_public_repo_audit(config, "https://github.com/example/public-repo")

    assert result["status"] == "started"
    assert result["resolved_repo_url"] == "https://github.com/example/public-repo.git"
    assert result["pid"] == 4242
    assert "--repo-url" in captured["command"]
    assert captured["cwd"] == str(tmp_path.resolve())
    assert (tmp_path / "runs" / ".launches").exists()


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