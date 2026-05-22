from __future__ import annotations

from pathlib import Path

from kit import runner


def test_launch_runner_subprocess_uses_legacy_cli_args(monkeypatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    class FakeProcess:
        pid = 10101

    def _fake_popen(command, stdout, stderr, env):
        captured["command"] = command
        captured["stderr"] = stderr
        captured["env"] = env
        return FakeProcess()

    monkeypatch.setattr(runner.subprocess, "Popen", _fake_popen)

    exit_code, result = runner._launch_runner_subprocess(
        "repo",
        {
            "artifact_dir": str(tmp_path / "runs"),
            "repo_url": "https://github.com/example/repo",
            "output": str(tmp_path / "ignored.json"),
            "cli_only": False,
        },
    )

    assert exit_code == 0
    assert result["status"] == "started"
    command = captured["command"]
    assert command[0].endswith("python") or command[0].endswith("python3")
    assert command[1:5] == ["-m", "kit.runner", "--mode", "repo"]
    assert "run" not in command
