from __future__ import annotations

import json

from engine.repo_audit import run_repo_audit
from kit import runner


def test_repo_audit_detects_secret_literal(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "app.py").write_text('API_KEY = "supersecretvalue123456"\n')

    summary = run_repo_audit(tmp_path)

    assert summary["mode"] == "repo"
    assert summary["findings_total"] >= 1
    assert summary["findings_by_severity"]["HIGH"] >= 1
    assert any(f["type"] == "api_key_literal" for f in summary["findings"])


def test_repo_audit_gate_fails_on_critical_private_key(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "secrets.txt").write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")

    summary = run_repo_audit(tmp_path)
    assert summary["findings_by_severity"]["CRITICAL"] >= 1
    assert summary["gates"]["pass"] is False


def test_cli_repo_mode_writes_summary(monkeypatch, tmp_path) -> None:
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    (repo_dir / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (repo_dir / "README.md").write_text("ok\n")

    output = tmp_path / "repo_summary.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode",
            "repo",
            "--repo-path",
            str(repo_dir),
            "--output",
            str(output),
        ],
    )

    rc = runner.cli()
    assert rc == 0
    assert output.exists()

    data = json.loads(output.read_text())
    assert data["mode"] == "repo"
    assert data["repo_root"]
