from __future__ import annotations

import json
import subprocess

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
    (tmp_path / "app.py").write_text('API_KEY = "sk-test-0000000000000000"\n')  # aletheia-redteam:allowed-test-fixture

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
    (tmp_path / "secrets.txt").write_text("-----BEGIN RSA PRIVATE KEY-----\nfixture\n-----END RSA PRIVATE KEY-----\n")  # aletheia-redteam:allowed-test-fixture

    summary = run_repo_audit(tmp_path)
    assert summary["findings_by_severity"]["CRITICAL"] >= 1
    assert summary["gates"]["pass"] is False


def test_repo_audit_detects_python_runtime_execution_risks(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "risky.py").write_text(
        """
import subprocess
cmd = input("cmd>")
eval(input("expr>"))  # aletheia-redteam:allowed-test-fixture
subprocess.run(cmd, shell=True)  # aletheia-redteam:allowed-test-fixture
""".strip()
    )

    summary = run_repo_audit(tmp_path)
    finding_types = {f["type"] for f in summary["findings"]}

    assert "python_dynamic_exec_untrusted" in finding_types
    assert "python_subprocess_shell_true" in finding_types
    assert summary["findings_by_severity"]["HIGH"] >= 2


def test_repo_audit_detects_javascript_and_weak_crypto_patterns(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "server.js").write_text(
        """
const crypto = require('crypto');
const { exec } = require('child_process');
function run(req) {
  exec(req.query.cmd);
  return crypto.createHash('sha1').update('x').digest('hex');
}
""".strip()
    )

    summary = run_repo_audit(tmp_path)
    finding_types = {f["type"] for f in summary["findings"]}

    assert "javascript_child_process_exec_untrusted" in finding_types
    assert "weak_hash_sha1" in finding_types


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


def test_repo_audit_enriches_dependency_advisories_from_pip_audit(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "pip-audit-report.json").write_text(
        json.dumps(
            {
                "dependencies": [
                    {
                        "name": "urllib3",
                        "version": "1.26.4",
                        "vulns": [
                            {
                                "id": "PYSEC-TEST-1",
                                "description": "Example advisory",
                                "fix_versions": ["1.26.5"],
                            }
                        ],
                    }
                ]
            }
        )
    )

    summary = run_repo_audit(tmp_path)
    finding_types = {f["type"] for f in summary["findings"]}

    assert "dependency_vulnerability" in finding_types
    assert any("PYSEC-TEST-1" in (f.get("title") or "") for f in summary["findings"])


def test_repo_audit_auto_runs_pip_audit_when_python_manifest_present(monkeypatch, tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )

    def _fake_run(*args, **kwargs):
        payload = {
            "dependencies": [
                {
                    "name": "urllib3",
                    "version": "1.26.4",
                    "vulns": [
                        {
                            "id": "PYSEC-TEST-AUTO",
                            "description": "Auto scan advisory",
                            "fix_versions": ["1.26.5"],
                        }
                    ],
                }
            ]
        }
        return subprocess.CompletedProcess(args=args, returncode=1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr("engine.repo_audit.scanner.shutil.which", lambda binary: f"/usr/bin/{binary}")
    monkeypatch.setattr("engine.repo_audit.scanner.subprocess.run", _fake_run)

    summary = run_repo_audit(tmp_path, deps_scan="auto")

    assert summary["dependencies"]["tools"]["pip_audit"]["status"] == "executed"
    assert summary["dependencies"]["findings_total"] >= 1
    assert summary["findings_by_type"].get("dependency_vulnerability", 0) >= 1


def test_repo_audit_applies_threat_feed_context(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "risky.py").write_text(
        """
import subprocess
cmd = input("cmd>")
subprocess.run(cmd, shell=True)  # aletheia-redteam:allowed-test-fixture
""".strip()
    )
    (tmp_path / "threat_feed.json").write_text(
        json.dumps(
            [
                {
                    "finding_type": "python_subprocess_shell_true",
                    "threat": "Command injection",
                    "reference": "https://example.test/command-injection",
                }
            ]
        )
    )

    summary = run_repo_audit(tmp_path)
    assert summary["threat_feed"]["matches_total"] >= 1
    assert summary["threat_feed"]["matches_by_type"]["python_subprocess_shell_true"] >= 1
    assert any(
        (f.get("type") == "python_subprocess_shell_true") and f.get("threat_context")
        for f in summary["findings"]
    )


def test_repo_audit_detects_high_entropy_secret_literals(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "settings.py").write_text(
        'SESSION_TOKEN = "a9Xk_12LmN-45pqR+stuVw8Y=zzA"\n'  # aletheia-redteam:allowed-test-fixture
    )

    summary = run_repo_audit(tmp_path)
    finding_types = {f["type"] for f in summary["findings"]}

    assert "high_entropy_secret_literal" in finding_types


def test_repo_audit_detects_config_drift_patterns(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "service.py").write_text(
        """
import requests
response = requests.get("https://example.test", verify=False)  # aletheia-redteam:allowed-test-fixture
jwt_opts = {"alg": "none"}  # aletheia-redteam:allowed-test-fixture
""".strip()
    )

    summary = run_repo_audit(tmp_path)
    finding_types = {f["type"] for f in summary["findings"]}

    assert "tls_verification_disabled" in finding_types
    assert "jwt_none_algorithm" in finding_types


def test_repo_audit_ignores_test_fixture_secrets_by_default(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_fixture.py").write_text('API_KEY = "sk-test-0000000000000000"\n')

    summary = run_repo_audit(tmp_path)

    assert summary["findings_by_type"].get("api_key_literal", 0) == 0
    assert summary["secret_scan"]["include_test_fixtures"] is False


def test_repo_audit_can_include_test_fixture_findings_with_override(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_fixture.py").write_text(
        'API_KEY = "sk-test-0000000000000000"\nsubprocess.run(cmd, shell=True)  # aletheia-redteam:allowed-test-fixture\n'
    )

    summary = run_repo_audit(tmp_path, include_test_fixtures=True)

    assert summary["findings_by_type"]["api_key_literal"] >= 1
    assert summary["findings_by_type"].get("python_subprocess_shell_true", 0) == 0
    assert summary["secret_scan"]["include_test_fixtures"] is True


def test_cli_repo_mode_can_include_test_fixture_secrets(monkeypatch, tmp_path) -> None:
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
    tests_dir = repo_dir / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_fixture.py").write_text('API_KEY = "sk-test-0000000000000000"\n')
    output = tmp_path / "repo_summary.json"

    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode",
            "repo",
            "--repo-path",
            str(repo_dir),
            "--repo-include-test-fixtures",
            "--output",
            str(output),
        ],
    )

    rc = runner.cli()
    assert rc == 0

    data = json.loads(output.read_text())
    assert data["findings_by_type"]["api_key_literal"] >= 1


def test_repo_audit_ignores_generated_summary_artifacts(tmp_path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
    )
    (tmp_path / "summary.json").write_text(
        '{"receipt": "-----BEGIN RSA PRIVATE KEY-----\\nfixture\\n-----END RSA PRIVATE KEY-----"}'
    )

    summary = run_repo_audit(tmp_path)

    assert summary["findings_by_severity"].get("CRITICAL", 0) == 0
    assert "summary.json" in summary["ignored_artifacts"]
