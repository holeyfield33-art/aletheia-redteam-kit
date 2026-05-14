from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from engine.repo_audit import run_repo_audit
from engine.repo_audit import scanner
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
    return crypto.createHash('sha1').update('x').digest('hex'); // nosec aletheia-redteam:allowed-test-fixture intentional weak hash fixture
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

def test_repo_audit_can_clone_public_github_repo(monkeypatch, tmp_path) -> None:
    created: dict[str, Path] = {}

    def _fake_run(cmd, *args, **kwargs):
        # Only simulate the git clone; other subprocess calls (e.g. pip-audit)
        # should succeed silently without touching created[].
        if cmd and cmd[0] == "git":
            clone_root = Path(cmd[-1])
            clone_root.mkdir(parents=True, exist_ok=True)
            (clone_root / "pyproject.toml").write_text(
                """
[project]
name = "sample"
version = "0.0.1"
dependencies = ["httpx>=0.27"]
""".strip()
            )
            (clone_root / "app.py").write_text('API_KEY = "sk-test-0000000000000000"\n')  # aletheia-redteam:allowed-test-fixture
            created["clone_root"] = clone_root
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr("engine.repo_audit.scanner.subprocess.run", _fake_run)

    summary = run_repo_audit(repo_url="https://github.com/example/public-sample")

    assert summary["source"]["kind"] == "github_public"
    assert summary["source"]["resolved"] == "https://github.com/example/public-sample.git"
    assert summary["repo_root"] == str(created["clone_root"])
    assert summary["findings_total"] >= 1
    assert any(f["type"] == "api_key_literal" for f in summary["findings"])

def test_normalize_public_github_repo_url_rejects_non_github() -> None:
    with pytest.raises(ValueError):
        scanner._normalize_public_github_repo_url("https://gitlab.com/example/repo")


def test_normalize_public_github_repo_url_rejects_non_root_path() -> None:
    with pytest.raises(ValueError):
        scanner._normalize_public_github_repo_url("https://github.com/example/repo/tree/main")


def test_normalize_public_github_repo_url_rejects_embedded_credentials() -> None:
    with pytest.raises(ValueError):
        scanner._normalize_public_github_repo_url("https://token@github.com/example/repo")


def test_clone_public_github_repo_times_out(monkeypatch, tmp_path) -> None:
    def _fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr("engine.repo_audit.scanner.subprocess.run", _fake_run)

    with pytest.raises(RuntimeError):
        scanner._clone_public_github_repo("https://github.com/example/public-sample", tmp_path / "clone")


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


def test_repo_audit_summarizes_top_vulnerable_dependencies(tmp_path) -> None:
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
                                "description": "High severity issue",
                                "severity": "HIGH",
                                "fix_versions": ["1.26.5"],
                            },
                            {
                                "id": "PYSEC-TEST-2",
                                "description": "Moderate follow-up issue",
                                "severity": "MODERATE",
                                "fix_versions": ["1.26.6"],
                            },
                        ],
                    },
                    {
                        "name": "requests-typos",
                        "version": "0.1.0",
                        "vulns": [
                            {
                                "id": "OSV-TYPOSQUAT-1",
                                "description": "Potential typosquatting package substitution",
                                "severity": "HIGH",
                                "fix_versions": ["remove-package"],
                            }
                        ],
                    },
                ]
            }
        )
    )

    summary = run_repo_audit(tmp_path)
    top_packages = summary["dependencies"]["top_packages"]

    assert top_packages[0]["name"] == "urllib3"
    assert top_packages[0]["advisory_count"] == 2
    assert top_packages[0]["max_severity"] == "HIGH"
    assert "PYSEC-TEST-1" in top_packages[0]["advisory_ids"]
    assert top_packages[1]["name"] == "requests-typos"
    assert top_packages[1]["finding_types"]["dependency_tampering_risk"] == 1


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


# ---------------------------------------------------------------------------
# Phase 3: scan profile tests
# ---------------------------------------------------------------------------

def test_resolve_scan_profile_medium_is_default() -> None:
    from engine.repo_audit.scanner import _resolve_scan_profile, SCAN_PROFILE_MEDIUM
    assert _resolve_scan_profile(None) == set(SCAN_PROFILE_MEDIUM)
    assert _resolve_scan_profile("medium") == set(SCAN_PROFILE_MEDIUM)


def test_resolve_scan_profile_light() -> None:
    from engine.repo_audit.scanner import _resolve_scan_profile, SCAN_PROFILE_LIGHT
    assert _resolve_scan_profile("light") == set(SCAN_PROFILE_LIGHT)
    assert "dep_advisories" not in _resolve_scan_profile("light")


def test_resolve_scan_profile_full() -> None:
    from engine.repo_audit.scanner import _resolve_scan_profile, SCAN_PROFILE_FULL
    result = _resolve_scan_profile("full")
    assert result == set(SCAN_PROFILE_FULL)
    assert "semgrep" in result
    assert "bandit" in result
    assert "trivy" in result
    assert "npm_audit" in result


def test_resolve_scan_profile_custom(tmp_path) -> None:
    from engine.repo_audit.scanner import _resolve_scan_profile
    profile_file = tmp_path / "profile.json"
    profile_file.write_text(json.dumps({"scanners": ["secrets", "bandit"]}))
    result = _resolve_scan_profile("custom", str(profile_file))
    assert result == {"secrets", "bandit"}


def test_resolve_scan_profile_custom_requires_file() -> None:
    from engine.repo_audit.scanner import _resolve_scan_profile
    with pytest.raises(ValueError, match="--scan-profile-file"):
        _resolve_scan_profile("custom", None)


def test_resolve_scan_profile_unknown_raises() -> None:
    from engine.repo_audit.scanner import _resolve_scan_profile
    with pytest.raises(ValueError, match="Unknown scan profile"):
        _resolve_scan_profile("bogus")


def test_scan_profile_light_skips_dep_advisories(tmp_path) -> None:
    """Light profile must NOT trigger dependency advisory scanning."""
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = \"sample\"\nversion = \"0.0.1\"\ndependencies = []\n"
    )
    summary = run_repo_audit(tmp_path, scan_profile="light")
    # When dep_advisories is skipped, the dependencies summary reflects it.
    assert "dep_advisories" not in summary.get("enabled_scanners", [])
    assert summary["scan_profile"] == "light"


def test_run_repo_audit_scan_profile_stored_in_summary(tmp_path) -> None:
    summary = run_repo_audit(tmp_path, scan_profile="medium")
    assert summary["scan_profile"] == "medium"


def test_semgrep_unavailable_returns_tool_status(tmp_path) -> None:
    from engine.repo_audit.scanner import _scan_semgrep
    import shutil as _shutil
    orig = _shutil.which

    def _no_semgrep(name):
        if name == "semgrep":
            return None
        return orig(name)

    import unittest.mock as _mock
    with _mock.patch("shutil.which", side_effect=_no_semgrep):
        findings, meta = _scan_semgrep(tmp_path)
    assert findings == []
    assert meta["semgrep"]["status"] == "unavailable"


def test_bandit_unavailable_returns_tool_status(tmp_path) -> None:
    from engine.repo_audit.scanner import _scan_bandit
    import shutil as _shutil
    import unittest.mock as _mock
    orig = _shutil.which

    def _no_bandit(name):
        if name == "bandit":
            return None
        return orig(name)

    with _mock.patch("shutil.which", side_effect=_no_bandit):
        findings, meta = _scan_bandit(tmp_path)
    assert findings == []
    assert meta["bandit"]["status"] == "unavailable"


def test_trivy_unavailable_returns_tool_status(tmp_path) -> None:
    from engine.repo_audit.scanner import _scan_trivy
    import shutil as _shutil
    import unittest.mock as _mock
    orig = _shutil.which

    def _no_trivy(name):
        if name == "trivy":
            return None
        return orig(name)

    with _mock.patch("shutil.which", side_effect=_no_trivy):
        findings, meta = _scan_trivy(tmp_path)
    assert findings == []
    assert meta["trivy"]["status"] == "unavailable"


def test_npm_audit_no_package_json_returns_skipped(tmp_path) -> None:
    from engine.repo_audit.scanner import _scan_npm_audit
    import shutil as _shutil
    import unittest.mock as _mock

    def _fake_which(name):
        return "/usr/bin/npm" if name == "npm" else _shutil.which(name)

    with _mock.patch("shutil.which", side_effect=_fake_which):
        findings, meta = _scan_npm_audit(tmp_path)
    assert findings == []
    assert meta["npm_audit"]["status"] == "skipped"


def test_run_repo_audit_token_not_in_summary(tmp_path, monkeypatch) -> None:
    """Token must never appear in the source.resolved or source.value fields."""
    import unittest.mock as _mock

    def _fake_clone(repo_url, clone_root, *, token=None):
        clone_root.mkdir(parents=True, exist_ok=True)
        return clone_root, "https://github.com/example/private-repo.git"

    monkeypatch.setattr(scanner, "_clone_github_repo", _fake_clone)
    summary = run_repo_audit(
        repo_url="https://github.com/example/private-repo",
        repo_token="super-secret-token-abc123",
    )
    summary_json = json.dumps(summary)
    assert "super-secret-token-abc123" not in summary_json
    assert summary["source"]["authenticated"] is True
    assert summary["source"]["kind"] == "github_private"


def test_cli_repo_mode_with_scan_profile(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    output = tmp_path / "repo_summary.json"
    captured: dict = {}

    def _fake_run_repo_audit(repo_path, repo_url=None, threat_feed_path=None,
                              include_test_fixtures=False, deps_scan="auto",
                              repo_token=None, scan_profile=None, scan_profile_file=None,
                              **_kwargs):
        captured["scan_profile"] = scan_profile
        captured["repo_token"] = repo_token
        return {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "mode": "repo",
            "repo_root": str(repo_path),
            "scan_profile": scan_profile or "medium",
            "files_scanned": 0,
            "findings_total": 0,
            "findings_by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "findings_by_type": {},
            "risk_score": 100,
            "gates": {"pass": True, "violations": []},
            "findings": [],
        }

    monkeypatch.setattr(runner, "run_repo_audit", _fake_run_repo_audit)
    monkeypatch.setattr(
        "sys.argv",
        [
            "kit.runner",
            "--mode", "repo",
            "--repo-path", str(tmp_path),
            "--scan-profile", "full",
            "--output", str(output),
        ],
    )

    rc = runner.cli()
    assert rc == 0
    assert captured["scan_profile"] == "full"
    assert captured["repo_token"] is None
